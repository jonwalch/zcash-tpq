//! Private watch state and a durable payment journal. Recovery authority remains
//! the encrypted manifest; losing the journal requires pending-payment
//! reconciliation. Filesystem paths and cached coins never establish chain validity.
use crate::{
    canonical, scan::Scan, ChainSource, Checkpoint, Coin, Error, Hex, Manifest, Profile, Receiver,
    ScanStatus,
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(crate) mod archive;

const MAX_STATE: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// The public watcher role; only an allocator can issue receivers.
pub enum WatchMode {
    Monitor,
    Allocator,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    format: String,
    pub manifest: Manifest,
    pub(crate) mode: WatchMode,
    pub(crate) payments: crate::payment::Book,
    receive_next: u64,
    scan: Scan,
    #[serde(skip)]
    pub(crate) journal: Option<archive::Root>,
}
impl State {
    fn validate(&self) -> Result<(), Error> {
        if self.format != "ZcashTransparentPQ/watch-state/v2" {
            return Err(Error::UnsupportedFormat);
        }
        self.manifest.validate()?;
        if self.receive_next < self.manifest.retired_receive_end
            || self.receive_next > self.manifest.receive_end
        {
            return Err(Error::RecoveryIncomplete);
        }
        self.scan.validate(&self.manifest)?;
        self.payments.validate(&self.manifest)
    }
}

/// One locked local allocator/monitor. Keep its directory and ancestors trusted
/// and stable. Copying a live allocator directory is unsupported. After loss,
/// restore/retire the covered inventory and reconcile the previous allocator.
pub struct WatchStore {
    path: PathBuf,
    directory: File,
    _lock: File,
    pub(crate) state: State,
    poisoned: bool,
    pub(crate) journal_usage: Option<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StateStage {
    Journal(crate::journal::Stage),
    FileWrite,
    FileSync,
    Publish,
    DirectorySync,
}

impl WatchStore {
    pub(crate) fn journal_path(&self) -> Result<&Path, Error> {
        self.ready()?;
        Ok(&self.path)
    }

    pub(crate) fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Create a new private watcher from an independently authenticated inventory.
    pub fn create(
        path: &Path,
        bytes: &[u8],
        approved: Hex<32>,
        profile: &Profile,
        mode: WatchMode,
    ) -> Result<Self, Error> {
        let manifest = paired(bytes, approved, profile)?;
        #[cfg(not(unix))]
        {
            let _ = (path, manifest, mode);
            Err(Error::UnsupportedContext)
        }
        #[cfg(unix)]
        {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(Error::Storage)?;
            let (directory, lock) = open_lock(path)?;
            let state = State {
                format: "ZcashTransparentPQ/watch-state/v2".into(),
                payments: crate::payment::Book {
                    change_next: manifest.retired_change_end,
                    ..Default::default()
                },
                receive_next: manifest.retired_receive_end,
                /// The validated cumulative public inventory.
                manifest,
                mode,
                scan: Scan::default(),
                journal: None,
            };
            let mut store = Self {
                path: path.into(),
                directory,
                _lock: lock,
                state: state.clone(),
                poisoned: false,
                journal_usage: None,
            };
            store.commit(state)?;
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            File::open(parent)
                .and_then(|f| f.sync_all())
                .map_err(Error::Storage)?;
            Ok(store)
        }
    }

    /// Open and lock existing private state against the approved profile.
    pub fn open(path: &Path, profile: &Profile) -> Result<Self, Error> {
        profile.validate()?;
        let (directory, lock) = open_lock(path)?;
        let bytes = read_private(&path.join("state.json"), archive::MAX_V3)?;
        let state = archive::decode(&bytes)?;
        state.validate()?;
        if &state.manifest.profile != profile {
            return Err(Error::UnsupportedContext);
        }
        let mut store = Self {
            path: path.into(),
            directory,
            _lock: lock,
            state,
            poisoned: false,
            journal_usage: None,
        };
        if store.state.journal.is_some() {
            store.load_v3()?;
        }
        Ok(store)
    }

    /// The validated cumulative public inventory.
    pub fn manifest(&self) -> &Manifest {
        &self.state.manifest
    }
    /// Whether this watcher owns the receiver allocator.
    pub fn mode(&self) -> WatchMode {
        self.state.mode
    }
    /// The monotonic next receive index, including retired ranges.
    pub fn receive_next(&self) -> u64 {
        self.state.receive_next
    }
    /// Cached observed coins; current node unspentness is checked separately.
    pub fn coins(&self) -> &[Coin] {
        &self.state.scan.coins
    }
    /// Cached scan completeness and balance; unavailable history is incomplete.
    pub fn status(&self) -> Result<ScanStatus, Error> {
        self.ready()?;
        self.state.scan.status(&self.state.manifest)
    }

    /// The supplied fingerprint must come from authenticated pairing, not from
    /// simply hashing the same untrusted file. Extensions/earlier birthdays
    /// restart discovery; unchanged allocator IDs preserve every reservation.
    pub fn import(&mut self, bytes: &[u8], approved: Hex<32>) -> Result<(), Error> {
        self.ready()?;
        let manifest = paired(bytes, approved, &self.state.manifest.profile)?;
        self.state.manifest.check_update(&manifest)?;
        if manifest == self.state.manifest {
            return Ok(());
        }
        let mut candidate = self.state.clone();
        if manifest.entries != candidate.manifest.entries
            || manifest.birthday_height != candidate.manifest.birthday_height
        {
            candidate.scan = Scan::default();
        }
        if manifest.allocator_id != candidate.manifest.allocator_id {
            // An old allocator cannot silently claim the replacement identity.
            candidate.mode = WatchMode::Monitor;
        }
        candidate.receive_next = candidate.receive_next.max(manifest.retired_receive_end);
        candidate.payments.change_next = candidate
            .payments
            .change_next
            .max(manifest.retired_change_end);
        candidate.manifest = manifest;
        self.commit(candidate)
    }

    /// Burn the next receive slot durably before revealing it. Crashes/output
    /// failures can skip a slot; they must not cause it to be returned again.
    pub fn receive(&mut self) -> Result<Receiver, Error> {
        self.receive_with_hook(|_| Ok(()))
    }

    fn receive_with_hook(
        &mut self,
        hook: impl FnMut(StateStage) -> Result<(), Error>,
    ) -> Result<Receiver, Error> {
        self.ready()?;
        if self.state.mode != WatchMode::Allocator {
            return Err(Error::MonitorOnly);
        }
        if self.state.receive_next == self.state.manifest.receive_end {
            return Err(Error::Exhausted);
        }
        let entry = self
            .state
            .manifest
            .entries
            .iter()
            .find(|entry| {
                entry.role == 0
                    && entry
                        .local(self.state.manifest.wallet_id)
                        .is_ok_and(|(_, origin)| u64::from(origin.index) == self.state.receive_next)
            })
            .ok_or(Error::RecoveryIncomplete)?;
        self.manifest()
            .profile
            .check_policy(&entry.suite_policy()?)?;
        let receiver = entry.receiver()?;
        let mut candidate = self.state.clone();
        candidate.receive_next = candidate
            .receive_next
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        self.commit_with_hook(candidate, hook)?;
        Ok(receiver)
    }

    /// Synchronize up to max_blocks and persist after every block/rollback.
    /// No mempool receipt is included. Unavailable or inconsistent history is
    /// an error with incomplete cached status, not a zero/current balance.
    pub fn sync(
        &mut self,
        source: &mut impl ChainSource,
        max_blocks: u32,
    ) -> Result<ScanStatus, Error> {
        self.ready()?;
        if max_blocks == 0 || max_blocks > 10_000 {
            return Err(Error::Limits);
        }
        let mut candidate = self.state.clone();
        candidate.scan.complete = false;
        candidate.scan.context = None;
        self.commit(candidate)?;
        let context = source.context()?;
        context.validate(&self.state.manifest)?;
        if source.block_hash(0)? != self.state.manifest.profile.genesis_hash {
            return Err(Error::UnsupportedContext);
        }
        if source.block_hash(context.tip.height)? != context.tip.hash {
            return Err(Error::ChainChanged);
        }
        if self.state.manifest.birthday_height > context.tip.height {
            return Err(Error::HistoryUnavailable);
        }
        loop {
            let Some(point) = self.state.scan.checkpoint else {
                if let Some(height) = self.state.manifest.birthday_height.checked_sub(1) {
                    let mut candidate = self.state.clone();
                    candidate.scan.checkpoint = Some(Checkpoint {
                        height,
                        hash: source.block_hash(height)?,
                    });
                    self.commit(candidate)?;
                }
                break;
            };
            if point.height <= context.tip.height && source.block_hash(point.height)? == point.hash
            {
                break;
            }
            let mut candidate = self.state.clone();
            candidate.scan.rollback();
            self.commit(candidate)?;
        }
        for _ in 0..max_blocks {
            let next = self
                .state
                .scan
                .checkpoint
                .map_or(0, |p| u64::from(p.height) + 1);
            if next > u64::from(context.tip.height) {
                break;
            }
            let height = u32::try_from(next).map_err(|_| Error::Limits)?;
            let point = Checkpoint {
                height,
                hash: source.block_hash(height)?,
            };
            let bytes = source.block_bytes(point.hash)?;
            let mut candidate = self.state.clone();
            let observed_change_end = candidate.scan.apply(&candidate.manifest, point, &bytes)?;
            candidate.payments.change_next =
                candidate.payments.change_next.max(observed_change_end);
            if source.block_hash(height)? != point.hash {
                return Err(Error::ChainChanged);
            }
            self.commit(candidate)?;
        }
        if self.state.scan.checkpoint == Some(context.tip) {
            if source.context()? != context
                || source.block_hash(context.tip.height)? != context.tip.hash
            {
                return Err(Error::ChainChanged);
            }
            let mut candidate = self.state.clone();
            candidate.scan.context = Some(context);
            candidate.scan.complete = true;
            self.commit(candidate)?;
        }
        self.status()
    }

    pub(crate) fn ready(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::ReopenRequired)
        } else {
            Ok(())
        }
    }

    pub(crate) fn commit(&mut self, candidate: State) -> Result<(), Error> {
        self.commit_with_hook(candidate, |_| Ok(()))
    }

    pub(crate) fn commit_with_hook(
        &mut self,
        mut candidate: State,
        mut hook: impl FnMut(StateStage) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.ready()?;
        candidate.validate()?;
        if candidate.journal.is_some() {
            if let Err(error) = self.stage_v3(&mut candidate, &mut hook) {
                if matches!(error, Error::JournalCorrupt | Error::Storage(_)) {
                    self.poison();
                }
                return Err(error);
            }
        } else if self.state.journal.is_some() {
            return Err(Error::JournalCorrupt);
        }
        let bytes = archive::encode(&candidate)?;
        let result = (|| {
            let mut temporary = tempfile::Builder::new()
                .prefix(".watch-")
                .tempfile_in(&self.path)
                .map_err(Error::Storage)?;
            hook(StateStage::FileWrite)?;
            temporary.write_all(&bytes).map_err(Error::Storage)?;
            hook(StateStage::FileSync)?;
            temporary.as_file().sync_all().map_err(Error::Storage)?;
            hook(StateStage::Publish)?;
            temporary
                .persist(self.path.join("state.json"))
                .map_err(|e| Error::Storage(e.error))?;
            hook(StateStage::DirectorySync)?;
            self.directory.sync_all().map_err(Error::Storage)
        })();
        if let Err(error) = result {
            self.poisoned = true;
            return Err(error);
        }
        self.state = candidate;
        Ok(())
    }
}

// V1 never held payment reservations. Preserve pairing/receive issuance but
// rescan active history to record even previously spent change addresses.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyState {
    format: String,
    manifest: Manifest,
    mode: WatchMode,
    receive_next: u64,
    scan: Scan,
}
impl LegacyState {
    fn migrate(self) -> Result<State, Error> {
        if self.format != "ZcashTransparentPQ/watch-state/v1" {
            return Err(Error::UnsupportedFormat);
        }
        self.scan.validate(&self.manifest)?;
        let state = State {
            format: "ZcashTransparentPQ/watch-state/v2".into(),
            payments: crate::payment::Book {
                change_next: self.manifest.retired_change_end,
                ..Default::default()
            },
            manifest: self.manifest,
            mode: self.mode,
            receive_next: self.receive_next,
            scan: Scan::default(),
            journal: None,
        };
        state.validate()?;
        Ok(state)
    }
}

fn paired(bytes: &[u8], approved: Hex<32>, profile: &Profile) -> Result<Manifest, Error> {
    profile.validate()?;
    let manifest = Manifest::from_json(bytes)?;
    if &manifest.profile != profile {
        return Err(Error::UnsupportedContext);
    }
    if manifest.fingerprint()? != approved {
        return Err(Error::Pairing);
    }
    Ok(manifest)
}

#[cfg(unix)]
fn open_lock(path: &Path) -> Result<(File, File), Error> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(Error::Storage)?;
    if directory
        .metadata()
        .map_err(Error::Storage)?
        .permissions()
        .mode()
        & 0o077
        != 0
    {
        return Err(Error::RecoveryIncomplete);
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.join("allocator.lock"))
        .map_err(Error::Storage)?;
    let meta = lock.metadata().map_err(Error::Storage)?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        return Err(Error::RecoveryIncomplete);
    }
    lock.try_lock().map_err(|_| Error::Locked)?;
    Ok((directory, lock))
}
#[cfg(not(unix))]
fn open_lock(_path: &Path) -> Result<(File, File), Error> {
    Err(Error::UnsupportedContext)
}

/// Read public transfer files with a byte bound. Final symlinks/nonregular files
/// are rejected; the caller must trust the containing directory and ancestors.
pub fn read_inventory(path: &Path) -> Result<Vec<u8>, Error> {
    read_private(path, crate::manifest::MAX_PLAINTEXT)
}

/// Read a bounded public payment transfer using the same private-file rules.
pub fn read_transfer(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    if limit > crate::manifest::MAX_PLAINTEXT {
        return Err(Error::Limits);
    }
    read_private(path, limit)
}

#[cfg(unix)]
fn read_private(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(Error::Storage)?;
    let meta = file.metadata().map_err(Error::Storage)?;
    if !meta.is_file() || meta.len() > limit as u64 || meta.permissions().mode() & 0o077 != 0 {
        return Err(Error::Limits);
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(Error::Storage)?;
    if bytes.len() > limit {
        return Err(Error::Limits);
    }
    Ok(bytes)
}
#[cfg(not(unix))]
fn read_private(_path: &Path, _limit: usize) -> Result<Vec<u8>, Error> {
    Err(Error::UnsupportedContext)
}

/// Publish a new public inventory without clobbering an existing file. Callers
/// must have verified a durable backup covering this manifest before transfer.
#[cfg(unix)]
pub fn export_inventory(manifest: &Manifest, path: &Path) -> Result<(), Error> {
    let bytes = manifest.to_json()?;
    write_transfer(path, &bytes)
}

/// Publish public proposal/partial bytes without replacing an existing file.
/// This is storage, not schema validation; callers use the typed encoders first.
#[cfg(unix)]
pub fn write_transfer(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > crate::manifest::MAX_PLAINTEXT {
        return Err(Error::Limits);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
        .map_err(Error::Storage)?;
    let mut file = tempfile::Builder::new()
        .prefix(".inventory-")
        .tempfile_in(parent)
        .map_err(Error::Storage)?;
    file.write_all(bytes).map_err(Error::Storage)?;
    file.as_file().sync_all().map_err(Error::Storage)?;
    file.persist_noclobber(path)
        .map_err(|e| Error::Storage(e.error))?;
    directory.sync_all().map_err(Error::Storage)
}
#[cfg(not(unix))]
pub fn export_inventory(_manifest: &Manifest, _path: &Path) -> Result<(), Error> {
    Err(Error::UnsupportedContext)
}
#[cfg(not(unix))]
pub fn write_transfer(_path: &Path, _bytes: &[u8]) -> Result<(), Error> {
    Err(Error::UnsupportedContext)
}

#[cfg(test)]
pub(crate) mod tests;
