//! Recovery coordinates existing encrypted backups and coherent private watch stores.
//! A receipt binds bytes; only independently trusted provenance establishes known authority.
use crate::{
    canonical, storage, watch::archive::JournalSnapshotMetadata, Error, Hex, Profile, Wallet,
    WatchMode, WatchStore,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

const FORMAT: &str = "ZcashTransparentPQ/operational-snapshot-receipt/v1";
const MAX_RECEIPT: usize = 4096;
const MAX_ROOT_FILES: u64 = 4096;
const MAX_ROOT_BYTES: u64 = 128 * 1024 * 1024;

/// Independently supplied recovery authority. Hashing an untrusted receipt does
/// not establish trust, backup freshness, or that another allocator has stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotTrust {
    /// The snapshot's completeness is unknown; restore remains monitor-only.
    Unknown,
    /// The caller independently retained this trusted receipt, reconciled the
    /// latest authority generation, and retired every previous allocator.
    KnownAuthority {
        /// Fingerprint received through the trusted backup/receipt channel.
        trusted_receipt: Hex<32>,
    },
}

/// Public receipt for an exact encrypted backup and coherent existing store.
/// Retain this through a protected channel if known-authority recovery is needed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotReceipt {
    backup_sha256: Hex<32>,
    change_next: u64,
    format: String,
    inventory_fingerprint: Hex<32>,
    journal: JournalSnapshotMetadata,
    profile: Profile,
    receive_next: u64,
    state_sha256: Hex<32>,
    suite: u8,
    wallet_id: Hex<16>,
}
impl SnapshotReceipt {
    /// Validate and decode the bounded canonical receipt.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let receipt: Self = canonical::decode(bytes, MAX_RECEIPT)?;
        receipt.validate()?;
        Ok(receipt)
    }
    /// Encode exact bounded canonical metadata, without asserting provenance.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        Ok(canonical::encode(self, MAX_RECEIPT)?.to_vec())
    }
    /// Domain-separated identity to retain independently of the snapshot files.
    pub fn fingerprint(&self) -> Result<Hex<32>, Error> {
        let mut hash = Sha256::new();
        hash.update(b"ZcashTransparentPQ/operational-snapshot-receipt/v1\0");
        hash.update(self.to_json()?);
        Ok(Hex(hash.finalize().into()))
    }
    /// The captured journal generation, absent for a legacy v2 store.
    pub fn generation(&self) -> Option<u64> {
        self.journal.generation
    }
    fn validate(&self) -> Result<(), Error> {
        if self.format != FORMAT || self.suite != crate::Suite::SlhDsaB128sExpV1.byte() {
            return Err(Error::UnsupportedFormat);
        }
        self.profile.validate()?;
        if self.journal.generation.is_some() != self.journal.journal_id.is_some()
            || self.receive_next > 1u64 << 32
            || self.change_next > 1u64 << 32
        {
            return Err(Error::RecoveryIncomplete);
        }
        Ok(())
    }
}

/// An unlocked restored root, its locked watcher, and explicit authority status.
/// Observations remain cached until trusted-node synchronization; fresh issuance
/// starts only after new enrollment and its covering durable backup.
pub struct RestoredWallet {
    /// Root reconstructed from the authenticated encrypted backup.
    pub wallet: Wallet,
    /// Restored public history and durable reservations, locked in the new directory.
    pub watch: WatchStore,
    /// Whether independently trusted snapshot completeness was asserted.
    pub authority: SnapshotTrust,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryStage {
    Copy,
    Verify,
    Publish,
    DirectorySync,
}

impl WatchStore {
    /// Capture the exact encrypted backup and coherent existing watch/journal
    /// files under this allocator lock. The destination must be a NEW directory
    /// beneath a trusted stable parent. Retain the returned receipt independently.
    pub fn save_operational_snapshot(
        &mut self,
        backup: &Path,
        password: &[u8],
        destination: &Path,
    ) -> Result<SnapshotReceipt, Error> {
        self.save_snapshot_with_hook(backup, password, destination, |_| Ok(()))
    }

    pub(crate) fn save_snapshot_with_hook(
        &mut self,
        backup: &Path,
        password: &[u8],
        destination: &Path,
        mut hook: impl FnMut(RecoveryStage) -> Result<(), Error>,
    ) -> Result<SnapshotReceipt, Error> {
        let encrypted = storage::read_file(backup)?;
        let wallet = Wallet::decrypt(&encrypted, password, &self.manifest().profile)?;
        if wallet.manifest() != self.manifest() {
            return Err(Error::RecoveryIncomplete);
        }
        let snapshot = self.journal_snapshot()?;
        let receipt = SnapshotReceipt {
            backup_sha256: digest(&encrypted),
            change_next: snapshot.change_next(),
            format: FORMAT.into(),
            inventory_fingerprint: snapshot.manifest().fingerprint()?,
            journal: snapshot.metadata().clone(),
            profile: snapshot.manifest().profile.clone(),
            receive_next: snapshot.receive_next(),
            state_sha256: hash_private(
                &snapshot.directory()?.join("state.json"),
                crate::watch::archive::MAX_V3 as u64,
            )?,
            suite: snapshot.manifest().suite,
            wallet_id: snapshot.manifest().wallet_id,
        };
        let staging = staging(destination)?;
        hook(RecoveryStage::Copy)?;
        copy_watch(
            snapshot.directory()?,
            &staging.path().join("watch"),
            &receipt.journal,
        )?;
        write_private(&staging.path().join("backup.tpq"), &encrypted)?;
        write_private(&staging.path().join("receipt.json"), &receipt.to_json()?)?;
        hook(RecoveryStage::Verify)?;
        let mut copied = WatchStore::open(&staging.path().join("watch"), &receipt.profile)?;
        check_snapshot(&mut copied, &receipt, &encrypted)?;
        drop(copied);
        publish(staging, destination, &mut hook)?;
        Ok(receipt)
    }
}

/// Restore an encrypted inventory into a NEW private directory, retire issuance
/// ranges and rotate the allocator. This mode has no known payment-authority
/// history and therefore always returns a monitor. `approved_inventory` must
/// come from independently reconciled latest available backup inventory.
pub fn restore_inventory(
    backup: &Path,
    password: &[u8],
    profile: &Profile,
    approved_inventory: Hex<32>,
    destination: &Path,
) -> Result<RestoredWallet, Error> {
    let encrypted = storage::read_file(backup)?;
    let mut wallet = Wallet::decrypt(&encrypted, password, profile)?;
    if wallet.manifest().fingerprint()? != approved_inventory {
        return Err(Error::Pairing);
    }
    let staging = staging(destination)?;
    write_private(&staging.path().join("backup-original.tpq"), &encrypted)?;
    wallet.retire_for_restore()?;
    wallet.save_backup(&staging.path().join("backup-restored.tpq"), password)?;
    let watch = WatchStore::create(
        &staging.path().join("watch"),
        &wallet.manifest().to_json()?,
        wallet.manifest().fingerprint()?,
        profile,
        WatchMode::Monitor,
    )?;
    drop(watch);
    publish(staging, destination, &mut |_| Ok(()))?;
    let watch = WatchStore::open(&destination.join("watch"), profile)?;
    Ok(RestoredWallet {
        wallet,
        watch,
        authority: SnapshotTrust::Unknown,
    })
}

/// Restore ONLY from the documented snapshot directory: exact `backup.tpq`,
/// `receipt.json` and coherent `watch/` copy. Validation never authenticates a
/// replacement snapshot's completeness. Unknown authority stays monitor-only,
/// including after empty-mempool observations and restarts. Existing state is
/// never overwritten. Known authority still requires trusted-node reconciliation.
pub fn restore_operational_snapshot(
    source: &Path,
    password: &[u8],
    profile: &Profile,
    trust: SnapshotTrust,
    destination: &Path,
) -> Result<RestoredWallet, Error> {
    private_directory(source)?;
    let receipt = SnapshotReceipt::from_json(&crate::read_transfer(
        &source.join("receipt.json"),
        MAX_RECEIPT,
    )?)?;
    if &receipt.profile != profile {
        return Err(Error::UnsupportedContext);
    }
    if let SnapshotTrust::KnownAuthority { trusted_receipt } = trust {
        if receipt.fingerprint()? != trusted_receipt {
            return Err(Error::Pairing);
        }
    }
    let encrypted = storage::read_file(&source.join("backup.tpq"))?;
    let mut wallet = Wallet::decrypt(&encrypted, password, profile)?;
    let mut original = WatchStore::open(&source.join("watch"), profile)?;
    check_snapshot(&mut original, &receipt, &encrypted)?;
    if wallet.manifest() != original.manifest() {
        return Err(Error::RecoveryIncomplete);
    }
    let staging = staging(destination)?;
    let snapshot = original.journal_snapshot()?;
    copy_watch(
        snapshot.directory()?,
        &staging.path().join("watch"),
        snapshot.metadata(),
    )?;
    write_private(&staging.path().join("backup-original.tpq"), &encrypted)?;
    write_private(
        &staging.path().join("recovery-receipt.json"),
        &receipt.to_json()?,
    )?;
    let mut copied = WatchStore::open(&staging.path().join("watch"), profile)?;
    check_snapshot(&mut copied, &receipt, &encrypted)?;
    wallet.retire_for_restore()?;
    wallet.save_backup(&staging.path().join("backup-restored.tpq"), password)?;
    copied.restore_reconciled_inventory(
        wallet.manifest(),
        matches!(trust, SnapshotTrust::KnownAuthority { .. }),
    )?;
    // Revalidate every retained authoritative object after manifest rotation.
    copied.journal_snapshot()?;
    drop(copied);
    publish(staging, destination, &mut |_| Ok(()))?;
    let watch = WatchStore::open(&destination.join("watch"), profile)?;
    Ok(RestoredWallet {
        wallet,
        watch,
        authority: trust,
    })
}

fn check_snapshot(
    store: &mut WatchStore,
    receipt: &SnapshotReceipt,
    encrypted: &[u8],
) -> Result<(), Error> {
    let snapshot = store.journal_snapshot()?;
    if digest(encrypted) != receipt.backup_sha256
        || snapshot.manifest().fingerprint()? != receipt.inventory_fingerprint
        || snapshot.manifest().profile != receipt.profile
        || snapshot.manifest().wallet_id != receipt.wallet_id
        || snapshot.manifest().suite != receipt.suite
        || snapshot.receive_next() != receipt.receive_next
        || snapshot.change_next() != receipt.change_next
        || snapshot.metadata() != &receipt.journal
        || hash_private(
            &snapshot.directory()?.join("state.json"),
            crate::watch::archive::MAX_V3 as u64,
        )? != receipt.state_sha256
    {
        return Err(Error::RecoveryIncomplete);
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> Hex<32> {
    Hex(Sha256::digest(bytes).into())
}

fn parent(path: &Path) -> Result<&Path, Error> {
    if path.file_name().is_none() {
        return Err(Error::Encoding);
    }
    Ok(path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new(".")))
}

fn staging(destination: &Path) -> Result<tempfile::TempDir, Error> {
    let parent = parent(destination)?;
    open_directory(parent)?;
    if fs::symlink_metadata(destination).is_ok() {
        return Err(Error::Storage(std::io::ErrorKind::AlreadyExists.into()));
    }
    tempfile::Builder::new()
        .prefix(".tpq-restore-")
        .tempdir_in(parent)
        .map_err(Error::Storage)
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn publish(
    staging: tempfile::TempDir,
    destination: &Path,
    hook: &mut impl FnMut(RecoveryStage) -> Result<(), Error>,
) -> Result<(), Error> {
    private_directory(staging.path())?
        .sync_all()
        .map_err(Error::Storage)?;
    let parent = open_directory(parent(destination)?)?;
    hook(RecoveryStage::Publish)?;
    rustix::fs::renameat_with(
        &parent,
        staging.path().file_name().ok_or(Error::Encoding)?,
        &parent,
        destination.file_name().ok_or(Error::Encoding)?,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| Error::Storage(error.into()))?;
    // The temporary name no longer exists; do not remove the published destination.
    let _old_name = staging.keep();
    hook(RecoveryStage::DirectorySync)?;
    parent.sync_all().map_err(Error::Storage)
}
#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn publish(
    _staging: tempfile::TempDir,
    _destination: &Path,
    _hook: &mut impl FnMut(RecoveryStage) -> Result<(), Error>,
) -> Result<(), Error> {
    Err(Error::UnsupportedContext)
}

#[cfg(unix)]
fn open_directory(path: &Path) -> Result<File, Error> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(Error::Storage)
}
#[cfg(not(unix))]
fn open_directory(_path: &Path) -> Result<File, Error> {
    Err(Error::UnsupportedContext)
}

#[cfg(unix)]
fn private_directory(path: &Path) -> Result<File, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(Error::Storage)?;
    if file
        .metadata()
        .map_err(Error::Storage)?
        .permissions()
        .mode()
        & 0o077
        != 0
    {
        return Err(Error::RecoveryIncomplete);
    }
    Ok(file)
}
#[cfg(not(unix))]
fn private_directory(_path: &Path) -> Result<File, Error> {
    Err(Error::UnsupportedContext)
}

#[cfg(unix)]
fn create_directory(path: &Path) -> Result<(), Error> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(Error::Storage)
}
#[cfg(not(unix))]
fn create_directory(_path: &Path) -> Result<(), Error> {
    Err(Error::UnsupportedContext)
}

#[cfg(unix)]
fn open_private(path: &Path, limit: u64) -> Result<File, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(Error::Storage)?;
    let metadata = file.metadata().map_err(Error::Storage)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 || metadata.len() > limit {
        return Err(Error::Limits);
    }
    Ok(file)
}
#[cfg(not(unix))]
fn open_private(_path: &Path, _limit: u64) -> Result<File, Error> {
    Err(Error::UnsupportedContext)
}

#[cfg(unix)]
fn new_private(path: &Path) -> Result<File, Error> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(Error::Storage)
}
#[cfg(not(unix))]
fn new_private(_path: &Path) -> Result<File, Error> {
    Err(Error::UnsupportedContext)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut file = new_private(path)?;
    file.write_all(bytes).map_err(Error::Storage)?;
    file.sync_all().map_err(Error::Storage)
}

fn hash_private(path: &Path, limit: u64) -> Result<Hex<32>, Error> {
    stream_private(path, None, limit).map(|(_, hash)| hash)
}

fn stream_private(
    source: &Path,
    destination: Option<&Path>,
    limit: u64,
) -> Result<(u64, Hex<32>), Error> {
    let mut source = open_private(source, limit)?;
    let expected = source.metadata().map_err(Error::Storage)?.len();
    let mut target = destination.map(new_private).transpose()?;
    let mut total = 0u64;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = source.read(&mut buffer).map_err(Error::Storage)?;
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or(Error::Limits)?;
        if total > limit || total > expected {
            return Err(Error::Limits);
        }
        hash.update(&buffer[..count]);
        if let Some(file) = &mut target {
            file.write_all(&buffer[..count]).map_err(Error::Storage)?;
        }
    }
    if total != expected {
        return Err(Error::RecoveryIncomplete);
    }
    if let Some(file) = target {
        file.sync_all().map_err(Error::Storage)?;
    }
    Ok((total, Hex(hash.finalize().into())))
}

fn copy_watch(
    source: &Path,
    destination: &Path,
    metadata: &JournalSnapshotMetadata,
) -> Result<(), Error> {
    private_directory(source)?;
    create_directory(destination)?;
    let mut root_count = 0u64;
    let mut root_bytes = 0u64;
    for entry in fs::read_dir(source).map_err(Error::Storage)? {
        let entry = entry.map_err(Error::Storage)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(Error::Encoding)?;
        if name == "allocator.lock" {
            continue;
        }
        if name == "journal" {
            copy_journal(&entry.path(), &destination.join(name), metadata)?;
            continue;
        }
        if name != "state.json"
            && !(name.starts_with("state-pre-v3-") && name.ends_with(".json"))
            && !name.starts_with(".watch-")
            && !name.starts_with(".recovery-")
        {
            return Err(Error::RecoveryIncomplete);
        }
        root_count = root_count.checked_add(1).ok_or(Error::Limits)?;
        if root_count > MAX_ROOT_FILES {
            return Err(Error::Limits);
        }
        let (bytes, _) = stream_private(
            &entry.path(),
            Some(&destination.join(name)),
            crate::watch::archive::MAX_V3 as u64,
        )?;
        root_bytes = root_bytes.checked_add(bytes).ok_or(Error::Limits)?;
        if root_bytes > MAX_ROOT_BYTES {
            return Err(Error::Limits);
        }
    }
    private_directory(destination)?
        .sync_all()
        .map_err(Error::Storage)
}

fn copy_journal(
    source: &Path,
    destination: &Path,
    metadata: &JournalSnapshotMetadata,
) -> Result<(), Error> {
    private_directory(source)?;
    for entry in fs::read_dir(source).map_err(Error::Storage)? {
        if entry.map_err(Error::Storage)?.file_name() != "objects" {
            return Err(Error::RecoveryIncomplete);
        }
    }
    create_directory(destination)?;
    let objects = source.join("objects");
    match fs::symlink_metadata(&objects) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if metadata.retained_bytes != 0 || metadata.retained_objects != 0 {
                return Err(Error::RecoveryIncomplete);
            }
            // An interrupted initial migration can leave only journal/.
            return private_directory(destination)?
                .sync_all()
                .map_err(Error::Storage);
        }
        Err(error) => return Err(Error::Storage(error)),
        Ok(_) => (),
    }
    private_directory(&objects)?;
    let target = destination.join("objects");
    create_directory(&target)?;
    let mut count = 0u64;
    let mut bytes = 0u64;
    for entry in fs::read_dir(objects).map_err(Error::Storage)? {
        let entry = entry.map_err(Error::Storage)?;
        count = count.checked_add(1).ok_or(Error::Limits)?;
        if count > metadata.retained_objects {
            return Err(Error::JournalQuota);
        }
        let (length, _) = stream_private(
            &entry.path(),
            Some(&target.join(entry.file_name())),
            metadata.retained_bytes.saturating_sub(bytes),
        )?;
        bytes = bytes.checked_add(length).ok_or(Error::JournalQuota)?;
    }
    if (count, bytes) != (metadata.retained_objects, metadata.retained_bytes) {
        return Err(Error::RecoveryIncomplete);
    }
    private_directory(&target)?
        .sync_all()
        .map_err(Error::Storage)?;
    private_directory(destination)?
        .sync_all()
        .map_err(Error::Storage)
}

#[cfg(all(test, unix))]
mod tests;
