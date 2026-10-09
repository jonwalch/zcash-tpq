use super::*;
use crate::{Manifest, WatchStore};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    CreateJournal,
    CreateObjects,
    ObjectWrite,
    ObjectVerify,
    ObjectSync,
    ObjectPublish,
    ObjectsSync,
    JournalSync,
    WatchSync,
    RecoveryWrite,
    RecoveryVerify,
    RecoverySync,
    RecoveryPublish,
    RecoveryDirectorySync,
}

/// An exclusive borrow keeps the existing allocator lock alive and prevents a
/// second journal handle from racing its incremental quota accounting.
pub(crate) struct Journal<'a> {
    watch: &'a mut WatchStore,
    path: PathBuf,
    directory: File,
    pub(super) id: Hex<16>,
    pub(super) limits: Limits,
    pub(super) used_bytes: u64,
    pub(super) used_objects: u64,
    poisoned: bool,
    snapshot: Option<Snapshot>,
    pub(super) cache: VecDeque<(Hash, Page)>,
}
impl<'a> Journal<'a> {
    /// Initialize only before the first authoritative v3 root. Opening an
    /// existing v3 store must use `open`, which never creates missing directories.
    pub fn create(
        watch: &'a mut WatchStore,
        id: Hex<16>,
        limits: Limits,
        mut hook: impl FnMut(Stage) -> Result<()>,
    ) -> Result<Self> {
        limits.validate()?;
        let path = watch
            .journal_path()
            .map_err(|_| Error::ReopenRequired)?
            .to_path_buf();
        let result = (|| {
            hook(Stage::CreateJournal)?;
            create_directory(&path.join("journal"))?;
            hook(Stage::CreateObjects)?;
            create_directory(&path.join("journal/objects"))?;
            for (stage, directory) in [
                (Stage::ObjectsSync, path.join("journal/objects")),
                (Stage::JournalSync, path.join("journal")),
                (Stage::WatchSync, path.clone()),
            ] {
                hook(stage)?;
                private_directory(&directory)?.sync_all()?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            watch.poison();
            return Err(error);
        }
        Self::open(watch, id, limits)
    }

    pub fn open(watch: &'a mut WatchStore, id: Hex<16>, limits: Limits) -> Result<Self> {
        watch.journal_usage = None;
        Self::resume(watch, id, limits)
    }

    /// Reuse usage only while the same WatchStore owns the exclusive lock.
    pub fn resume(watch: &'a mut WatchStore, id: Hex<16>, limits: Limits) -> Result<Self> {
        limits.validate()?;
        let root = watch
            .journal_path()
            .map_err(|_| Error::ReopenRequired)?
            .to_path_buf();
        let path = root.join("journal/objects");
        let result = (|| {
            private_directory(&root.join("journal"))?;
            let directory = private_directory(&path)?;
            if let Some((bytes, objects)) = watch.journal_usage {
                if bytes > limits.bytes {
                    return Err(Error::Quota);
                }
                if objects > limits.objects {
                    return Err(Error::ObjectLimit);
                }
                return Ok((directory, bytes, objects));
            }
            let mut bytes = 0u64;
            let mut objects = 0u64;
            // Include orphan objects and temporary files. Never load their
            // bodies or accept a symlink as free space.
            for item in fs::read_dir(&path)? {
                objects += 1;
                if objects > limits.objects {
                    return Err(Error::ObjectLimit);
                }
                let item = item?;
                let metadata = fs::symlink_metadata(item.path())?;
                check_file(&metadata)?;
                bytes = bytes.checked_add(metadata.len()).ok_or(Error::Quota)?;
                if bytes > limits.bytes {
                    return Err(Error::Quota);
                }
            }
            Ok((directory, bytes, objects))
        })();
        let (directory, used_bytes, used_objects) = match result {
            Ok(value) => value,
            Err(error) => {
                watch.poison();
                return Err(error);
            }
        };
        Ok(Self {
            watch,
            path,
            directory,
            id,
            limits,
            used_bytes,
            used_objects,
            poisoned: false,
            snapshot: None,
            cache: VecDeque::new(),
        })
    }

    pub(crate) fn retained_usage(&self) -> (u64, u64) {
        (self.used_bytes, self.used_objects)
    }

    pub(crate) fn object_limit(&self) -> u64 {
        self.limits.objects
    }

    pub(super) fn ready(&self) -> Result<()> {
        if self.poisoned {
            return Err(Error::ReopenRequired);
        }
        self.watch
            .journal_path()
            .map_err(|_| Error::ReopenRequired)?;
        Ok(())
    }
    fn poison<T>(&mut self, result: Result<T>) -> Result<T> {
        if matches!(result, Err(Error::Corrupt | Error::Storage(_))) {
            self.poisoned = true;
            self.watch.poison();
            self.cache.clear();
        }
        result
    }
    pub(super) fn pin(&mut self, snapshot: &Snapshot) -> Result<()> {
        self.ready()?;
        if snapshot.journal_id != self.id {
            return self.poison(Err(Error::Corrupt));
        }
        if self.snapshot.as_ref() != Some(snapshot) {
            self.cache.clear();
            self.snapshot = Some(snapshot.clone());
        }
        Ok(())
    }
    pub(super) fn load_page(
        &mut self,
        reference: &Reference,
        kind: Kind,
        root: bool,
        batch: Option<&Batch>,
        budget: &mut ReadBudget,
    ) -> Result<Page> {
        self.ready()?;
        let result = (|| {
            reference.validate(kind)?;
            let page = if let Some(object) = batch.and_then(|b| b.objects.get(&reference.hash)) {
                Page::decode(&object.bytes, self.id, kind)?
            } else if let Some((_, page)) =
                self.cache.iter().find(|(hash, _)| *hash == reference.hash)
            {
                page.clone()
            } else {
                budget.charge()?;
                let bytes = self.read_object(reference.hash, PAGE_BYTES)?;
                let page = Page::decode(&bytes, self.id, kind)?;
                if self.cache.len() == CACHE_PAGES {
                    self.cache.pop_front();
                }
                self.cache.push_back((reference.hash, page.clone()));
                page
            };
            page.validate(root)?;
            if page.kind != kind || page.reference()? != *reference {
                return Err(Error::Corrupt);
            }
            Ok(page)
        })();
        self.poison(result)
    }
    fn read_object(&self, hash: Hash, limit: usize) -> Result<Vec<u8>> {
        let (_, bytes) = read_private(&self.path.join(hex::encode(hash.0)), limit)?;
        if Encoded::new(&bytes).hash != hash {
            return Err(Error::Corrupt);
        }
        Ok(bytes)
    }
    pub fn capability(
        &mut self,
        hash: Hash,
        manifest: &Manifest,
        change_next: u64,
    ) -> Result<Capability> {
        self.ready()?;
        let result = self
            .read_object(hash, CAPABILITY_BYTES)
            .and_then(|bytes| Capability::decode(&bytes, self.id, manifest, change_next));
        self.poison(result)
    }

    /// Return only after every object and its directory are durable. This does
    /// not publish a wallet root or validate cross-index payment relationships.
    pub fn publish(
        &mut self,
        batch: &Batch,
        mut hook: impl FnMut(Stage) -> Result<()>,
    ) -> Result<()> {
        self.ready()?;
        if batch.invalid || batch.journal_id != self.id {
            return Err(Error::InvalidBatch);
        }
        if batch.bytes > self.limits.commit_bytes
            || batch.objects.len() > self.limits.commit_objects
        {
            return Err(Error::Limit);
        }
        let preflight = self.preflight(batch);
        self.poison(preflight)?;
        let result = self.publish_inner(batch, &mut hook);
        // An injected failure has the same uncertain durability as an OS error.
        if result.is_err() {
            self.poisoned = true;
            self.watch.poison();
            self.cache.clear();
        }
        result
    }
    fn preflight(&self, batch: &Batch) -> Result<()> {
        let mut new_bytes = 0u64;
        let mut new_objects = 0u64;
        let mut largest = 0u64;
        for object in batch.objects.values() {
            let path = self.path.join(hex::encode(object.hash.0));
            match fs::symlink_metadata(path) {
                Ok(_) => {
                    self.existing(object)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    new_bytes += object.bytes.len() as u64;
                    new_objects += 1;
                    largest = largest.max(object.bytes.len() as u64);
                }
                Err(e) => return Err(e.into()),
            }
        }
        // persist_noclobber may momentarily hard-link both names. Count both
        // file lengths and directory entries even on platforms using rename.
        if self
            .used_bytes
            .checked_add(new_bytes)
            .and_then(|n| n.checked_add(largest))
            .is_none_or(|n| n > self.limits.bytes)
        {
            return Err(Error::Quota);
        }
        let temporary = u64::from(new_objects != 0);
        if self.used_objects + new_objects + temporary > self.limits.objects {
            return Err(Error::ObjectLimit);
        }
        Ok(())
    }
    fn publish_inner(
        &mut self,
        batch: &Batch,
        hook: &mut impl FnMut(Stage) -> Result<()>,
    ) -> Result<()> {
        for object in batch.objects.values() {
            let destination = self.path.join(hex::encode(object.hash.0));
            if fs::symlink_metadata(&destination).is_ok() {
                hook(Stage::ObjectSync)?;
                self.existing(object)?.sync_all()?;
                continue;
            }
            let mut file = tempfile::Builder::new()
                .prefix(".object-")
                .tempfile_in(&self.path)?;
            hook(Stage::ObjectWrite)?;
            file.write_all(&object.bytes)?;
            hook(Stage::ObjectVerify)?;
            let (_, actual) = read_private(file.path(), object.bytes.len())?;
            if actual.as_slice() != object.bytes.as_ref() {
                return Err(Error::Corrupt);
            }
            hook(Stage::ObjectSync)?;
            file.as_file().sync_all()?;
            hook(Stage::ObjectPublish)?;
            file.persist_noclobber(destination)
                .map_err(|e| Error::Storage(e.error))?;
            self.used_bytes += object.bytes.len() as u64;
            self.used_objects += 1;
        }
        hook(Stage::ObjectsSync)?;
        self.directory.sync_all()?;
        Ok(())
    }
    fn existing(&self, object: &Encoded) -> Result<File> {
        let (file, bytes) = read_private(
            &self.path.join(hex::encode(object.hash.0)),
            object.bytes.len(),
        )?;
        if bytes.as_slice() != object.bytes.as_ref() {
            return Err(Error::Corrupt);
        }
        Ok(file)
    }

    /// Preserve the exact legacy root before migration. Copies are never opened
    /// as authoritative state. Directory/file syncs repeat on a matching retry.
    pub fn save_legacy(&mut self, mut hook: impl FnMut(Stage) -> Result<()>) -> Result<PathBuf> {
        self.ready()?;
        let result = (|| {
            let root = self
                .watch
                .journal_path()
                .map_err(|_| Error::ReopenRequired)?;
            let (_, bytes) = read_private(&root.join("state.json"), 32 * 1024 * 1024)?;
            #[derive(serde::Deserialize)]
            struct Format {
                format: String,
            }
            let format: Format = serde_json::from_slice(&bytes).map_err(|_| Error::Corrupt)?;
            if !matches!(
                format.format.as_str(),
                "ZcashTransparentPQ/watch-state/v1" | "ZcashTransparentPQ/watch-state/v2"
            ) {
                return Err(Error::Corrupt);
            }
            use sha2::{Digest, Sha256};
            let destination = root.join(format!(
                "state-pre-v3-{}.json",
                hex::encode(Sha256::digest(&bytes))
            ));
            match fs::symlink_metadata(&destination) {
                Ok(_) => {
                    hook(Stage::RecoveryVerify)?;
                    let (file, saved) = read_private(&destination, bytes.len())?;
                    if saved != bytes {
                        return Err(Error::Corrupt);
                    }
                    hook(Stage::RecoverySync)?;
                    file.sync_all()?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let mut file = tempfile::Builder::new()
                        .prefix(".recovery-")
                        .tempfile_in(root)?;
                    hook(Stage::RecoveryWrite)?;
                    file.write_all(&bytes)?;
                    hook(Stage::RecoveryVerify)?;
                    if read_private(file.path(), bytes.len())?.1 != bytes {
                        return Err(Error::Corrupt);
                    }
                    hook(Stage::RecoverySync)?;
                    file.as_file().sync_all()?;
                    hook(Stage::RecoveryPublish)?;
                    file.persist_noclobber(&destination)
                        .map_err(|e| Error::Storage(e.error))?;
                }
                Err(e) => return Err(e.into()),
            }
            hook(Stage::RecoveryDirectorySync)?;
            private_directory(root)?.sync_all()?;
            Ok(destination)
        })();
        if result.is_err() {
            self.poisoned = true;
            self.watch.poison();
        }
        result
    }
}

#[cfg(unix)]
fn check_file(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::Corrupt);
    }
    Ok(())
}
#[cfg(not(unix))]
fn check_file(_: &fs::Metadata) -> Result<()> {
    Err(Error::Unsupported)
}

#[cfg(unix)]
fn private_directory(path: &Path) -> Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    if directory.metadata()?.permissions().mode() & 0o077 != 0 {
        return Err(Error::Corrupt);
    }
    Ok(directory)
}
#[cfg(not(unix))]
fn private_directory(_: &Path) -> Result<File> {
    Err(Error::Unsupported)
}

#[cfg(unix)]
fn create_directory(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    private_directory(path)?;
    Ok(())
}
#[cfg(not(unix))]
fn create_directory(_: &Path) -> Result<()> {
    Err(Error::Unsupported)
}

#[cfg(unix)]
fn read_private(path: &Path, limit: usize) -> Result<(File, Vec<u8>)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    check_file(&metadata)?;
    if metadata.len() > limit as u64 {
        return Err(Error::Corrupt);
    }
    let mut bytes = Vec::new();
    (&file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(Error::Corrupt);
    }
    Ok((file, bytes))
}
#[cfg(not(unix))]
fn read_private(_: &Path, _: usize) -> Result<(File, Vec<u8>)> {
    Err(Error::Unsupported)
}

impl Drop for Journal<'_> {
    fn drop(&mut self) {
        if !self.poisoned {
            self.watch.journal_usage = Some((self.used_bytes, self.used_objects));
        }
    }
}
