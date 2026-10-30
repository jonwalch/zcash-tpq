//! Opt-in durable native identity for managed deployments, not ordinary fallback.

use super::{Config, NodeId, NodeSecretKey, ZakuraSecretKeyError};

impl Config {
    /// Ensure a durable owner-only native identity and return only its public ID.
    /// Creates a key only before `zakura.expected_node_id` is pinned. Startup
    /// with that pin never creates or replaces a missing/invalid key. The absolute
    /// identity directory must have an operator-trusted, stable parent tree and
    /// remain separate from chain snapshots. Non-Unix platforms refuse.
    pub fn ensure_managed_zakura_identity(&self) -> Result<NodeId, ZakuraSecretKeyError> {
        load(self, self.zakura.expected_node_id.is_none()).map(|key| key.public())
    }
}

#[cfg(not(unix))]
pub(super) fn load(_config: &Config, _create: bool) -> Result<NodeSecretKey, ZakuraSecretKeyError> {
    Err(ZakuraSecretKeyError::ManagedStorage)
}

#[cfg(unix)]
pub(super) fn load(config: &Config, create: bool) -> Result<NodeSecretKey, ZakuraSecretKeyError> {
    use rustix::fs::{open, openat, Mode, OFlags};
    use std::{
        fs::{DirBuilder, File},
        io::{Read, Write},
        os::unix::fs::{DirBuilderExt, MetadataExt},
        str::FromStr,
    };
    use ZakuraSecretKeyError::{ManagedMismatch, ManagedOverride, ManagedStorage};

    if config.zakura_node_secret_key.is_some() {
        return Err(ManagedOverride);
    }
    if !config.identity_dir.is_absolute() {
        return Err(ManagedStorage);
    }
    if create {
        match DirBuilder::new().mode(0o700).create(&config.identity_dir) {
            Ok(()) => {
                File::open(config.identity_dir.parent().ok_or(ManagedStorage)?)
                    .and_then(|parent| parent.sync_all())
                    .map_err(|_| ManagedStorage)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(ManagedStorage),
        }
    }
    let directory = File::from(
        open(
            &config.identity_dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ManagedStorage)?,
    );
    let metadata = directory.metadata().map_err(|_| ManagedStorage)?;
    let owner = rustix::process::geteuid().as_raw();
    if metadata.uid() != owner || metadata.mode() & 0o077 != 0 || metadata.mode() & 0o500 != 0o500 {
        return Err(ManagedStorage);
    }
    let key_path = super::zakura_secret_key_file_path(&config.identity_dir, &config.network);
    let name = key_path.file_name().ok_or(ManagedStorage)?;
    let open_key = || {
        openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
    };
    let key_file = match open_key() {
        Ok(file) => file,
        Err(rustix::io::Errno::NOENT) if create && metadata.mode() & 0o200 != 0 => {
            let key = NodeSecretKey::generate();
            let mut temporary = tempfile::NamedTempFile::new_in(&config.identity_dir)
                .map_err(|_| ManagedStorage)?;
            temporary
                .write_all(key.to_hex().as_bytes())
                .and_then(|()| temporary.as_file().sync_all())
                .map_err(|_| ManagedStorage)?;
            match temporary.persist_noclobber(&key_path) {
                Ok(_) => {}
                // A concurrent ensure may win; never replace its key.
                Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(ManagedStorage),
            }
            directory.sync_all().map_err(|_| ManagedStorage)?;
            open_key().map_err(|_| ManagedStorage)?
        }
        Err(_) => return Err(ManagedStorage),
    };
    let key_file = File::from(key_file);
    let metadata = key_file.metadata().map_err(|_| ManagedStorage)?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o400 == 0
        || metadata.len() > 128
    {
        return Err(ManagedStorage);
    }
    key_file.sync_all().map_err(|_| ManagedStorage)?;
    directory.sync_all().map_err(|_| ManagedStorage)?;
    let mut text = String::new();
    key_file
        .take(129)
        .read_to_string(&mut text)
        .map_err(|_| ManagedStorage)?;
    if text.len() > 128 {
        return Err(ManagedStorage);
    }
    let key = NodeSecretKey::from_str(text.trim()).map_err(|_| ManagedStorage)?;
    if config
        .zakura
        .expected_node_id
        .is_some_and(|id| id != key.public())
    {
        return Err(ManagedMismatch);
    }
    Ok(key)
}
