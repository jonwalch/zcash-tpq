//! Create-new private files. No encryption or multi-writer coordinator is implied.
use crate::{require, Result};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};

pub fn create_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::DirBuilder::new().mode(0o700).create(path)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err("private storage requires Unix permissions".into())
    }
}

pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, bytes);
        Err("private storage requires Unix permissions".into())
    }
}

pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    require(
        fs::metadata(path)?.is_file(),
        "input must be a regular file",
    )?;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit.checked_add(1).ok_or("file limit overflow")?)
        .read_to_end(&mut bytes)?;
    require(u64::try_from(bytes.len())? <= limit, "file exceeds bound")?;
    Ok(bytes)
}

pub fn read_private(path: &Path, limit: u64) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(path)?;
        require(
            metadata.is_file() && metadata.permissions().mode() & 0o077 == 0,
            "private file requires mode 0600 or stricter, no symlink",
        )?;
        let parent = path.parent().ok_or("private file needs a parent")?;
        let metadata = fs::symlink_metadata(parent)?;
        require(
            metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
            "private directory requires mode 0700, no symlink",
        )?;
        read_bounded(path, limit)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, limit);
        Err("private storage requires Unix permissions".into())
    }
}
