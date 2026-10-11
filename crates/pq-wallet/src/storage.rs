//! Local Unix filesystem publication in an operator-trusted directory.
use crate::{backup, Error, Profile, Wallet};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stage {
    Write,
    FileSync,
    Verify,
    Publish,
    DirectorySync,
}

impl Wallet {
    /// Read a bounded regular file without following its final symlink component.
    /// The parent directory and its ancestors must be trusted and stable. This
    /// does not authenticate freshness or reconcile the previous allocator.
    pub fn load_backup(path: &Path, password: &[u8], profile: &Profile) -> Result<Self, Error> {
        Self::decrypt(&read_file(path)?, password, profile)
    }

    /// Publish a verified backup under a NEW generation filename, never replace
    /// an existing entry. Success includes file and directory sync. A directory
    /// sync failure can leave the new file present but reports failure; keep the
    /// previous generation and do not issue receivers on any error.
    ///
    /// This only establishes local durability. The caller must establish a
    /// recovery copy outside its disposable database before publishing inventory.
    pub fn save_backup(&self, path: &Path, password: &[u8]) -> Result<(), Error> {
        self.save_with_hook(path, password, |_| Ok(()))
    }

    #[cfg(unix)]
    pub(crate) fn save_with_hook(
        &self,
        path: &Path,
        password: &[u8],
        mut hook: impl FnMut(Stage) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let parent = parent(path)?;
        // Last-component symlinks are refused; ancestors are part of the trusted
        // directory contract. Random temporary files are created with O_EXCL.
        let directory = open_directory(parent)?;
        if fs::symlink_metadata(path).is_ok() {
            return Err(Error::Storage(std::io::Error::from(
                std::io::ErrorKind::AlreadyExists,
            )));
        }
        let blob = self.encrypt(password)?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".tpq-backup-")
            .tempfile_in(parent)
            .map_err(Error::Storage)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(Error::Storage)?;
        hook(Stage::Write)?;
        temporary.write_all(&blob).map_err(Error::Storage)?;
        temporary.flush().map_err(Error::Storage)?;
        hook(Stage::FileSync)?;
        temporary.as_file().sync_all().map_err(Error::Storage)?;
        hook(Stage::Verify)?;
        let mut reopened = temporary.reopen().map_err(Error::Storage)?;
        let readback = bounded_read(&mut reopened)?;
        if readback != blob {
            return Err(Error::Storage(std::io::Error::other(
                "backup verification failed",
            )));
        }
        Self::decrypt(&readback, password, &self.manifest.profile)?;
        hook(Stage::Publish)?;
        // On Unix this may use a hard link followed by unlinking the temporary
        // name. Publication is atomic and refuses to clobber a concurrent writer.
        temporary
            .persist_noclobber(path)
            .map_err(|error| Error::Storage(error.error))?;
        hook(Stage::DirectorySync)?;
        directory.sync_all().map_err(Error::Storage)
    }

    #[cfg(not(unix))]
    pub(crate) fn save_with_hook(
        &self,
        _path: &Path,
        _password: &[u8],
        _hook: impl FnMut(Stage) -> Result<(), Error>,
    ) -> Result<(), Error> {
        Err(Error::UnsupportedContext)
    }
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

#[cfg(unix)]
fn open_directory(path: &Path) -> Result<File, Error> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(Error::Storage)
}

pub(crate) fn read_file(path: &Path) -> Result<Vec<u8>, Error> {
    #[cfg(unix)]
    {
        let _directory = open_directory(parent(path)?)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(Error::Storage)?;
        let metadata = file.metadata().map_err(Error::Storage)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Storage(std::io::Error::other(
                "expected a restricted regular backup file",
            )));
        }
        bounded_read(&mut file)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(Error::UnsupportedContext)
    }
}

fn bounded_read(file: &mut File) -> Result<Vec<u8>, Error> {
    if file.metadata().map_err(Error::Storage)?.len() > backup::MAX_FILE as u64 {
        return Err(Error::Limits);
    }
    let mut bytes = Vec::new();
    file.take(backup::MAX_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(Error::Storage)?;
    if bytes.len() > backup::MAX_FILE {
        return Err(Error::Limits);
    }
    Ok(bytes)
}
