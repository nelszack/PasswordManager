use crate::file::{SERVER_LOCK_FILE, set_private_perms};
use std::{
    fs::{File, OpenOptions, TryLockError},
    path::Path,
};

pub(super) fn acquire_server_lock(directory: &Path) -> Result<File, String> {
    let path = directory.join(SERVER_LOCK_FILE);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|error| format!("could not open server lock: {error}"))?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Err(
            "A password manager server already owns this data directory. Stop it before starting another server, even on a different port.".into()
        ),
        Err(TryLockError::Error(error)) => return Err(format!("could not lock server data directory: {error}")),
    }
    set_private_perms(&path).map_err(|error| format!("could not protect server lock: {error}"))?;
    // Keep this file in place. Unlinking it would let another process lock a
    // different inode while the current server still owns the original lock.
    // Closing the handle releases ownership, including after a process crash.
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_ownership_is_exclusive_and_released_on_drop() {
        let directory = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let first = acquire_server_lock(directory.path()).unwrap();
        let error = acquire_server_lock(directory.path()).unwrap_err();
        assert!(error.contains("already owns this data directory"));
        let _independent = acquire_server_lock(other.path()).unwrap();
        drop(first);
        let _restarted = acquire_server_lock(directory.path()).unwrap();
    }
}
