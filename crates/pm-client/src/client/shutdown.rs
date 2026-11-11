//! Wait on an owned Windows process handle, never a PID that can be reused.
use std::{
    fs::{File, TryLockError},
    io::Read,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
};
use windows_sys::Win32::{
    Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
};

pub(super) struct ShutdownWait(OwnedHandle);

impl ShutdownWait {
    // Called after authenticating the server, before sending Kill. Old servers
    // have no PID sidecar; their acknowledgement must not promise process exit.
    pub(super) fn capture(token_path: &Path) -> Result<Option<Self>, String> {
        let path = token_path.with_file_name(crate::file::SERVER_LOCK_FILE);
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("could not read server process ID: {error}")),
        };
        match file.try_lock() {
            Err(TryLockError::WouldBlock) => {}
            Ok(()) => return Err("Server exited before shutdown could be requested".into()),
            Err(TryLockError::Error(error)) => {
                return Err(format!("could not verify server ownership: {error}"));
            }
        }
        let pid_file = match File::open(token_path.with_file_name(crate::file::SERVER_PID_FILE)) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("could not read server process ID: {error}")),
        };
        let mut pid = String::new();
        pid_file
            .take(32)
            .read_to_string(&mut pid)
            .map_err(|error| format!("could not read server process ID: {error}"))?;
        let pid = pid
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|pid| *pid != 0 && *pid != std::process::id())
            .ok_or("Invalid server process ID")?;
        // SAFETY: request synchronization access only; the returned handle is
        // checked before transferring its unique ownership to OwnedHandle.
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
        if handle.is_null() {
            return Err(format!(
                "could not open server process for shutdown waiting: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Some(Self(unsafe { OwnedHandle::from_raw_handle(handle) })))
    }

    pub(super) fn wait(self) -> Result<(), String> {
        // SAFETY: this owned process handle remains valid throughout the wait.
        match unsafe { WaitForSingleObject(self.0.as_raw_handle(), 10_000) } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err(
                "Server accepted shutdown but is still stopping after 10 seconds; process exit has not been confirmed".into(),
            ),
            _ => Err(format!(
                "Server accepted shutdown but process exit could not be verified: {}",
                std::io::Error::last_os_error()
            )),
        }
    }
}
