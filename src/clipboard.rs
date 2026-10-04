use arboard::Clipboard;
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    sync::{OnceLock, mpsc},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

trait ClipboardAccess {
    fn set_text(&mut self, secret: &str) -> Result<(), String>;
    fn get_text(&mut self) -> Result<String, String>;
    fn clear(&mut self) -> Result<(), String>;
}

impl ClipboardAccess for Clipboard {
    fn set_text(&mut self, secret: &str) -> Result<(), String> {
        Clipboard::set_text(self, secret).map_err(|error| error.to_string())
    }
    fn get_text(&mut self) -> Result<String, String> {
        Clipboard::get_text(self).map_err(|error| error.to_string())
    }
    fn clear(&mut self) -> Result<(), String> {
        Clipboard::clear(self).map_err(|error| error.to_string())
    }
}

fn clear_if_unchanged(clipboard: &mut impl ClipboardAccess, secret: &str) -> Result<bool, String> {
    let current = Zeroizing::new(clipboard.get_text()?);
    if current.as_str() != secret {
        return Ok(false);
    }
    clipboard.clear()?;
    Ok(true)
}

struct PendingCopy {
    secret: Zeroizing<String>,
    deadline: Instant,
}

#[derive(Default)]
struct ClipboardState {
    pending: Option<PendingCopy>,
}

impl ClipboardState {
    fn copy(
        &mut self,
        clipboard: &mut impl ClipboardAccess,
        secret: Zeroizing<String>,
        timeout: u8,
        now: Instant,
    ) -> Result<(), String> {
        if timeout == 0 {
            return Ok(());
        }
        clipboard.set_text(&secret)?;
        self.pending = Some(PendingCopy {
            secret,
            deadline: now + Duration::from_secs(timeout.into()),
        });
        Ok(())
    }

    fn clear(&mut self, clipboard: &mut impl ClipboardAccess) -> Result<(), String> {
        if let Some(pending) = self.pending.as_ref() {
            clear_if_unchanged(clipboard, &pending.secret)?;
        }
        self.pending.take();
        Ok(())
    }

    fn expire(&mut self, clipboard: &mut impl ClipboardAccess, now: Instant) -> Result<(), String> {
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.deadline <= now)
        {
            self.clear(clipboard)?;
        }
        Ok(())
    }
}

type Reply = mpsc::SyncSender<Result<(), String>>;
enum ClipboardCommand {
    Copy(Zeroizing<String>, u8, Reply),
    Clear(Reply),
}

static MANAGER: OnceLock<Result<mpsc::Sender<ClipboardCommand>, String>> = OnceLock::new();

fn manager() -> Result<&'static mpsc::Sender<ClipboardCommand>, String> {
    MANAGER
        .get_or_init(|| {
            let (sender, receiver) = mpsc::channel();
            thread::Builder::new()
                .name("pm-clipboard".into())
                .spawn(move || {
                    let mut clipboard: Option<Clipboard> = None;
                    let mut state = ClipboardState::default();
                    loop {
                        let wait = state
                            .pending
                            .as_ref()
                            .map_or(Duration::from_secs(60), |pending| {
                                pending.deadline.saturating_duration_since(Instant::now())
                            })
                            .max(Duration::from_millis(100));
                        match receiver.recv_timeout(wait) {
                            Ok(ClipboardCommand::Copy(secret, timeout, reply)) => {
                                let result = (|| {
                                    if clipboard.is_none() {
                                        clipboard = Some(
                                            Clipboard::new().map_err(|error| error.to_string())?,
                                        );
                                    }
                                    state.copy(
                                        clipboard.as_mut().unwrap(),
                                        secret,
                                        timeout,
                                        Instant::now(),
                                    )
                                })();
                                let _ = reply.send(result);
                            }
                            Ok(ClipboardCommand::Clear(reply)) => {
                                let result = match clipboard.as_mut() {
                                    Some(clipboard) => state.clear(clipboard),
                                    None => Ok(()),
                                };
                                if result.is_err()
                                    && let Some(pending) = state.pending.as_mut()
                                {
                                    pending.deadline = Instant::now() + Duration::from_secs(1);
                                }
                                let _ = reply.send(result);
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                if let Some(clipboard) = clipboard.as_mut()
                                    && let Err(error) = state.expire(clipboard, Instant::now())
                                {
                                    eprintln!("Warning: clipboard cleanup failed: {error}");
                                    // Retain ownership for a retry without spinning or flooding logs.
                                    if let Some(pending) = state.pending.as_mut() {
                                        pending.deadline = Instant::now() + Duration::from_secs(1);
                                    }
                                }
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => {
                                if let Some(clipboard) = clipboard.as_mut() {
                                    let _ = state.clear(clipboard);
                                }
                                break;
                            }
                        }
                    }
                })
                .map_err(|error| format!("could not start clipboard manager: {error}"))?;
            Ok(sender)
        })
        .as_ref()
        .map_err(Clone::clone)
}

pub fn copy_in_background(secret: String, timeout: u8) {
    if let Err(error) = try_copy_in_background(secret, timeout) {
        eprintln!("Warning: could not copy secret: {error}");
    }
}

pub fn try_copy_in_background(secret: String, timeout: u8) -> Result<(), String> {
    let secret = Zeroizing::new(secret);
    if timeout == 0 {
        return Ok(());
    }
    let (reply, response) = mpsc::sync_channel(1);
    manager()?
        .send(ClipboardCommand::Copy(secret, timeout, reply))
        .map_err(|_| "clipboard manager stopped".to_string())?;
    response
        .recv()
        .map_err(|_| "clipboard manager stopped".to_string())?
}

/// A lock waits for queued copies and cleanup, but never for their countdown.
pub fn clear_owned() -> Result<(), String> {
    let Some(manager) = MANAGER.get() else {
        return Ok(());
    };
    let manager = manager.as_ref().map_err(Clone::clone)?;
    let (reply, response) = mpsc::sync_channel(1);
    manager
        .send(ClipboardCommand::Clear(reply))
        .map_err(|_| "clipboard manager stopped".to_string())?;
    response
        .recv()
        .map_err(|_| "clipboard manager stopped".to_string())?
}

/// A short-lived CLI cannot keep a thread alive after exit. A detached helper
/// owns its clipboard until expiration; the secret travels through stdin only.
pub fn copy_with_timeout(secret: &str, timeout: u8) -> Result<(), String> {
    if timeout == 0 {
        return Ok(());
    }
    if secret.len() > 1024 * 1024 {
        return Err("clipboard secret exceeds the 1 MiB limit".into());
    }
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let mut command = Command::new(executable);
    command
        .args(["clipboard-helper", "--timeout", &timeout.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(crate::file::WINDOWS_CREATE_NO_WINDOW);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start clipboard owner: {error}"))?;
    let result = (|| {
        let mut stdin = child
            .stdin
            .take()
            .ok_or("clipboard owner stdin unavailable")?;
        stdin
            .write_all(secret.as_bytes())
            .map_err(|error| error.to_string())?;
        drop(stdin);
        let mut stdout = child
            .stdout
            .take()
            .ok_or("clipboard owner stdout unavailable")?;
        let mut ready = [0u8; 1];
        stdout
            .read_exact(&mut ready)
            .map_err(|error| format!("clipboard owner failed to start: {error}"))?;
        if ready[0] != 1 {
            let mut error = String::new();
            stdout
                .take(4096)
                .read_to_string(&mut error)
                .map_err(|error| error.to_string())?;
            return Err(error);
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    } else {
        // Reap while the caller lives; after CLI exit the OS adopts the helper.
        thread::spawn(move || {
            let _ = child.wait();
        });
    }
    result
}

pub fn run_helper(timeout: u8) -> Result<(), String> {
    let result = (|| {
        let mut secret = Zeroizing::new(String::new());
        std::io::stdin()
            .take(1024 * 1024 + 1)
            .read_to_string(&mut secret)
            .map_err(|error| error.to_string())?;
        if secret.len() > 1024 * 1024 {
            return Err("clipboard secret exceeds the 1 MiB limit".into());
        }
        let mut clipboard =
            Clipboard::new().map_err(|error| format!("clipboard unavailable: {error}"))?;
        let mut state = ClipboardState::default();
        state.copy(&mut clipboard, secret, timeout, Instant::now())?;
        std::io::stdout()
            .write_all(&[1])
            .and_then(|_| std::io::stdout().flush())
            .map_err(|error| error.to_string())?;
        thread::sleep(Duration::from_secs(timeout.into()));
        state.clear(&mut clipboard)
    })();
    if let Err(error) = &result {
        let _ = std::io::stdout().write_all(&[0]);
        let _ = std::io::stdout().write_all(error.as_bytes());
    }
    result
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Default)]
    struct FakeClipboard {
        value: Option<String>,
        cleared: bool,
        fail_reads: bool,
    }

    impl ClipboardAccess for FakeClipboard {
        fn set_text(&mut self, secret: &str) -> Result<(), String> {
            self.value = Some(secret.to_owned());
            self.cleared = false;
            Ok(())
        }
        fn get_text(&mut self) -> Result<String, String> {
            if self.fail_reads {
                Err("unavailable".into())
            } else {
                self.value.clone().ok_or_else(|| "empty".into())
            }
        }

        fn clear(&mut self) -> Result<(), String> {
            self.value = None;
            self.cleared = true;
            Ok(())
        }
    }

    #[test]
    fn clears_only_the_secret_that_was_copied() {
        let mut matching = FakeClipboard {
            value: Some("secret".into()),
            ..FakeClipboard::default()
        };
        assert_eq!(clear_if_unchanged(&mut matching, "secret"), Ok(true));
        assert!(matching.cleared);

        let mut replaced = FakeClipboard {
            value: Some("user replacement".into()),
            ..FakeClipboard::default()
        };
        assert_eq!(clear_if_unchanged(&mut replaced, "secret"), Ok(false));
        assert!(!replaced.cleared);

        let mut unavailable = FakeClipboard {
            fail_reads: true,
            ..FakeClipboard::default()
        };
        assert!(clear_if_unchanged(&mut unavailable, "secret").is_err());
        assert!(!unavailable.cleared);
    }
    #[test]
    fn test_zero_timeout_does_not_panic() {
        assert!(copy_with_timeout("secret", 0).is_ok());
    }
}

#[cfg(test)]
mod manager_tests {
    use super::*;

    #[derive(Default)]
    struct FakeClipboard {
        value: String,
        fail_read: bool,
    }
    impl ClipboardAccess for FakeClipboard {
        fn set_text(&mut self, secret: &str) -> Result<(), String> {
            self.value = secret.into();
            Ok(())
        }
        fn get_text(&mut self) -> Result<String, String> {
            if self.fail_read {
                Err("clipboard temporarily unavailable".into())
            } else {
                Ok(self.value.clone())
            }
        }
        fn clear(&mut self) -> Result<(), String> {
            self.value.clear();
            Ok(())
        }
    }

    #[test]
    fn repeated_copies_replace_the_secret_and_reset_the_deadline() {
        let start = Instant::now();
        let mut clipboard = FakeClipboard::default();
        let mut state = ClipboardState::default();
        state
            .copy(&mut clipboard, Zeroizing::new("first".into()), 5, start)
            .unwrap();
        state
            .copy(
                &mut clipboard,
                Zeroizing::new("second".into()),
                10,
                start + Duration::from_secs(4),
            )
            .unwrap();
        state
            .expire(&mut clipboard, start + Duration::from_secs(5))
            .unwrap();
        assert_eq!(clipboard.value, "second");
        state
            .expire(&mut clipboard, start + Duration::from_secs(14))
            .unwrap();
        assert!(clipboard.value.is_empty());
        assert!(state.pending.is_none());
    }

    #[test]
    fn lock_clears_owned_secrets_immediately_and_preserves_user_replacements() {
        let mut clipboard = FakeClipboard::default();
        let mut state = ClipboardState::default();
        for replaced in [false, true] {
            state
                .copy(
                    &mut clipboard,
                    Zeroizing::new("secret".into()),
                    255,
                    Instant::now(),
                )
                .unwrap();
            if replaced {
                clipboard.value = "user text".into();
            }
            state.clear(&mut clipboard).unwrap();
            assert_eq!(clipboard.value, if replaced { "user text" } else { "" });
            assert!(state.pending.is_none());
        }
    }

    #[test]
    fn cleanup_failure_retains_ownership_for_a_retry() {
        let mut clipboard = FakeClipboard::default();
        let mut state = ClipboardState::default();
        state
            .copy(
                &mut clipboard,
                Zeroizing::new("secret".into()),
                1,
                Instant::now(),
            )
            .unwrap();
        clipboard.fail_read = true;
        assert!(state.clear(&mut clipboard).is_err());
        assert!(state.pending.is_some());
        clipboard.fail_read = false;
        state.clear(&mut clipboard).unwrap();
        assert!(state.pending.is_none());
        assert!(clipboard.value.is_empty());
    }
}
