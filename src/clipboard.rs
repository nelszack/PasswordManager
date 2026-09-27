use arboard::Clipboard;
use std::{io::Write, thread, time::Duration};
use zeroize::Zeroize;

trait ClipboardAccess {
    fn get_text(&mut self) -> Result<String, String>;
    fn clear(&mut self) -> Result<(), String>;
}

impl ClipboardAccess for Clipboard {
    fn get_text(&mut self) -> Result<String, String> {
        Clipboard::get_text(self).map_err(|error| error.to_string())
    }

    fn clear(&mut self) -> Result<(), String> {
        Clipboard::clear(self).map_err(|error| error.to_string())
    }
}

fn clear_if_unchanged(clipboard: &mut impl ClipboardAccess, secret: &str) -> bool {
    if clipboard.get_text().ok().as_deref() != Some(secret) {
        return false;
    }
    clipboard.clear().is_ok()
}

pub fn copy_with_timeout(secret: &str, timeout: u8) -> Result<(), String> {
    if timeout == 0 {
        return Ok(());
    }
    let mut clipboard = Clipboard::new().map_err(|e| format!("clipboard unavailable: {e}"))?;
    clipboard
        .set_text(secret)
        .map_err(|e| format!("could not copy password: {e}"))?;
    println!("Copied to clipboard.");
    let mut secret = secret.to_owned();
    let size = (timeout.ilog10() as usize) + 1;
    let t = thread::spawn(move || {
        thread::sleep(Duration::from_secs(timeout as u64));
        if let Ok(mut cb) = Clipboard::new()
            && clear_if_unchanged(&mut cb, &secret)
        {
            let add_size = size + 22;
            println!("\rClipboard cleared.{:add_size$}", "")
        }
        secret.zeroize();
    });
    for i in (1..=timeout).rev() {
        print!("\rClearing clipboard in {:>size$}s", i);
        let _ = std::io::stdout().flush();
        thread::sleep(Duration::from_secs(1));
    }
    t.join()
        .map_err(|_| "clipboard cleanup thread failed".to_string())?;
    Ok(())
}

/// Copy without blocking the server while the clipboard timeout counts down.
pub fn copy_in_background(mut secret: String, timeout: u8) {
    if timeout == 0 {
        secret.zeroize();
        return;
    }
    thread::spawn(move || {
        if let Err(error) = copy_with_timeout(&secret, timeout) {
            eprintln!("Warning: {error}");
        }
        secret.zeroize();
    });
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
        assert!(clear_if_unchanged(&mut matching, "secret"));
        assert!(matching.cleared);

        let mut replaced = FakeClipboard {
            value: Some("user replacement".into()),
            ..FakeClipboard::default()
        };
        assert!(!clear_if_unchanged(&mut replaced, "secret"));
        assert!(!replaced.cleared);

        let mut unavailable = FakeClipboard {
            fail_reads: true,
            ..FakeClipboard::default()
        };
        assert!(!clear_if_unchanged(&mut unavailable, "secret"));
        assert!(!unavailable.cleared);
    }
    #[test]
    fn test_zero_timeout_does_not_panic() {
        assert!(copy_with_timeout("secret", 0).is_ok());
    }
}
