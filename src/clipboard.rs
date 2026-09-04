use arboard::Clipboard;
use std::{io::Write, thread, time::Duration};

pub fn copy_with_timeout(secret: &str, timeout: u8) -> Result<(), String> {
    if timeout == 0 {
        return Ok(());
    }
    let mut clipboard = Clipboard::new().map_err(|e| format!("clipboard unavailable: {e}"))?;
    clipboard
        .set_text(secret)
        .map_err(|e| format!("could not copy password: {e}"))?;
    println!("Copied to clipboard.");
    let secret = secret.to_owned();
    let size = (timeout.ilog10() as usize) + 1;
    let t = thread::spawn(move || {
        thread::sleep(Duration::from_secs(timeout as u64));
        if let Ok(mut cb) = Clipboard::new()
            && cb.get_text().ok().as_deref() == Some(&secret)
        {
            let _ = cb.clear();
            let add_size = size + 22;
            println!("\rClipboard cleared.{:add_size$}", "")
        }
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
pub fn copy_in_background(secret: String, timeout: u8) {
    if timeout == 0 {
        return;
    }
    thread::spawn(move || {
        if let Err(error) = copy_with_timeout(&secret, timeout) {
            eprintln!("Warning: {error}");
        }
    });
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::Mutex;

    static CLIPBOARD_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_copy_and_clear() {
        let _guard = CLIPBOARD_TEST_LOCK.lock().unwrap();
        let mut clipboard = Clipboard::new().unwrap();
        copy_with_timeout("this is a test", 2).unwrap();
        let content = clipboard.get_text().ok();
        assert_eq!(content, None);
    }
    #[test]
    fn test_zero_timeout_does_not_panic() {
        let _guard = CLIPBOARD_TEST_LOCK.lock().unwrap();
        let mut clipboard = Clipboard::new().unwrap();
        clipboard.set_text("keep me").unwrap();
        copy_with_timeout("secret", 0).unwrap();
        let content = clipboard.get_text().ok();
        assert!(
            content.is_some(),
            "clipboard must not be cleared when timeout is 0"
        );
    }
}
