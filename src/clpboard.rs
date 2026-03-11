use arboard::Clipboard;
use std::{io::Write, thread, time::Duration};

pub fn cpy(secret: &str, timeout: u8) {
    let mut clipboard = Clipboard::new().unwrap();
    clipboard.set_text(secret).unwrap();
    println!("copyied to clipboard");
    let secret = secret.to_owned();
    let size = (timeout.ilog10() as usize) + 1;
    let t = thread::spawn(move || {
        thread::sleep(Duration::from_secs(timeout as u64));
        if let Ok(mut cb) = Clipboard::new() {
            if cb.get_text().ok().as_deref() == Some(&secret) {
                cb.clear().unwrap();
                let add_size = size + 12;
                println!("\rclipboard cleared {:add_size$}", "")
            }
        }
    });
    for i in (1..=timeout).rev() {
        print!("\rclear clipboard in {:^size$} seconds", i);
        std::io::stdout().flush().unwrap();
        thread::sleep(Duration::from_secs(1));
    }
    t.join().unwrap();
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_clp() {
        let mut clipboard = Clipboard::new().unwrap();
        cpy("this is a test", 2);
        let content = clipboard.get_text().ok();
        assert_eq!(content, None);
    }
}
