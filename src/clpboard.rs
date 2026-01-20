use arboard::Clipboard;
use std::{io::Write, time::Duration,thread};

pub fn cpy(secret: &str, timeout: u8) {
    let mut clipboard = Clipboard::new().unwrap();
    clipboard.set_text(secret).unwrap();
    println!("copyied to clipboard");
    let secret = secret.to_owned();
    let size = (timeout.ilog10() as usize) + 1;
    println!("{}",size);
    let t = thread::spawn(move || {
        thread::sleep(Duration::from_secs(timeout as u64));
        if let Ok(mut cb) = Clipboard::new() {
            if cb.get_text().ok().as_deref() == Some(&secret) {
                // let _ = cb.set_text("");
                let _ = cb.clear();
                let add_size=size+12;
                println!("\rclipboard cleared {:add_size$}","")
            }
        }
    });
    for i in (1..=timeout).rev() {
        print!("\rclear clipboard in {:^size$} seconds", i);
        std::io::stdout().flush().unwrap();
        thread::sleep(Duration::from_secs(1));
    }
    let _ = t.join();
}
