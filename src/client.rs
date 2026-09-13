use crate::file::{TOKEN_FILE, data_dir};
use crate::server::ADDR;
use crate::types::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    fs,
    io::{self, Read, Write},
    net::TcpStream,
    time::Duration,
};
use zeroize::Zeroize;

static JSON_OUTPUT: AtomicBool = AtomicBool::new(false);
static QUIET_OUTPUT: AtomicBool = AtomicBool::new(false);

pub fn configure_output(json: bool, quiet: bool) {
    JSON_OUTPUT.store(json, Ordering::Relaxed);
    QUIET_OUTPUT.store(quiet, Ordering::Relaxed);
}

pub fn print_error(error: &str) {
    if JSON_OUTPUT.load(Ordering::Relaxed) {
        println!("{}", serde_json::json!({ "ok": false, "error": error }));
    } else {
        eprintln!("Error: {error}");
    }
}

pub fn exit_error(error: &str, code: i32) -> ! {
    print_error(error);
    std::process::exit(code);
}

pub fn send_command(command: ServerCommand) {
    match request(command) {
        Ok(response) => {
            let exit_code = response_exit_code(&response);
            if JSON_OUTPUT.load(Ordering::Relaxed) {
                if exit_code == 0 {
                    println!(
                        "{}",
                        serde_json::json!({ "ok": true, "output": response.trim_end() })
                    );
                } else {
                    println!(
                        "{}",
                        serde_json::json!({ "ok": false, "error": response.trim_end(), "code": exit_code })
                    );
                }
            } else if !QUIET_OUTPUT.load(Ordering::Relaxed) || exit_code != 0 {
                if exit_code == 0 {
                    print!("{response}");
                } else {
                    eprint!("{response}");
                }
            }
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        Err(error) => exit_error(&error, 1),
    }
}

fn response_exit_code(response: &str) -> i32 {
    let response = response.trim().to_ascii_lowercase();
    if response.contains("not found")
        || response.starts_with("invalid id")
        || response.starts_with("no matching entries")
    {
        3
    } else if response.contains("already exists") || response.contains("duplicate") {
        4
    } else if response.starts_with("vault locked")
        || response.contains(" failed")
        || response.contains(" unavailable:")
        || response.starts_with("wrong ")
        || response.starts_with("could not ")
    {
        1
    } else {
        0
    }
}

fn server_token() -> Result<String, String> {
    let path = data_dir().join(TOKEN_FILE);
    let token = fs::read_to_string(&path)
        .map_err(|e| format!("could not read session token at {}: {e}", path.display()))?
        .trim()
        .to_string();
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("invalid session token at {}", path.display()));
    }
    Ok(token)
}

pub fn request(command: ServerCommand) -> Result<String, String> {
    let mut connection = TcpStream::connect(ADDR)
        .map_err(|e| format!("could not connect to the password manager server: {e}"))?;
    connection
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("could not configure server connection: {e}"))?;
    let mut token = server_token()?;
    let mut data =
        rmp_serde::to_vec(&command).map_err(|e| format!("could not encode command: {e}"))?;
    let send_result = connection
        .write_all(token.as_bytes())
        .and_then(|_| connection.write_all(&(data.len() as u32).to_be_bytes()))
        .and_then(|_| connection.write_all(&data))
        .and_then(|_| connection.flush())
        .map_err(|e| format!("could not send command: {e}"));
    token.zeroize();
    data.zeroize();
    send_result?;

    let mut buf = vec![0u8; 64 * 1024];
    let mut total = Vec::new();
    loop {
        match connection.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => total.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err("server response timed out".to_string());
            }
            Err(e) => return Err(format!("could not read server response: {e}")),
        }
        if total.len() > 1024 * 1024 {
            eprintln!("Response too large, truncating.");
            break;
        }
    }
    String::from_utf8(total).map_err(|_| "server returned invalid UTF-8".to_string())
}

#[cfg(test)]
mod test {
    use super::response_exit_code;

    #[test]
    fn server_responses_have_stable_exit_code_classes() {
        assert_eq!(response_exit_code("Entry added."), 0);
        assert_eq!(response_exit_code("Vault is already locked."), 0);
        assert_eq!(response_exit_code("Vault locked."), 1);
        assert_eq!(response_exit_code("Entry not found."), 3);
        assert_eq!(response_exit_code("Entry already exists."), 4);
    }
}
