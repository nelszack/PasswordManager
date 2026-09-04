use crate::file::{TOKEN_FILE, data_dir};
use crate::server::ADDR;
use crate::types::*;
use std::{
    fs,
    io::{self, Read, Write},
    net::TcpStream,
    time::Duration,
};

pub fn send_command(command: ServerCommand) {
    if let Err(error) = try_send_command(command) {
        eprintln!("Error: {error}");
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

fn try_send_command(command: ServerCommand) -> Result<(), String> {
    let mut connection = TcpStream::connect(ADDR)
        .map_err(|e| format!("could not connect to the password manager server: {e}"))?;
    connection
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("could not configure server connection: {e}"))?;
    let token = server_token()?;
    let data =
        bincode::serialize(&command).map_err(|e| format!("could not encode command: {e}"))?;
    connection
        .write_all(token.as_bytes())
        .and_then(|_| connection.write_all(&(data.len() as u32).to_be_bytes()))
        .and_then(|_| connection.write_all(&data))
        .and_then(|_| connection.flush())
        .map_err(|e| format!("could not send command: {e}"))?;

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
    let response = String::from_utf8_lossy(&total);
    print!("{}", response);
    Ok(())
}
