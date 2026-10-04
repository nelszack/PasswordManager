use crate::file::{TOKEN_FILE, data_dir};
use crate::types::*;
use crate::{
    protocol::{
        ProtocolResponse, ResponseCode, SECURE_HELLO_LEN, SECURE_PREFACE, decode_responses,
        decrypt_record_stream, encrypt_record, verify_server_hello,
    },
    server::{DEFAULT_PORT, server_addr},
};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::{
    fs,
    io::{self, Read, Write},
    net::TcpStream,
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

static JSON_OUTPUT: AtomicBool = AtomicBool::new(false);
static QUIET_OUTPUT: AtomicBool = AtomicBool::new(false);
static SERVER_PORT: AtomicU16 = AtomicU16::new(DEFAULT_PORT);
const MAX_SERVER_RESPONSE: usize = 128 * 1024 * 1024;

pub fn configure_output(json: bool, quiet: bool) {
    JSON_OUTPUT.store(json, Ordering::Relaxed);
    QUIET_OUTPUT.store(quiet, Ordering::Relaxed);
}

pub fn configure_port(port: u16) {
    SERVER_PORT.store(port, Ordering::Relaxed);
}

pub fn print_error(error: &str) {
    if JSON_OUTPUT.load(Ordering::Relaxed) {
        println!("{}", serde_json::json!({ "ok": false, "error": error }));
    } else {
        eprintln!("Error: {error}");
    }
}

pub fn print_success(output: &str) {
    let rendered = if JSON_OUTPUT.load(Ordering::Relaxed) {
        format!(
            "{}\n",
            serde_json::json!({ "ok": true, "output": output.trim_end() })
        )
    } else if QUIET_OUTPUT.load(Ordering::Relaxed) {
        return;
    } else if output.ends_with('\n') {
        output.to_string()
    } else {
        format!("{output}\n")
    };
    let _ = io::stdout().write_all(rendered.as_bytes());
}

pub fn print_warning(warning: &str) {
    if !QUIET_OUTPUT.load(Ordering::Relaxed) {
        eprintln!("Warning: {warning}");
    }
}

pub fn exit_error(error: &str, code: i32) -> ! {
    print_error(error);
    std::process::exit(code);
}

pub fn send_command(command: ServerCommand) {
    match request_response(command) {
        Ok(response) => {
            let exit_code = response.code;
            if JSON_OUTPUT.load(Ordering::Relaxed) {
                if exit_code == 0 {
                    println!(
                        "{}",
                        serde_json::json!({ "ok": true, "output": response.message.trim_end() })
                    );
                } else {
                    println!(
                        "{}",
                        serde_json::json!({ "ok": false, "error": response.message.trim_end(), "code": exit_code })
                    );
                }
            } else if !QUIET_OUTPUT.load(Ordering::Relaxed) || exit_code != 0 {
                if exit_code == 0 {
                    print!("{}", response.message);
                } else {
                    eprint!("{}", response.message);
                }
            }
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        Err(error) => exit_error(&error, 1),
    }
}

fn server_token() -> Result<String, String> {
    let path = data_dir().join(TOKEN_FILE);
    let contents = Zeroizing::new(
        fs::read_to_string(&path)
            .map_err(|e| format!("could not read session token at {}: {e}", path.display()))?,
    );
    let token = contents.trim().to_string();
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("invalid session token at {}", path.display()));
    }
    Ok(token)
}

pub fn request(command: ServerCommand) -> Result<String, String> {
    let response = request_response(command)?;
    if response.code == ResponseCode::Success as i32 {
        Ok(response.message)
    } else {
        Err(response.message.trim_end().to_string())
    }
}

fn request_response(command: ServerCommand) -> Result<ProtocolResponse, String> {
    let command = Zeroizing::new(command);
    let read_timeout = if matches!(
        &*command,
        ServerCommand::Audit(AuditOptions {
            check_breaches: true,
            ..
        })
    ) {
        Duration::from_secs(5 * 60)
    } else {
        Duration::from_secs(5)
    };
    let address = server_addr(SERVER_PORT.load(Ordering::Relaxed));
    let mut connection = TcpStream::connect(address)
        .map_err(|e| format!("could not connect to the password manager server: {e}"))?;
    connection
        .set_read_timeout(Some(read_timeout))
        .map_err(|e| format!("could not configure server connection: {e}"))?;
    let token = Zeroizing::new(server_token()?);
    connection
        .write_all(SECURE_PREFACE)
        .and_then(|_| connection.flush())
        .map_err(|e| format!("could not start secure server handshake: {e}"))?;
    let mut hello = [0u8; SECURE_HELLO_LEN];
    connection
        .read_exact(&mut hello)
        .map_err(|e| format!("could not authenticate the password manager server: {e}"))?;
    let keys = verify_server_hello(&token, &hello)
        .ok_or_else(|| "password manager server authentication failed".to_string())?;
    let data = Zeroizing::new(
        rmp_serde::to_vec(&*command).map_err(|e| format!("could not encode command: {e}"))?,
    );
    let mut encrypted_request = encrypt_record(&keys.request, &data)
        .ok_or_else(|| "could not encrypt command".to_string())?;
    let send_result = connection
        .write_all(&encrypted_request)
        .and_then(|_| connection.flush())
        .map_err(|e| format!("could not send encrypted command: {e}"));
    encrypted_request.zeroize();
    send_result?;

    let mut buf = vec![0u8; 64 * 1024];
    let mut total = Vec::new();
    loop {
        match connection.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if total.len().saturating_add(n) > MAX_SERVER_RESPONSE {
                    total.zeroize();
                    return Err("server response exceeds the 128 MiB limit".to_string());
                }
                total.extend_from_slice(&buf[..n]);
            }
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
    }
    let mut plaintext = decrypt_record_stream(&keys.response, &total, MAX_SERVER_RESPONSE)?;
    total.zeroize();
    let response = decode_responses(&plaintext);
    plaintext.zeroize();
    response
}
