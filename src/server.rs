use crate::{
    clipboard::copy_in_background,
    file::{TOKEN_FILE, data_dir, set_private_perms, sync_parent},
    protocol::{
        ResponseCode, SECURE_HELLO_LEN, SECURE_PREFACE, SECURE_RECORD_HEADER_LEN, decode_responses,
        decrypt_record, decrypt_record_stream, encode_response, encrypt_record, server_hello,
        verify_server_hello,
    },
    types::*,
    vault::{Vault, VaultAccess, create_vault, delete_vault, restore_encrypted_backup},
};
use rand::RngExt;
use serde::Deserialize;
use std::{
    cell::RefCell,
    fs,
    io::{Cursor, Read, Write},
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore, mpsc},
};
use zeroize::{Zeroize, Zeroizing};

mod commands;
mod presentation;
use commands::handle_connection_inner;
mod response;
use response::{
    deliver_entry, respond_domain_error, respond_domain_error_with_context, respond_domain_result,
};
use response::{flush_buffered_responses, respond_conflict, respond_failure, respond_not_found};
pub use response::{respond, respond_with_code};
mod session_token;
use session_token::*;

#[derive(Debug)]
pub struct ServerInfo {
    pub locked: bool,
    pub keypass: Option<PasswordType>,
}

impl Default for ServerInfo {
    fn default() -> Self {
        Self {
            locked: true,
            keypass: None,
        }
    }
}

impl Zeroize for ServerInfo {
    fn zeroize(&mut self) {
        self.locked.zeroize();
        self.keypass.zeroize();
        *self = Self::default()
    }
}
pub const DEFAULT_PORT: u16 = 7878;

pub fn server_addr(port: u16) -> std::net::SocketAddr {
    ([127, 0, 0, 1], port).into()
}

const MAX_TCP_MSG: usize = 16 * 1024 * 1024;
const TOKEN_HEX_LEN: usize = 64;
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CLIENT_CONNECTIONS: usize = 128;

struct BufferedResponse {
    code: ResponseCode,
    message: String,
}

impl Drop for BufferedResponse {
    fn drop(&mut self) {
        self.message.zeroize();
    }
}

tokio::task_local! {
    static RESPONSE_BUFFER: RefCell<Vec<BufferedResponse>>;
    static TRANSPORT_RESPONSE_KEY: RefCell<Option<Zeroizing<[u8; 32]>>>;
}
pub fn is_running(port: u16) -> bool {
    let path = data_dir().join(TOKEN_FILE);
    let Ok(mut token) = fs::read_to_string(path) else {
        return false;
    };
    token.truncate(token.trim_end().len());
    if token.len() != TOKEN_HEX_LEN || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        token.zeroize();
        return false;
    }
    let Ok(mut stream) =
        std::net::TcpStream::connect_timeout(&server_addr(port), Duration::from_millis(500))
    else {
        token.zeroize();
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    let Ok(mut command) = rmp_serde::to_vec(&ServerCommand::StatusData) else {
        token.zeroize();
        return false;
    };
    let result = (|| {
        stream.write_all(SECURE_PREFACE)?;
        stream.flush()?;
        let mut hello = [0u8; SECURE_HELLO_LEN];
        stream.read_exact(&mut hello)?;
        let keys = verify_server_hello(&token, &hello)
            .ok_or_else(|| std::io::Error::other("server authentication failed"))?;
        let mut request = encrypt_record(&keys.request, &command)
            .ok_or_else(|| std::io::Error::other("request encryption failed"))?;
        let sent = stream.write_all(&request).and_then(|_| stream.flush());
        request.zeroize();
        sent?;

        let mut encrypted = Vec::new();
        stream.read_to_end(&mut encrypted)?;
        let decrypted = decrypt_record_stream(&keys.response, &encrypted, 1024 * 1024)
            .map_err(std::io::Error::other)?;
        encrypted.zeroize();
        Ok::<Vec<u8>, std::io::Error>(decrypted)
    })();
    token.zeroize();
    command.zeroize();
    let Ok(mut response) = result else {
        return false;
    };
    let valid = decode_responses(&response).is_ok_and(|response| {
        response.code == ResponseCode::Success as i32
            && serde_json::from_str::<crate::protocol::ServerStatus>(&response.message).is_ok()
    });
    response.zeroize();
    valid
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

fn status_message(locked: bool, warning: Option<&str>) -> String {
    format!(
        "Status: {}\nVersion: {}{}",
        if locked { "Locked" } else { "Unlocked" },
        env!("CARGO_PKG_VERSION"),
        warning
            .map(|warning| format!("\nWarning: {warning}"))
            .unwrap_or_default()
    )
}

pub fn start(port: u16) -> Result<String, String> {
    if is_running(port) {
        return Ok("Server is already running.".to_string());
    }
    if std::net::TcpStream::connect_timeout(&server_addr(port), Duration::from_millis(250)).is_ok()
    {
        return Err(format!(
            "{} is already in use by another process",
            server_addr(port)
        ));
    }
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not locate the pm executable: {error}"))?;
    let mut command = Command::new(executable);
    command
        .args(["--port", &port.to_string(), "run"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(crate::file::WINDOWS_CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return Err(format!("failed to start background process: {error}")),
    };
    let pid = child.id();
    for _ in 0..20 {
        if is_running(port) {
            break;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(format!("server exited during startup with {status}"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("could not verify server startup: {error}"));
            }
        }
    }
    if !is_running(port) {
        let _ = child.kill();
        let _ = child.wait();
        return Err("server did not become ready within two seconds".to_string());
    }
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(format!("Server started (PID {pid})"))
}

fn schedule_auto_lock(
    time: u64,
    generation: u64,
    lock_generation: Arc<AtomicU64>,
    server_info: Arc<Mutex<ServerInfo>>,
    vlt: Arc<Mutex<Option<Vault>>>,
    background_error: Arc<Mutex<Option<String>>>,
) {
    if time == 0 {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(time)).await;
        if lock_generation.load(Ordering::Acquire) != generation {
            return;
        }
        let mut server_info = server_info.lock().await;
        let mut vlt = vlt.lock().await;
        if lock_generation.load(Ordering::Acquire) == generation
            && !server_info.locked
            && vlt.is_some()
        {
            let result = lock_vlt(&mut vlt, &mut server_info);
            let mut last_error = background_error.lock().await;
            match result {
                Ok(()) => *last_error = None,
                Err(error) => {
                    let message = format!("Automatic lock failed: {error}");
                    eprintln!("{message}");
                    *last_error = Some(message);
                }
            }
        }
    });
}
pub async fn server(
    port: u16,
    password_history_limit: usize,
    trash_retention_days: u64,
) -> Result<(), String> {
    let address = server_addr(port);
    let listener = TcpListener::bind(address)
        .await
        .map_err(|error| format!("could not bind password manager server to {address}: {error}"))?;
    let token_path = data_dir().join(TOKEN_FILE);
    let mut token = rotate_token_file(&token_path)
        .map_err(|error| format!("could not initialize server: {error}"))?;

    let server_info = Arc::new(Mutex::new(ServerInfo {
        locked: true,
        keypass: None,
    }));
    let vlt: Arc<Mutex<Option<Vault>>> = Arc::new(Mutex::new(None));
    let lock_generation = Arc::new(AtomicU64::new(0));
    let inactivity_timeout = Arc::new(AtomicU64::new(0));
    let background_error = Arc::new(Mutex::new(None));
    let (kill_tx, mut kill_rx) = mpsc::channel::<()>(1);
    let connection_slots = Arc::new(Semaphore::new(MAX_CLIENT_CONNECTIONS));

    loop {
        tokio::select! {
            _ = kill_rx.recv() => break,
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        eprintln!("Could not accept server connection: {error}");
                        continue;
                    }
                };
                let state = ConnectionState {
                    server_info: Arc::clone(&server_info),
                    vlt: Arc::clone(&vlt),
                    kill_tx: kill_tx.clone(),
                    token: token.clone(),
                    lock_generation: Arc::clone(&lock_generation),
                    inactivity_timeout: Arc::clone(&inactivity_timeout),
                    background_error: Arc::clone(&background_error),
                    password_history_limit,
                    trash_retention_days,
                };
                let permit = match Arc::clone(&connection_slots).acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    handle_connection(stream, state).await;
                });
            }
        }
    }
    let _ = crate::clipboard::clear_owned();
    remove_token_file_if_current(&token_path, &token);
    token.zeroize();
    Ok(())
}

#[derive(Clone)]
struct ConnectionState {
    server_info: Arc<Mutex<ServerInfo>>,
    vlt: Arc<Mutex<Option<Vault>>>,
    kill_tx: mpsc::Sender<()>,
    token: String,
    lock_generation: Arc<AtomicU64>,
    inactivity_timeout: Arc<AtomicU64>,
    background_error: Arc<Mutex<Option<String>>>,
    password_history_limit: usize,
    trash_retention_days: u64,
}

async fn handle_connection(mut stream: TcpStream, state: ConnectionState) {
    TRANSPORT_RESPONSE_KEY
        .scope(RefCell::new(None), async {
            RESPONSE_BUFFER
                .scope(RefCell::new(Vec::new()), async {
                    handle_connection_inner(&mut stream, state).await;
                    flush_buffered_responses(&mut stream).await;
                })
                .await;
        })
        .await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

async fn handle_tcp(message: &mut TcpStream, token: &str) -> Option<ServerCommand> {
    let mut preface = [0u8; SECURE_PREFACE.len()];
    if message.read_exact(&mut preface).await.is_err() || &preface != SECURE_PREFACE {
        return None;
    }
    let (hello, keys) = server_hello(token)?;
    if message.write_all(&hello).await.is_err() || message.flush().await.is_err() {
        return None;
    }
    let mut record_header = [0u8; SECURE_RECORD_HEADER_LEN];
    if message.read_exact(&mut record_header).await.is_err() {
        return None;
    }
    let len = u32::from_be_bytes(record_header[24..].try_into().ok()?) as usize;
    if !(16..=MAX_TCP_MSG + 16).contains(&len) {
        return None;
    }
    let mut ciphertext = vec![0u8; len];
    if message.read_exact(&mut ciphertext).await.is_err() {
        return None;
    }
    let mut buf = decrypt_record(&keys.request, &record_header[..24], &ciphertext)?;
    ciphertext.zeroize();
    TRANSPORT_RESPONSE_KEY.with(|key| {
        *key.borrow_mut() = Some(Zeroizing::new(keys.response));
    });
    let parsed = {
        let mut cursor = Cursor::new(buf.as_slice());
        let mut deserializer = rmp_serde::Deserializer::new(&mut cursor);
        ServerCommand::deserialize(&mut deserializer)
            .ok()
            .filter(|_| cursor.position() == buf.len() as u64)
    };
    buf.zeroize();
    parsed
}
async fn handler(message: &mut TcpStream, token: &str) -> Option<ServerCommand> {
    let mut buff = [0u8; 16];
    let n = message.peek(&mut buff).await.ok()?;
    if n == 0 {
        return None;
    }
    if buff.starts_with(SECURE_PREFACE) {
        handle_tcp(message, token).await
    } else {
        None
    }
}

fn lock_vlt(
    vlt: &mut Option<Vault>,
    server_info: &mut ServerInfo,
) -> Result<(), crate::vault::VaultError> {
    vlt.lock_vault(server_info)?;
    vlt.zeroize();
    server_info.zeroize();
    crate::clipboard::clear_owned().map_err(|error| {
        crate::vault::VaultError::Persistence(format!(
            "vault locked, but clipboard cleanup failed: {error}"
        ))
    })?;
    Ok(())
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod test;
