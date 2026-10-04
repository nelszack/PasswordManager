use crate::{
    clipboard::copy_in_background,
    file::{TOKEN_FILE, data_dir, set_private_perms, sync_parent},
    protocol::{
        ResponseCode, SECURE_PREFACE, SECURE_RECORD_HEADER_LEN, decrypt_record, encode_response,
        encrypt_record, server_hello,
    },
    types::*,
    vault::{Vault, VaultSession, create_vault, delete_vault, restore_encrypted_backup},
};
use rand::RngExt;
use serde::Deserialize;
use std::{
    cell::RefCell,
    fs,
    io::{Cursor, Write},
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
pub(crate) mod presentation;
use commands::execute_command;
mod outcome;
mod response;
use response::deliver_responses;
pub use response::{respond, respond_with_code};
mod session_token;
use session_token::*;

pub use crate::vault::VaultCredentials as ServerInfo;
pub const DEFAULT_PORT: u16 = 7878;

pub fn server_addr(port: u16) -> std::net::SocketAddr {
    ([127, 0, 0, 1], port).into()
}

#[cfg(test)]
const TOKEN_HEX_LEN: usize = 64;
const MAX_TCP_MSG: usize = 16 * 1024 * 1024;
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CLIENT_CONNECTIONS: usize = 128;
// Reserve space for both ciphertext and decrypted payload before allocating.
// Fail fast under pressure rather than queue unauthenticated requests.
const REQUEST_MEMORY_KIB: usize = 64 * 1024;
static REQUEST_MEMORY: Semaphore = Semaphore::const_new(REQUEST_MEMORY_KIB);

fn reserve_request_memory(
    budget: &Semaphore,
    bytes: usize,
) -> Option<tokio::sync::SemaphorePermit<'_>> {
    let kib = bytes.checked_mul(2)?.div_ceil(1024);
    budget.try_acquire_many(u32::try_from(kib).ok()?).ok()
}

struct BufferedResponse {
    code: ResponseCode,
    message: String,
}

#[derive(Default)]
enum CommandEffect {
    #[default]
    None,
    StopServer,
    Audit(crate::vault::AuditSnapshot, bool),
}

impl Drop for BufferedResponse {
    fn drop(&mut self) {
        self.message.zeroize();
    }
}

tokio::task_local! {
    static TRANSPORT_RESPONSE_KEY: RefCell<Option<Zeroizing<[u8; 32]>>>;
}
pub fn is_running(port: u16) -> bool {
    crate::client::AuthenticatedClient::probe(port)
        .request_response(ServerCommand::StatusData)
        .is_ok_and(|response| {
            response.code == ResponseCode::Success as i32
                && serde_json::from_str::<crate::protocol::ServerStatus>(&response.message).is_ok()
        })
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
    session: Arc<Mutex<VaultSession>>,
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
        let mut session = session.lock_owned().await;
        let result = tokio::task::spawn_blocking(move || {
            if lock_generation.load(Ordering::Acquire) == generation && !session.is_locked() {
                Some(lock_session(&mut session))
            } else {
                None
            }
        })
        .await;
        let warning = match result {
            Ok(Some(Ok(()))) => None,
            Ok(Some(Err(error))) => Some(format!("Automatic lock failed: {error}")),
            Ok(None) => return,
            Err(error) => Some(format!("Automatic lock worker failed: {error}")),
        };
        if let Some(message) = warning.as_deref() {
            eprintln!("{message}");
        }
        *background_error.lock().await = warning;
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

    let session = Arc::new(Mutex::new(VaultSession::default()));
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
                    session: Arc::clone(&session),
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
    session: Arc<Mutex<VaultSession>>,
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
        .scope(RefCell::new(None), async move {
            let Ok(Some(command)) =
                tokio::time::timeout(CLIENT_IO_TIMEOUT, handler(&mut stream, &state.token)).await
            else {
                return;
            };
            let kill_tx = state.kill_tx.clone();
            // Wait for vault ownership asynchronously. Only its current owner
            // occupies a blocking worker; the connection limit bounds the queue.
            let mut session = Arc::clone(&state.session).lock_owned().await;
            let result =
                tokio::task::spawn_blocking(move || execute_command(state, command, &mut session))
                    .await;
            let mut outcome = match result {
                Ok(outcome) => outcome,
                Err(error) => {
                    eprintln!("Vault command worker failed: {error}");
                    return;
                }
            };
            let stop_server = matches!(&outcome.effect, CommandEffect::StopServer);
            if let CommandEffect::Audit(snapshot, check_breaches) = outcome.effect {
                // Network calls run after releasing the vault session.
                let audit = snapshot.audit(check_breaches).await;
                let code = if audit.incomplete {
                    ResponseCode::Failure
                } else {
                    ResponseCode::Success
                };
                outcome::respond_with_code(
                    code,
                    &presentation::audit(&audit.report),
                    &mut outcome.responses,
                );
            }
            deliver_responses(outcome.responses, &mut stream).await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
            if stop_server {
                let _ = kill_tx.send(()).await;
            }
        })
        .await;
}

async fn handle_tcp(message: &mut TcpStream, token: &str) -> Option<ServerCommand> {
    handle_tcp_with_budget(message, token, &REQUEST_MEMORY).await
}

async fn handle_tcp_with_budget(
    message: &mut TcpStream,
    token: &str,
    budget: &Semaphore,
) -> Option<ServerCommand> {
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
    let _memory = reserve_request_memory(budget, len)?;
    let mut ciphertext = vec![0u8; len];
    if message.read_exact(&mut ciphertext).await.is_err() {
        return None;
    }
    let mut buf = decrypt_record(&keys.request, &record_header[..24], &ciphertext)?;
    ciphertext.zeroize();
    drop(ciphertext);
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
    // TCP does not preserve write boundaries. handle_tcp reads the complete
    // preface under the connection's handshake timeout before validating it.
    handle_tcp(message, token).await
}

fn lock_vlt(
    vlt: &mut Option<Vault>,
    server_info: &mut ServerInfo,
) -> Result<(), crate::vault::VaultError> {
    vlt.zeroize();
    server_info.zeroize();
    crate::clipboard::clear_owned().map_err(|error| {
        crate::vault::VaultError::Persistence(format!(
            "vault locked, but clipboard cleanup failed: {error}"
        ))
    })?;
    Ok(())
}

fn lock_session(session: &mut VaultSession) -> Result<(), crate::vault::VaultError> {
    let (credentials, vault) = session.parts_mut();
    lock_vlt(vault, credentials)
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod test;
