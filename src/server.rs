use crate::{
    clipboard::copy_in_background,
    file::{TOKEN_FILE, data_dir, set_private_perms, sync_parent},
    protocol::{
        RequestEnvelope, ResponseCode, ResponsePayload, RpcResponse, SECURE_PREFACE,
        SECURE_RECORD_HEADER_LEN, decrypt_record, encrypt_record, server_hello,
    },
    types::*,
    vault::{Vault, VaultSession, create_vault, delete_vault, restore_encrypted_backup},
};
use rand::RngExt;
use serde::Deserialize;
use std::{
    fs,
    io::{Cursor, Write},
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
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
use commands::execute_command;
mod outcome;
mod response;
use response::deliver_responses;
mod worker;
use worker::VaultWorker;
mod session_token;
use session_token::*;
mod instance_lock;
mod system_lock;
use instance_lock::acquire_server_lock;

pub use crate::protocol::{DEFAULT_PORT, server_addr};
pub use crate::vault::VaultCredentials as ServerInfo;

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

#[derive(Default)]
enum CommandEffect {
    #[default]
    None,
    StopServer,
    Audit(crate::vault::AuditSnapshot, bool),
    Duo(Box<crate::vault::PreparedDuoPoll>),
    DuoEnrollment(Box<crate::vault::PreparedDuoEnrollment>),
}

struct AuthenticatedRequest {
    request: RequestEnvelope,
    response_key: Zeroizing<[u8; 32]>,
}
pub fn is_running(port: u16) -> bool {
    crate::client::AuthenticatedClient::probe(port)
        .request_response(ServerCommand::Status)
        .is_ok_and(|response| {
            response.code == ResponseCode::Success as i32
                && matches!(response.payload, ResponsePayload::Status(_))
        })
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
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
    // Provide an actionable startup error. The child acquires and holds the
    // authoritative lock itself, closing the race between this check and spawn.
    drop(acquire_server_lock(&data_dir())?);
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

pub async fn server(
    port: u16,
    password_history_limit: usize,
    trash_retention_days: u64,
) -> Result<(), String> {
    let directory = data_dir();
    let instance_lock = Arc::new(acquire_server_lock(&directory)?);
    let address = server_addr(port);
    let listener = TcpListener::bind(address)
        .await
        .map_err(|error| format!("could not bind password manager server to {address}: {error}"))?;
    let token_path = directory.join(TOKEN_FILE);
    let mut token = rotate_token_file(&token_path)
        .map_err(|error| format!("could not initialize server: {error}"))?;

    let inactivity_timeout = Arc::new(AtomicU64::new(0));
    let stopping = Arc::new(AtomicBool::new(false));
    let background_error = Arc::new(Mutex::new(None));
    let worker = VaultWorker::start(
        VaultSession::default(),
        Arc::clone(&inactivity_timeout),
        Arc::clone(&background_error),
    );
    let system_lock =
        system_lock::Monitor::start(worker.system_lock_handler(Arc::clone(&background_error)));
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
                    instance_lock: Some(Arc::clone(&instance_lock)),
                    kill_tx: kill_tx.clone(),
                    token: token.clone(),
                    inactivity_timeout: Arc::clone(&inactivity_timeout),
                    stopping: Arc::clone(&stopping),
                    background_error: Arc::clone(&background_error),
                    system_lock: Some(Arc::clone(&system_lock)),
                    password_history_limit,
                    trash_retention_days,
                };
                let permit = match Arc::clone(&connection_slots).acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };
                let connection_worker = worker.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    handle_connection(stream, state, connection_worker).await;
                });
            }
        }
    }
    stopping.store(true, Ordering::Release);
    system_lock.stop();
    worker.lock().await;
    let _ = crate::clipboard::clear_owned();
    remove_token_file_if_current(&token_path, &token);
    token.zeroize();
    Ok(())
}

#[derive(Clone)]
struct ConnectionState {
    // Accepted commands retain directory ownership through blocking work and
    // response delivery, even if the listener has already stopped.
    instance_lock: Option<Arc<fs::File>>,
    kill_tx: mpsc::Sender<()>,
    token: Zeroizing<String>,
    inactivity_timeout: Arc<AtomicU64>,
    stopping: Arc<AtomicBool>,
    background_error: Arc<Mutex<Option<String>>>,
    system_lock: Option<Arc<system_lock::Monitor>>,
    password_history_limit: usize,
    trash_retention_days: u64,
}

async fn handle_connection(mut stream: TcpStream, state: ConnectionState, worker: VaultWorker) {
    let _instance_lock = state.instance_lock.clone();
    let Ok(Some(AuthenticatedRequest {
        request,
        response_key,
    })) = tokio::time::timeout(CLIENT_IO_TIMEOUT, handler(&mut stream, &state.token)).await
    else {
        return;
    };
    let operation_id = request.operation_id.clone();
    let request_id = request.request_id.clone();
    let kill_tx = state.kill_tx.clone();
    let mut result =
        if matches!(request.command, ServerCommand::Status) && request.validate().is_ok() {
            // Status is nonsecret published state; it remains responsive while
            // the owner finishes a filesystem commit or derives a key.
            let warnings = [
                state.background_error.lock().await.clone(),
                state
                    .system_lock
                    .as_deref()
                    .and_then(system_lock::Monitor::warning),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
            let warning = (!warnings.is_empty()).then(|| warnings.join("; "));
            let session_id = worker.session_id();
            let mut response = RpcResponse::success(ResponsePayload::Status(
                crate::protocol::ServerStatus::new(session_id.is_none(), warning),
            ));
            response.session_id = session_id;
            outcome::CommandOutcome {
                responses: vec![response],
                effect: CommandEffect::None,
                ..Default::default()
            }
        } else {
            worker.execute(state, request).await
        };
    let stop_server = matches!(result.effect, CommandEffect::StopServer);
    if !matches!(
        result.effect,
        CommandEffect::None | CommandEffect::StopServer
    ) {
        result = finish_external_effect(result, worker, operation_id).await;
    }
    for response in &mut result.responses {
        response.request_id = Some(request_id.clone());
    }
    if let Err(error) = deliver_responses(result.responses, &mut stream, &response_key).await {
        eprintln!("Could not deliver authenticated response: {error}");
    }
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
    if stop_server {
        let _ = kill_tx.send(()).await;
    }
}

/// Finish asynchronous work through the same session check and response
/// binding for Duo polling, decisions, enrollment, and audit reports.
async fn finish_external_effect(
    mut result: outcome::CommandOutcome,
    worker: VaultWorker,
    operation_id: Option<String>,
) -> outcome::CommandOutcome {
    let effect = std::mem::take(&mut result.effect);
    match effect {
        CommandEffect::Duo(prepared) => {
            finish_duo(*prepared, worker.clone(), &mut result.responses).await
        }
        CommandEffect::DuoEnrollment(prepared) => {
            finish_duo_enrollment(*prepared, worker.clone(), &mut result.responses).await
        }
        CommandEffect::Audit(snapshot, check_breaches) => {
            let audit = snapshot.audit(check_breaches).await;
            let code = if audit.incomplete {
                ResponseCode::Failure
            } else {
                ResponseCode::Success
            };
            outcome::respond_payload(
                code,
                ResponsePayload::Audit(audit.report),
                &mut result.responses,
            );
        }
        _ => {}
    }
    worker.finish_external(result, operation_id).await
}

async fn finish_duo_enrollment(
    prepared: crate::vault::PreparedDuoEnrollment,
    worker: VaultWorker,
    responses: &mut Vec<RpcResponse>,
) {
    let result = tokio::task::spawn_blocking(move || {
        let material = prepared.enroll();
        (prepared, material)
    })
    .await;
    let (prepared, material) = match result {
        Ok((prepared, Ok(material))) => (prepared, material),
        Ok((_, Err(error))) => {
            outcome::respond_domain_error_with_context(
                &error,
                &format!("Duo setup failed: {error}"),
                responses,
            );
            return;
        }
        Err(_) => {
            outcome::respond_failure(
                "Duo enrollment worker failed; check enrollment before retrying.",
                responses,
            );
            return;
        }
    };
    let result = worker
        .with_session(move |session| {
            let mut edit = session.edit();
            let (key, vault) = edit.parts_mut();
            crate::vault::available(vault)
                .and_then(|v| v.finish_duo_enrollment(&prepared, material, key))
        })
        .await;
    match result {
        Ok(Ok(output)) => outcome::respond_domain_result(Ok(output), responses),
        Ok(Err(error)) => outcome::respond_domain_error_with_context(
            &error,
            &format!("Duo enrolled but saving failed: {error}. Check enrollment before retrying."),
            responses,
        ),
        Err(error) => outcome::respond_failure(&error, responses),
    }
}

async fn finish_duo(
    prepared: crate::vault::PreparedDuoPoll,
    worker: VaultWorker,
    responses: &mut Vec<RpcResponse>,
) {
    let crate::vault::PreparedDuoPoll { request, review } = prepared;
    let body = match request.execute().await {
        Ok(body) => body,
        Err(error) => {
            outcome::respond_domain_error(&error, responses);
            return;
        }
    };
    let result = worker
        .with_session(move |session| {
            let mut edit = session.edit();
            let (key, vault) = edit.parts_mut();
            crate::vault::available(vault).and_then(|v| v.finish_duo_poll(&review, &body, key))
        })
        .await;
    match result {
        Ok(Ok(crate::vault::DuoPollResult::Requests(output))) => outcome::respond_payload(
            ResponseCode::Success,
            ResponsePayload::DuoRequests(output),
            responses,
        ),
        Ok(Ok(crate::vault::DuoPollResult::Decision(request))) => {
            let result = (*request)
                .execute()
                .await
                .and_then(|body| crate::duo::acknowledge(&body));
            outcome::respond_domain_result(
                result.map(|_| "Duo decision accepted.".into()),
                responses,
            );
        }
        Ok(Err(error)) => outcome::respond_domain_error(&error, responses),
        Err(error) => outcome::respond_failure(&error, responses),
    }
}

async fn handle_tcp(message: &mut TcpStream, token: &str) -> Option<AuthenticatedRequest> {
    handle_tcp_with_budget(message, token, &REQUEST_MEMORY).await
}

async fn handle_tcp_with_budget(
    message: &mut TcpStream,
    token: &str,
    budget: &Semaphore,
) -> Option<AuthenticatedRequest> {
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
    let parsed = {
        let mut cursor = Cursor::new(buf.as_slice());
        let mut deserializer = rmp_serde::Deserializer::new(&mut cursor);
        RequestEnvelope::deserialize(&mut deserializer)
            .ok()
            .filter(|_| cursor.position() == buf.len() as u64)
    };
    buf.zeroize();
    parsed.map(|request| AuthenticatedRequest {
        request,
        response_key: Zeroizing::new(keys.response),
    })
}
async fn handler(message: &mut TcpStream, token: &str) -> Option<AuthenticatedRequest> {
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
    session.lock();
    crate::clipboard::clear_owned().map_err(|error| {
        crate::vault::VaultError::Persistence(format!(
            "vault locked, but clipboard cleanup failed: {error}"
        ))
    })
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod test;
