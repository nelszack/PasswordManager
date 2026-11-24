use crate::{
    file::{TOKEN_FILE, data_dir, sync_parent},
    protocol::{
        RequestEnvelope, ResponseCode, ResponsePayload, RpcResponse, SECURE_PREFACE,
        SECURE_RECORD_HEADER_LEN, decrypt_record, encrypt_record, server_hello,
    },
    types::*,
    vault::{
        Vault, VaultCredentials, VaultSession, create_vault, delete_vault, restore_encrypted_backup,
    },
};
use rand::RngExt;
use serde::Deserialize;
use std::{
    fs,
    io::Cursor,
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

mod cloud;
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
mod ssh_agent;
pub use ssh_agent::socket_path as ssh_agent_socket;
mod passkey_approvals;
mod unlock_throttle;

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
    /// Network or CPU work finished outside the vault queue (never `Deferred::None`).
    Deferred(crate::operations::Deferred),
}

impl From<crate::operations::Deferred> for CommandEffect {
    fn from(deferred: crate::operations::Deferred) -> Self {
        match deferred {
            crate::operations::Deferred::None => Self::None,
            work => Self::Deferred(work),
        }
    }
}

/// The vault worker as seen by deferred work and cloud sync running outside
/// its queue. Nothing is applied once the server starts stopping.
struct DesktopHost<'a> {
    worker: &'a VaultWorker,
    stopping: Arc<AtomicBool>,
}

impl crate::operations::VaultHost for DesktopHost<'_> {
    fn with_session<T: Send + 'static>(
        &self,
        expected: Option<String>,
        apply: impl FnOnce(&mut Vault, &mut VaultCredentials) -> Result<T, crate::vault::VaultError>
        + Send
        + 'static,
    ) -> impl std::future::Future<Output = Result<Result<T, crate::vault::VaultError>, String>> + Send
    {
        let stopping = self.stopping.clone();
        let applied = self.worker.with_session(move |session| {
            if stopping.load(Ordering::Acquire) {
                return Err("Server is stopping; the vault was not changed".to_owned());
            }
            if expected.is_none() || session.session_id() != expected {
                return Err(SESSION_CHANGED.to_owned());
            }
            Ok(session.with_unlocked(apply))
        });
        async move { applied.await? }
    }

    fn staleness(
        &self,
        session: Option<String>,
        revision: Option<u64>,
    ) -> crate::operations::Stale {
        let worker = self.worker.clone();
        Arc::new(move || {
            session.is_none()
                || worker.session_id() != session
                || revision.is_some_and(|revision| worker.vault_revision() != Some(revision))
        })
    }

    fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> crate::operations::Blocking<T> {
        // One CPU-heavy strength scoring at a time, outside the vault queue.
        static SCORING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
        Box::pin(async move {
            let _permit = SCORING.acquire().await.ok()?;
            tokio::task::spawn_blocking(work).await.ok()
        })
    }
}

/// Reported when deferred work returns to a vault that was locked or replaced.
pub(crate) const SESSION_CHANGED: &str = "Vault locked or switched; nothing was applied";

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
    ssh_agent: bool,
) -> Result<(), String> {
    let directory = data_dir();
    let instance_lock = Arc::new(acquire_server_lock(&directory)?);
    #[cfg(target_os = "windows")]
    // Use a sidecar: Windows byte-range locks also prevent other handles from
    // reading the ownership file. Publish before the authenticated listener.
    crate::cloud::write_private(
        &directory.join(crate::file::SERVER_PID_FILE),
        std::process::id().to_string().as_bytes(),
        true,
    )?;
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
    let ssh_approvals: Arc<ssh_agent::SshApprovals> = Arc::default();
    let passkey_approvals: Arc<passkey_approvals::PasskeyApprovals> = Arc::default();
    let cloud_task = cloud::start(worker.clone(), stopping.clone());
    // An agent failure is reported, not fatal: the vault service still runs.
    #[cfg(any(unix, windows))]
    let agent = match ssh_agent
        .then(|| ssh_agent::Agent::start(worker.clone(), Arc::clone(&ssh_approvals)))
    {
        Some(Ok(agent)) => Some(agent),
        Some(Err(error)) => {
            let _ = ssh_agent::UNAVAILABLE.set(format!("SSH agent unavailable: {error}"));
            None
        }
        None => None,
    };
    #[cfg(not(any(unix, windows)))]
    if ssh_agent {
        let _ = ssh_agent::UNAVAILABLE
            .set("The SSH agent is not available on this platform yet.".into());
    }
    let (kill_tx, mut kill_rx) = mpsc::channel::<()>(1);
    let connection_slots = Arc::new(Semaphore::new(MAX_CLIENT_CONNECTIONS));
    let status_subscribers = Arc::new(Semaphore::new(MAX_STATUS_SUBSCRIBERS));
    let unlock_throttle = Arc::default();

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
                    status_subscribers: Arc::clone(&status_subscribers),
                    unlock_throttle: Arc::clone(&unlock_throttle),
                    ssh_approvals: Arc::clone(&ssh_approvals),
                    passkey_approvals: Arc::clone(&passkey_approvals),
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
    cloud_task.abort();
    #[cfg(any(unix, windows))]
    if let Some(agent) = agent {
        agent.stop();
    }
    system_lock.stop();
    worker.lock().await;
    let _ = crate::clipboard::clear_owned();
    remove_token_file_if_current(&token_path, &token);
    #[cfg(target_os = "windows")]
    let _ = fs::remove_file(directory.join(crate::file::SERVER_PID_FILE));
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
    /// Bounds long-lived status subscriptions for this server.
    status_subscribers: Arc<Semaphore>,
    /// Shared by every connection so repeated wrong passwords slow down.
    unlock_throttle: Arc<std::sync::Mutex<unlock_throttle::UnlockThrottle>>,
    /// SSH agent signatures waiting for a decision.
    ssh_approvals: Arc<ssh_agent::SshApprovals>,
    /// Browser passkey requests waiting for the person's confirmation.
    passkey_approvals: Arc<passkey_approvals::PasskeyApprovals>,
}

async fn handle_connection(mut stream: TcpStream, mut state: ConnectionState, worker: VaultWorker) {
    let instance_lock = state.instance_lock.clone();
    let Ok(Some(AuthenticatedRequest {
        request,
        response_key,
    })) = tokio::time::timeout(CLIENT_IO_TIMEOUT, handler(&mut stream, &state.token)).await
    else {
        return;
    };
    if matches!(request.command, ServerCommand::StatusEvents) {
        // A subscription is long-lived and runs no command, so it must not
        // keep the data directory owned after the server stops.
        drop(instance_lock);
        state.instance_lock = None;
        if request.validate().is_ok() {
            stream_status(stream, &state, &worker, &response_key, &request.request_id).await;
        }
        return;
    }
    let _instance_lock = instance_lock;
    // Bound audit-owned cold-password snapshots before the vault clones them.
    static AUDIT_REQUEST: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    let _audit_permit = if matches!(request.command, ServerCommand::Audit(_)) {
        match AUDIT_REQUEST.try_acquire() {
            Ok(permit) => Some(permit),
            Err(_) => {
                let mut response = RpcResponse::message(
                    ResponseCode::Failure,
                    "An audit is already running; try again after it finishes",
                );
                response.request_id = Some(request.request_id.clone());
                response.session_id = worker.session_id();
                let _ = deliver_responses(Some(response), &mut stream, &response_key).await;
                return;
            }
        }
    } else {
        None
    };
    let operation_id = request.operation_id.clone();
    let stopping = state.stopping.clone();
    let request_id = request.request_id.clone();
    let kill_tx = state.kill_tx.clone();
    let mut result =
        if matches!(request.command, ServerCommand::Status) && request.validate().is_ok() {
            // Status is nonsecret published state; it remains responsive while
            // the owner finishes a filesystem commit or derives a key.
            outcome::CommandOutcome {
                reply: Some(current_status(&state, &worker).await),
                effect: CommandEffect::None,
                ..Default::default()
            }
        } else if let ServerCommand::PasskeyVerification { origin } = &request.command {
            // Waits for the person, so it never occupies the vault worker.
            let session = worker.session_id();
            let result = if let Err(e) = request.validate() {
                Err(e)
            } else if session.is_none() {
                Err(crate::protocol::VAULT_LOCKED.into())
            } else if request.expected_session.is_some() && request.expected_session != session {
                Err("Unlock session changed; try the passkey request again".into())
            } else if !worker.passkey_confirmation().0 {
                Err("This vault has no master password or passkey PIN to confirm with.".into())
            } else {
                // Locking (or any session change) ends the wait at once.
                let asked = session.clone().unwrap_or_default();
                let mut sessions = worker.changes().0;
                let ended = async {
                    while sessions.changed().await.is_ok() {
                        if sessions.borrow().as_deref() != Some(asked.as_str()) {
                            break;
                        }
                    }
                };
                tokio::select! {
                    result = state.passkey_approvals.ask(origin.clone(), asked.clone()) => result,
                    () = ended => Err("The vault locked; try the passkey request again".into()),
                }
            };
            let mut response = match result {
                Ok(token) => RpcResponse::success(ResponsePayload::Message(token)),
                Err(error) => RpcResponse::message(ResponseCode::Failure, error),
            };
            response.session_id = session;
            outcome::CommandOutcome {
                reply: Some(response),
                ..Default::default()
            }
        } else if let ServerCommand::Cloud(action) = &request.command {
            let result = if state.stopping.load(Ordering::Acquire) {
                Err("Server is stopping".into())
            } else if let Err(e) = request.validate() {
                Err(e)
            } else if request
                .expected_session
                .as_ref()
                .is_some_and(|s| worker.session_id().as_ref() != Some(s))
            {
                Err("Unlock session changed; reopen the vault before syncing".into())
            } else {
                cloud::command(
                    &worker,
                    action.clone(),
                    request
                        .expected_session
                        .clone()
                        .or_else(|| worker.session_id()),
                    state.stopping.clone(),
                )
                .await
            };
            let mut response = match result {
                Ok(payload) => RpcResponse::success(payload),
                Err(error) => RpcResponse::message(ResponseCode::Failure, error),
            };
            response.session_id = worker.session_id();
            outcome::CommandOutcome {
                reply: Some(response),
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
        result = finish_external_effect(result, worker, stopping, operation_id).await;
    }
    if let Some(response) = result.reply.as_mut() {
        response.request_id = Some(request_id.clone());
    }
    if let Err(error) = deliver_responses(result.reply, &mut stream, &response_key).await {
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
    stopping: Arc<AtomicBool>,
    operation_id: Option<String>,
) -> outcome::CommandOutcome {
    if let CommandEffect::Deferred(work) = std::mem::take(&mut result.effect) {
        let host = DesktopHost {
            worker: &worker,
            stopping,
        };
        let session = result.session_id.clone();
        crate::operations::finish_deferred(work, &host, session, &mut result.reply).await;
    }
    worker.finish_external(result, operation_id).await
}

/// Nonsecret published state. Reading it never touches the vault queue or
/// counts as activity, so it cannot keep a vault unlocked.
async fn current_status(state: &ConnectionState, worker: &VaultWorker) -> RpcResponse {
    let warnings = [
        state.background_error.lock().await.clone(),
        state
            .system_lock
            .as_deref()
            .and_then(system_lock::Monitor::warning),
        ssh_agent::UNAVAILABLE.get().cloned(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let warning = (!warnings.is_empty()).then(|| warnings.join("; "));
    let session_id = worker.session_id();
    let mut response = RpcResponse::success(ResponsePayload::Status(
        crate::protocol::ServerStatus::new(session_id.is_none(), warning),
    ));
    if let ResponsePayload::Status(status) = &mut response.payload {
        status.vault_revision = worker.vault_revision();
        status.cloud_warning = worker.cloud_warning().await;
        status.ssh_requests = state.ssh_approvals.list();
        (status.passkey_verification, status.passkey_pin) = worker.passkey_confirmation();
        status.passkey_requests = state.passkey_approvals.list_for(session_id.as_deref());
    }
    response.session_id = session_id;
    response
}

/// Concurrent status subscribers; each also holds a connection slot.
const MAX_STATUS_SUBSCRIBERS: usize = 8;
/// Warnings have no change signal, so they are rechecked in memory this often.
const STATUS_WARNING_CHECK: Duration = Duration::from_secs(2);
/// An unchanged stream still sends a record this often, so clients detect a
/// stopped server and refresh anything outside the published status.
const STATUS_HEARTBEAT: Duration = Duration::from_secs(20);

/// Push a status record whenever the session, revision, or warnings change.
/// Record `n` is encrypted under its own key derived from the connection's
/// response key, so records cannot be replayed, dropped, or reordered.
async fn stream_status(
    mut stream: TcpStream,
    state: &ConnectionState,
    worker: &VaultWorker,
    response_key: &[u8; 32],
    request_id: &str,
) {
    let Ok(_subscriber) = state.status_subscribers.try_acquire() else {
        let mut response = RpcResponse::message(
            ResponseCode::Failure,
            "Too many status subscribers; poll status instead",
        );
        response.request_id = Some(request_id.to_owned());
        let key = crate::protocol::stream_record_key(response_key, 0);
        let _ = write_status_record(&mut stream, &key, &response).await;
        return;
    };
    let (mut sessions, mut revisions) = worker.changes();
    let mut sequence = 0u64;
    let mut last_sent: Option<Zeroizing<Vec<u8>>> = None;
    let mut last_write = tokio::time::Instant::now();
    loop {
        if state.stopping.load(Ordering::Acquire) {
            return;
        }
        let mut response = current_status(state, worker).await;
        response.request_id = Some(request_id.to_owned());
        let Ok(encoded) = crate::protocol::encode_rpc_response(&response) else {
            return;
        };
        if last_sent.as_ref() != Some(&encoded) || last_write.elapsed() >= STATUS_HEARTBEAT {
            let key = crate::protocol::stream_record_key(response_key, sequence);
            if write_status_record(&mut stream, &key, &response)
                .await
                .is_err()
            {
                return;
            }
            sequence += 1;
            last_sent = Some(encoded);
            last_write = tokio::time::Instant::now();
        }
        tokio::select! {
            changed = sessions.changed() => if changed.is_err() { return },
            changed = revisions.changed() => if changed.is_err() { return },
            () = state.ssh_approvals.changed.notified() => {}
            () = state.passkey_approvals.changed.notified() => {}
            _ = tokio::time::sleep(STATUS_WARNING_CHECK) => {}
            readable = stream.readable() => {
                // Clients never write after subscribing: data or EOF ends it.
                if readable.is_err() {
                    return;
                }
                match stream.try_read(&mut [0u8; 1]) {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    _ => return,
                }
            }
        }
    }
}

async fn write_status_record(
    stream: &mut TcpStream,
    key: &[u8; 32],
    response: &RpcResponse,
) -> std::io::Result<()> {
    let frame = crate::protocol::encode_rpc_response(response).map_err(std::io::Error::other)?;
    let record = encrypt_record(key, &frame)
        .ok_or_else(|| std::io::Error::other("could not encrypt status record"))?;
    tokio::time::timeout(Duration::from_secs(2), async {
        stream.write_all(&record).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "status write timed out"))?
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
