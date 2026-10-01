use crate::{
    clipboard::copy_in_background,
    file::{TOKEN_FILE, data_dir, set_private_perms, sync_parent},
    protocol::{
        ResponseCode, SECURE_HELLO_LEN, SECURE_PREFACE, SECURE_RECORD_HEADER_LEN, decode_responses,
        decrypt_record, decrypt_record_stream, encode_response, encrypt_record, server_hello,
        verify_server_hello,
    },
    types::*,
    vault::{Vault, VaultAccess, VaultEntry, create_vault, delete_vault, restore_encrypted_backup},
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

mod response;
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
impl Zeroize for PasswordType {
    fn zeroize(&mut self) {
        match self {
            PasswordType::Key(k) => {
                k.zeroize();
                *self = PasswordType::Key(String::new())
            }
            PasswordType::Password(p) => {
                p.zeroize();
                *self = PasswordType::Password(String::new())
            }
            PasswordType::Session {
                encryption_key,
                salt,
                kdf,
                memory_kib,
                iterations,
                parallelism,
            } => {
                encryption_key.zeroize();
                salt.zeroize();
                kdf.zeroize();
                memory_kib.zeroize();
                iterations.zeroize();
                parallelism.zeroize();
                *self = PasswordType::Password(String::new())
            }
        }
    }
}
impl Zeroize for Vault {
    fn zeroize(&mut self) {
        self.entries.zeroize();
        self.metadata.zeroize();
        self.recovery.zeroize();
        *self = Self::default();
    }
}
impl Zeroize for VaultEntry {
    fn zeroize(&mut self) {
        self.created.zeroize();
        self.id.zeroize();
        self.modified.zeroize();
        self.name.zeroize();
        self.notes.zeroize();
        self.password.zeroize();
        self.url.zeroize();
        self.username.zeroize();
        *self = Self::default();
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
    let Ok(mut command) = rmp_serde::to_vec(&ServerCommand::Status) else {
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
        response.code == ResponseCode::Success as i32 && response.message.starts_with("Status: ")
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

#[allow(clippy::needless_borrow)]
async fn handle_connection_inner(mut stream: &mut TcpStream, state: ConnectionState) {
    let ConnectionState {
        server_info,
        vlt,
        kill_tx,
        token,
        lock_generation,
        inactivity_timeout,
        background_error,
        password_history_limit,
        trash_retention_days,
    } = state;
    let Ok(Some(msg)) = tokio::time::timeout(CLIENT_IO_TIMEOUT, handler(&mut stream, &token)).await
    else {
        return;
    };
    let server_info_handle = Arc::clone(&server_info);
    let vlt_handle = Arc::clone(&vlt);
    let mut server_info = server_info.lock().await;
    let mut vlt = vlt.lock().await;
    if !server_info.locked
        && !matches!(
            &msg,
            ServerCommand::Kill
                | ServerCommand::Lock(_)
                | ServerCommand::Unlock(_)
                | ServerCommand::Status
        )
    {
        let generation = lock_generation.fetch_add(1, Ordering::AcqRel) + 1;
        schedule_auto_lock(
            inactivity_timeout.load(Ordering::Acquire),
            generation,
            Arc::clone(&lock_generation),
            Arc::clone(&server_info_handle),
            Arc::clone(&vlt_handle),
            Arc::clone(&background_error),
        );
    }
    match msg {
        ServerCommand::Kill => {
            lock_generation.fetch_add(1, Ordering::AcqRel);
            if !server_info.locked
                && let Err(error) = lock_vlt(&mut vlt, &mut server_info)
            {
                respond_failure(
                    &format!("Could not stop server safely: {error}"),
                    &mut stream,
                )
                .await;
                return;
            }
            respond("Server stopped.", &mut stream).await;
            drop(vlt);
            drop(server_info);
            flush_buffered_responses(&mut stream).await;
            let _ = kill_tx.send(()).await;
        }
        ServerCommand::Lock(send) => {
            lock_generation.fetch_add(1, Ordering::AcqRel);
            if !server_info.locked && vlt.is_some() {
                match lock_vlt(&mut vlt, &mut server_info) {
                    Ok(()) if send => {
                        *background_error.lock().await = None;
                        respond("Vault locked.", &mut stream).await
                    }
                    Ok(()) => *background_error.lock().await = None,
                    Err(error) if send => {
                        respond_failure(&format!("Lock failed: {error}"), &mut stream).await
                    }
                    _ => {}
                }
            } else if send {
                respond("Vault is already locked.", &mut stream).await;
            }
        }
        ServerCommand::Unlock(info) => {
            if server_info.locked {
                if let Some(mut old) = server_info.keypass.take() {
                    old.zeroize();
                }
                server_info.keypass = Some(info.key);
                match vlt.unlock_vault(&mut server_info) {
                    Ok(()) => {
                        let expired = if let Some(vault) = vlt.as_mut() {
                            vault.purge_expired_trash(trash_retention_days, &mut server_info)
                        } else {
                            Ok(0)
                        };
                        if let Err(error) = expired {
                            let _ = lock_vlt(&mut vlt, &mut server_info);
                            respond_failure(
                                &format!("Unlock failed while applying trash retention: {error}"),
                                &mut stream,
                            )
                            .await;
                            return;
                        }
                        inactivity_timeout.store(info.timeout, Ordering::Release);
                        let generation = lock_generation.fetch_add(1, Ordering::AcqRel) + 1;
                        schedule_auto_lock(
                            info.timeout,
                            generation,
                            Arc::clone(&lock_generation),
                            server_info_handle,
                            vlt_handle,
                            Arc::clone(&background_error),
                        );
                        *background_error.lock().await = None;
                        respond("Vault unlocked.", &mut stream).await;
                    }
                    Err(e) => {
                        server_info.zeroize();
                        respond_failure(&format!("Unlock failed: {}", e), &mut stream).await
                    }
                }
            } else {
                respond_failure(
                    "A vault is already unlocked. Lock it before unlocking another one.",
                    &mut stream,
                )
                .await;
            }
        }
        ServerCommand::Status => {
            let warning = background_error.lock().await.clone();
            respond(
                &status_message(server_info.locked, warning.as_deref()),
                &mut stream,
            )
            .await;
        }
        ServerCommand::New(key_path) => {
            lock_generation.fetch_add(1, Ordering::AcqRel);
            if !server_info.locked
                && let Err(error) = lock_vlt(&mut vlt, &mut server_info)
            {
                respond_failure(
                    &format!("Could not lock current vault: {error}"),
                    &mut stream,
                )
                .await;
                return;
            }
            if let Some(mut old) = server_info.keypass.take() {
                old.zeroize();
            }
            server_info.keypass = Some(key_path);
            match create_vault(&mut vlt, &mut server_info, true) {
                Ok(()) => respond("Vault created.", &mut stream).await,
                Err(e) => respond_failure(&e, &mut stream).await,
            }
        }
        ServerCommand::Rekey(new_key) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_mut() {
                match vault.rekey(&mut server_info, new_key) {
                    Ok(()) => respond("Vault re-encrypted with the new key.", &mut stream).await,
                    Err(error) => {
                        respond_failure(&format!("Rekey failed: {error}"), &mut stream).await
                    }
                }
            } else {
                respond_failure("Vault unavailable.", &mut stream).await;
            }
        }
        ServerCommand::Add(info) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else {
                let mut pass = info.copy.then(|| info.password.clone());
                match vlt.add_entry(info, &mut server_info) {
                    Ok(true) => {
                        respond("Entry added.", &mut stream).await;
                        if let Some(p) = pass.as_deref() {
                            copy_in_background(p.to_owned(), 10);
                        }
                    }
                    Ok(false) => respond_conflict("Entry already exists.", &mut stream).await,
                    Err(error) => {
                        respond_failure(&format!("Add failed: {error}"), &mut stream).await
                    }
                }
                if let Some(p) = pass.as_mut() {
                    p.zeroize();
                }
            }
        }
        ServerCommand::AddTyped(info) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else {
                let mut pass = info.entry.copy.then(|| info.entry.password.clone());
                match vlt.add_typed_entry(info, &mut server_info) {
                    Ok(true) => {
                        respond("Item added.", &mut stream).await;
                        if let Some(password) = pass.as_deref() {
                            copy_in_background(password.to_owned(), 10);
                        }
                    }
                    Ok(false) => respond_conflict("Item already exists.", &mut stream).await,
                    Err(error) => {
                        respond_failure(&format!("Add failed: {error}"), &mut stream).await
                    }
                }
                if let Some(password) = pass.as_mut() {
                    password.zeroize();
                }
            }
        }
        ServerCommand::AddTypedWithOptions {
            entry: info,
            copy_timeout,
        } => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else {
                let mut pass = info.entry.copy.then(|| info.entry.password.clone());
                match vlt.add_typed_entry(info, &mut server_info) {
                    Ok(true) => {
                        respond("Item added.", &mut stream).await;
                        if let Some(password) = pass.as_deref() {
                            copy_in_background(password.to_owned(), copy_timeout);
                        }
                    }
                    Ok(false) => respond_conflict("Item already exists.", &mut stream).await,
                    Err(error) => {
                        respond_failure(&format!("Add failed: {error}"), &mut stream).await
                    }
                }
                if let Some(password) = pass.as_mut() {
                    password.zeroize();
                }
            }
        }
        ServerCommand::Delete(id) => match id {
            Target::Vault { key, keep_key } => {
                lock_generation.fetch_add(1, Ordering::AcqRel);
                if let Err(error) = lock_vlt(&mut vlt, &mut server_info) {
                    respond_failure(
                        &format!("Delete failed while locking vault: {error}"),
                        &mut stream,
                    )
                    .await;
                    return;
                }
                match delete_vault(key, keep_key) {
                    Ok(()) => respond("Vault deleted.", &mut stream).await,
                    Err(e) => respond_failure(&format!("Delete failed: {e}"), &mut stream).await,
                }
            }
            _ if !server_info.locked => match vlt.delete_entry(id, &mut server_info) {
                Ok(true) => respond("Entry moved to trash.", &mut stream).await,
                Ok(false) => respond_not_found("Entry not found.", &mut stream).await,
                Err(error) => {
                    respond_failure(&format!("Delete failed: {error}"), &mut stream).await
                }
            },
            _ => respond_failure("Vault locked.", &mut stream).await,
        },
        ServerCommand::History(target) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_ref() {
                vault.view_password_history(target, &mut stream).await;
            }
        }
        ServerCommand::RestorePassword { target, revision } => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_mut() {
                match vault.restore_password(target, revision, &mut server_info) {
                    Ok(true) => respond("Password restored.", &mut stream).await,
                    Ok(false) => respond_not_found("Entry not found.", &mut stream).await,
                    Err(error) => {
                        respond_failure(&format!("Password restore failed: {error}"), &mut stream)
                            .await
                    }
                }
            }
        }
        ServerCommand::Trash => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_ref() {
                vault.view_trash(&mut stream).await;
            }
        }
        ServerCommand::RestoreTrash(id) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_mut() {
                match vault.restore_trashed(id, &mut server_info) {
                    Ok(true) => respond("Entry restored.", &mut stream).await,
                    Ok(false) => respond_not_found("Trash entry not found.", &mut stream).await,
                    Err(error) => {
                        respond_failure(&format!("Restore failed: {error}"), &mut stream).await
                    }
                }
            }
        }
        ServerCommand::PurgeTrash(id) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_mut() {
                match vault.purge_trash(id, &mut server_info) {
                    Ok(true) => respond("Trash purged.", &mut stream).await,
                    Ok(false) => respond_not_found("Trash entry not found.", &mut stream).await,
                    Err(error) => {
                        respond_failure(&format!("Purge failed: {error}"), &mut stream).await
                    }
                }
            }
        }
        ServerCommand::Audit(options) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_ref() {
                // Build the local findings and one-way password hashes while
                // the vault is available, then release the live state before
                // any network-backed breach checks begin.
                let audit_snapshot = vault.audit_snapshot(&options);
                drop(vlt);
                drop(server_info);
                audit_snapshot
                    .audit(options.check_breaches, &mut stream)
                    .await;
            }
        }
        ServerCommand::Totp(mut command) => {
            if server_info.locked {
                command.zeroize();
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_mut() {
                match command {
                    TotpCommand::Set {
                        target,
                        mut configuration,
                    } => {
                        let result = vault.set_totp(target, &configuration, &mut server_info);
                        configuration.zeroize();
                        match result {
                            Ok(Some(bits)) if bits < 128 => {
                                respond(
                                    &format!(
                                        "TOTP authenticator saved. Warning: provider supplied a {bits}-bit secret; RFC 4226 recommends at least 128 bits."
                                    ),
                                    &mut stream
)
                                .await
                            }
                            Ok(Some(_)) => {
                                respond("TOTP authenticator saved.", &mut stream).await
                            }
                            Ok(None) => {
                                respond_not_found("Entry not found.", &mut stream).await
                            }
                            Err(error) => {
                                respond_failure(
                                    &format!("TOTP setup failed: {error}"),
                                    &mut stream
)
                                .await
                            }
                        }
                    }
                    TotpCommand::Show {
                        target,
                        copy_timeout,
                    } => match vault.current_totp(target) {
                        Ok((mut code, ttl)) => {
                            respond(&format!("TOTP: {code} ({ttl}s remaining)"), &mut stream).await;
                            if let Some(timeout) = copy_timeout {
                                copy_in_background(code.clone(), timeout);
                            }
                            code.zeroize();
                        }
                        Err(error) => {
                            respond_failure(&format!("TOTP unavailable: {error}"), &mut stream)
                                .await
                        }
                    },
                    TotpCommand::Remove { target } => {
                        match vault.remove_totp(target, &mut server_info) {
                            Ok(true) => respond("TOTP authenticator removed.", &mut stream).await,
                            Ok(false) => {
                                respond_not_found(
                                    "Entry not found or has no TOTP authenticator.",
                                    &mut stream,
                                )
                                .await
                            }
                            Err(error) => {
                                respond_failure(
                                    &format!("TOTP removal failed: {error}"),
                                    &mut stream,
                                )
                                .await
                            }
                        }
                    }
                }
            } else {
                command.zeroize();
                respond_failure("Vault unavailable.", &mut stream).await;
            }
        }
        ServerCommand::View(options) => {
            if !server_info.locked {
                vlt.view_entries(options, &mut stream).await;
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::BrowserAutofill => {
            if !server_info.locked {
                if let Some(vault) = vlt.as_ref() {
                    vault.browser_autofill(&mut stream).await;
                }
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::BrowserAutofillItem(id) => {
            if !server_info.locked {
                if let Some(vault) = vlt.as_ref() {
                    vault.browser_autofill_item(id, &mut stream).await;
                }
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::Search(filter) => {
            if !server_info.locked {
                if let Some(vault) = vlt.as_ref() {
                    vault.search(filter, &mut stream).await;
                }
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::Get(a) => {
            if !server_info.locked {
                vlt.get_entry(a, &mut stream).await;
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::GetWithOptions {
            target,
            copy_timeout,
        } => {
            if !server_info.locked {
                if let Some(vault) = vlt.as_ref() {
                    vault
                        .get_entry_with_timeout(target, copy_timeout, &mut stream)
                        .await;
                }
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::GetSecret(target) => {
            if !server_info.locked {
                vlt.get_secret(target, &mut stream).await;
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::Update(a) => {
            if !server_info.locked {
                match vlt.update_entry_with_limit(a, &mut server_info, password_history_limit) {
                    Ok(true) => respond("Entry updated.", &mut stream).await,
                    Ok(false) => respond_not_found("Entry not found.", &mut stream).await,
                    Err(error) => {
                        respond_failure(&format!("Update failed: {error}"), &mut stream).await
                    }
                }
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::UpdateTyped(update) => {
            if !server_info.locked {
                match vlt.update_typed_entry_with_limit(
                    update,
                    &mut server_info,
                    password_history_limit,
                ) {
                    Ok(true) => respond("Item updated.", &mut stream).await,
                    Ok(false) => {
                        respond_not_found("Item not found or unchanged.", &mut stream).await
                    }
                    Err(error) => {
                        respond_failure(&format!("Update failed: {error}"), &mut stream).await
                    }
                }
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::Export { path, force } => match vlt.export(path, force) {
            Ok(()) => {
                respond(
                    "Export finished. WARNING: the export contains plaintext secrets.",
                    &mut stream,
                )
                .await
            }
            Err(e) => respond_failure(&format!("Export failed: {e}"), &mut stream).await,
        },
        ServerCommand::Backup(mut request) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_ref() {
                let result = vault.encrypted_backup(
                    request.path.clone(),
                    &mut request.key_pass,
                    request.force,
                );
                match result {
                    Ok(()) => respond("Encrypted backup created.", &mut stream).await,
                    Err(error) => {
                        respond_failure(&format!("Backup failed: {error}"), &mut stream).await
                    }
                }
            } else {
                respond_failure("Vault unavailable.", &mut stream).await;
            }
            request.zeroize();
        }
        ServerCommand::RestoreBackup(mut request) => {
            if !server_info.locked {
                respond_failure(
                    "Lock the current vault before restoring a backup.",
                    &mut stream,
                )
                .await;
            } else {
                match restore_encrypted_backup(
                    &request.path,
                    &mut request.key_pass,
                    request.force,
                ) {
                    Ok(filename) => {
                        respond(
                            &format!(
                                "Encrypted backup restored as {filename}. Unlock it with the backup password/key."
                            ),
                            &mut stream
)
                        .await
                    }
                    Err(error) => {
                        respond_failure(
                            &format!("Backup restore failed: {error}"),
                            &mut stream
)
                        .await
                    }
                }
            }
            request.zeroize();
        }
        ServerCommand::Import(args) => {
            let ImportRequest {
                path,
                new,
                key_pass,
                preview,
                conflicts,
                password_history_limit,
            } = args;
            if new && preview {
                let mut preview_vault = Vault::default();
                let result = preview_vault.import_with_options(
                    path,
                    conflicts,
                    true,
                    password_history_limit,
                    &mut ServerInfo::default(),
                );
                match result {
                    Ok(report) => respond(&report.to_string(), &mut stream).await,
                    Err(error) => {
                        respond_failure(&format!("Import preview failed: {error}"), &mut stream)
                            .await
                    }
                }
                preview_vault.zeroize();
                return;
            }
            if !new {
                if server_info.locked {
                    respond_failure("Vault locked.", &mut stream).await;
                    return;
                }
                match vlt.import_with_options(
                    path,
                    conflicts,
                    preview,
                    password_history_limit,
                    &mut server_info,
                ) {
                    Ok(report) => respond(&report.to_string(), &mut stream).await,
                    Err(error) => {
                        respond_failure(&format!("Import failed: {error}"), &mut stream).await
                    }
                }
                return;
            }

            lock_generation.fetch_add(1, Ordering::AcqRel);
            if !server_info.locked
                && let Err(error) = lock_vlt(&mut vlt, &mut server_info)
            {
                respond_failure(
                    &format!("Import failed while locking vault: {error}"),
                    &mut stream,
                )
                .await;
                return;
            }
            if let Some(mut old) = server_info.keypass.take() {
                old.zeroize();
            }
            let Some(key_pass) = key_pass else {
                respond_failure(
                    "A password or key is required for a new imported vault.",
                    &mut stream,
                )
                .await;
                return;
            };
            *server_info = ServerInfo {
                locked: true,
                keypass: Some(key_pass),
            };
            let error = create_vault(&mut vlt, &mut server_info, false).err();

            match error {
                Some(e) => respond_failure(&format!("Import failed: {}", e), &mut stream).await,
                None => match vlt.import_with_options(
                    path,
                    conflicts,
                    preview,
                    password_history_limit,
                    &mut server_info,
                ) {
                    Ok(report) => {
                        vlt.zeroize();
                        server_info.zeroize();
                        respond(&report.to_string(), &mut stream).await
                    }
                    Err(e) => {
                        let _ = lock_vlt(&mut vlt, &mut server_info);
                        respond_failure(&format!("Import failed: {e}"), &mut stream).await;
                    }
                },
            }
        }
    }
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

fn lock_vlt(vlt: &mut Option<Vault>, server_info: &mut ServerInfo) -> Result<(), String> {
    vlt.lock_vault(server_info)?;
    vlt.zeroize();
    server_info.zeroize();
    Ok(())
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod test;
