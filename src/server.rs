use crate::{
    cli::UpdateArgs,
    clipboard::copy_in_background,
    file::{TOKEN_FILE, data_dir, set_private_perms},
    protocol::{ResponseCode, decode_responses, encode_response},
    types::*,
    vault::{Vault, VaultAccess, VaultEntry, create_vault, delete_vault, restore_encrypted_backup},
};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
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
    sync::{Mutex, mpsc},
};
use zeroize::Zeroize;

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

pub const ADDR: &str = "127.0.0.1:7878";

const MAX_TCP_MSG: usize = 16 * 1024 * 1024;
const MAX_HTTP_REQ: usize = 1024 * 1024;
const TOKEN_HEX_LEN: usize = 64;
pub fn is_running() -> bool {
    let path = data_dir().join(TOKEN_FILE);
    let Ok(mut token) = fs::read_to_string(path) else {
        return false;
    };
    token.truncate(token.trim_end().len());
    if token.len() != TOKEN_HEX_LEN || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        token.zeroize();
        return false;
    }
    let Ok(mut stream) = std::net::TcpStream::connect_timeout(
        &ADDR.parse().expect("valid server address"),
        Duration::from_millis(500),
    ) else {
        token.zeroize();
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    let Ok(mut command) = rmp_serde::to_vec(&ServerCommand::Status) else {
        token.zeroize();
        return false;
    };
    let result = stream
        .write_all(token.as_bytes())
        .and_then(|_| stream.write_all(&(command.len() as u32).to_be_bytes()))
        .and_then(|_| stream.write_all(&command))
        .and_then(|_| stream.flush());
    token.zeroize();
    command.zeroize();
    if result.is_err() {
        return false;
    }
    let mut response = Vec::new();
    if stream.read_to_end(&mut response).is_err() {
        return false;
    }
    decode_responses(&response).is_ok_and(|response| {
        response.code == ResponseCode::Success as i32 && response.message.starts_with("Status: ")
    })
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

fn write_token_file(token: &str, path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "session token path has no parent directory".to_string())?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("could not create session token: {error}"))?;
    set_private_perms(temporary.path())
        .map_err(|error| format!("could not protect session token: {error}"))?;
    temporary
        .write_all(token.as_bytes())
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| format!("could not write session token: {error}"))?;
    temporary
        .persist(path)
        .map_err(|error| format!("could not replace session token: {}", error.error))?;
    Ok(())
}

fn load_or_create_token() -> Result<String, String> {
    let path = data_dir().join(TOKEN_FILE);
    if let Ok(t) = fs::read_to_string(&path) {
        let t = t.trim().to_string();
        if t.len() == TOKEN_HEX_LEN && t.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Ok(t);
        }
    }
    let token = random_token();
    write_token_file(&token, &path)?;
    Ok(token)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

pub fn start() -> Result<(), String> {
    if is_running() {
        println!("Server is already running.");
        return Ok(());
    }
    if std::net::TcpStream::connect_timeout(
        &ADDR.parse().expect("valid server address"),
        Duration::from_millis(250),
    )
    .is_ok()
    {
        return Err(format!("{ADDR} is already in use by another process"));
    }
    let token = random_token();
    let token_path = data_dir().join(TOKEN_FILE);
    write_token_file(&token, &token_path)?;
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not locate the pm executable: {error}"))?;
    let mut child = match Command::new(executable)
        .arg("run")
        .stdin(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return Err(format!("failed to start background process: {error}")),
    };
    let pid = child.id();
    for _ in 0..20 {
        if is_running() {
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
    if !is_running() {
        let _ = child.kill();
        let _ = child.wait();
        return Err("server did not become ready within two seconds".to_string());
    }
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    println!("Server started (PID {})", pid);
    Ok(())
}

fn schedule_auto_lock(
    time: u64,
    generation: u64,
    lock_generation: Arc<AtomicU64>,
    server_info: Arc<Mutex<ServerInfo>>,
    vlt: Arc<Mutex<Option<Vault>>>,
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
            && let Err(error) = lock_vlt(&mut vlt, &mut server_info)
        {
            eprintln!("Automatic lock failed: {error}");
        }
    });
}
pub async fn server(
    password_history_limit: usize,
    trash_retention_days: u64,
) -> Result<(), String> {
    let token =
        load_or_create_token().map_err(|error| format!("could not initialize server: {error}"))?;
    let listener = TcpListener::bind(ADDR)
        .await
        .map_err(|error| format!("could not bind password manager server to {ADDR}: {error}"))?;

    let server_info = Arc::new(Mutex::new(ServerInfo {
        locked: true,
        keypass: None,
    }));
    let vlt: Arc<Mutex<Option<Vault>>> = Arc::new(Mutex::new(None));
    let lock_generation = Arc::new(AtomicU64::new(0));
    let inactivity_timeout = Arc::new(AtomicU64::new(0));
    let (kill_tx, mut kill_rx) = mpsc::channel::<()>(1);

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
                    password_history_limit,
                    trash_retention_days,
                };
                tokio::spawn(handle_connection(stream, state));
            }
        }
    }
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
    password_history_limit: usize,
    trash_retention_days: u64,
}

async fn handle_connection(mut stream: TcpStream, state: ConnectionState) {
    let ConnectionState {
        server_info,
        vlt,
        kill_tx,
        token,
        lock_generation,
        inactivity_timeout,
        password_history_limit,
        trash_retention_days,
    } = state;
    let Some((msg, http)) = handler(&mut stream, &token).await else {
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
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
                    http,
                )
                .await;
                return;
            }
            respond("Server stopped.", &mut stream, http).await;
            let _ = stream.shutdown().await;
            let _ = kill_tx.send(()).await;
            return;
        }
        ServerCommand::Lock(send) => {
            lock_generation.fetch_add(1, Ordering::AcqRel);
            if !server_info.locked && vlt.is_some() {
                match lock_vlt(&mut vlt, &mut server_info) {
                    Ok(()) if send => respond("Vault locked.", &mut stream, http).await,
                    Err(error) if send => {
                        respond_failure(&format!("Lock failed: {error}"), &mut stream, http).await
                    }
                    _ => {}
                }
            } else if send {
                respond("Vault is already locked.", &mut stream, http).await;
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
                                http,
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
                        );
                        respond("Vault unlocked.", &mut stream, http).await;
                    }
                    Err(e) => {
                        respond_failure(&format!("Unlock failed: {}", e), &mut stream, http).await
                    }
                }
            } else {
                respond_failure(
                    "A vault is already unlocked. Lock it before unlocking another one.",
                    &mut stream,
                    http,
                )
                .await;
            }
        }
        ServerCommand::Status => {
            respond(
                &format!(
                    "Status: {}",
                    if server_info.locked {
                        "Locked"
                    } else {
                        "Unlocked"
                    }
                ),
                &mut stream,
                http,
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
                    http,
                )
                .await;
                return;
            }
            if let Some(mut old) = server_info.keypass.take() {
                old.zeroize();
            }
            server_info.keypass = Some(key_path);
            match create_vault(&mut vlt, &mut server_info, true) {
                Ok(()) => respond("Vault created.", &mut stream, http).await,
                Err(e) => respond_failure(&e, &mut stream, http).await,
            }
        }
        ServerCommand::Rekey(new_key) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream, http).await;
            } else if let Some(vault) = vlt.as_mut() {
                match vault.rekey(&mut server_info, new_key) {
                    Ok(()) => {
                        respond("Vault re-encrypted with the new key.", &mut stream, http).await
                    }
                    Err(error) => {
                        respond_failure(&format!("Rekey failed: {error}"), &mut stream, http).await
                    }
                }
            } else {
                respond_failure("Vault unavailable.", &mut stream, http).await;
            }
        }
        ServerCommand::Add(info) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream, http).await;
            } else {
                let mut pass = info.copy.then(|| info.password.clone());
                match vlt.add_entry(info, &mut server_info) {
                    Ok(true) => {
                        respond("Entry added.", &mut stream, http).await;
                        if let Some(p) = pass.as_deref() {
                            copy_in_background(p.to_owned(), 10);
                        }
                    }
                    Ok(false) => respond_conflict("Entry already exists.", &mut stream, http).await,
                    Err(error) => {
                        respond_failure(&format!("Add failed: {error}"), &mut stream, http).await
                    }
                }
                if let Some(p) = pass.as_mut() {
                    p.zeroize();
                }
            }
        }
        ServerCommand::AddTyped(info) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream, http).await;
            } else {
                let mut pass = info.entry.copy.then(|| info.entry.password.clone());
                match vlt.add_typed_entry(info, &mut server_info) {
                    Ok(true) => {
                        respond("Item added.", &mut stream, http).await;
                        if let Some(password) = pass.as_deref() {
                            copy_in_background(password.to_owned(), 10);
                        }
                    }
                    Ok(false) => respond_conflict("Item already exists.", &mut stream, http).await,
                    Err(error) => {
                        respond_failure(&format!("Add failed: {error}"), &mut stream, http).await
                    }
                }
                if let Some(password) = pass.as_mut() {
                    password.zeroize();
                }
            }
        }
        ServerCommand::Delete(id) => match id {
            Target::Vault(k) => {
                lock_generation.fetch_add(1, Ordering::AcqRel);
                if let Err(error) = lock_vlt(&mut vlt, &mut server_info) {
                    respond_failure(
                        &format!("Delete failed while locking vault: {error}"),
                        &mut stream,
                        http,
                    )
                    .await;
                    return;
                }
                match delete_vault(k) {
                    Ok(()) => respond("Vault deleted.", &mut stream, http).await,
                    Err(e) => {
                        respond_failure(&format!("Delete failed: {e}"), &mut stream, http).await
                    }
                }
            }
            _ if !server_info.locked => match vlt.delete_entry(id, &mut server_info) {
                Ok(true) => respond("Entry moved to trash.", &mut stream, http).await,
                Ok(false) => respond_not_found("Entry not found.", &mut stream, http).await,
                Err(error) => {
                    respond_failure(&format!("Delete failed: {error}"), &mut stream, http).await
                }
            },
            _ => respond_failure("Vault locked.", &mut stream, http).await,
        },
        ServerCommand::History(target) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream, http).await;
            } else if let Some(vault) = vlt.as_ref() {
                vault.view_password_history(target, &mut stream, http).await;
            }
        }
        ServerCommand::RestorePassword { target, revision } => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream, http).await;
            } else if let Some(vault) = vlt.as_mut() {
                match vault.restore_password(target, revision, &mut server_info) {
                    Ok(true) => respond("Password restored.", &mut stream, http).await,
                    Ok(false) => respond_not_found("Entry not found.", &mut stream, http).await,
                    Err(error) => {
                        respond_failure(
                            &format!("Password restore failed: {error}"),
                            &mut stream,
                            http,
                        )
                        .await
                    }
                }
            }
        }
        ServerCommand::Trash => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream, http).await;
            } else if let Some(vault) = vlt.as_ref() {
                vault.view_trash(&mut stream, http).await;
            }
        }
        ServerCommand::RestoreTrash(id) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream, http).await;
            } else if let Some(vault) = vlt.as_mut() {
                match vault.restore_trashed(id, &mut server_info) {
                    Ok(true) => respond("Entry restored.", &mut stream, http).await,
                    Ok(false) => {
                        respond_not_found("Trash entry not found.", &mut stream, http).await
                    }
                    Err(error) => {
                        respond_failure(&format!("Restore failed: {error}"), &mut stream, http)
                            .await
                    }
                }
            }
        }
        ServerCommand::PurgeTrash(id) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream, http).await;
            } else if let Some(vault) = vlt.as_mut() {
                match vault.purge_trash(id, &mut server_info) {
                    Ok(true) => respond("Trash purged.", &mut stream, http).await,
                    Ok(false) => {
                        respond_not_found("Trash entry not found.", &mut stream, http).await
                    }
                    Err(error) => {
                        respond_failure(&format!("Purge failed: {error}"), &mut stream, http).await
                    }
                }
            }
        }
        ServerCommand::Audit(options) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream, http).await;
            } else if let Some(vault) = vlt.as_ref() {
                // Network-backed breach checks must not hold the live vault
                // mutex. Otherwise status, explicit lock, and auto-lock all
                // wait behind every remote range request.
                let mut audit_snapshot = vault.clone();
                drop(vlt);
                drop(server_info);
                audit_snapshot.audit(options, &mut stream, http).await;
                audit_snapshot.zeroize();
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
                return;
            }
        }
        ServerCommand::Totp(mut command) => {
            if server_info.locked {
                command.zeroize();
                respond_failure("Vault locked.", &mut stream, http).await;
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
                                    &mut stream,
                                    http,
                                )
                                .await
                            }
                            Ok(Some(_)) => {
                                respond("TOTP authenticator saved.", &mut stream, http).await
                            }
                            Ok(None) => {
                                respond_not_found("Entry not found.", &mut stream, http).await
                            }
                            Err(error) => {
                                respond_failure(
                                    &format!("TOTP setup failed: {error}"),
                                    &mut stream,
                                    http,
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
                            if http {
                                respond(
                                    &json!({ "code": code, "expires_in": ttl }).to_string(),
                                    &mut stream,
                                    true,
                                )
                                .await;
                            } else {
                                respond(
                                    &format!("TOTP: {code} ({ttl}s remaining)"),
                                    &mut stream,
                                    false,
                                )
                                .await;
                            }
                            if let Some(timeout) = copy_timeout {
                                copy_in_background(code.clone(), timeout);
                            }
                            code.zeroize();
                        }
                        Err(error) => {
                            respond_failure(
                                &format!("TOTP unavailable: {error}"),
                                &mut stream,
                                http,
                            )
                            .await
                        }
                    },
                    TotpCommand::Remove { target } => {
                        match vault.remove_totp(target, &mut server_info) {
                            Ok(true) => {
                                respond("TOTP authenticator removed.", &mut stream, http).await
                            }
                            Ok(false) => {
                                respond_not_found(
                                    "Entry not found or has no TOTP authenticator.",
                                    &mut stream,
                                    http,
                                )
                                .await
                            }
                            Err(error) => {
                                respond_failure(
                                    &format!("TOTP removal failed: {error}"),
                                    &mut stream,
                                    http,
                                )
                                .await
                            }
                        }
                    }
                }
            } else {
                command.zeroize();
                respond_failure("Vault unavailable.", &mut stream, http).await;
            }
        }
        ServerCommand::View(options) => {
            if !server_info.locked {
                vlt.view_entries(options, &mut stream, http).await;
            } else {
                respond_failure("Vault locked.", &mut stream, http).await;
            }
        }
        ServerCommand::BrowserAutofill => {
            if !server_info.locked {
                if let Some(vault) = vlt.as_ref() {
                    vault.browser_autofill(&mut stream, http).await;
                }
            } else {
                respond_failure("Vault locked.", &mut stream, http).await;
            }
        }
        ServerCommand::Search(filter) => {
            if !server_info.locked {
                if let Some(vault) = vlt.as_ref() {
                    vault.search(filter, &mut stream, http).await;
                }
            } else {
                respond_failure("Vault locked.", &mut stream, http).await;
            }
        }
        ServerCommand::Get(a) => {
            if !server_info.locked {
                vlt.get_entry(a, &mut stream, http).await;
            } else {
                respond_failure("Vault locked.", &mut stream, http).await;
            }
        }
        ServerCommand::GetSecret(target) => {
            if !server_info.locked {
                vlt.get_secret(target, &mut stream, http).await;
            } else {
                respond_failure("Vault locked.", &mut stream, http).await;
            }
        }
        ServerCommand::Update(a) => {
            if !server_info.locked {
                match vlt.update_entry_with_limit(a, &mut server_info, password_history_limit) {
                    Ok(true) => respond("Entry updated.", &mut stream, http).await,
                    Ok(false) => respond_not_found("Entry not found.", &mut stream, http).await,
                    Err(error) => {
                        respond_failure(&format!("Update failed: {error}"), &mut stream, http).await
                    }
                }
            } else {
                respond_failure("Vault locked.", &mut stream, http).await;
            }
        }
        ServerCommand::UpdateTyped(update) => {
            if !server_info.locked {
                match vlt.update_typed_entry_with_limit(
                    update,
                    &mut server_info,
                    password_history_limit,
                ) {
                    Ok(true) => respond("Item updated.", &mut stream, http).await,
                    Ok(false) => {
                        respond_not_found("Item not found or unchanged.", &mut stream, http).await
                    }
                    Err(error) => {
                        respond_failure(&format!("Update failed: {error}"), &mut stream, http).await
                    }
                }
            } else {
                respond_failure("Vault locked.", &mut stream, http).await;
            }
        }
        ServerCommand::Export(path) => match vlt.export(path) {
            Ok(()) => {
                respond(
                    "Export finished. WARNING: the export contains plaintext passwords.",
                    &mut stream,
                    http,
                )
                .await
            }
            Err(e) => respond_failure(&format!("Export failed: {e}"), &mut stream, http).await,
        },
        ServerCommand::Backup(mut request) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream, http).await;
            } else if let Some(vault) = vlt.as_ref() {
                let result = vault.encrypted_backup(
                    request.path.clone(),
                    &mut request.key_pass,
                    request.force,
                );
                match result {
                    Ok(()) => respond("Encrypted backup created.", &mut stream, http).await,
                    Err(error) => {
                        respond_failure(&format!("Backup failed: {error}"), &mut stream, http).await
                    }
                }
            } else {
                respond_failure("Vault unavailable.", &mut stream, http).await;
            }
            request.zeroize();
        }
        ServerCommand::RestoreBackup(mut request) => {
            if !server_info.locked {
                respond_failure(
                    "Lock the current vault before restoring a backup.",
                    &mut stream,
                    http,
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
                            &mut stream,
                            http,
                        )
                        .await
                    }
                    Err(error) => {
                        respond_failure(
                            &format!("Backup restore failed: {error}"),
                            &mut stream,
                            http,
                        )
                        .await
                    }
                }
            }
            request.zeroize();
        }
        ServerCommand::Import(args) => {
            lock_generation.fetch_add(1, Ordering::AcqRel);
            if args.new && args.preview {
                let mut preview_vault = Vault::default();
                let result = preview_vault.import_with_options(
                    args.path,
                    args.conflicts,
                    true,
                    args.password_history_limit,
                    &mut ServerInfo::default(),
                );
                match result {
                    Ok(report) => respond(&report.to_string(), &mut stream, http).await,
                    Err(error) => {
                        respond_failure(
                            &format!("Import preview failed: {error}"),
                            &mut stream,
                            http,
                        )
                        .await
                    }
                }
                preview_vault.zeroize();
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
                return;
            }
            if !server_info.locked
                && let Err(error) = lock_vlt(&mut vlt, &mut server_info)
            {
                respond_failure(
                    &format!("Import failed while locking vault: {error}"),
                    &mut stream,
                    http,
                )
                .await;
                return;
            }
            if let Some(mut old) = server_info.keypass.take() {
                old.zeroize();
            }
            let mut error = None;
            if args.new {
                *server_info = ServerInfo {
                    locked: true,
                    keypass: Some(args.key_pass),
                };
                if let Err(e) = create_vault(&mut vlt, &mut server_info, false) {
                    error = Some(e);
                }
            } else if server_info.locked {
                server_info.keypass = Some(args.key_pass);
                if let Err(e) = vlt.unlock_vault(&mut server_info) {
                    error = Some(e);
                }
            }

            match error {
                Some(e) => {
                    respond_failure(&format!("Import failed: {}", e), &mut stream, http).await
                }
                None => match vlt.import_with_options(
                    args.path,
                    args.conflicts,
                    args.preview,
                    args.password_history_limit,
                    &mut server_info,
                ) {
                    Ok(report) => {
                        vlt.zeroize();
                        server_info.zeroize();
                        respond(&report.to_string(), &mut stream, http).await
                    }
                    Err(e) => {
                        let _ = lock_vlt(&mut vlt, &mut server_info);
                        respond_failure(&format!("Import failed: {e}"), &mut stream, http).await;
                    }
                },
            }
        }
    }
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

async fn handle_tcp(message: &mut TcpStream, token: &str) -> Option<ServerCommand> {
    let mut token_buff = [0u8; TOKEN_HEX_LEN];
    if message.read_exact(&mut token_buff).await.is_err() {
        return None;
    }
    if !ct_eq(&token_buff, token.as_bytes()) {
        return None;
    }
    let mut len_buff = [0u8; 4];
    if message.read_exact(&mut len_buff).await.is_err() {
        return None;
    }
    let len = u32::from_be_bytes(len_buff) as usize;
    if len > MAX_TCP_MSG {
        return None;
    }
    let mut buf = vec![0u8; len];
    if message.read_exact(&mut buf).await.is_err() {
        return None;
    }
    let mut cursor = Cursor::new(buf.as_slice());
    let msg = {
        let mut deserializer = rmp_serde::Deserializer::new(&mut cursor);
        ServerCommand::deserialize(&mut deserializer).ok()?
    };
    if cursor.position() != buf.len() as u64 {
        buf.zeroize();
        return None;
    }
    buf.zeroize();
    Some(msg)
}
#[derive(Serialize, Deserialize, Debug)]
struct HttpInfo {
    command: String,
    extra_info: Vec<Option<String>>,
}

fn browser_totp_command(extra_info: &[Option<String>]) -> Option<ServerCommand> {
    extra_info
        .first()
        .and_then(Option::as_deref)
        .and_then(|id| id.parse::<usize>().ok())
        .map(|id| {
            ServerCommand::Totp(TotpCommand::Show {
                target: Target::Id(id),
                copy_timeout: None,
            })
        })
}

async fn handle_http(message: &mut TcpStream, token: &str) -> Option<ServerCommand> {
    let mut request_str = String::new();
    let mut buf = [0u8; 1024];
    let mut header_end = 0;
    loop {
        let n = match message.read(&mut buf).await {
            Ok(n) => n,
            Err(_) => return None,
        };
        if n == 0 {
            break;
        }
        request_str.push_str(&String::from_utf8_lossy(&buf[..n]));
        if request_str.len() > MAX_HTTP_REQ {
            return None;
        }
        let Some(end) = request_str.find("\r\n\r\n") else {
            continue;
        };
        header_end = end;
        let header = &request_str[..end];
        let content_len = header
            .lines()
            .find_map(|l| {
                l.trim()
                    .to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|v| v.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        if content_len > MAX_HTTP_REQ {
            return None;
        }
        if request_str[end + 4..].len() >= content_len {
            break;
        }
    }
    let auth_ok = request_str[..header_end].lines().any(|l| {
        let lower = l.trim().to_ascii_lowercase();
        let Some(rest) = lower.strip_prefix("authorization:") else {
            return false;
        };
        let Some(bearer) = rest.trim().strip_prefix("bearer ") else {
            return false;
        };
        ct_eq(bearer.trim().as_bytes(), token.as_bytes())
    });
    if !auth_ok {
        let _ = message
            .write_all(
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .as_bytes(),
            )
            .await;
        return None;
    }
    let body = match request_str.find("\r\n\r\n") {
        Some(i) => &request_str[i + 4..],
        None => &request_str,
    };
    let body_line = body.lines().last().unwrap_or("");
    let request: HttpInfo = match serde_json::from_str(body_line.trim()) {
        Ok(r) => r,
        Err(_) => return None,
    };
    if request.command == "totp" {
        return browser_totp_command(&request.extra_info);
    }
    let mut extra = request.extra_info.into_iter();
    match request.command.as_str() {
        "view" | "veiw" => Some(ServerCommand::View(ListOptions::default())),
        "lock" => match extra.next().flatten().as_deref() {
            Some("true") => Some(ServerCommand::Lock(true)),
            Some("false") => Some(ServerCommand::Lock(false)),
            _ => None,
        },
        "status" => Some(ServerCommand::Status),
        "get" => extra
            .next()
            .flatten()
            .map(|url| ServerCommand::Get(Target::Url(url))),
        "kill" => Some(ServerCommand::Kill),
        "add" => {
            let mut it = extra;
            match (
                it.next().flatten(),
                it.next().flatten(),
                it.next().flatten(),
                it.next().flatten(),
            ) {
                (Some(url), Some(username), Some(password), Some(name)) => {
                    Some(ServerCommand::Add(PasswordEntry {
                        name,
                        username: Some(username),
                        password,
                        url: Some(url),
                        notes: None,
                        copy: false,
                    }))
                }
                _ => None,
            }
        }
        "update" => {
            let mut it = extra;
            match (
                it.next().flatten(),
                it.next().flatten(),
                it.next().flatten(),
                it.next().flatten(),
                it.next().flatten(),
            ) {
                (Some(url), Some(username), Some(password), Some(name), id) => {
                    Some(ServerCommand::Update(EntryUpdate {
                        target: match id {
                            Some(id) => match id.parse::<usize>() {
                                Ok(n) => Target::Id(n),
                                Err(_) => Target::Name(name.clone()),
                            },
                            None => Target::Name(name.clone()),
                        },
                        update: UpdateArgs {
                            name: None,
                            username: Some(username),
                            password: true,
                            generate_password: false,
                            url: Some(url),
                            notes: None,
                        },
                        password: Some(password),
                    }))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

async fn handler(message: &mut TcpStream, token: &str) -> Option<(ServerCommand, bool)> {
    let mut buff = [0u8; 16];
    let n = message.peek(&mut buff).await.ok()?;
    if n == 0 {
        return None;
    }
    const METHODS: [&str; 9] = [
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
    ];
    let is_http = METHODS.iter().any(|m| buff.starts_with(m.as_bytes()));
    if is_http {
        Some((handle_http(message, token).await?, true))
    } else {
        Some((handle_tcp(message, token).await?, false))
    }
}

fn lock_vlt(vlt: &mut Option<Vault>, server_info: &mut ServerInfo) -> Result<(), String> {
    vlt.lock_vault(server_info)?;
    vlt.zeroize();
    server_info.zeroize();
    Ok(())
}

pub async fn respond(message: &str, stream: &mut TcpStream, http: bool) {
    respond_with_code(ResponseCode::Success, message, stream, http).await;
}

async fn respond_failure(message: &str, stream: &mut TcpStream, http: bool) {
    respond_with_code(ResponseCode::Failure, message, stream, http).await;
}

async fn respond_not_found(message: &str, stream: &mut TcpStream, http: bool) {
    respond_with_code(ResponseCode::NotFound, message, stream, http).await;
}

async fn respond_conflict(message: &str, stream: &mut TcpStream, http: bool) {
    respond_with_code(ResponseCode::Conflict, message, stream, http).await;
}

pub async fn respond_with_code(
    code: ResponseCode,
    message: &str,
    stream: &mut TcpStream,
    http: bool,
) {
    if http {
        let body = json!({
            "ok": code == ResponseCode::Success,
            "code": code as u8,
            "message": message,
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len(),
        );
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            stream.write_all(response.as_bytes()),
        )
        .await;
    } else {
        let frame = encode_response(code, message);
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            stream.write_all(&frame).await
        })
        .await;
    }
    let _ = stream.flush().await;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::vault::{Vault, VaultEntry, VaultMetadata};

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn response_codes_are_explicit_and_independent_of_message_wording() {
        let (mut client, mut server) = tcp_pair().await;
        respond("Entry not found.", &mut server, false).await;
        server.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        let response = decode_responses(&bytes).unwrap();
        assert_eq!(response.code, ResponseCode::Success as i32);

        let (mut client, mut server) = tcp_pair().await;
        respond_with_code(
            ResponseCode::NotFound,
            "wording without classification keywords",
            &mut server,
            false,
        )
        .await;
        server.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        let response = decode_responses(&bytes).unwrap();
        assert_eq!(response.code, ResponseCode::NotFound as i32);
        assert_eq!(
            response.message,
            "wording without classification keywords\n"
        );
    }

    #[test]
    fn test_server_info_default() {
        let info = ServerInfo::default();
        assert!(info.locked);
        assert!(info.keypass.is_none());
    }

    #[test]
    fn test_server_info_with_password() {
        let mut info = ServerInfo {
            locked: false,
            keypass: Some(PasswordType::Password("secret".to_string())),
        };
        info.zeroize();
        assert!(info.locked);
        assert!(info.keypass.is_none());
    }

    #[test]
    fn test_browser_totp_command_requires_numeric_entry_id() {
        let command = browser_totp_command(&[Some("42".to_string())]).unwrap();
        assert!(matches!(
            command,
            ServerCommand::Totp(TotpCommand::Show {
                target: Target::Id(42),
                copy_timeout: None,
            })
        ));
        assert!(browser_totp_command(&[Some("not-an-id".to_string())]).is_none());
        assert!(browser_totp_command(&[]).is_none());
    }

    #[test]
    fn test_server_info_with_key() {
        let mut info = ServerInfo {
            locked: false,
            keypass: Some(PasswordType::Key("key.pem".to_string())),
        };
        info.zeroize();
        assert!(info.locked);
        assert!(info.keypass.is_none());
    }

    #[test]
    fn test_password_type_zeroize_password() {
        let mut pt = PasswordType::Password("secret_password".to_string());
        pt.zeroize();
        match pt {
            PasswordType::Password(s) => assert_eq!(s, ""),
            _ => panic!("Expected Password variant"),
        }
    }

    #[test]
    fn test_password_type_zeroize_key() {
        let mut pt = PasswordType::Key("secret_key.pem".to_string());
        pt.zeroize();
        match pt {
            PasswordType::Key(s) => assert_eq!(s, ""),
            _ => panic!("Expected Key variant"),
        }
    }

    #[test]
    fn test_password_type_clone() {
        let pt1 = PasswordType::Password("test".to_string());
        let pt2 = pt1.clone();
        assert_eq!(pt1, pt2);
    }

    #[test]
    fn test_vault_entries_zeroize() {
        let mut entry = VaultEntry {
            id: 42,
            name: "test".to_string(),
            username: Some("user".to_string()),
            password: "secret".to_string(),
            url: Some("https://example.com".to_string()),
            notes: Some("important".to_string()),
            created: "2024-01-01".to_string(),
            modified: "2024-01-01".to_string(),
        };
        entry.zeroize();
        assert_eq!(entry.id, 0);
        assert_eq!(entry.name, "");
        assert_eq!(entry.username, None);
        assert_eq!(entry.password, "");
        assert_eq!(entry.url, None);
        assert_eq!(entry.notes, None);
    }

    #[test]
    fn test_vault_zeroize() {
        let mut vault = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: "test".to_string(),
                username: Some("user".to_string()),
                password: "secret".to_string(),
                url: None,
                notes: None,
                created: "2024-01-01".to_string(),
                modified: "2024-01-01".to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".to_string(),
            },
            recovery: crate::vault::RecoveryData::default(),
        };
        vault.zeroize();
        assert!(vault.entries.is_empty());
        assert_eq!(vault.metadata.filename, "");
    }

    #[test]
    fn test_addr_constant() {
        assert_eq!(ADDR, "127.0.0.1:7878");
    }

    #[test]
    fn session_tokens_are_random_256_bit_hex_values() {
        let first = random_token();
        let second = random_token();
        assert_eq!(first.len(), TOKEN_HEX_LEN);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[cfg(unix)]
    #[test]
    fn session_token_files_have_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(TOKEN_FILE);
        write_token_file(&random_token(), &path).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn authenticated_tcp_protocol_decodes_a_complete_command() {
        let token = "a".repeat(TOKEN_HEX_LEN);
        let command = rmp_serde::to_vec(&ServerCommand::Status).unwrap();
        let mut request = token.as_bytes().to_vec();
        request.extend_from_slice(&(command.len() as u32).to_be_bytes());
        request.extend_from_slice(&command);

        let (mut client, mut server) = tcp_pair().await;
        client.write_all(&request).await.unwrap();

        let parsed = handler(&mut server, &token).await;
        assert!(matches!(parsed, Some((ServerCommand::Status, false))));
    }

    #[tokio::test]
    async fn tcp_protocol_rejects_wrong_tokens_and_oversized_messages() {
        let token = "a".repeat(TOKEN_HEX_LEN);
        let (mut client, mut server) = tcp_pair().await;
        client
            .write_all(format!("{}{}", "b".repeat(TOKEN_HEX_LEN), "\0\0\0\0").as_bytes())
            .await
            .unwrap();
        assert!(handler(&mut server, &token).await.is_none());

        let (mut client, mut server) = tcp_pair().await;
        let mut request = token.as_bytes().to_vec();
        request.extend_from_slice(&((MAX_TCP_MSG as u32) + 1).to_be_bytes());
        client.write_all(&request).await.unwrap();
        assert!(handler(&mut server, &token).await.is_none());

        let (mut client, mut server) = tcp_pair().await;
        let mut command = rmp_serde::to_vec(&ServerCommand::Status).unwrap();
        command.push(0);
        let mut request = token.as_bytes().to_vec();
        request.extend_from_slice(&(command.len() as u32).to_be_bytes());
        request.extend_from_slice(&command);
        client.write_all(&request).await.unwrap();
        assert!(handler(&mut server, &token).await.is_none());
    }

    #[tokio::test]
    async fn http_protocol_requires_a_valid_bearer_token() {
        let token = "c".repeat(TOKEN_HEX_LEN);
        let body = r#"{"command":"status","extra_info":[]}"#;
        let request = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (mut client, mut server) = tcp_pair().await;
        client.write_all(request.as_bytes()).await.unwrap();

        assert!(handler(&mut server, &token).await.is_none());
        let mut response = [0u8; 128];
        let length = client.read(&mut response).await.unwrap();
        assert!(response[..length].starts_with(b"HTTP/1.1 401 Unauthorized"));
    }

    #[tokio::test]
    async fn authenticated_http_protocol_decodes_extension_commands() {
        let token = "d".repeat(TOKEN_HEX_LEN);
        let body = r#"{"command":"totp","extra_info":["47"]}"#;
        let request = format!(
            "POST / HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (mut client, mut server) = tcp_pair().await;
        client.write_all(request.as_bytes()).await.unwrap();

        assert!(matches!(
            handler(&mut server, &token).await,
            Some((
                ServerCommand::Totp(TotpCommand::Show {
                    target: Target::Id(47),
                    copy_timeout: None,
                }),
                true,
            ))
        ));
    }

    #[tokio::test]
    async fn http_protocol_rejects_privileged_and_oversized_requests() {
        let token = "e".repeat(TOKEN_HEX_LEN);
        let body = r#"{"command":"backup","extra_info":[]}"#;
        let request = format!(
            "POST / HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (mut client, mut server) = tcp_pair().await;
        client.write_all(request.as_bytes()).await.unwrap();
        assert!(handler(&mut server, &token).await.is_none());

        let request = format!(
            "POST / HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n",
            MAX_HTTP_REQ + 1
        );
        let (mut client, mut server) = tcp_pair().await;
        client.write_all(request.as_bytes()).await.unwrap();
        assert!(handler(&mut server, &token).await.is_none());
    }
}
