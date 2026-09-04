use crate::{
    cli::UpdateArgs,
    clipboard::copy_in_background,
    file::{TOKEN_FILE, data_dir, set_private_perms},
    types::*,
    vault::{Vault, VaultAccess, VaultEntry, create_vault, delete_vault},
};
use rand::Rng;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs,
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
    std::net::TcpStream::connect_timeout(
        &ADDR.parse().expect("valid server address"),
        Duration::from_secs(1),
    )
    .is_ok()
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill(&mut bytes);
    hex::encode(bytes)
}

fn write_token_file(token: &str, path: &Path) {
    fs::write(path, token).unwrap();
    set_private_perms(path);
}

fn load_or_create_token() -> String {
    let path = data_dir().join(TOKEN_FILE);
    if let Ok(t) = fs::read_to_string(&path) {
        let t = t.trim().to_string();
        if t.len() == TOKEN_HEX_LEN && t.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return t;
        }
    }
    let token = random_token();
    write_token_file(&token, &path);
    token
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

pub fn start() {
    if is_running() {
        println!("Server is already running.");
        return;
    }
    let token = random_token();
    let token_path = data_dir().join(TOKEN_FILE);
    write_token_file(&token, &token_path);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("run")
        .stdin(Stdio::null())
        .spawn()
        .expect("failed to start background process");
    let pid = child.id();
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    println!("Server started (PID {})", pid);
    println!("Session token file: {}", token_path.display());
}

fn schedule_auto_lock(
    time: u8,
    generation: u64,
    lock_generation: Arc<AtomicU64>,
    server_info: Arc<Mutex<ServerInfo>>,
    vlt: Arc<Mutex<Option<Vault>>>,
) {
    if time == 0 {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(time.into())).await;
        if lock_generation.load(Ordering::Acquire) != generation {
            return;
        }
        let mut server_info = server_info.lock().await;
        let mut vlt = vlt.lock().await;
        if lock_generation.load(Ordering::Acquire) == generation
            && !server_info.locked
            && vlt.is_some()
        {
            lock_vlt(&mut vlt, &mut server_info);
        }
    });
}
pub async fn server() {
    let token = load_or_create_token();
    let listener = TcpListener::bind(ADDR).await.unwrap();

    let server_info = Arc::new(Mutex::new(ServerInfo {
        locked: true,
        keypass: None,
    }));
    let vlt: Arc<Mutex<Option<Vault>>> = Arc::new(Mutex::new(None));
    let lock_generation = Arc::new(AtomicU64::new(0));
    let (kill_tx, mut kill_rx) = mpsc::channel::<()>(1);

    loop {
        tokio::select! {
            _ = kill_rx.recv() => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted.unwrap();
                let si = Arc::clone(&server_info);
                let v = Arc::clone(&vlt);
                let kt = kill_tx.clone();
                let tk = token.clone();
                let lg = Arc::clone(&lock_generation);
                tokio::spawn(handle_connection(stream, si, v, kt, tk, lg));
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    server_info: Arc<Mutex<ServerInfo>>,
    vlt: Arc<Mutex<Option<Vault>>>,
    kill_tx: mpsc::Sender<()>,
    token: String,
    lock_generation: Arc<AtomicU64>,
) {
    let Some((msg, http)) = handler(&mut stream, &token).await else {
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
        return;
    };
    let server_info_handle = Arc::clone(&server_info);
    let vlt_handle = Arc::clone(&vlt);
    let mut server_info = server_info.lock().await;
    let mut vlt = vlt.lock().await;
    match msg {
        ServerCommand::Kill => {
            lock_generation.fetch_add(1, Ordering::AcqRel);
            if !server_info.locked {
                lock_vlt(&mut vlt, &mut server_info);
            }
            respond("Server stopped.", &mut stream, http).await;
            let _ = stream.shutdown().await;
            let _ = kill_tx.send(()).await;
            return;
        }
        ServerCommand::Lock(send) => {
            lock_generation.fetch_add(1, Ordering::AcqRel);
            if !server_info.locked && vlt.is_some() {
                lock_vlt(&mut vlt, &mut server_info);
                if send {
                    respond("Vault locked.", &mut stream, http).await;
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
                    Err(e) => respond(&format!("Unlock failed: {}", e), &mut stream, http).await,
                }
            } else {
                respond(
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
            if !server_info.locked {
                lock_vlt(&mut vlt, &mut server_info);
            }
            if let Some(mut old) = server_info.keypass.take() {
                old.zeroize();
            }
            server_info.keypass = Some(key_path);
            match create_vault(&mut vlt, &mut server_info, true) {
                Ok(()) => respond("Vault created.", &mut stream, http).await,
                Err(e) => respond(&e, &mut stream, http).await,
            }
        }
        ServerCommand::Add(info) => {
            if server_info.locked {
                respond("Vault locked.", &mut stream, http).await;
            } else {
                let mut pass = info.copy.then(|| info.password.clone());
                let added = vlt.add_entry(info, &mut server_info);
                if added {
                    respond("Entry added.", &mut stream, http).await;
                    if let Some(p) = pass.as_deref() {
                        copy_in_background(p.to_owned(), 10);
                    }
                } else {
                    respond("Entry already exists.", &mut stream, http).await;
                }
                if let Some(p) = pass.as_mut() {
                    p.zeroize();
                }
            }
        }
        ServerCommand::Delete(id) => match id {
            Target::Vault(k) => {
                lock_generation.fetch_add(1, Ordering::AcqRel);
                lock_vlt(&mut vlt, &mut server_info);
                match delete_vault(k) {
                    Ok(()) => respond("Vault deleted.", &mut stream, http).await,
                    Err(e) => respond(&format!("Delete failed: {e}"), &mut stream, http).await,
                }
            }
            _ if !server_info.locked => {
                let deleted = vlt.delete_entry(id, &mut server_info);
                respond(
                    if deleted {
                        "Entry deleted."
                    } else {
                        "Entry not found."
                    },
                    &mut stream,
                    http,
                )
                .await;
            }
            _ => respond("Vault locked.", &mut stream, http).await,
        },
        ServerCommand::View => {
            if !server_info.locked {
                vlt.view_entries(&mut stream, http).await;
            } else {
                respond("Vault locked.", &mut stream, http).await;
            }
        }
        ServerCommand::Get(a) => {
            if !server_info.locked {
                vlt.get_entry(a, &mut stream, http).await;
            } else {
                respond("Vault locked.", &mut stream, http).await;
            }
        }
        ServerCommand::Update(a) => {
            if !server_info.locked {
                let updated = vlt.update_entry(a, &mut server_info);
                respond(
                    if updated {
                        "Entry updated."
                    } else {
                        "Entry not found."
                    },
                    &mut stream,
                    http,
                )
                .await;
            } else {
                respond("Vault locked.", &mut stream, http).await;
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
            Err(e) => respond(&format!("Export failed: {e}"), &mut stream, http).await,
        },
        ServerCommand::Import(args) => {
            lock_generation.fetch_add(1, Ordering::AcqRel);
            if !server_info.locked {
                lock_vlt(&mut vlt, &mut server_info);
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
                Some(e) => respond(&format!("Import failed: {}", e), &mut stream, http).await,
                None => match vlt.import(args.path) {
                    Ok(()) => {
                        lock_vlt(&mut vlt, &mut server_info);
                        respond("Import finished.", &mut stream, http).await;
                    }
                    Err(e) => {
                        lock_vlt(&mut vlt, &mut server_info);
                        respond(&format!("Import failed: {e}"), &mut stream, http).await;
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
    let msg: ServerCommand = bincode::deserialize(&buf).ok()?;
    buf.zeroize();
    Some(msg)
}
#[derive(Serialize, Deserialize, Debug)]
struct HttpInfo {
    command: String,
    extra_info: Vec<Option<String>>,
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
    let mut extra = request.extra_info.into_iter();
    match request.command.as_str() {
        "view" | "veiw" => Some(ServerCommand::View),
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

fn lock_vlt(vlt: &mut Option<Vault>, server_info: &mut ServerInfo) {
    vlt.lock_vault(server_info);
    vlt.zeroize();
    server_info.zeroize();
}

pub async fn respond(message: &str, stream: &mut TcpStream, http: bool) {
    if http {
        let body = json!(message).to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len(),
        );
        let _ = stream.write_all(response.as_bytes()).await;
    } else {
        let _ = stream.write_all(format!("{message}\n").as_bytes()).await;
    }
    let _ = stream.flush().await;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::vault::{Vault, VaultEntry, VaultMetadata};

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
        };
        vault.zeroize();
        assert!(vault.entries.is_empty());
        assert_eq!(vault.metadata.filename, "");
    }

    #[test]
    fn test_addr_constant() {
        assert_eq!(ADDR, "127.0.0.1:7878");
    }
}
