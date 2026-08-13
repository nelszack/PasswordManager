use crate::{
    cli::UpdateArgs,
    client::manager,
    clpboard::cpy,
    file::{TOKEN_FILE, data_dir, set_private_perms},
    types::*,
    vault::{Vault, VaultEnteries, VaultFns, create_vault, delete_vault},
};
use rand::Rng;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{watch, Mutex},
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
        self.enteries.zeroize();
        self.metadata.zeroize();
        *self = Self::default();
    }
}
impl Zeroize for VaultEnteries {
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
    if std::net::TcpStream::connect_timeout(&ADDR.parse().unwrap(), Duration::from_secs(1)).is_ok() {
        return true;
    }
    false
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
        if !t.is_empty() {
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
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn start() {
    if is_running() {
        println!("server already running");
        return;
    }
    let token = random_token();
    write_token_file(&token, &data_dir().join(TOKEN_FILE));
    // let stdout = File::create("worker.out").expect("couldnt create file out");
    // let stderr = File::create("worker.err").expect("couldnt create file err");
    let child = Command::new(std::env::current_exe().unwrap())
        .arg("run")
        .env("PM_SERVER_TOKEN", token)
        .stdin(Stdio::null())
        // .stdout(Stdio::from(stdout))
        // .stderr(Stdio::from(stderr))
        .spawn()
        .expect("failed to start background process");
    println!("Started (PID {})", child.id());
    println!("session token file: {}", data_dir().join(TOKEN_FILE).display());
    std::mem::forget(child);
}

fn auto_lock(time: u8) {
    if time == 0 {
        return;
    }
    thread::sleep(Duration::from_secs(time.into()));
    manager(ServerCommands::Lock(false));
}
pub async fn server() {
    let token = std::env::var("PM_SERVER_TOKEN").unwrap_or_else(|_| load_or_create_token());
    let listener = TcpListener::bind(ADDR).await.unwrap();

    let server_info = Arc::new(Mutex::new(ServerInfo {
        locked: true,
        keypass: None,
    }));
    let vlt: Arc<Mutex<Option<Vault>>> = Arc::new(Mutex::new(None));
    let (kill_tx, mut kill_rx) = watch::channel(false);

    loop {
        tokio::select! {
            _ = kill_rx.changed() => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted.unwrap();
                let si = Arc::clone(&server_info);
                let v = Arc::clone(&vlt);
                let kt = kill_tx.clone();
                let tk = token.clone();
                tokio::spawn(handle_connection(stream, si, v, kt, tk));
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    server_info: Arc<Mutex<ServerInfo>>,
    vlt: Arc<Mutex<Option<Vault>>>,
    kill_tx: watch::Sender<bool>,
    token: String,
) {
    let Some((msg, http)) = handler(&mut stream, &token).await else {
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
        return;
    };
    let mut server_info = server_info.lock().await;
    let mut vlt = vlt.lock().await;
    match msg {
        ServerCommands::Kill => {
            if !server_info.locked {
                lock_vlt(&mut vlt, &mut server_info);
            }
            respond("server killed", &mut stream, http).await;
            let _ = stream.shutdown().await;
            let _ = kill_tx.send(true);
            return;
        }
        ServerCommands::Lock(send) => {
            if !server_info.locked && vlt.is_some() {
                lock_vlt(&mut vlt, &mut server_info);
                if send {
                    respond("Vault locked", &mut stream, http).await;
                }
            } else if send {
                respond("Vault already locked", &mut stream, http).await;
            }
        }
        ServerCommands::UnLock(info) => {
            if server_info.locked {
                if let Some(mut old) = server_info.keypass.take() {
                    old.zeroize();
                }
                server_info.keypass = Some(info.key);
                match vlt.unlock_vault(&mut server_info) {
                    Ok(()) => {
                        thread::spawn(move || auto_lock(info.timeout));
                        respond("Vault unlocked", &mut stream, http).await;
                    }
                    Err(e) => respond(&format!("unlock failed: {}", e), &mut stream, http).await,
                }
            } else {
                respond(
                    "A vault is already unlocked lock it before trying to unlock another one",
                    &mut stream,
                    http,
                )
                .await;
            }
        }
        ServerCommands::Status => {
            respond(
                &format!(
                    "status {}",
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
        ServerCommands::New(key_path) => {
            if !server_info.locked {
                lock_vlt(&mut vlt, &mut server_info);
            }
            if let Some(mut old) = server_info.keypass.take() {
                old.zeroize();
            }
            server_info.keypass = Some(key_path);
            create_vault(&mut vlt, &mut server_info, true);
            respond("vault created", &mut stream, http).await;
        }
        ServerCommands::Add(info) => {
            if server_info.locked {
                respond("Vault locked", &mut stream, http).await;
            } else {
                let mut pass = info.copy.then(|| info.password.clone());
                let added = vlt.add_entry(info, &mut server_info);
                if added {
                    respond("entry added", &mut stream, http).await;
                    if let Some(p) = pass.as_deref() {
                        cpy(p, 10);
                    }
                } else {
                    respond("entry already exists", &mut stream, http).await;
                }
                if let Some(p) = pass.as_mut() {
                    p.zeroize();
                }
            }
        }
        ServerCommands::Delete(id) => match id {
            DeleteType::Vault(k) => {
                lock_vlt(&mut vlt, &mut server_info);
                delete_vault(k);
                respond("vault deleted", &mut stream, http).await;
            }
            _ if !server_info.locked => {
                let deleted = vlt.delete_entry(id, &mut server_info);
                respond(
                    if deleted {
                        "entry deleted"
                    } else {
                        "entry not found"
                    },
                    &mut stream,
                    http,
                )
                .await;
            }
            _ => respond("Vault locked", &mut stream, http).await,
        },
        ServerCommands::View => {
            if !server_info.locked {
                vlt.view_entries(&mut stream, http).await;
            } else {
                respond("Vault locked", &mut stream, http).await;
            }
        }
        ServerCommands::Get(a) => {
            if !server_info.locked {
                vlt.get_entry(a, &mut stream, http).await;
            } else {
                respond("Vault locked", &mut stream, http).await;
            }
        }
        ServerCommands::Update(a) => {
            if !server_info.locked {
                let updated = vlt.update_entry(a, &mut server_info);
                respond(
                    if updated {
                        "entry updated"
                    } else {
                        "entry not found"
                    },
                    &mut stream,
                    http,
                )
                .await;
            } else {
                respond("Vault locked", &mut stream, http).await;
            }
        }
        ServerCommands::Export(path) => vlt.export(path),
        ServerCommands::Import(args) => {
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
                create_vault(&mut vlt, &mut server_info, false);
            } else if server_info.locked {
                server_info.keypass = Some(args.key_pass);
                if let Err(e) = vlt.unlock_vault(&mut server_info) {
                    error = Some(e);
                }
            }

            match error {
                Some(e) => respond(&format!("import failed: {}", e), &mut stream, http).await,
                None => {
                    vlt.import(args.path);
                    lock_vlt(&mut vlt, &mut server_info);
                    respond("finished import", &mut stream, http).await;
                }
            }
        }
    }
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

async fn handle_tcp(message: &mut TcpStream, token: &str) -> Option<ServerCommands> {
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
    let msg = match bincode::deserialize(&buf) {
        Ok(m) => m,
        Err(_) => return None,
    };
    buf.zeroize();
    Some(msg)
}
#[derive(Serialize, Deserialize, Debug)]
struct HttpInfo {
    command: String,
    extra_info: Vec<Option<String>>,
}
async fn handle_http(message: &mut TcpStream, token: &str) -> Option<ServerCommands> {
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
        "veiw" => Some(ServerCommands::View),
        "lock" => match extra.next().flatten().as_deref() {
            Some("true") => Some(ServerCommands::Lock(true)),
            Some("false") => Some(ServerCommands::Lock(false)),
            _ => None,
        },
        "status" => Some(ServerCommands::Status),
        "get" => extra
            .next()
            .flatten()
            .map(|url| ServerCommands::Get(DeleteType::Url(url))),
        "kill" => Some(ServerCommands::Kill),
        "add" => {
            let mut it = extra;
            match (it.next().flatten(), it.next().flatten(), it.next().flatten(), it.next().flatten()) {
                (Some(url), Some(username), Some(password), Some(name)) => {
                    Some(ServerCommands::Add(PasswordEntry {
                        which: None,
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
            match (it.next().flatten(), it.next().flatten(), it.next().flatten(), it.next().flatten(), it.next().flatten()) {
                (Some(url), Some(username), Some(password), Some(name), id) => {
                    Some(ServerCommands::Update(UpdateStruct {
                        which: match id {
                            Some(id) => match id.parse::<usize>() {
                                Ok(n) => DeleteType::Id(n),
                                Err(_) => DeleteType::Name(name.clone()),
                            },
                            None => DeleteType::Name(name.clone()),
                        },
                        update: UpdateArgs {
                            name: None,
                            username: Some(username),
                            password: true,
                            gen_pass: false,
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

async fn handler(message: &mut TcpStream, token: &str) -> Option<(ServerCommands, bool)> {
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
        let msg = json!(message);
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    serde_json::to_vec(&msg).unwrap().len(),
                    msg
                )
                .as_bytes(),
            )
            .await
            .unwrap()
    } else {
        stream
            .write_all(format!("{}\n", message).as_bytes())
            .await
            .unwrap()
    }
    stream.flush().await.unwrap();
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::vault::{Vault, VaultEnteries, VaultMetadata};

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
    fn test_vault_enteries_zeroize() {
        let mut entry = VaultEnteries {
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
            enteries: vec![VaultEnteries {
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
        assert!(vault.enteries.is_empty());
        assert_eq!(vault.metadata.filename, "");
    }

    #[test]
    fn test_addr_constant() {
        assert_eq!(ADDR, "127.0.0.1:7878");
    }
}
