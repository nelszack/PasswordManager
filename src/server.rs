use crate::{
    cli::UpdateArgs,
    client::manager,
    clpboard::cpy,
    types::*,
    vault::{Vault, VaultEnteries, VaultFns, create_vault, delete_vault},
};
use bincode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    io::ErrorKind,
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

pub fn is_running() -> bool {
    if std::net::TcpStream::connect_timeout(&ADDR.parse().unwrap(), Duration::from_secs(1)).is_ok() {
        return true;
    }
    return false;
}
pub fn start() {
    if is_running() {
        println!("server already running");
        return;
    }
    // let stdout = File::create("worker.out").expect("couldnt create file out");
    // let stderr = File::create("worker.err").expect("couldnt create file err");
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["run", "--key", "master_key"])
        .stdin(Stdio::null())
        // .stdout(Stdio::from(stdout))
        // .stderr(Stdio::from(stderr))
        .spawn()
        .expect("failed to start background process");
    println!("Started (PID {})", child.id());
}

fn auto_lock(time: u8) {
    if time == 0 {
        return;
    }
    thread::sleep(Duration::from_secs(time.into()));
    manager(ServerCommands::Lock(false));
}
pub async fn server(key: String) {
    if key != "master_key" {
        panic!("unotherized run");
    }
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
                tokio::spawn(handle_connection(stream, si, v, kt));
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    server_info: Arc<Mutex<ServerInfo>>,
    vlt: Arc<Mutex<Option<Vault>>>,
    kill_tx: watch::Sender<bool>,
) {
    let Some((msg, http)) = handler(&mut stream).await else {
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
        return;
    };
    let mut server_info = server_info.lock().await;
    let mut vlt = vlt.lock().await;
    match msg {
        ServerCommands::Kill => {
            if !server_info.locked {
                lock_vlt(&mut *vlt, &mut *server_info);
            }
            respond("server killed", &mut stream, http).await;
            let _ = stream.shutdown().await;
            let _ = kill_tx.send(true);
            return;
        }
        ServerCommands::Lock(send) => {
            if !server_info.locked && vlt.is_some() {
                if send {
                    lock_vlt(&mut *vlt, &mut *server_info);
                    respond("Vault locked", &mut stream, http).await;
                }
            }
        }
        ServerCommands::UnLock(info) => {
            if server_info.locked {
                server_info.keypass = Some(info.key);
                vlt.unlock_vault(&mut *server_info);
                thread::spawn(move || auto_lock(info.timeout));
                respond("Vault unlocked", &mut stream, http).await;
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
                lock_vlt(&mut *vlt, &mut *server_info);
            }
            server_info.keypass = Some(key_path);
            create_vault(&mut *vlt, &mut *server_info, true);
            respond("vault created", &mut stream, http).await;
        }
        ServerCommands::Add(info) => {
            if server_info.locked {
                respond("Vault locked", &mut stream, http).await;
            } else {
                let copy = info.copy.clone();
                let mut pass = info.password.clone();
                vlt.add_entry(info, &mut *server_info);
                respond("entry added", &mut stream, http).await;
                if copy {
                    cpy(&pass, 10);
                }
                pass.zeroize();
            }
        }
        ServerCommands::Delete(id) => match id {
            DeleteType::Vault(k) => {
                lock_vlt(&mut *vlt, &mut *server_info);
                delete_vault(k);
                respond("vault deleted", &mut stream, http).await;
            }
            _ if !server_info.locked => {
                vlt.delete_entry(id, &mut *server_info);
                respond("entry deleted", &mut stream, http).await;
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
                vlt.update_entry(a, &mut *server_info);
            } else {
                respond("Vault locked", &mut stream, http).await;
            }
        }
        ServerCommands::Export(path) => vlt.export(path),
        ServerCommands::Import(args) => {
            if !server_info.locked {
                lock_vlt(&mut *vlt, &mut *server_info);
            }
            if args.new {
                *server_info = ServerInfo {
                    locked: true,
                    keypass: Some(args.key_pass),
                };
                create_vault(&mut *vlt, &mut *server_info, false);
            } else if server_info.locked {
                server_info.keypass = Some(args.key_pass);
                vlt.unlock_vault(&mut *server_info);
            }

            vlt.import(args.path);
            lock_vlt(&mut *vlt, &mut *server_info);
            respond("finished import", &mut stream, http).await;
        }
    }
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

async fn handle_tcp(message: &mut TcpStream) -> ServerCommands {
    let mut len_buff = [0u8; 4];
    message.read_exact(&mut len_buff).await.unwrap();
    let len = u32::from_be_bytes(len_buff) as usize;
    let mut buf = vec![0u8; len];
    match message.read_exact(&mut buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {}
        Err(e) => panic!("error {}", e),
    };
    let msg: ServerCommands = bincode::deserialize(&buf).unwrap();
    message.flush().await.unwrap();
    msg
}
#[derive(Serialize, Deserialize, Debug)]
struct HttpInfo {
    command: String,
    extra_info: Vec<Option<String>>,
}
async fn handle_http(message: &mut TcpStream) -> ServerCommands {
    let mut buf = [0u8; 1024];
    message.flush().await.unwrap();
    let size = message.read(&mut buf).await.unwrap();
    let request_str = String::from_utf8_lossy(&buf[..size]);
    let lines = request_str.lines();
    if let Some(h) = lines.last() {
        let request: HttpInfo = serde_json::from_str(h.trim()).unwrap();
        match request.command {
            val if val == "veiw".to_string() => ServerCommands::View,
            val if val == "lock".to_string() => {
                let lock = match &request.extra_info[0].clone().unwrap() {
                    val if val == &"true".to_string() => true,
                    val if val == &"false".to_string() => false,
                    _ => panic!(""),
                };
                ServerCommands::Lock(lock)
            }
            val if val == "status".to_string() => ServerCommands::Status,
            val if val == "get".to_string() => {
                let url = request.extra_info[0].clone().unwrap();
                ServerCommands::Get(DeleteType::Url(url))
            }
            val if val == "kill".to_string() => ServerCommands::Kill,
            val if val == "add".to_string() => {
                if let (Some(url), Some(username), Some(password), Some(name)) = (
                    request.extra_info[0].clone(),
                    request.extra_info[1].clone(),
                    request.extra_info[2].clone(),
                    request.extra_info[3].clone(),
                ) {
                    ServerCommands::Add(PasswordEntry {
                        which: None,
                        name: name.clone(),
                        username: Some(username),
                        password: password,
                        url: Some(url),
                        notes: None,
                        copy:false,
                    })
                } else {
                    panic!("bad args")
                }
            }
            val if val == "update" => {
                if let (Some(url), Some(username), Some(password), Some(name)) = (
                    request.extra_info[0].clone(),
                    request.extra_info[1].clone(),
                    request.extra_info[2].clone(),
                    request.extra_info[3].clone(),
                ) {
                    ServerCommands::Update(UpdateStruct {
                        which: match request.extra_info.get(4).cloned().flatten() {
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
                    })
                } else {
                    panic!(
                        "bad args {:?}",
                        (
                            request.extra_info[0].clone(),
                            request.extra_info[1].clone(),
                            request.extra_info[2].clone(),
                            request.extra_info[3].clone()
                        )
                    )
                }
            }
            _ => panic!("not supported yet"),
        }
    } else {
        panic!("")
    }
}

async fn handler(message: &mut TcpStream) -> Option<(ServerCommands, bool)> {
    let mut buff = [0u8; 1024];
    let n = message.peek(&mut buff).await.unwrap();
    if n > 400 {
        return Some((handle_http(message).await, true));
    } else if n > 0 {
        return Some((handle_tcp(message).await, false));
    }
    None
}

fn lock_vlt(vlt: &mut Option<Vault>, mut server_info: &mut ServerInfo) {
    vlt.lock_vault(&mut server_info);
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
