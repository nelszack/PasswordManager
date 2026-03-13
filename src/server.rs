use crate::{
    client::manager,
    clpboard::cpy,
    types::*,
    vault::{Vault, VaultEnteries, VaultFns, create_vault},
};
use bincode;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{ErrorKind, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    process::{Command, Stdio},
    thread,
    time::Duration,
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

fn is_running() -> bool {
    if TcpStream::connect_timeout(&ADDR.parse().unwrap(), Duration::from_secs(1)).is_ok() {
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
    let stderr = File::create("worker.err").expect("couldnt create file err");
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["run", "--key", "master_key"])
        .stdin(Stdio::null())
        // .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
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
pub fn server(key: String) {
    if key != "master_key" {
        panic!("unotherized run");
    }
    let listener = TcpListener::bind(ADDR).unwrap();

    let mut server_info = ServerInfo {
        locked: true,
        keypass: None,
    };
    let mut vlt: Option<Vault> = None;
    for stream in listener.incoming() {
        let mut stream1 = stream.unwrap();
        let Some((msg, http)) = handler(&stream1) else {
            stream1.flush().unwrap();
            stream1.shutdown(Shutdown::Both).unwrap();
            continue;
        };
        match msg {
            ServerCommands::Kill => {
                if !server_info.locked {
                    lock_vlt(&mut vlt, &mut server_info);
                }

                respond("server killed", &mut stream1, http);
                stream1.shutdown(Shutdown::Both).unwrap();

                break;
            }
            ServerCommands::Lock(send) => {
                if !server_info.locked && vlt.is_some() {
                    if send {
                        lock_vlt(&mut vlt, &mut server_info);
                        respond("Vault locked", &mut stream1, http);
                    }
                }
            }
            ServerCommands::UnLock(info) => {
                // if locked{
                //     lock_vlt(&mut vlt, &mut server_info);
                // }
                if server_info.locked {
                    server_info.keypass = Some(info.key);
                    vlt.unlock_vault(&mut server_info);
                    thread::spawn(move || auto_lock(info.timeout));
                    respond("Vault unlocked", &mut stream1, http);
                } else {
                    respond(
                        "A vault is already unlocked lock it before trying to unlock another one",
                        &mut stream1,
                        http,
                    );
                }
            }
            ServerCommands::Status => {
                respond(
                    &format!(
                        "status {}\n",
                        if server_info.locked {
                            "Locked"
                        } else {
                            "Unlocked"
                        }
                    ),
                    &mut stream1,
                    http,
                );
            }
            ServerCommands::New { key_path } => {
                if !server_info.locked {
                    lock_vlt(&mut vlt, &mut server_info);
                }
                server_info.keypass = Some(key_path);
                create_vault(&mut vlt, &mut server_info, true);
                respond("vault created", &mut stream1, http);
            }
            ServerCommands::Add(info) => {
                if server_info.locked {
                    respond("Vault locked", &mut stream1, http);
                } else {
                    let mut pass = info.password.clone();
                    vlt.add_entry(info);
                    respond("entry added", &mut stream1, http);
                    cpy(&pass, 10);
                    pass.zeroize();
                }
            }
            ServerCommands::Delete(id) => {
                if server_info.locked {
                    respond("Vault locked", &mut stream1, http);
                } else {
                    vlt.delete_entry(id);
                    respond("entry deleted", &mut stream1, http);
                }
            }
            ServerCommands::View => {
                if !server_info.locked {
                    vlt.view_entries(&mut stream1, http);
                } else {
                    respond("Vault locked", &mut stream1, http);
                }
            }
            ServerCommands::Get(a) => {
                if !server_info.locked {
                    vlt.get_entry(a, &mut stream1, http);
                } else {
                    respond("Vault locked", &mut stream1, http);
                }
            }
            ServerCommands::Update(a) => {
                if !server_info.locked {
                    vlt.update_entry(a);
                } else {
                    respond("Vault locked", &mut stream1, http);
                }
            }
            ServerCommands::Export(path) => vlt.export(path),
            ServerCommands::Import(args) => {
                if !server_info.locked {
                    lock_vlt(&mut vlt, &mut server_info);
                }
                if args.new {
                    server_info = ServerInfo {
                        locked: true,
                        keypass: Some(args.key_pass),
                    };
                    create_vault(&mut vlt, &mut server_info, false);
                    // respond("Vault locked", &mut stream1, http);
                } else if server_info.locked {
                    server_info.keypass = Some(args.key_pass);
                    vlt.unlock_vault(&mut server_info);
                }

                vlt.import(args.path);
                lock_vlt(&mut vlt, &mut server_info);
                respond("finished import", &mut stream1, http);
            }
        }
        stream1.flush().unwrap();
        stream1.shutdown(Shutdown::Both).unwrap();
    }
}

fn handle_tcp(mut message: &TcpStream) -> ServerCommands {
    let mut len_buff = [0u8; 4];
    message.read_exact(&mut len_buff).unwrap();
    let len = u32::from_be_bytes(len_buff) as usize;
    let mut buf = vec![0u8; len];
    match message.read_exact(&mut buf) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {}
        Err(e) => panic!("error {}", e),
    };
    let msg: ServerCommands = bincode::deserialize(&buf).unwrap();
    message.flush().unwrap();
    msg
}
#[derive(Serialize, Deserialize, Debug)]
struct HttpInfo {
    command: String,
    extra_info: Vec<Option<String>>,
}
fn handle_http(mut message: &TcpStream) -> ServerCommands {
    let mut buf = [0u8; 1024];
    message.flush().unwrap();
    let size = message.read(&mut buf).unwrap();
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
            _ => panic!("not supported yet"),
        }
    } else {
        panic!("")
    }
}

fn handler(message: &TcpStream) -> Option<(ServerCommands, bool)> {
    let mut buff = [0u8; 1024];
    let n = message.peek(&mut buff).unwrap();
    if n > 400 {
        return Some((handle_http(message), true));
    } else if n > 0 {
        return Some((handle_tcp(message), false));
    }
    None
}

fn lock_vlt(vlt: &mut Option<Vault>, mut server_info: &mut ServerInfo) {
    vlt.lock_vault(&mut server_info);
    vlt.zeroize();
    server_info.zeroize();
}

pub fn respond(message: &str, stream: &mut TcpStream, http: bool) {
    if http {
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    message.len(),
                    message
                )
                .as_bytes(),
            )
            .unwrap()
    } else {
        stream.write_all(message.as_bytes()).unwrap()
    }
    stream.flush().unwrap();
}

// add tests
