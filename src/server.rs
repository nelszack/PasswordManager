use crate::{
    client::manager,
    types::*,
    vault::{Vault, VaultEnteries, VaultFns,create_vault},
};
use bincode;
use std::{
    fs::File,
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
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
            PasswordType::Key(k) => k.zeroize(),
            PasswordType::Password(p) => p.zeroize(),
        }
    }
}
impl Zeroize for Vault {
    fn zeroize(&mut self) {
        self.enteries.zeroize();
        self.metadata.zeroize()
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
        let msg = handler(&stream1);
        match msg {
            ServerCommands::Kill => {
                if !server_info.locked {
                    lock_vlt(&mut vlt, &mut server_info);
                }
                stream1.write_all(b"server killed\n").unwrap();
                break;
            }
            ServerCommands::Lock(send) => {
                if !server_info.locked && vlt.is_some() {
                    if send {
                        lock_vlt(&mut vlt, &mut server_info);
                        stream1.write_all(b"Vault locked\n").unwrap();
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
                    thread::spawn(move || auto_lock(info.timeout.unwrap_or(0)));
                    stream1.write_all(b"Vault unlocked\n").unwrap();
                } else {
                    stream1.write_all(b"A vault is already unlocked lock it before trying to unlock another one\n").unwrap();

                }
            }
            ServerCommands::Status => {
                stream1
                    .write_all(
                        format!(
                            "status {}\n",
                            if server_info.locked {
                                "Locked"
                            } else {
                                "Unlocked"
                            }
                        )
                        .as_bytes(),
                    )
                    .unwrap();

            }
            ServerCommands::New { key_path } => {
                if !server_info.locked {
                    lock_vlt(&mut vlt, &mut server_info);
                }
                server_info.keypass = Some(key_path);
                create_vault(&mut vlt, &mut server_info, true);
                stream1.write_all(b"vault created").unwrap();
            }
            ServerCommands::Add(info) => {
                if server_info.locked {
                    stream1.write_all(b"Vault locked\n").unwrap();
                } else {
                    vlt.add_entry(info);
                    stream1.write_all(b"entry added\n").unwrap();
                }
            }
            ServerCommands::Delete(id) => {
                if server_info.locked {
                    stream1.write_all(b"Vault locked\n").unwrap();
                } else {
                    vlt.delete_entry(id);
                    stream1.write_all(b"entry deleted\n").unwrap();
                }
            }
            ServerCommands::View => {
                if !server_info.locked {
                    vlt.view_entries(&mut stream1);
                } else {
                    stream1.write_all(b"Vault locked\n").unwrap();
                }
            }
            ServerCommands::Get(a) => {
                if !server_info.locked {
                    vlt.get_entry(a,&mut stream1);
                } else {
                    stream1.write_all(b"Vault locked\n").unwrap();
                }
            }
            ServerCommands::Update(a) => {
                if !server_info.locked {
                    vlt.update_entry(a);
                } else {
                    stream1.write_all(b"Vault locked\n").unwrap();
                }
            }
            ServerCommands::Export(path) => vlt.export(path),
            ServerCommands::Import(args) => {
                if !server_info.locked {
                    lock_vlt(&mut vlt, &mut server_info);
                }
                if args.new{
                    create_vault(&mut vlt, &mut server_info, false);
                    stream1.write_all(b"vault created").unwrap();
                }
                else if server_info.locked {
                    server_info.keypass = Some(args.key_pass);
                    unlock_vlt(&mut vlt, &mut server_info);
                }

                vlt.import(args.path);
                lock_vlt(&mut vlt, &mut server_info);
                stream1.write_all(b"finished import\n").unwrap();
            }
        }
    }
}

fn handler(mut message: &TcpStream) -> ServerCommands {
    let mut len_buff = [0u8; 4];
    match message.read_exact(&mut len_buff) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {}
        Err(e) => panic!("error {}", e),
    };
    let len = u32::from_be_bytes(len_buff) as usize;
    let mut buf = vec![0u8; len];
    match message.read_exact(&mut buf) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {}
        Err(e) => panic!("error {}", e),
    };
    let msg: ServerCommands = bincode::deserialize(&buf).unwrap();
    msg
}

fn lock_vlt(vlt: &mut Option<Vault>, mut server_info: &mut ServerInfo) {
    vlt.lock_vault(&mut server_info);
    vlt.zeroize();
    server_info.zeroize();
}

fn unlock_vlt(vlt: &mut Option<Vault>, server_info: &mut ServerInfo) {
    vlt.unlock_vault(server_info);
}
