// use crate::client::manager;
use crate::{
    client::manager,
    types::*,
    vault::{Vault, VaultFns},
};
use bincode;
use std::{
    fs::File,
    io::{
        ErrorKind,
        Read, // , Write
    },
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

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
    let mut locked = true;
    let mut key_pass: Option<PasswordType> = None;
    let mut vlt: Option<Vault> = None;
    for stream in listener.incoming() {
        let stream1 = stream.unwrap();
        let msg = handler(&stream1);
        match msg {
            ServerCommands::Kill => {
                if !locked {
                    manager(ServerCommands::Lock(false));
                }
                println!("server kiilled");
                break;
            }
            ServerCommands::Lock(send) => {
                if !locked && vlt.is_some() {
                    vlt.lock_vault(&mut key_pass.unwrap());
                    vlt = None;
                    key_pass = None;
                    locked = true;

                    if send {
                        println!("Vault locked")
                    }
                }
            }
            ServerCommands::UnLock(mut info) => {
                // if locked{
                //     vlt.lock_vault(key_pass.unwrap());
                // }
                if locked {
                    vlt.unlock_vault(&mut info.key);
                    locked = false;
                    key_pass = Some(info.key);
                    thread::spawn(move || auto_lock(info.timeout.unwrap_or(0)));
                    println!("vault unlocked");
                } else {
                    println!(
                        "A vault is already unlocked lock it before trying to unlock another one"
                    );
                }
            }
            ServerCommands::Status => {
                println!(
                    "{}",
                    format!("status {}", if locked { "Locked" } else { "Unlocked" })
                )
            }
            ServerCommands::Add(info) => {
                if locked {
                    println!("vault locked");
                } else {
                    vlt.add_entry(info);
                    println!("entry added");
                }
            }
            ServerCommands::Delete(id) => {
                if locked {
                    println!("vault locked");
                } else {
                    vlt.delete_entry(id);
                    println!("entry deleted");
                }
            }
            ServerCommands::View => {
                if !locked {
                    vlt.view_entries();
                } else {
                    println!("vault locked");
                }
            }
            ServerCommands::Get(a) => {
                if !locked {
                    vlt.get_entry(a);
                } else {
                    println!("vault locked");
                }
            }
            ServerCommands::Update(a) => {
                if !locked {
                    vlt.update_entry(a);
                } else {
                    println!("vault locked");
                }
            }
            ServerCommands::Export(path) => vlt.export(path),
            ServerCommands::Import(args) => {
                if !locked {
                    manager(ServerCommands::Lock(false));
                }
                manager(ServerCommands::UnLock(UnlockInfo {
                    key: if args.key_path.is_some() {
                        PasswordType::Key(args.key_path.unwrap())
                    } else {
                        PasswordType::Password(None)
                    },
                    timeout: None,
                }));
                vlt.import(args.path);
                manager(ServerCommands::Lock(false));
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
