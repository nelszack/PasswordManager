use crate::client::manager;
use crate::vault::unlock_vault;
use crate::{
    types::*,
    vault::{Vault, add_entry, delete_entry, get_entry, lock_vault, update_entry, view_entries},
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
        let mut stream1 = stream.unwrap();
        let msg = handler(&stream1);
        match msg {
            ServerCommands::Kill => {
                if !locked {
                    lock_vault(key_pass.unwrap(), vlt.unwrap());
                    vlt = None;
                    key_pass = None;
                    locked = true;
                    let _ = format!("{:?} {:?} {:?}", vlt, key_pass, locked);
                }
                stream1.write_all(b"server killed\n").unwrap();
                stream1.flush().unwrap();
                break;
            }
            ServerCommands::Lock(send) => {
                if !locked && vlt.is_some() {
                    lock_vault(key_pass.unwrap(), vlt.unwrap());

                    vlt = None;
                    key_pass = None;
                    locked = true;

                    if send {
                        stream1.write_all(b"locked\n").unwrap();
                        stream1.flush().unwrap();
                    }
                }
            }
            ServerCommands::UnLock(mut info) => {
                vlt = Some(unlock_vault(&mut info.key));
                locked = false;
                key_pass = Some(info.key);
                thread::spawn(move || auto_lock(info.timeout.unwrap_or(0)));
            }
            ServerCommands::Status => {
                stream1
                    .write_all(
                        format!("status {}\n", if locked { "Locked" } else { "Unlocked" })
                            .as_bytes(),
                    )
                    .unwrap();
            }
            ServerCommands::Add(info) => {
                if locked {
                    stream1.write_all(b"vault locked\n").unwrap()
                } else {
                    vlt = Some(add_entry(vlt.unwrap(), info))
                }
            }
            ServerCommands::Delete(id) => {
                if locked {
                    stream1.write_all(b"vault locked\n").unwrap()
                } else {
                    vlt = Some(delete_entry(vlt.unwrap(), id))
                }
            }
            ServerCommands::View => {
                if !locked {
                    vlt = Some(view_entries(vlt.unwrap()));
                }
            }
            ServerCommands::Get(a) => {
                if !locked {
                    vlt = Some(get_entry(vlt.unwrap(), a))
                }
            }
            ServerCommands::Update(a) => {
                if !locked {
                    vlt = Some(update_entry(vlt.unwrap(), a))
                }
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
