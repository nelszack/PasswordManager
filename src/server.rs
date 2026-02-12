use crate::client::manager;
use crate::{
    file::import,
    types::*,
    vault::{Vault, VaultFns},
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
                    vlt.lock_vault(&mut key_pass.unwrap());
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
                    vlt.lock_vault(&mut key_pass.unwrap());

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
                // if locked{
                //     vlt.lock_vault(key_pass.unwrap());
                // }
                if locked {
                    vlt.unlock_vault(&mut info.key);
                    locked = false;
                    key_pass = Some(info.key);
                    thread::spawn(move || auto_lock(info.timeout.unwrap_or(0)));
                    stream1.write_all(b"vault unlocked\n").unwrap();
                } else {
                    stream1.write_all(b"A vault is already unlocked lock it before trying to unlock another one").unwrap();
                }
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
                    vlt.add_entry(info);

                    stream1.write_all(b"entry added\n").unwrap();
                }
            }
            ServerCommands::Delete(id) => {
                if locked {
                    stream1.write_all(b"vault locked\n").unwrap()
                } else {
                    vlt.delete_entry(id);
                    stream1.write_all(b"entry deleted\n").unwrap();
                }
            }
            ServerCommands::View => {
                if !locked {
                    vlt.view_entries();
                } else {
                    stream1.write_all(b"vault locked\n").unwrap();
                }
            }
            ServerCommands::Get(a) => {
                if !locked {
                    // vlt = Some(get_entry(vlt.unwrap(), a));
                    vlt.get_entry(a);
                } else {
                    stream1.write_all(b"vault locked\n").unwrap();
                }
            }
            ServerCommands::Update(a) => {
                if !locked {
                    vlt.update_entry(a);
                } else {
                    stream1.write_all(b"vault locked\n").unwrap();
                }
            }
            ServerCommands::Export(path) => vlt.export(path),
            ServerCommands::Import(args) => {
                if !locked {
                    vlt.lock_vault(&mut key_pass.unwrap());
                    vlt = None;
                    key_pass = None;
                    locked = true;
                    let _ = format!("{:?} {}", key_pass, locked);
                }
                let key_pass1 = if args.key_path.is_some() {
                    Some(PasswordType::Key(args.key_path.unwrap()))
                } else {
                    Some(PasswordType::Password(None))
                };
                key_pass = key_pass1.clone();
                vlt.unlock_vault(&mut key_pass1.unwrap());
                import(args.path, &mut vlt);
                vlt.lock_vault(&mut key_pass.unwrap());
                vlt = None;
                key_pass = None;
                locked = true;
                let _ = format!("{:?}", key_pass);
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
