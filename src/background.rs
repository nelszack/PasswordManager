use std::{fs::{File}, io::{Read, Write}, net::{TcpListener, TcpStream}, process::{Command,Stdio}, thread, time::Duration};
use crate::{PassType, ServerCommands, UnlockArgs, file_exists,vault::{OpenVault, unlock_vault_from_key_pass}};
use rpassword::prompt_password;
use serde::{Serialize, Deserialize};
use bincode;
const ADDR: &str = "127.0.0.1:7878";

#[derive(Serialize, Deserialize)]
enum Message{
    Command(String),
    Openvault(UnlockArgs),
    // Closevault(Option<Vault>),
}

pub fn manager(args:UnlockArgs){
    match args.command {
        ServerCommands::Start(t)=>start(t.time),
        ServerCommands::Unlock=>send_command(Message::Openvault(args)),
        ServerCommands::Lock=>send_command(Message::Command("lock".into())),
        ServerCommands::Status=>send_command(Message::Command("status".into())),
        ServerCommands::Kill=>send_command(Message::Command("kill".into())),
        ServerCommands::Run(t)=>run(t.time),
        
    }

}

pub fn start(time:u64){
    if is_running(){
        return;
    }
    let stdout=File::create("worker.out").expect("couldnt create file out");
    let stderr=File::create("worker.err").expect("couldnt create file err");
    let child=Command::new(std::env::current_exe().unwrap())
        .arg("server")
        .arg("run")
        .arg("--time")
        .arg(format!("{}",time))
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("failed to start background process");
    println!("Started (PID {})", child.id());

}
fn run(time: u64) {
    worker_loop(time)
}
fn worker_time_keeper(time: u64) {
    thread::sleep(Duration::from_secs(time));
    send_command(Message::Command("lock".into()))
}

fn worker_loop(time: u64) {
    let listener = TcpListener::bind(ADDR).expect("Failed to bind socket");
    listener
        .set_nonblocking(true)
        .expect("Failed to set nonblocking");

    println!("Worker listening on {}", ADDR);
    let mut running = true;
    let mut unlocked=false;
    let mut unlock_vault:OpenVault;
    thread::spawn(move || worker_time_keeper(time));
    while running {
        // Simulate work
        // println!("Working... {}", counter);
        thread::sleep(Duration::from_secs(2));

        // Check for incoming connections
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 128];
            if let Ok(len) = stream.read(&mut buf) {
                let msg:Message = bincode::deserialize(&buf[..len]).unwrap();

                match msg {
                    Message::Command(k) => {
                        match k.as_str(){
                            "kill"=>{
                                println!("Received stop command");
                                running = false;
                                let _ = stream.write_all(b"Stopping...\n");

                                }
                            "lock"=>{unlocked=false}
                            "status" => {
                                let response = format!("Worker is running, unlocked={}",unlocked);
                                let _ = stream.write_all(response.as_bytes());
                                }
                            _=>{panic!("unkown thing")}
                        }
                    }
                    Message::Openvault(thing)=>{unlock_vault=unlock(thing);unlocked=true;for i in unlock_vault.entries{println!("{:?}",i.text)}}
                    
                }
            }
        }
    }

    println!("Worker exiting");
}




fn unlock(thing: UnlockArgs)->OpenVault {
    if let Some(f) = thing.key {
        if file_exists(&f) {
            let mut file = File::open(f).unwrap();
            let mut key = [0u8; 32];
            file.read_exact(&mut key).unwrap();
            unlock_vault_from_key_pass(PassType::Key(key))
        } else {
            panic!("file doesnt exist");
        }
    } else {
        let s = prompt_password("password: ").unwrap();
        unlock_vault_from_key_pass(PassType::Word(s))
        
    }
}



fn is_running()->bool{
     if TcpStream::connect(ADDR).is_ok() {
        println!("Worker already running");
        return true;
    }
    return false
}

fn send_command(command: Message) {

    match TcpStream::connect(ADDR) {
        Ok(mut stream) => {
            let msg=match command{
                Message::Openvault(m)=>bincode::serialize(&m).unwrap(),
                Message::Command(m)=>bincode::serialize(&m).unwrap()
            };
            let _ = stream.write_all(&msg);
            let mut buf = [0u8; 256];
            if let Ok(len) = stream.read(&mut buf) {
                print!("{}", String::from_utf8_lossy(&buf[..len]));
            }
        }
        Err(_) => {
            println!("Worker is not running");
        }
    }
}