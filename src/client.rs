use crate::file::{TOKEN_FILE, data_dir};
use crate::server::ADDR;
use crate::types::*;
use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};

pub fn manager(command: ServerCommands) {
    send_command(command)
}

fn server_token() -> String {
    let path = data_dir().join(TOKEN_FILE);
    fs::read_to_string(&path)
        .expect("Could not read session token. Is the server running?")
        .trim()
        .to_string()
}

fn send_command(cmd: ServerCommands) {
    let mut con = TcpStream::connect(ADDR).unwrap();
    con.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let token = server_token();
    con.write_all(token.as_bytes()).unwrap();
    con.flush().unwrap();
    let data = bincode::serialize(&cmd).unwrap();
    con.write_all(&(data.len() as u32).to_be_bytes()).unwrap();
    con.flush().unwrap();
    con.write_all(&data).unwrap();
    con.flush().unwrap();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = Vec::new();
    loop {
        match con.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => total.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
        if total.len() > 1024 * 1024 {
            eprintln!("Response too large, truncating.");
            break;
        }
    }
    let response = String::from_utf8_lossy(&total);
    print!("{}", response);
}
