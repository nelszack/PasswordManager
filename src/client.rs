use crate::server::ADDR;
use crate::types::*;
use bincode;
use std::{
    io::{Read, Write},
    net::TcpStream,
};

pub fn manager(command: ServerCommands)
// ->String
{
    send_command(command)
}
fn send_command(cmd: ServerCommands)
// ->String
{
    let mut con = TcpStream::connect(ADDR).unwrap();
    let data = bincode::serialize(&cmd).unwrap();
    con.write_all(&(data.len() as u32).to_be_bytes()).unwrap();
    // println!("shere3");
    con.flush().unwrap();
    con.write_all(&data).unwrap();
    con.flush().unwrap();
    let mut responce: String = String::new();
    con.read_to_string(&mut responce).unwrap();
    print!("{}", responce);
    // responce
}
