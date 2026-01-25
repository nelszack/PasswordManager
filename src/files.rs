use crate::{encryption::*};
use serde::{Deserialize, Serialize};
use std::{path::Path};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
pub enum PassType {
    Word(String),
    Key([u8; 32]),
    Empty,
}
impl PassType {
    pub fn into_vec(&self) -> Vec<u8> {
        let thing = match &self {
            Self::Word(s) => s.clone().into_bytes(),
            Self::Key(s) => s.to_vec(),
            _ => Vec::new(),
        };
        thing
    }
}
impl Zeroize for PassType {
    fn zeroize(&mut self) {
        match self {
            PassType::Word(s) => s.zeroize(),
            PassType::Key(s) => s.zeroize(),
            _ => {}
        }
        *self = PassType::Empty
    }
}

pub fn find_file(pass: &PassType)->String {
    let fname = generate_file_name(&pass);
    if file_exists(&format!("{}.enc", fname)) {
        fname
    } else {
        panic!("file dosent exist")
    }
}
pub fn file_exists(file_path: &str) -> bool {
    if Path::new(file_path).exists() {
        return true;
    }
    return false;
}


