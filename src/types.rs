use serde::{Deserialize, Serialize};

use crate::cli::UpdateArgs;

#[derive(Serialize, Deserialize, Debug)]
pub enum PasswordType {
    Password(Option<String>),
    Key(String),
}
impl Clone for PasswordType {
    fn clone(&self) -> Self {
        match self {
            PasswordType::Key(key) => PasswordType::Key(key.clone()),
            PasswordType::Password(pass) => PasswordType::Password(pass.clone()),
        }
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub enum ServerCommands {
    Kill,
    Lock(bool),
    UnLock(UnlockInfo),
    Status,
    View,
    Add(PasswordEntry),
    Get(DeleteType),
    Delete(DeleteType),
    Update(UpdateStruct),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UnlockInfo {
    pub key: PasswordType,
    pub timeout: Option<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PasswordEntry {
    pub which: Option<DeleteType>,
    pub name: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DeleteType {
    Id(usize),
    Name(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateStruct {
    pub which: DeleteType,
    pub update: UpdateArgs,
}
