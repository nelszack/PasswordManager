use crate::cli::UpdateArgs;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum PasswordType {
    Password(String),
    Key(String),
}
#[derive(Serialize, Deserialize, Debug)]
pub enum ServerCommand {
    Kill,
    Lock(bool),
    Unlock(UnlockInfo),
    Status,
    View,
    Add(PasswordEntry),
    Get(Target),
    Delete(Target),
    Update(EntryUpdate),
    Export(String),
    Import(ImportRequest),
    New(PasswordType),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UnlockInfo {
    pub key: PasswordType,
    pub timeout: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PasswordEntry {
    pub name: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub copy: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Target {
    Id(usize),
    Name(String),
    Url(String),
    Vault(PasswordType),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EntryUpdate {
    pub target: Target,
    pub update: UpdateArgs,
    pub password: Option<String>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ImportRequest {
    pub path: String,
    pub new: bool,
    pub key_pass: PasswordType,
}
