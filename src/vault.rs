use crate::{
    encryption::{create_password, decrypt_file, encrypt_file, gen_master_key},
    file::file_exists,
    server::{ServerInfo, respond},
    types::{DeleteType, PasswordEntry, PasswordType, UpdateStruct},
};
use blake3;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, read, write},
    net::TcpStream,
    path::Path,
};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct VaultEnteries {
    pub id: usize,
    pub name: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created: String,
    pub modified: String,
}
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct VaultMetadata {
    pub filename: String,
}
impl Zeroize for VaultMetadata {
    fn zeroize(&mut self) {
        self.filename.zeroize();
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Vault {
    pub enteries: Vec<VaultEnteries>,
    pub metadata: VaultMetadata,
}

fn filename_key_from_master(master_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("vault-filename-v1", master_key)
}

fn vault_filename_from_key(filename_key: &[u8; 32]) -> String {
    let hash = blake3::hash(filename_key);
    let short = &hash.as_bytes()[..16];
    format!("{}.enc", hex::encode(short))
}

fn get_filename(mut key_pass: &mut PasswordType, new: bool) -> String {
    let master_key = gen_master_key(&mut key_pass, new);
    let filename_key = filename_key_from_master(&master_key);
    vault_filename_from_key(&filename_key)
}

pub fn create_vault(vlt: &mut Option<Vault>, server_info: &mut ServerInfo, lock: bool) {
    let fname = get_filename(&mut server_info.keypass.as_mut().unwrap(), true);
    if file_exists(&fname) {
        panic!("file already exists")
    }
    File::create(Path::new(&fname)).unwrap();
    *vlt = Some(Vault {
        enteries: Vec::new(),
        metadata: VaultMetadata {
            filename: fname.clone(),
        },
    });
    if lock {
        vlt.lock_vault(&mut ServerInfo {
            locked: false,
            keypass: server_info.keypass.clone(),
        });
        vlt.zeroize();
        server_info.zeroize();
    }
}

fn unlock_vault(key_pass: &mut ServerInfo) -> Vault {
    let fname = get_filename(&mut key_pass.keypass.as_mut().unwrap(), false);
    let contents = read(fname).unwrap();
    let dec = decrypt_file(&mut key_pass.keypass.as_mut().unwrap(), &contents);
    let vault: Vault = rmp_serde::from_slice(&dec.unwrap()).unwrap();
    key_pass.locked = false;
    vault
}

impl Vault {
    pub fn get_entry(&self, a: DeleteType, stream: &mut TcpStream, http: bool) {
        match a {
            DeleteType::Id(i) => {
                if i < self.enteries.len() {
                    respond(&format!("{:?}\n", self.enteries[i - 1]), stream, http);
                } else {
                    respond(&format!("id not found\n"), stream, http);
                }
            }
            DeleteType::Name(n) => {
                let mut found = false;
                for i in 0..self.enteries.len() {
                    if self.enteries[i].name == n {
                        respond(&format!("{:?}\n", self.enteries[i]), stream, http);
                        found = true;
                        break;
                    }
                }
                if !found {
                    respond(&format!("not found\n"), stream, http);
                }
            }
            DeleteType::Url(u)=>{
                let mut found=false;
                for i in 0..self.enteries.len(){
                    if let Some(url)=&self.enteries[i].url{
                        println!("{} {}",url,u);
                        if url==&u{
                            respond("this is a test", stream, http);
                            found=true
                        }
                    }
                }
                if !found{
                    respond("not found\n", stream, http);
                }
            }
        }
    }

    pub fn add_entry(&mut self, info: PasswordEntry) {
        let nid = self.enteries.len() + 1;

        let mut exists = false;
        for i in &self.enteries {
            if i.name == info.name {
                exists = true;
                break;
            }
        }
        if exists {
            println!("name already exists choose another name");
            return;
        }

        let nentrty = VaultEnteries {
            id: nid,
            name: info.name,
            username: info.username,
            password: info.password,
            url: info.url,
            notes: info.notes,
            created: chrono::Local::now().to_string(),
            modified: chrono::Local::now().to_string(),
        };
        self.enteries.append(&mut vec![nentrty]);
    }

    pub fn delete_entry(&mut self, id: DeleteType) {
        match id {
            DeleteType::Id(i) => {
                self.enteries.remove(i - 1);
            }
            DeleteType::Name(n) => {
                for i in 0..self.enteries.len() {
                    if self.enteries[i].name == n {
                        self.enteries.remove(i);
                        break;
                    }
                }
            }
            DeleteType::Url(_u)=>todo!()
        }

        for i in 1..=self.enteries.len() {
            self.enteries[i - 1].id = i;
        }
    }

    pub fn update_entry(&mut self, add: UpdateStruct) {
        match add.which {
            DeleteType::Id(mut i) => {
                if i == 0 || i > self.enteries.len() {
                    panic!("not valid id");
                }
                i = i - 1;
                let mut modified = false;
                if add.update.name.is_some() {
                    self.enteries[i].name = add.update.name.unwrap();
                    modified = true;
                }
                if add.update.notes.is_some() {
                    self.enteries[i].notes = add.update.notes;
                    modified = true;
                }
                if add.update.password {
                    self.enteries[i].password = create_password();
                    modified = true;
                }
                if add.update.url.is_some() {
                    self.enteries[i].url = add.update.url;
                    modified = true;
                }
                if add.update.username.is_some() {
                    self.enteries[i].username = add.update.username;
                    modified = true;
                }
                if modified {
                    self.enteries[i].modified = chrono::Local::now().to_string()
                }
            }
            DeleteType::Name(n) => {
                for i in 0..self.enteries.len() {
                    if self.enteries[i].name == n {
                        let mut modified = false;
                        if add.update.name.is_some() {
                            self.enteries[i].name = add.update.name.unwrap();
                            modified = true;
                        }
                        if add.update.notes.is_some() {
                            self.enteries[i].notes = add.update.notes;
                            modified = true;
                        }
                        if add.update.password {
                            self.enteries[i].password = create_password();
                            modified = true;
                        }
                        if add.update.url.is_some() {
                            self.enteries[i].url = add.update.url;
                            modified = true;
                        }
                        if add.update.username.is_some() {
                            self.enteries[i].username = add.update.username;
                            modified = true;
                        }
                        if modified {
                            self.enteries[i].modified = chrono::Local::now().to_string();
                        }
                        break;
                    }
                }
            }
            DeleteType::Url(_u)=>todo!()
        }
    }

    pub fn view_entries(&self, stream: &mut TcpStream, http: bool) {
        let enteries = &self.enteries[..];
        if enteries.len() == 0 {
            respond("No entries", stream, http);
            // stream.write_all(b"No entries").unwrap();
        }
        for i in enteries {
            respond(
                &format!(
                    "{}. {} {:?} {:?} {:?}\n",
                    i.id, i.name, i.username, i.url, i.notes
                ),
                stream,
                http,
            );
        }
    }

    pub fn lock_vault(&self, key_pass: &mut ServerInfo) {
        let fname = self.metadata.filename.clone();
        let buf = rmp_serde::to_vec(&self).unwrap();
        let txt = encrypt_file(&mut key_pass.keypass.as_mut().unwrap(), &buf[..]);
        write(fname, txt).unwrap();
        key_pass.zeroize();
    }
    pub fn export(&self, path: String) {
        let mut wtr = csv::Writer::from_path(path).unwrap();
        for i in &self.enteries {
            wtr.serialize(i).unwrap();
        }
    }
    pub fn append(&mut self, ent: &mut Vec<VaultEnteries>) {
        self.enteries.append(ent);
    }
    pub fn import(&mut self, path: String) {
        let mut rdr = csv::Reader::from_path(path).unwrap();
        for i in rdr.deserialize() {
            let ent: VaultEnteries = i.unwrap();
            self.append(&mut vec![ent]);
        }
    }
}

pub trait VaultFns {
    fn get_entry(&self, a: DeleteType, stream: &mut TcpStream, http: bool);
    fn add_entry(&mut self, info: PasswordEntry);
    fn delete_entry(&mut self, id: DeleteType);
    fn update_entry(&mut self, add: UpdateStruct);
    fn view_entries(&self, stream: &mut TcpStream, http: bool);
    fn lock_vault(&self, key_pass: &mut ServerInfo);
    fn unlock_vault(&mut self, key_pass: &mut ServerInfo);
    fn export(&self, path: String);
    fn import(&mut self, path: String);
}

impl VaultFns for Option<Vault> {
    fn get_entry(&self, a: DeleteType, stream: &mut TcpStream, http: bool) {
        if let Some(vlt) = self {
            vlt.get_entry(a, stream, http)
        }
    }
    fn add_entry(&mut self, info: PasswordEntry) {
        if let Some(vlt) = self {
            vlt.add_entry(info)
        }
    }
    fn delete_entry(&mut self, id: DeleteType) {
        if let Some(vlt) = self {
            vlt.delete_entry(id);
        }
    }

    fn update_entry(&mut self, add: UpdateStruct) {
        if let Some(vlt) = self {
            vlt.update_entry(add);
        }
    }
    fn view_entries(&self, stream: &mut TcpStream, http: bool) {
        if let Some(vlt) = self {
            vlt.view_entries(stream, http);
        }
    }
    fn lock_vault(&self, key_pass: &mut ServerInfo) {
        if let Some(vlt) = self {
            vlt.lock_vault(key_pass);
        }
        key_pass.zeroize();
    }
    fn unlock_vault(&mut self, key_pass: &mut ServerInfo) {
        if let Some(_) = self {
            panic!("A vault is already unlocked lock it before unlocking another one");
        } else {
            *self = Some(unlock_vault(key_pass))
        }
    }
    fn export(&self, path: String) {
        if let Some(vlt) = self {
            vlt.export(path);
        }
    }
    fn import(&mut self, path: String) {
        if let Some(vlt) = self {
            vlt.import(path)
        }
    }
}
