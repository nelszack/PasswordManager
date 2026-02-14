use crate::{
    encryption::{create_password, decrypt_file, encrypt_file, gen_master_key},
    file::{file_exists},
    types::{DeleteType, PasswordEntry, PasswordType, UpdateStruct},
};
use blake3;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, read, write},
    path::Path,
};

#[derive(Serialize, Deserialize, Debug)]
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
#[derive(Serialize, Deserialize, Debug)]
struct VaultMetadata {
    filename: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    pub enteries: Vec<VaultEnteries>,
    metadata: VaultMetadata,
}

fn filename_key_from_master(master_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("vault-filename-v1", master_key)
}

fn vault_filename_from_key(filename_key: &[u8; 32]) -> String {
    let hash = blake3::hash(filename_key);
    let short = &hash.as_bytes()[..16]; // 128-bit filename
    format!("{}.enc", hex::encode(short))
}

fn get_filename(mut key_pass: &mut PasswordType, new: bool) -> String {
    let master_key = gen_master_key(&mut key_pass, new);
    let filename_key = filename_key_from_master(&master_key);
    vault_filename_from_key(&filename_key)
}

pub fn create_vault(pass_type: &mut PasswordType) {
    let fname = get_filename(pass_type, true);

    if file_exists(&fname) {
        panic!("file already exists")
    }
    File::create(Path::new(&fname)).unwrap();
    let vault = Vault {
        enteries: Vec::new(),
        metadata: VaultMetadata {
            filename: fname.clone(),
        },
    };
    vault.lock_vault(pass_type);
    println!("Vault created");
}

fn unlock_vault(mut key_pass: &mut PasswordType) -> Vault {
    let fname = get_filename(&mut key_pass, false);
    let contents = read(fname).unwrap();
    let dec = decrypt_file(&mut key_pass, &contents);
    let vault: Vault = rmp_serde::from_slice(&dec.unwrap()).unwrap();
    // println!("{:?}", vault);
    vault
}

impl Vault {
    pub fn get_entry(&self, a: DeleteType) {
        match a {
            DeleteType::Id(i) => {
                println!("{:?}", self.enteries[i - 1])
            }
            DeleteType::Name(n) => {
                for i in 0..self.enteries.len() {
                    if self.enteries[i].name == n {
                        println!("{:?}", self.enteries[i - 1]);
                        break;
                    }
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
                self.enteries.remove(i);
                // for i in 0..self.enteries.len() {
                //     if self.enteries[i].id == j {
                //         self.enteries.remove(i);
                //         break;
                //     }
                // }
            }
            DeleteType::Name(n) => {
                for i in 0..self.enteries.len() {
                    if self.enteries[i].name == n {
                        self.enteries.remove(i);
                        break;
                    }
                }
            }
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
        }
    }

    pub fn view_entries(&self) {
        let enteries = &self.enteries[..];
        if enteries.len() == 0 {
            println!("No entries");
        }
        for i in enteries {
            println!("{}. {} {:?}", i.id, i.name, i.username);
        }
    }

    pub fn lock_vault(&self, key_pass: &mut PasswordType) {
        let fname = self.metadata.filename.clone();
        let buf = rmp_serde::to_vec(&self).unwrap();
        let txt = encrypt_file(key_pass, &buf[..]);
        write(fname, txt).unwrap();
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
            // println!("{:?}",ent);
            self.append(&mut vec![ent]);
        }
    }
}

pub trait VaultFns {
    fn get_entry(&self, a: DeleteType);
    fn add_entry(&mut self, info: PasswordEntry);
    fn delete_entry(&mut self, id: DeleteType);
    fn update_entry(&mut self, add: UpdateStruct);
    fn view_entries(&self);
    fn lock_vault(&self, key_pass: &mut PasswordType);
    fn unlock_vault(&mut self, key_pass: &mut PasswordType);
    fn export(&self, path: String);
    // fn append(&mut self, ent: &mut Vec<VaultEnteries>);
    fn import(&mut self, path: String);
}

impl VaultFns for Option<Vault> {
    fn get_entry(&self, a: DeleteType) {
        if let Some(vlt) = self {
            vlt.get_entry(a)
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
    fn view_entries(&self) {
        if let Some(vlt) = self {
            vlt.view_entries();
        }
    }
    fn lock_vault(&self, key_pass: &mut PasswordType) {
        if let Some(vlt) = self {
            vlt.lock_vault(key_pass);
        }
    }
    fn unlock_vault(&mut self, key_pass: &mut PasswordType) {
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
    // fn append(&mut self, ent: &mut Vec<VaultEnteries>) {
    //     if let Some(vlt) = self {
    //         vlt.append(ent);
    //     }
    // }
    fn import(&mut self, path: String) {
        if let Some(vlt) = self {
            vlt.import(path)
        }
    }
}
