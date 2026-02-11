use crate::{
    encryption::{decrypt_file, encrypt_file, gen_master_key},
    file::file_exists,
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
    pub id: u64,
    pub name: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
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

pub fn create_vault(mut pass_type: PasswordType) {
    let fname = get_filename(&mut pass_type, true);

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
    lock_vault(pass_type, vault);
    println!("Vault created");
}
pub fn lock_vault(key_pass: PasswordType, vlt: Vault) {
    let fname = vlt.metadata.filename.clone();
    let buf = rmp_serde::to_vec(&vlt).unwrap();
    let txt = encrypt_file(key_pass, &buf[..]);
    write(fname, txt).unwrap();
}
pub fn unlock_vault(mut key_pass: &mut PasswordType) -> Vault {
    let fname = get_filename(&mut key_pass, false);
    let contents = read(fname).unwrap();
    let dec = decrypt_file(&mut key_pass, &contents);
    let vault: Vault = rmp_serde::from_slice(&dec.unwrap()).unwrap();
    // println!("{:?}", vault);
    vault
}
pub fn add_entry(mut vlt: Vault, info: PasswordEntry) -> Vault {
    let nid = vlt.enteries.len() + 1;
    let nentrty = VaultEnteries {
        id: nid as u64,
        name: info.name,
        username: info.username,
        password: info.password,
        url: info.url,
        notes: info.notes,
    };
    vlt.enteries.append(&mut vec![nentrty]);
    vlt
}
pub fn delete_entry(mut vlt: Vault, id: DeleteType) -> Vault {
    match id {
        DeleteType::Id(j) => {
            for i in 0..vlt.enteries.len() {
                if vlt.enteries[i].id == j {
                    vlt.enteries.remove(i);
                    break;
                }
            }
        }
        DeleteType::Name(n) => {
            for i in 0..vlt.enteries.len() {
                if vlt.enteries[i].name == n {
                    vlt.enteries.remove(i);
                    break;
                }
            }
        }
    }

    for i in 1..=vlt.enteries.len() {
        vlt.enteries[i - 1].id = i as u64;
    }
    vlt
}

pub fn view_entries(vlt: Vault) -> Vault {
    for i in &vlt.enteries[..] {
        println!("{}. {} {:?}", i.id, i.name, i.username);
    }
    vlt
}

pub fn update_entry(mut vlt: Vault, add: UpdateStruct) -> Vault {
    match add.which {
        DeleteType::Id(j) => {
            for i in 0..vlt.enteries.len() {
                if vlt.enteries[i].id == j {
                    if add.update.name.is_some() {
                        vlt.enteries[i].name = add.update.name.unwrap()
                    }
                    if add.update.notes.is_some() {
                        vlt.enteries[i].notes = add.update.notes
                    }
                    if add.update.password.is_some() {
                        vlt.enteries[i].password = add.update.password.unwrap()
                    }
                    if add.update.url.is_some() {
                        vlt.enteries[i].url = add.update.url
                    }
                    if add.update.username.is_some() {
                        vlt.enteries[i].username = add.update.username
                    }

                    break;
                }
            }
        }
        DeleteType::Name(n) => {
            for i in 0..vlt.enteries.len() {
                if vlt.enteries[i].name == n {
                    if add.update.name.is_some() {
                        vlt.enteries[i].name = add.update.name.unwrap()
                    }
                    if add.update.notes.is_some() {
                        vlt.enteries[i].notes = add.update.notes
                    }
                    if add.update.password.is_some() {
                        vlt.enteries[i].password = add.update.password.unwrap()
                    }
                    if add.update.url.is_some() {
                        vlt.enteries[i].url = add.update.url
                    }
                    if add.update.username.is_some() {
                        vlt.enteries[i].username = add.update.username
                    }
                    break;
                }
            }
        }
    }

    vlt
}
pub fn get_entry(vlt: Vault, a: DeleteType) -> Vault {
    match a {
        DeleteType::Id(j) => {
            for i in 0..vlt.enteries.len() {
                if vlt.enteries[i].id == j {
                    println!("{:?}", vlt.enteries[i]);
                    break;
                }
            }
        }
        DeleteType::Name(n) => {
            for i in 0..vlt.enteries.len() {
                if vlt.enteries[i].name == n {
                    println!("{:?}", vlt.enteries[i]);
                    break;
                }
            }
        }
    }
    vlt
}
