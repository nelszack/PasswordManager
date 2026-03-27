use crate::{
    encryption::{decrypt_file, encrypt_file, gen_master_key},
    file::file_exists,
    server::{ServerInfo, respond},
    types::{DeleteType, PasswordEntry, PasswordType, UpdateStruct},
};
use blake3;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, read, write},
    net::TcpStream,
};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
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
#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct VaultMetadata {
    pub filename: String,
}
impl Zeroize for VaultMetadata {
    fn zeroize(&mut self) {
        self.filename.zeroize();
        *self = Self::default();
    }
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
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
    let proj_dir = ProjectDirs::from("com", "myproject", "password_manager").unwrap();
    let data_path = proj_dir.data_dir();
    let file_path = data_path.join(&fname);
    if file_exists(&file_path.to_str().unwrap()) {
        panic!("file already exists")
    }
    File::create(file_path).unwrap();
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
    let proj_dir = ProjectDirs::from("com", "myproject", "password_manager").unwrap();
    let data_path = proj_dir.data_dir();
    let file_path = data_path.join(&fname);
    let contents = read(file_path).unwrap();
    let dec = decrypt_file(&mut key_pass.keypass.as_mut().unwrap(), &contents);
    let vault: Vault = rmp_serde::from_slice(&dec.unwrap()).unwrap();
    key_pass.locked = false;
    vault
}

impl Vault {
    pub fn get_entry(&self, a: DeleteType, stream: &mut TcpStream, http: bool) {
        match a {
            DeleteType::Id(i) => {
                if i == 0 || i > self.enteries.len() {
                    panic!("not valid id");
                }
                if i <= self.enteries.len() {
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
            DeleteType::Url(u) => {
                let mut found = false;
                let mut l1 = Vec::<String>::new();
                for i in 0..self.enteries.len() {
                    if let Some(url) = &self.enteries[i].url {
                        if url == &u || url.contains(&u) {
                            l1.append(&mut vec![format!(
                                "{{\"username\": {:?}, \"password\": \"{}\", \"name\": \"{}\"}}",
                                self.enteries[i]
                                    .username
                                    .clone()
                                    .unwrap_or("None".to_string()),
                                self.enteries[i].password,
                                self.enteries[i].name
                            )]);
                            found = true
                        }
                    }
                }
                if !found {
                    respond("not found\n", stream, http);
                } else {
                    respond(&format!("{}", l1.join(",")), stream, http);
                }
            }
            DeleteType::Vault(_) => unreachable!(),
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
            password: info.password.clone(),
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
                if i == 0 || i > self.enteries.len() {
                    panic!("not valid id");
                }
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
            _ => unreachable!(),
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
                    self.enteries[i].password = add.password.unwrap();
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
                            self.enteries[i].password = add.password.unwrap();
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
            _ => unreachable!(),
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
        let proj_dir = ProjectDirs::from("com", "myproject", "password_manager").unwrap();
        let data_path = proj_dir.data_dir();
        let file_path = data_path.join(&fname);
        let buf = rmp_serde::to_vec(&self).unwrap();
        let txt = encrypt_file(&mut key_pass.keypass.as_mut().unwrap(), &buf[..]);
        write(file_path, txt).unwrap();
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
pub fn delete_vault(mut key: PasswordType) {
    use directories::ProjectDirs;
    let proj_dir = ProjectDirs::from("com", "myproject", "password_manager").unwrap();
    let data = proj_dir.data_dir();
    let filename = get_filename(&mut key, false);
    fs::remove_file(data.join(filename)).unwrap();
    match key {
        PasswordType::Key(key) => {
            fs::remove_file(data.join(key)).unwrap();
        }
        _ => {}
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::cli::UpdateArgs;
    use chrono::FixedOffset;
    use std::{fs, path::Path, thread};
    use tempfile::NamedTempFile;

    fn time_close(time: String) -> bool {
        let thing =
            chrono::DateTime::<FixedOffset>::parse_from_str(&time, "%Y-%m-%d %H:%M:%S%.f %:z")
                .unwrap();
        let diff = chrono::Local::now().signed_duration_since(thing);
        diff.num_seconds() < 1
    }
    #[test]
    fn test_add_entry() {
        let mut vault: Vault = Vault {
            enteries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vault.add_entry(PasswordEntry {
            which: None,
            name: String::from("test"),
            username: Some(String::from("test")),
            password: String::from("test123"),
            url: None,
            notes: None,
            copy: false,
        });
        let expected = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: vault.enteries[0].created.clone(),
                modified: vault.enteries[0].modified.clone(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        assert_eq!(vault, expected);
        assert!(time_close(vault.enteries[0].created.clone()));
        assert!(time_close(vault.enteries[0].modified.clone()));
    }
    #[test]
    fn test_delete_id() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.delete_entry(DeleteType::Id(1));
        assert_eq!(
            vlt,
            Vault {
                enteries: vec![],
                metadata: VaultMetadata {
                    filename: "test.enc".into(),
                }
            }
        )
    }
    #[test]
    fn test_delete_name() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.delete_entry(DeleteType::Name("test".into()));
        assert_eq!(
            vlt,
            Vault {
                enteries: vec![],
                metadata: VaultMetadata {
                    filename: "test.enc".into(),
                }
            }
        )
    }
    #[test]
    fn test_update_id() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.update_entry(UpdateStruct {
            which: DeleteType::Id(1),
            update: UpdateArgs {
                name: Some(String::from("test2")),
                username: Some(String::from("test2")),
                password: false,
                gen_pass: false,
                url: None,
                notes: None,
            },
            password: None,
        });
        let expected = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test2"),
                username: Some(String::from("test2")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: vlt.enteries[0].created.clone(),
                modified: vlt.enteries[0].modified.clone(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        assert_eq!(vlt, expected);
        assert!(time_close(vlt.enteries[0].modified.clone()))
    }
    #[test]
    fn test_update_name() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.update_entry(UpdateStruct {
            which: DeleteType::Name(String::from("test")),
            update: UpdateArgs {
                name: Some(String::from("test2")),
                username: Some(String::from("test2")),
                password: false,
                gen_pass: false,
                url: None,
                notes: None,
            },
            password: None,
        });
        let expected = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test2"),
                username: Some(String::from("test2")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: vlt.enteries[0].created.clone(),
                modified: vlt.enteries[0].modified.clone(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        assert_eq!(vlt, expected);
        assert!(time_close(vlt.enteries[0].modified.clone()))
    }
    #[test]
    fn test_export_import() {
        let file = NamedTempFile::new().unwrap();

        let vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.export(file.path().to_str().unwrap().to_string());
        let mut vlt1 = Vault {
            enteries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt1.import(file.path().to_str().unwrap().to_string());
        assert_eq!(vlt, vlt1);
    }
    #[test]
    fn test_lock_unlock_key() {
        let temp = Path::new("test_lock_unlock_key.pem");
        gen_master_key(
            &mut PasswordType::Key("test_lock_unlock_key.pem".to_string()),
            true,
        );
        let filename = get_filename(
            &mut PasswordType::Key(temp.to_str().unwrap().to_string()),
            false,
        );
        let vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: filename.clone(),
            },
        };
        let pass = PasswordType::Key(temp.to_str().unwrap().to_string());
        let pass1 = PasswordType::Key(temp.to_str().unwrap().to_string());
        vlt.lock_vault(&mut ServerInfo {
            locked: false,
            keypass: Some(pass),
        });
        let vlt1 = unlock_vault(&mut ServerInfo {
            locked: true,
            keypass: Some(pass1),
        });
        let proj_dir = ProjectDirs::from("com", "myproject", "password_manager").unwrap();
        let data_path = proj_dir.data_dir();
        let file_path = data_path.join(&filename);
        let file_path2 = data_path.join(temp);
        fs::remove_file(file_path2).unwrap();
        fs::remove_file(file_path).unwrap();
        assert_eq!(vlt, vlt1)
    }
    #[test]
    fn test_lock_unlock_password() {
        let filename = get_filename(
            &mut PasswordType::Password("test_password1234!".to_string()),
            true,
        );
        let vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: filename.clone(),
            },
        };
        let pass = PasswordType::Password("test_password1234!".to_string());
        let pass1 = PasswordType::Password("test_password1234!".to_string());
        vlt.lock_vault(&mut ServerInfo {
            locked: false,
            keypass: Some(pass),
        });
        let vlt1 = unlock_vault(&mut ServerInfo {
            locked: true,
            keypass: Some(pass1),
        });
        let proj_dir = ProjectDirs::from("com", "myproject", "password_manager").unwrap();
        let data_path = proj_dir.data_dir();
        let file_path = data_path.join(&filename);
        fs::remove_file(file_path).unwrap();
        assert_eq!(vlt, vlt1)
    }
    #[test]
    fn test_create_vault_key() {
        let mut vlt = None;
        create_vault(
            &mut vlt,
            &mut ServerInfo {
                locked: true,
                keypass: Some(PasswordType::Key("create_vault.enc".to_string())),
            },
            false,
        );
        let filename = get_filename(
            &mut PasswordType::Key("create_vault.enc".to_string()),
            false,
        );
        let proj_dir = ProjectDirs::from("com", "myproject", "password_manager").unwrap();
        let data_path = proj_dir.data_dir();
        let file_path = data_path.join(&filename);
        let file_path2 = data_path.join("create_vault.enc");
        fs::remove_file(file_path).unwrap();
        fs::remove_file(file_path2).unwrap();
        assert_eq!(
            vlt,
            Some(Vault {
                enteries: Vec::new(),
                metadata: VaultMetadata { filename: filename },
            })
        )
    }
    #[test]
    fn test_create_vault_key_lock() {
        let mut vlt = None;
        create_vault(
            &mut vlt,
            &mut ServerInfo {
                locked: true,
                keypass: Some(PasswordType::Key("create_vault_lock.enc".to_string())),
            },
            true,
        );
        let filename = get_filename(
            &mut PasswordType::Key("create_vault_lock.enc".to_string()),
            false,
        );
        let proj_dir = ProjectDirs::from("com", "myproject", "password_manager").unwrap();
        let data_path = proj_dir.data_dir();
        let file_path = data_path.join(&filename);
        let file_path2 = data_path.join("create_vault_lock.enc");
        fs::remove_file(file_path).unwrap();
        fs::remove_file(file_path2).unwrap();
        assert_eq!(vlt, None)
    }
    #[test]
    fn test_create_vault_password() {
        let mut vlt = None;
        create_vault(
            &mut vlt,
            &mut ServerInfo {
                locked: true,
                keypass: Some(PasswordType::Password("test123456!".to_string())),
            },
            false,
        );
        let filename = get_filename(
            &mut PasswordType::Password("test123456!".to_string()),
            false,
        );
        let proj_dir = ProjectDirs::from("com", "myproject", "password_manager").unwrap();
        let data_path = proj_dir.data_dir();
        let file_path = data_path.join(&filename);
        fs::remove_file(file_path).unwrap();
        assert_eq!(
            vlt,
            Some(Vault {
                enteries: Vec::new(),
                metadata: VaultMetadata { filename: filename },
            })
        )
    }
    #[test]
    fn test_create_vault_password_lock() {
        let mut vlt = None;
        create_vault(
            &mut vlt,
            &mut ServerInfo {
                locked: true,
                keypass: Some(PasswordType::Password("test1234567!".to_string())),
            },
            true,
        );
        let filename = get_filename(
            &mut PasswordType::Password("test1234567!".to_string()),
            false,
        );
        let proj_dir = ProjectDirs::from("com", "myproject", "password_manager").unwrap();
        let data_path = proj_dir.data_dir();
        let file_path = data_path.join(&filename);
        fs::remove_file(file_path).unwrap();
        assert_eq!(vlt, None)
    }
    #[test]
    fn test_add_duplicate_entry_name() {
        let mut vlt = Vault {
            enteries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.add_entry(PasswordEntry {
            which: None,
            name: String::from("test"),
            username: Some(String::from("user1")),
            password: String::from("pass1"),
            url: None,
            notes: None,
            copy: false,
        });
        let initial_len = vlt.enteries.len();
        vlt.add_entry(PasswordEntry {
            which: None,
            name: String::from("test"),
            username: Some(String::from("user2")),
            password: String::from("pass2"),
            url: None,
            notes: None,
            copy: false,
        });
        assert_eq!(vlt.enteries.len(), initial_len);
    }
    #[test]
    fn test_add_multiple_entries_ids_sequential() {
        let mut vlt = Vault {
            enteries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        for i in 0..5 {
            vlt.add_entry(PasswordEntry {
                which: None,
                name: format!("entry{}", i),
                username: Some(format!("user{}", i)),
                password: format!("pass{}", i),
                url: None,
                notes: None,
                copy: false,
            });
        }
        for (i, entry) in vlt.enteries.iter().enumerate() {
            assert_eq!(entry.id, i + 1);
        }
    }
    #[test]
    fn test_delete_entry_reindexes_ids() {
        let mut vlt = Vault {
            enteries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        for i in 0..5 {
            vlt.add_entry(PasswordEntry {
                which: None,
                name: format!("entry{}", i),
                username: Some(format!("user{}", i)),
                password: format!("pass{}", i),
                url: None,
                notes: None,
                copy: false,
            });
        }
        vlt.delete_entry(DeleteType::Id(2));
        for (i, entry) in vlt.enteries.iter().enumerate() {
            assert_eq!(entry.id, i + 1);
        }
    }
    #[test]
    fn test_update_password_changes() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("oldpass"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.update_entry(UpdateStruct {
            which: DeleteType::Id(1),
            update: UpdateArgs {
                name: None,
                username: None,
                password: true,
                gen_pass: false,
                url: None,
                notes: None,
            },
            password: Some(String::from("newpass")),
        });
        assert_eq!(vlt.enteries[0].password, "newpass");
    }
    #[test]
    fn test_update_url_changes() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.update_entry(UpdateStruct {
            which: DeleteType::Id(1),
            update: UpdateArgs {
                name: None,
                username: None,
                password: false,
                gen_pass: false,
                url: Some(String::from("https://example.com")),
                notes: None,
            },
            password: None,
        });
        assert_eq!(
            vlt.enteries[0].url,
            Some(String::from("https://example.com"))
        );
    }
    #[test]
    fn test_update_notes_changes() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.update_entry(UpdateStruct {
            which: DeleteType::Id(1),
            update: UpdateArgs {
                name: None,
                username: None,
                password: false,
                gen_pass: false,
                url: None,
                notes: Some(String::from("important notes")),
            },
            password: None,
        });
        assert_eq!(vlt.enteries[0].notes, Some(String::from("important notes")));
    }

    #[test]
    #[should_panic(expected = "not valid id")]
    fn test_delete_entry_invalid_id_zero() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.delete_entry(DeleteType::Id(0));
    }

    #[test]
    #[should_panic(expected = "not valid id")]
    fn test_delete_entry_invalid_id_out_of_bounds() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.delete_entry(DeleteType::Id(100));
    }

    #[test]
    #[should_panic(expected = "not valid id")]
    fn test_update_entry_invalid_id_zero() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.update_entry(UpdateStruct {
            which: DeleteType::Id(0),
            update: UpdateArgs {
                name: Some(String::from("new")),
                username: None,
                password: false,
                gen_pass: false,
                url: None,
                notes: None,
            },
            password: None,
        });
    }

    #[test]
    #[should_panic(expected = "not valid id")]
    fn test_update_entry_invalid_id_out_of_bounds() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.update_entry(UpdateStruct {
            which: DeleteType::Id(100),
            update: UpdateArgs {
                name: Some(String::from("new")),
                username: None,
                password: false,
                gen_pass: false,
                url: None,
                notes: None,
            },
            password: None,
        });
    }

    #[test]
    fn test_delete_entry_by_name_no_match() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        let initial_len = vlt.enteries.len();
        vlt.delete_entry(DeleteType::Name("nonexistent".into()));
        assert_eq!(vlt.enteries.len(), initial_len);
    }

    #[test]
    fn test_update_entry_by_name_no_match() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        let original_modified = vlt.enteries[0].modified.clone();
        vlt.update_entry(UpdateStruct {
            which: DeleteType::Name(String::from("nonexistent")),
            update: UpdateArgs {
                name: Some(String::from("new")),
                username: None,
                password: false,
                gen_pass: false,
                url: None,
                notes: None,
            },
            password: None,
        });
        assert_eq!(vlt.enteries[0].name, "test");
        assert_eq!(vlt.enteries[0].modified, original_modified);
    }

    #[test]
    fn test_delete_name_with_only_first_match() {
        let mut vlt = Vault {
            enteries: vec![
                VaultEnteries {
                    id: 1,
                    name: String::from("dup"),
                    username: Some(String::from("user1")),
                    password: String::from("pass1"),
                    url: None,
                    notes: None,
                    created: chrono::Local::now().to_string(),
                    modified: chrono::Local::now().to_string(),
                },
                VaultEnteries {
                    id: 2,
                    name: String::from("dup"),
                    username: Some(String::from("user2")),
                    password: String::from("pass2"),
                    url: None,
                    notes: None,
                    created: chrono::Local::now().to_string(),
                    modified: chrono::Local::now().to_string(),
                },
            ],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.delete_entry(DeleteType::Name("dup".into()));
        assert_eq!(vlt.enteries.len(), 1);
        assert_eq!(vlt.enteries[0].id, 1);
        assert_eq!(vlt.enteries[0].username, Some(String::from("user2")));
    }

    #[test]
    fn test_add_entry_with_all_fields() {
        let mut vlt: Vault = Vault {
            enteries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.add_entry(PasswordEntry {
            which: None,
            name: String::from("full_entry"),
            username: Some(String::from("admin")),
            password: String::from("secret123"),
            url: Some(String::from("https://example.com")),
            notes: Some(String::from("important account")),
            copy: false,
        });
        assert_eq!(vlt.enteries.len(), 1);
        assert_eq!(vlt.enteries[0].name, "full_entry");
        assert_eq!(vlt.enteries[0].username, Some(String::from("admin")));
        assert_eq!(vlt.enteries[0].password, "secret123");
        assert_eq!(
            vlt.enteries[0].url,
            Some(String::from("https://example.com"))
        );
        assert_eq!(
            vlt.enteries[0].notes,
            Some(String::from("important account"))
        );
    }

    #[test]
    fn test_add_entry_with_minimal_fields() {
        let mut vlt: Vault = Vault {
            enteries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vlt.add_entry(PasswordEntry {
            which: None,
            name: String::from("minimal"),
            username: None,
            password: String::from("pass"),
            url: None,
            notes: None,
            copy: false,
        });
        assert_eq!(vlt.enteries.len(), 1);
        assert_eq!(vlt.enteries[0].name, "minimal");
        assert_eq!(vlt.enteries[0].username, None);
        assert_eq!(vlt.enteries[0].url, None);
        assert_eq!(vlt.enteries[0].notes, None);
    }

    #[test]
    fn test_update_all_fields_at_once() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("original"),
                username: Some(String::from("old_user")),
                password: String::from("old_pass"),
                url: Some(String::from("http://old.com")),
                notes: Some(String::from("old notes")),
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        let original_created = vlt.enteries[0].created.clone();
        vlt.update_entry(UpdateStruct {
            which: DeleteType::Id(1),
            update: UpdateArgs {
                name: Some(String::from("new_name")),
                username: Some(String::from("new_user")),
                password: true,
                gen_pass: false,
                url: Some(String::from("https://new.com")),
                notes: Some(String::from("new notes")),
            },
            password: Some(String::from("new_pass")),
        });
        assert_eq!(vlt.enteries[0].name, "new_name");
        assert_eq!(vlt.enteries[0].username, Some(String::from("new_user")));
        assert_eq!(vlt.enteries[0].password, "new_pass");
        assert_eq!(vlt.enteries[0].url, Some(String::from("https://new.com")));
        assert_eq!(vlt.enteries[0].notes, Some(String::from("new notes")));
        assert_eq!(vlt.enteries[0].created, original_created);
    }

    #[test]
    fn test_update_no_changes() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        let original_modified = vlt.enteries[0].modified.clone();
        thread::sleep(std::time::Duration::from_millis(10));
        vlt.update_entry(UpdateStruct {
            which: DeleteType::Id(1),
            update: UpdateArgs {
                name: None,
                username: None,
                password: false,
                gen_pass: false,
                url: None,
                notes: None,
            },
            password: None,
        });
        assert_eq!(vlt.enteries[0].modified, original_modified);
    }
}
