use crate::{
    clpboard::cpy, encryption::{decrypt_file, encrypt_file, gen_master_key, gen_master_key_legacy}, file::{data_dir, file_exists, set_private_perms}, server::{ServerInfo, respond}, types::{DeleteType, PasswordEntry, PasswordType, UpdateStruct}
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::{self, File, read, write};
use tokio::net::TcpStream;
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

fn get_filename(key_pass: &mut PasswordType, new: bool) -> String {
    let master_key = gen_master_key(key_pass, new);
    let filename_key = filename_key_from_master(&master_key);
    vault_filename_from_key(&filename_key)
}

fn get_legacy_filename(key_pass: &mut PasswordType) -> String {
    let master_key = gen_master_key_legacy(key_pass);
    let filename_key = filename_key_from_master(&master_key);
    vault_filename_from_key(&filename_key)
}

pub fn create_vault(vlt: &mut Option<Vault>, server_info: &mut ServerInfo, lock: bool) -> Result<(), String> {
    let fname = get_filename(server_info.keypass.as_mut().unwrap(), true);
    let file_path = data_dir().join(&fname);
    if file_exists(file_path.to_str().unwrap()) {
        return Err("A vault file with this key already exists.".to_string());
    }
    File::create(&file_path).unwrap();
    set_private_perms(&file_path);
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
    Ok(())
}
fn write_vault(vlt: &Vault, key_pass: &mut ServerInfo) {
    if key_pass.keypass.is_none() {
        return;
    }
    let fname = vlt.metadata.filename.clone();
    let file_path = data_dir().join(&fname);
    let buf = rmp_serde::to_vec(&vlt).unwrap();
    let txt = encrypt_file(key_pass.keypass.as_mut().unwrap(), &buf[..]);
    write(&file_path, txt).unwrap();
    set_private_perms(&file_path);
}

fn unlock_vault(key_pass: &mut ServerInfo) -> Option<Vault> {
    let kp = key_pass.keypass.as_mut()?;
    if let PasswordType::Key(key) = kp
        && !data_dir().join(key).exists() {
            return None;
        }
    let fname = get_filename(key_pass.keypass.as_mut().unwrap(), false);
    let mut file_path = data_dir().join(&fname);
    if !file_path.exists() {
        let legacy_fname = get_legacy_filename(key_pass.keypass.as_mut().unwrap());
        file_path = data_dir().join(&legacy_fname);
        if !file_path.exists() {
            return None;
        }
    }
    let contents = read(file_path).ok()?;
    let dec = decrypt_file(key_pass.keypass.as_mut().unwrap(), &contents)?;
    let vault: Vault = rmp_serde::from_slice(&dec).ok()?;
    key_pass.locked = false;
    Some(vault)
}

fn url_match_json(entries: &[VaultEnteries], url: &str) -> Option<String> {
    let mut results = Vec::new();
    for e in entries {
        if let Some(u) = &e.url
            && (u == url || u.contains(url)) {
                results.push(json!({
                    "id": e.id,
                    "username": e.username.clone().unwrap_or_else(|| "None".to_string()),
                    "password": e.password,
                    "name": e.name,
                }));
            }
    }
    if results.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&results).unwrap())
    }
}

impl Vault {
    pub async fn get_entry(&self, a: DeleteType, stream: &mut TcpStream, http: bool) {
        match a {
            DeleteType::Id(i) => {
                if i == 0 || i > self.enteries.len() {
                    respond("Invalid id.", stream, http).await;
                    return;
                }
                let entry = &self.enteries[i - 1];
                respond(&format!("{:?}\n", entry), stream, http).await;
                cpy(&entry.password, 15);
            }
            DeleteType::Name(n) => {
                let mut found = false;
                for i in 0..self.enteries.len() {
                    if self.enteries[i].name == n {
                        respond(&format!("{:?}\n", self.enteries[i]), stream, http).await;
                        found = true;
                        break;
                    }
                }
                if !found {
                    respond("Not found.\n", stream, http).await;
                }
            }
            DeleteType::Url(u) => {
                if let Some(json) = url_match_json(&self.enteries, &u) {
                    respond(&json, stream, http).await;
                } else {
                    respond("Not found.\n", stream, http).await;
                }
            }
            DeleteType::Vault(_) => unreachable!(),
        }
    }

    pub fn add_entry(&mut self, info: PasswordEntry, key_pass: &mut ServerInfo) -> bool {
        let nid = self.enteries.len() + 1;

        let mut exists = false;
        for i in &self.enteries {
            if i.name == info.name && i.username == info.username {
                exists = true;
                break;
            }
        }
        if exists {
            println!("An entry with this name and username already exists.");
            return false;
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
        write_vault(self, key_pass);
        true
    }

    pub fn delete_entry(&mut self, id: DeleteType, key_pass: &mut ServerInfo) -> bool {
        let mut removed = false;
        match id {
            DeleteType::Id(i) => {
                if i == 0 || i > self.enteries.len() {
                    return false;
                }
                self.enteries.remove(i - 1);
                removed = true;
            }
            DeleteType::Name(n) => {
                for i in 0..self.enteries.len() {
                    if self.enteries[i].name == n {
                        self.enteries.remove(i);
                        removed = true;
                        break;
                    }
                }
            }
            _ => unreachable!(),
        }

        if removed {
            for i in 1..=self.enteries.len() {
                self.enteries[i - 1].id = i;
            }
            write_vault(self, key_pass);
        }
        removed
    }

    pub fn update_entry(&mut self, add: UpdateStruct, key_pass: &mut ServerInfo) -> bool {
        match add.which {
            DeleteType::Id(i) => {
                if i == 0 || i > self.enteries.len() {
                    return false;
                }
                let mut modified = false;
                if let Some(name) = add.update.name {
                    self.enteries[i - 1].name = name;
                    modified = true;
                }
                if add.update.notes.is_some() {
                    self.enteries[i - 1].notes = add.update.notes;
                    modified = true;
                }
                if add.update.password {
                    self.enteries[i - 1].password = add.password.unwrap();
                    modified = true;
                }
                if add.update.url.is_some() {
                    self.enteries[i - 1].url = add.update.url;
                    modified = true;
                }
                if add.update.username.is_some() {
                    self.enteries[i - 1].username = add.update.username;
                    modified = true;
                }
                if modified {
                    self.enteries[i - 1].modified = chrono::Local::now().to_string();
                    write_vault(self, key_pass);
                }
                modified
            }
            DeleteType::Name(n) => {
                for i in 0..self.enteries.len() {
                    if self.enteries[i].name == n {
                        let mut modified = false;
                        if let Some(name) = add.update.name {
                            self.enteries[i].name = name;
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
                            write_vault(self, key_pass);
                        }
                        return modified;
                    }
                }
                false
            }
            _ => unreachable!(),
        }
    }

    pub async fn view_entries(&self, stream: &mut TcpStream, http: bool) {
        let enteries = &self.enteries[..];
        if enteries.is_empty() {
            respond("No entries.", stream, http).await;
            return;
        }
        for i in enteries {
            respond(
                &format!(
                    "{}. {} {:?} {:?} {:?}\n",
                    i.id, i.name, i.username, i.url, i.notes
                ),
                stream,
                http,
            )
            .await;
        }
    }

    pub fn lock_vault(&self, key_pass: &mut ServerInfo) {
        write_vault(self, key_pass);
        key_pass.zeroize();
    }
    pub fn export(&self, path: String) {
        println!("WARNING: Export writes passwords as plaintext CSV. Delete the file after use.");
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
    async fn get_entry(&self, a: DeleteType, stream: &mut TcpStream, http: bool);
    fn add_entry(&mut self, info: PasswordEntry, key_pass: &mut ServerInfo) -> bool;
    fn delete_entry(&mut self, id: DeleteType, key_pass: &mut ServerInfo) -> bool;
    fn update_entry(&mut self, add: UpdateStruct, key_pass: &mut ServerInfo) -> bool;
    async fn view_entries(&self, stream: &mut TcpStream, http: bool);
    fn lock_vault(&self, key_pass: &mut ServerInfo);
    fn unlock_vault(&mut self, key_pass: &mut ServerInfo) -> Result<(), String>;
    fn export(&self, path: String);
    fn import(&mut self, path: String);
}

impl VaultFns for Option<Vault> {
    async fn get_entry(&self, a: DeleteType, stream: &mut TcpStream, http: bool) {
        if let Some(vlt) = self {
            vlt.get_entry(a, stream, http).await
        }
    }
    fn add_entry(&mut self, info: PasswordEntry, key_pass: &mut ServerInfo) -> bool {
        match self {
            Some(vlt) => vlt.add_entry(info, key_pass),
            None => false,
        }
    }
    fn delete_entry(&mut self, id: DeleteType, key_pass: &mut ServerInfo) -> bool {
        match self {
            Some(vlt) => vlt.delete_entry(id, key_pass),
            None => false,
        }
    }

    fn update_entry(&mut self, add: UpdateStruct, key_pass: &mut ServerInfo) -> bool {
        match self {
            Some(vlt) => vlt.update_entry(add, key_pass),
            None => false,
        }
    }
    async fn view_entries(&self, stream: &mut TcpStream, http: bool) {
        if let Some(vlt) = self {
            vlt.view_entries(stream, http).await;
        }
    }
    fn lock_vault(&self, key_pass: &mut ServerInfo) {
        if let Some(vlt) = self {
            vlt.lock_vault(key_pass);
        }
        key_pass.zeroize();
    }
    fn unlock_vault(&mut self, key_pass: &mut ServerInfo) -> Result<(), String> {
        if self.is_some() {
            return Err(
                "a vault is already unlocked; lock it before unlocking another one".to_string(),
            );
        }
        match crate::vault::unlock_vault(key_pass) {
            Some(vault) => {
                *self = Some(vault);
                Ok(())
            }
            None => Err(
                "wrong master password, or no vault exists for this key".to_string(),
            ),
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
    let data = data_dir();
    let filename = get_filename(&mut key, false);
    fs::remove_file(data.join(filename)).unwrap();
    if let PasswordType::Key(key) = key {
        fs::remove_file(data.join(key)).unwrap();
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::cli::UpdateArgs;
    use crate::file::init_test_data_dir;
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
    fn test_url_match_json_escapes_special_chars() {
        let entries = vec![VaultEnteries {
            id: 1,
            name: String::from("site\"with\"quote"),
            username: Some(String::from("bob")),
            password: String::from("pa\"ss\\wrd"),
            url: Some(String::from("example.com")),
            notes: None,
            created: String::from("2026-01-01"),
            modified: String::from("2026-01-01"),
        }];
        let json = url_match_json(&entries, "example.com").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["password"], "pa\"ss\\wrd");
        assert_eq!(parsed[0]["name"], "site\"with\"quote");
        assert_eq!(parsed[0]["username"], "bob");
        assert_eq!(parsed[0]["id"], 1);
    }
    #[test]
    fn test_url_match_json_no_match_returns_none() {
        let entries = vec![VaultEnteries {
            id: 1,
            name: String::from("x"),
            username: None,
            password: String::from("p"),
            url: Some(String::from("other.com")),
            notes: None,
            created: String::from("2026-01-01"),
            modified: String::from("2026-01-01"),
        }];
        assert!(url_match_json(&entries, "example.com").is_none());
    }
    #[test]
    fn test_url_match_json_partial_match() {
        let entries = vec![VaultEnteries {
            id: 2,
            name: String::from("x"),
            username: None,
            password: String::from("p"),
            url: Some(String::from("https://mail.example.com/login")),
            notes: None,
            created: String::from("2026-01-01"),
            modified: String::from("2026-01-01"),
        }];
        let json = url_match_json(&entries, "example.com").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["id"], 2);
    }
    #[test]
    fn test_add_entry_returns_false_for_duplicate() {
        let mut vlt = Vault {
            enteries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        let entry = PasswordEntry {
            which: None,
            name: String::from("test"),
            username: Some(String::from("user1")),
            password: String::from("pass1"),
            url: None,
            notes: None,
            copy: false,
        };
        let mut si = ServerInfo {
            locked: true,
            keypass: None,
        };
        assert!(vlt.add_entry(entry.clone(), &mut si));
        assert!(!vlt.add_entry(entry, &mut si));
    }
    #[test]
    fn test_delete_entry_returns_false_when_not_found() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: None,
                password: String::from("p"),
                url: None,
                notes: None,
                created: String::from("2026-01-01"),
                modified: String::from("2026-01-01"),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        let mut si = ServerInfo {
            locked: true,
            keypass: None,
        };
        assert!(!vlt.delete_entry(DeleteType::Name("nope".into()), &mut si));
        assert!(vlt.delete_entry(DeleteType::Name("test".into()), &mut si));
    }
    #[test]
    fn test_update_entry_returns_false_when_not_found() {
        let mut vlt = Vault {
            enteries: vec![VaultEnteries {
                id: 1,
                name: String::from("test"),
                username: None,
                password: String::from("p"),
                url: None,
                notes: None,
                created: String::from("2026-01-01"),
                modified: String::from("2026-01-01"),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        let mut si = ServerInfo {
            locked: true,
            keypass: None,
        };
        let upd = UpdateStruct {
            which: DeleteType::Name("nope".into()),
            update: UpdateArgs {
                name: Some("x".into()),
                username: None,
                password: false,
                gen_password: false,
                url: None,
                notes: None,
            },
            password: None,
        };
        assert!(!vlt.update_entry(upd, &mut si));
    }
    #[test]
    fn test_add_entry() {
        let mut vault: Vault = Vault {
            enteries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
        };
        vault.add_entry(
            PasswordEntry {
                which: None,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                copy: false,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
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
        vlt.delete_entry(
            DeleteType::Id(1),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
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
        vlt.delete_entry(
            DeleteType::Name("test".into()),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
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
        vlt.update_entry(
            UpdateStruct {
                which: DeleteType::Id(1),
                update: UpdateArgs {
                    name: Some(String::from("test2")),
                    username: Some(String::from("test2")),
                    password: false,
                    gen_password: false,
                    url: None,
                    notes: None,
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
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
        vlt.update_entry(
            UpdateStruct {
                which: DeleteType::Name(String::from("test")),
                update: UpdateArgs {
                    name: Some(String::from("test2")),
                    username: Some(String::from("test2")),
                    password: false,
                    gen_password: false,
                    url: None,
                    notes: None,
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
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
    fn test_import_new_persists_vault_to_disk() {
        init_test_data_dir();
        let pass = PasswordType::Password("import_fix_test_pass!".to_string());
        let mut server_info = ServerInfo {
            locked: true,
            keypass: Some(pass.clone()),
        };
        let mut vlt: Option<Vault> = None;
        create_vault(&mut vlt, &mut server_info, false).unwrap();

        let mut tf = NamedTempFile::new().unwrap();
        {
            use std::io::Write;
            writeln!(tf, "id,name,username,password,url,notes,created,modified").unwrap();
            writeln!(tf, "1,example.com,bob,secret,,,2026-01-01 00:00:00,2026-01-01 00:00:00").unwrap();
            writeln!(tf, "2,test.org,alice,pw456,,,2026-01-02 00:00:00,2026-01-02 00:00:00").unwrap();
        }
        vlt.import(tf.path().to_str().unwrap().to_string());

        vlt.lock_vault(&mut server_info);

        let vlt1 = unlock_vault(&mut ServerInfo {
            locked: true,
            keypass: Some(pass),
        })
        .unwrap();
        assert_eq!(vlt1.enteries.len(), 2);
        assert_eq!(vlt1.enteries[0].name, "example.com");
        assert_eq!(vlt1.enteries[1].name, "test.org");

        let fname = vlt1.metadata.filename.clone();
        let _ = fs::remove_file(data_dir().join(fname));
    }
    #[test]
    fn test_lock_unlock_key() {
        init_test_data_dir();
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
        })
        .unwrap();
        let data_path = data_dir();
        let file_path = data_path.join(&filename);
        let file_path2 = data_path.join(temp);
        fs::remove_file(file_path2).unwrap();
        fs::remove_file(file_path).unwrap();
        assert_eq!(vlt, vlt1)
    }
    #[test]
    fn test_lock_unlock_password() {
        init_test_data_dir();
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
        })
        .unwrap();
        let data_path = data_dir();
        let file_path = data_path.join(&filename);
        fs::remove_file(file_path).unwrap();
        assert_eq!(vlt, vlt1)
    }
    #[test]
    fn test_create_vault_key() {
        init_test_data_dir();
        let mut vlt = None;
        create_vault(
            &mut vlt,
            &mut ServerInfo {
                locked: true,
                keypass: Some(PasswordType::Key("create_vault.enc".to_string())),
            },
            false,
        ).unwrap();
        let filename = get_filename(
            &mut PasswordType::Key("create_vault.enc".to_string()),
            false,
        );
        let data_path = data_dir();
        let file_path = data_path.join(&filename);
        let file_path2 = data_path.join("create_vault.enc");
        fs::remove_file(file_path).unwrap();
        fs::remove_file(file_path2).unwrap();
        assert_eq!(
            vlt,
            Some(Vault {
                enteries: Vec::new(),
                metadata: VaultMetadata { filename },
            })
        )
    }
    #[test]
    fn test_create_vault_key_lock() {
        init_test_data_dir();
        let mut vlt = None;
        create_vault(
            &mut vlt,
            &mut ServerInfo {
                locked: true,
                keypass: Some(PasswordType::Key("create_vault_lock.enc".to_string())),
            },
            true,
        ).unwrap();
        let filename = get_filename(
            &mut PasswordType::Key("create_vault_lock.enc".to_string()),
            false,
        );
        let data_path = data_dir();
        let file_path = data_path.join(&filename);
        let file_path2 = data_path.join("create_vault_lock.enc");
        fs::remove_file(file_path).unwrap();
        fs::remove_file(file_path2).unwrap();
        assert_eq!(vlt, None)
    }
    #[test]
    fn test_create_vault_password() {
        init_test_data_dir();
        let mut vlt = None;
        create_vault(
            &mut vlt,
            &mut ServerInfo {
                locked: true,
                keypass: Some(PasswordType::Password("test123456!".to_string())),
            },
            false,
        ).unwrap();
        let filename = get_filename(
            &mut PasswordType::Password("test123456!".to_string()),
            false,
        );
        let data_path = data_dir();
        let file_path = data_path.join(&filename);
        fs::remove_file(file_path).unwrap();
        assert_eq!(
            vlt,
            Some(Vault {
                enteries: Vec::new(),
                metadata: VaultMetadata { filename },
            })
        )
    }
    #[test]
    fn test_create_vault_password_lock() {
        init_test_data_dir();
        let mut vlt = None;
        create_vault(
            &mut vlt,
            &mut ServerInfo {
                locked: true,
                keypass: Some(PasswordType::Password("test1234567!".to_string())),
            },
            true,
        ).unwrap();
        let filename = get_filename(
            &mut PasswordType::Password("test1234567!".to_string()),
            false,
        );
        let data_path = data_dir();
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
        vlt.add_entry(
            PasswordEntry {
                which: None,
                name: String::from("test"),
                username: Some(String::from("user1")),
                password: String::from("pass1"),
                url: None,
                notes: None,
                copy: false,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        let initial_len = vlt.enteries.len();

        // Same name, different username -> allowed (multiple accounts per site)
        vlt.add_entry(
            PasswordEntry {
                which: None,
                name: String::from("test"),
                username: Some(String::from("user2")),
                password: String::from("pass2"),
                url: None,
                notes: None,
                copy: false,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.enteries.len(), initial_len + 1);

        // Same name AND same username -> still blocked
        vlt.add_entry(
            PasswordEntry {
                which: None,
                name: String::from("test"),
                username: Some(String::from("user1")),
                password: String::from("pass3"),
                url: None,
                notes: None,
                copy: false,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.enteries.len(), initial_len + 1);
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
            vlt.add_entry(
                PasswordEntry {
                    which: None,
                    name: format!("entry{}", i),
                    username: Some(format!("user{}", i)),
                    password: format!("pass{}", i),
                    url: None,
                    notes: None,
                    copy: false,
                },
                &mut ServerInfo {
                    locked: true,
                    keypass: None,
                },
            );
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
            vlt.add_entry(
                PasswordEntry {
                    which: None,
                    name: format!("entry{}", i),
                    username: Some(format!("user{}", i)),
                    password: format!("pass{}", i),
                    url: None,
                    notes: None,
                    copy: false,
                },
                &mut ServerInfo {
                    locked: true,
                    keypass: None,
                },
            );
        }
        vlt.delete_entry(
            DeleteType::Id(2),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
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
        vlt.update_entry(
            UpdateStruct {
                which: DeleteType::Id(1),
                update: UpdateArgs {
                    name: None,
                    username: None,
                    password: true,
                    gen_password: false,
                    url: None,
                    notes: None,
                },
                password: Some(String::from("newpass")),
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
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
        vlt.update_entry(
            UpdateStruct {
                which: DeleteType::Id(1),
                update: UpdateArgs {
                    name: None,
                    username: None,
                    password: false,
                    gen_password: false,
                    url: Some(String::from("https://example.com")),
                    notes: None,
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
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
        vlt.update_entry(
            UpdateStruct {
                which: DeleteType::Id(1),
                update: UpdateArgs {
                    name: None,
                    username: None,
                    password: false,
                    gen_password: false,
                    url: None,
                    notes: Some(String::from("important notes")),
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.enteries[0].notes, Some(String::from("important notes")));
    }

    #[test]
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
        let result = vlt.delete_entry(
            DeleteType::Id(0),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert!(!result);
    }

    #[test]
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
        let result = vlt.delete_entry(
            DeleteType::Id(100),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert!(!result);
    }

    #[test]
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
        let result = vlt.update_entry(
            UpdateStruct {
                which: DeleteType::Id(0),
                update: UpdateArgs {
                    name: Some(String::from("new")),
                    username: None,
                    password: false,
                    gen_password: false,
                    url: None,
                    notes: None,
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert!(!result);
    }

    #[test]
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
        let result = vlt.update_entry(
            UpdateStruct {
                which: DeleteType::Id(100),
                update: UpdateArgs {
                    name: Some(String::from("new")),
                    username: None,
                    password: false,
                    gen_password: false,
                    url: None,
                    notes: None,
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert!(!result);
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
        vlt.delete_entry(
            DeleteType::Name("nonexistent".into()),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
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
        vlt.update_entry(
            UpdateStruct {
                which: DeleteType::Name(String::from("nonexistent")),
                update: UpdateArgs {
                    name: Some(String::from("new")),
                    username: None,
                    password: false,
                    gen_password: false,
                    url: None,
                    notes: None,
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
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
        vlt.delete_entry(
            DeleteType::Name("dup".into()),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
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
        vlt.add_entry(
            PasswordEntry {
                which: None,
                name: String::from("full_entry"),
                username: Some(String::from("admin")),
                password: String::from("secret123"),
                url: Some(String::from("https://example.com")),
                notes: Some(String::from("important account")),
                copy: false,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
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
        vlt.add_entry(
            PasswordEntry {
                which: None,
                name: String::from("minimal"),
                username: None,
                password: String::from("pass"),
                url: None,
                notes: None,
                copy: false,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
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
        vlt.update_entry(
            UpdateStruct {
                which: DeleteType::Id(1),
                update: UpdateArgs {
                    name: Some(String::from("new_name")),
                    username: Some(String::from("new_user")),
                    password: true,
                    gen_password: false,
                    url: Some(String::from("https://new.com")),
                    notes: Some(String::from("new notes")),
                },
                password: Some(String::from("new_pass")),
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
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
        vlt.update_entry(
            UpdateStruct {
                which: DeleteType::Id(1),
                update: UpdateArgs {
                    name: None,
                    username: None,
                    password: false,
                    gen_password: false,
                    url: None,
                    notes: None,
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.enteries[0].modified, original_modified);
    }
}
