use super::*;
use crate::{
    cloud::CloudClient,
    passkey::{self, Passkey},
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

/// One vault per app process. The native bridge serializes all access, including
/// file replacement and sync. Adapters must also lock on background/screen lock.
pub struct MobileVault {
    directory: PathBuf,
    vault: Option<Vault>,
    credentials: VaultCredentials,
    touched: Instant,
    review: Option<MobileReview>,
    primary_unlock: bool,
}
struct MobileReview {
    token: String,
    revision: u64,
    server: String,
    version: String,
    bytes: Vec<u8>,
}
impl Drop for MobileVault {
    fn drop(&mut self) {
        self.lock();
    }
}
impl MobileVault {
    pub fn new(directory: PathBuf) -> Result<Self, String> {
        if !directory.is_absolute() {
            return Err("Mobile storage path must be absolute".into());
        }
        fs::create_dir_all(&directory).map_err(|_| "Could not create mobile storage")?;
        crate::file::set_private_dir_perms(&directory)
            .map_err(|_| "Could not protect mobile storage")?;
        Ok(Self {
            directory,
            vault: None,
            credentials: VaultCredentials::Locked,
            touched: Instant::now(),
            review: None,
            primary_unlock: false,
        })
    }
    pub fn lock(&mut self) {
        self.vault = None;
        self.credentials.zeroize();
        self.review = None;
        self.primary_unlock = false;
    }
    fn open(&mut self) -> Result<&mut Vault, String> {
        if self.touched.elapsed() >= Duration::from_secs(300) {
            self.lock();
        }
        self.touched = Instant::now();
        self.vault.as_mut().ok_or_else(|| "Vault is locked".into())
    }
    fn path(&self, name: &str) -> Result<PathBuf, String> {
        validate_vault_filename(name).map_err(|e| e.to_string())?;
        Ok(self.directory.join(name))
    }
    fn unlock(
        &mut self,
        name: &str,
        mut key: VaultCredentials,
        primary: bool,
    ) -> Result<(), String> {
        self.lock();
        let (_, vault) = persistence::lookup_vault_in(&self.directory, &mut key, Some(name))
            .map_err(|e| e.to_string())?
            .ok_or("Vault not found")?;
        self.vault = Some(vault);
        self.credentials = key;
        self.primary_unlock = primary;
        self.touched = Instant::now();
        Ok(())
    }
    fn passkeys(&self) -> Result<Vec<(usize, Passkey)>, String> {
        let vault = self.vault.as_ref().ok_or("Vault is locked")?;
        let mut result = Vec::new();
        for item in vault.active_items() {
            if let Some(field) = item
                .metadata
                .custom_fields
                .iter()
                .find(|f| f.name == passkey::FIELD)
            {
                let p: Passkey =
                    serde_json::from_str(&field.value).map_err(|_| "Invalid stored passkey")?;
                p.validate()?;
                result.push((item.entry.id, p));
            }
        }
        Ok(result)
    }
    fn save_passkey(&mut self, p: &Passkey) -> Result<(), String> {
        p.validate()?;
        let entry = TypedEntry {
            entry: crate::types::PasswordEntry {
                name: format!(
                    "Passkey: {} ({}) {}",
                    p.rp_id,
                    p.user_name,
                    &p.credential_id[..8]
                ),
                username: Some(p.user_name.clone()),
                password: "".into(),
                url: Some(format!("https://{}", p.rp_id)),
                notes: None,
                copy: false,
            },
            kind: ItemKind::Login,
            additional_urls: vec![],
            custom_fields: vec![CustomField {
                name: passkey::FIELD.into(),
                value: serde_json::to_string(p)
                    .map_err(|_| "Could not encode passkey")?
                    .into(),
                secret: true,
            }],
        };
        let added = self
            .vault
            .as_mut()
            .ok_or("Vault is locked")?
            .add_typed_entry(entry, &mut self.credentials)
            .map_err(|e| e.to_string())?;
        if !added {
            return Err("Passkey entry already exists; retry registration".into());
        }
        Ok(())
    }
    fn login_ids(&self, origin: &str) -> Vec<usize> {
        let Some(vault) = self.vault.as_ref() else {
            return vec![];
        };
        if origin.starts_with("androidapp://") {
            vault
                .active_items()
                .filter(|i| {
                    i.metadata.kind == ItemKind::Login
                        && !i.entry.password.is_empty()
                        && i.urls().any(|u| u == origin)
                })
                .map(|i| i.entry.id)
                .collect()
        } else if origin.starts_with("https://") {
            vault
                .browser_logins(origin)
                .into_iter()
                .filter(|i| {
                    vault
                        .item(i.id)
                        .is_some_and(|item| !item.entry.password.is_empty())
                })
                .map(|i| i.id)
                .collect()
        } else {
            vec![]
        }
    }
    /// JSON is only a process-local FFI envelope. Never log requests or results.
    pub fn call(&mut self, input: &str) -> Result<Value, String> {
        if input.len() > 180 * 1024 * 1024 {
            return Err("Mobile request exceeds limit".into());
        }
        let mut request: Value =
            serde_json::from_str(input).map_err(|_| "Invalid mobile request")?;
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.dispatch(&request)));
        wipe_json(&mut request);
        match result {
            Ok(result) => result,
            Err(_) => {
                self.lock();
                Err("Mobile operation failed; vault locked".into())
            }
        }
    }
    fn dispatch(&mut self, r: &Value) -> Result<Value, String> {
        let op = string(r, "op")?;
        match op {
            "lock" => {
                self.lock();
                return Ok(json!({}));
            }
            "status" => {
                let unlocked = self.open().is_ok();
                return Ok(json!({"unlocked":unlocked}));
            }
            "vaults" => {
                let mut names = Vec::new();
                for entry in fs::read_dir(&self.directory)
                    .map_err(|_| "Could not list vaults")?
                    .flatten()
                {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.ends_with(".enc")
                        && validate_vault_filename(&name).is_ok()
                        && entry.file_type().is_ok_and(|t| t.is_file())
                    {
                        names.push(name);
                    }
                }
                names.sort();
                return Ok(json!(names));
            }
            "unlock" => {
                self.lock();
                let name = string(r, "vault")?;
                let key = if let Some(bytes) = r.get("key_file").and_then(Value::as_str) {
                    let data = Zeroizing::new(passkey::decode(bytes)?);
                    let encrypted =
                        crate::file::read_bounded_file(&self.path(name)?, MAX_VAULT_BYTES)
                            .map_err(|_| "Could not read vault")?;
                    crate::encryption::credentials_from_keyfile_bytes(&encrypted, &data)?
                } else {
                    VaultCredentials::from(PasswordType::Password(string(r, "password")?.into()))
                };
                self.unlock(name, key, true)?;
                return Ok(json!({}));
            }
            "create" => {
                let password = string(r, "password")?;
                validate_new_password(password)?;
                let mut key = VaultCredentials::from(PasswordType::Password(password.into()));
                let mut vault = Vault::memory();
                let name = format!("{}.enc", hex::encode(vault.vault_id()));
                vault.store = VaultStore::File {
                    directory: self.directory.clone(),
                    filename: name.clone(),
                };
                vault.metadata.filename = name.clone();
                persistence::write_vault_with_key(&vault, &mut key).map_err(|e| e.to_string())?;
                self.lock();
                self.vault = Some(vault);
                self.credentials = key;
                self.primary_unlock = true;
                self.touched = Instant::now();
                return Ok(json!({"vault":name}));
            }
            "import_vault" => {
                let data = passkey::decode(string(r, "data")?)?;
                crate::encryption::validate_vault_header(&data)?;
                if data.len() as u64 > MAX_VAULT_BYTES {
                    return Err("Vault exceeds size limit".into());
                }
                let name = format!("{}.enc", hex::encode(rand::random::<[u8; 16]>()));
                crate::cloud::write_private(&self.path(&name)?, &data, false)?;
                return Ok(json!({"vault":name}));
            }
            "biometric_unlock" => {
                self.lock();
                let name = string(r, "vault")?;
                let data = Zeroizing::new(passkey::decode(string(r, "material")?)?);
                let encrypted = crate::file::read_bounded_file(&self.path(name)?, MAX_VAULT_BYTES)
                    .map_err(|_| "Could not read vault")?;
                crate::encryption::validate_vault_header(&encrypted)?;
                // 32-byte key + 38-byte authenticated format/KDF/salt prefix.
                if data.len() != 70 || data[32..] != encrypted[..38] {
                    return Err("Biometric key is stale; use password or key file".into());
                }
                let key = crate::encryption::cached_credentials(
                    &encrypted,
                    data[..32].try_into().map_err(|_| "Invalid key")?,
                )?;
                self.unlock(name, key, false)?;
                return Ok(json!({}));
            }
            "cloud_list" => {
                let client = client(r)?;
                let rt = mobile_runtime()?;
                return Ok(json!(rt.block_on(client.list())?));
            }
            "cloud_download" => {
                let id = string(r, "id")?;
                let client = client(r)?;
                let rt = mobile_runtime()?;
                let (version, bytes) = rt.block_on(client.download(id))?;
                let name = format!("{id}.enc");
                let path = self.path(&name)?;
                crate::cloud::write_private(&path, &bytes, false)?;
                crate::cloud::save_binding(
                    &path,
                    &crate::cloud::Binding {
                        server_url: client.url.clone(),
                        vault_id: id.into(),
                        version: Some(version),
                        digest: Some(crate::cloud::digest(&bytes)),
                        enabled: true,
                    },
                )?;
                return Ok(json!({"vault":name}));
            }
            _ => {}
        }
        self.open()?;
        match op {
            "list" => Ok(json!(self.vault.as_ref().unwrap().management_list(SearchFilter {query:r.get("query").and_then(Value::as_str).map(str::to_owned),..Default::default()}).map_err(|e|e.to_string())?)),
            "item" => {
                let mut detail=self.vault.as_ref().unwrap().management_item(id(r)?,true).map_err(|e|e.to_string())?;
                // Never send passkey private keys to the normal item UI.
                detail.fields.retain(|f|f.name!=passkey::FIELD);
                Ok(json!(detail))
            }
            "save" => {
                let name=string(r,"name")?;if name.trim().is_empty() {return Err("Name is required".into());}
                let vault=self.vault.as_mut().unwrap();
                let username=r.get("username").and_then(Value::as_str).map(str::to_owned);
                let url=r.get("url").and_then(Value::as_str).map(str::to_owned);
                let password=string(r,"password")?;
                let notes=r.get("notes").and_then(Value::as_str).map(SecretString::from);
                if let Some(id)=r.get("id").and_then(Value::as_u64) {
                    vault.update_entry_with_limit(EntryUpdate {target:Target::Id(id as usize),update:EntryChanges {name:Some(name.into()),username,url,notes},password:Some(password.into())},&mut self.credentials,10).map_err(|e|e.to_string())?;
                } else {
                    let added=vault.add_typed_entry(TypedEntry {entry:crate::types::PasswordEntry {name:name.into(),username,password:password.into(),url,notes,copy:false},kind:ItemKind::Login,additional_urls:vec![],custom_fields:vec![]},&mut self.credentials).map_err(|e|e.to_string())?;
                    if !added {return Err("An entry with this name and username already exists".into());}
                }
                Ok(json!({}))
            }
            "delete" => {self.vault.as_mut().unwrap().delete_entry(Target::Id(id(r)?),&mut self.credentials).map_err(|e|e.to_string())?;Ok(json!({}))}
            "generate" => Ok(json!({"password":crate::password::generate_password(24)})),
            "otp" => {let (code,expires)=self.vault.as_ref().unwrap().current_totp(Target::Id(id(r)?)).map_err(|e|e.to_string())?;Ok(json!({"code":code,"expires_in":expires}))}
            "logins" => {let vault=self.vault.as_ref().unwrap();Ok(json!(self.login_ids(string(r,"origin")?).iter().map(|id|vault.summary(vault.item(*id).unwrap())).collect::<Vec<_>>()))},
            "login" => {
                let id=id(r)?;
                if !self.login_ids(string(r,"origin")?).contains(&id) {return Err("No matching login".into());}
                let vault=self.vault.as_ref().unwrap();let item=vault.item(id).unwrap();
                Ok(json!(BrowserLogin {id,revision:item.revision,name:item.entry.name.clone(),username:item.entry.username.clone(),password:item.entry.password.clone(),has_totp:item.authenticator.is_some()}))
            }
            "snapshot" => {let path=self.vault.as_ref().unwrap().sync_path()?;Ok(json!({"data":passkey::encode(fs::read(path).map_err(|_|"Could not read encrypted vault")?)}))}
            "biometric_material" => {
                if !self.primary_unlock {return Err("Unlock with the original password or key file before enabling biometrics".into());}
                let path=self.vault.as_ref().unwrap().sync_path()?;
                let encrypted=crate::file::read_bounded_file(&path,MAX_VAULT_BYTES).map_err(|_|"Could not read vault")?;
                let VaultCredentials::Session {encryption_key,..}=&self.credentials else {return Err("Vault is locked".into());};
                let mut material=Zeroizing::new(encryption_key.to_vec());material.extend_from_slice(&encrypted[..38]);
                Ok(json!({"material":passkey::encode(&*material),"vault":self.vault.as_ref().unwrap().metadata.filename}))
            }
            "passkeys" => Ok(json!(self.passkeys()?.iter().filter(|(_,p)|r.get("request").is_none_or(|q|p.matches(q))).map(|(id,p)|json!({"id":id,"credential_id":p.credential_id,"rp_id":p.rp_id,"user_name":p.user_name,"display_name":p.display_name})).collect::<Vec<_>>())),
            "passkey_create" => {
                let existing=self.passkeys()?.into_iter().map(|(_,p)|p).collect::<Vec<_>>();
                let hash=r.get("client_hash").and_then(Value::as_str).map(passkey::decode).transpose()?;
                let (p,response)=passkey::create(&r["request"],string(r,"origin")?,hash.as_deref(),&existing)?;
                self.save_passkey(&p)?;Ok(response)
            }
            "passkey_get" => {
                let selected=id(r)?;
                let p=self.passkeys()?.into_iter().find(|(id,_)|*id==selected).ok_or("Passkey not found")?.1;
                let hash=r.get("client_hash").and_then(Value::as_str).map(passkey::decode).transpose()?;
                p.authenticate(&r["request"],string(r,"origin")?,hash.as_deref())
            }
            "sync" => self.sync(r),
            "cloud_conflicts" => self.conflicts(r),
            "cloud_resolve" => self.resolve(r),
            _=>Err("Unsupported mobile operation".into()),
        }
    }
    fn conflicts(&mut self, r: &Value) -> Result<Value, String> {
        let client = client(r)?;
        let vault = self.vault.as_ref().ok_or("Vault is locked")?;
        let path = vault.sync_path()?;
        let binding = crate::cloud::binding(&path)?.ok_or("Synchronize this vault first")?;
        if binding.server_url != client.url {
            return Err("Sync connection does not match this vault".into());
        }
        let rt = mobile_runtime()?;
        let (version, bytes) = rt.block_on(client.download(&hex::encode(vault.vault_id())))?;
        let items = vault.cloud_conflicts(&self.credentials, &bytes)?;
        let token = hex::encode(rand::random::<[u8; 32]>());
        self.review = Some(MobileReview {
            token: token.clone(),
            revision: vault.vault_revision(),
            server: client.url.clone(),
            version,
            bytes,
        });
        Ok(json!({"token":token,"items":items}))
    }
    fn resolve(&mut self, r: &Value) -> Result<Value, String> {
        let client = client(r)?;
        let review = self
            .review
            .take()
            .ok_or("Review the current conflicts first")?;
        let vault = self.vault.as_mut().ok_or("Vault is locked")?;
        if review.token != string(r, "review_token")?
            || review.revision != vault.vault_revision()
            || review.server != client.url
        {
            return Err("Conflict review is stale; review again".into());
        }
        let id = hex::encode(vault.vault_id());
        let path = vault.sync_path()?;
        let rt = mobile_runtime()?;
        if rt.block_on(client.head(&id))?.map(|v| v.version) != Some(review.version.clone()) {
            return Err("Cloud changed; review conflicts again".into());
        }
        let choices: Vec<crate::cloud::Choice> =
            serde_json::from_value(r["choices"].clone()).map_err(|_| "Invalid conflict choices")?;
        let prepared = vault.merge_cloud(&self.credentials, &review.bytes, &choices)?;
        // Save both original encrypted snapshots before any replacement.
        let nonce = hex::encode(rand::random::<[u8; 8]>());
        let local = fs::read(&path).map_err(|_| "Could not read local snapshot")?;
        crate::cloud::write_private(
            &self.directory.join(format!("recovery-local-{nonce}.enc")),
            &local,
            false,
        )?;
        crate::cloud::write_private(
            &self.directory.join(format!("recovery-cloud-{nonce}.enc")),
            &review.bytes,
            false,
        )?;
        vault
            .apply_prepared_cloud(&mut self.credentials, prepared)
            .map_err(|e| e.to_string())?;
        let binding = crate::cloud::Binding {
            server_url: client.url.clone(),
            vault_id: id,
            version: Some(review.version),
            digest: Some(crate::cloud::digest(&review.bytes)),
            enabled: true,
        };
        crate::cloud::save_binding(&path, &binding)?;
        self.sync(r)
    }
    fn sync(&mut self, r: &Value) -> Result<Value, String> {
        let client = client(r)?;
        let path = self.vault.as_ref().unwrap().sync_path()?;
        let vault_id = hex::encode(self.vault.as_ref().unwrap().vault_id());
        let mut binding = crate::cloud::binding(&path)?.unwrap_or(crate::cloud::Binding {
            server_url: client.url.clone(),
            vault_id: vault_id.clone(),
            version: None,
            digest: None,
            enabled: true,
        });
        if binding.server_url != client.url || binding.vault_id != vault_id {
            return Err("Sync connection does not match this vault".into());
        }
        let rt = mobile_runtime()?;
        let local = fs::read(&path).map_err(|_| "Could not read local snapshot")?;
        let digest = crate::cloud::digest(&local);
        let remote = rt.block_on(client.head(&vault_id))?;
        let remote_version = remote.as_ref().map(|v| v.version.clone());
        if remote.is_none() && binding.version.is_some() {
            return Err("Cloud vault is missing; local copy preserved".into());
        }
        if remote_version != binding.version && remote.is_some() {
            let (version, bytes) = rt.block_on(client.download(&vault_id))?;
            // Verify before storing or adopting remote ciphertext.
            let mut key = self.credentials.clone();
            let plain = Zeroizing::new(
                decrypt_file(&mut key, &bytes)
                    .ok_or("Cloud vault credentials changed; local copy preserved")?,
            );
            let data = persistence::decode_document(&plain).map_err(|e| e.to_string())?;
            if hex::encode(data.vault_id) != vault_id {
                return Err("Cloud vault identity mismatch".into());
            }
            if crate::cloud::digest(&bytes) == digest {
                binding.version = Some(version);
                binding.digest = Some(digest);
                crate::cloud::save_binding(&path, &binding)?;
                return Ok(json!({"synced":true}));
            }
            if binding.digest.as_ref() != Some(&digest) {
                // Preserve a comparison snapshot without overwriting either side.
                let comparison = self
                    .directory
                    .join(format!("conflict-{vault_id}-{version}.enc"));
                if !comparison.exists() {
                    crate::cloud::write_private(&comparison, &bytes, false)?;
                }
                return Err("Sync conflict: both copies preserved. Review the encrypted comparison copy before retrying".into());
            }
            self.vault
                .as_mut()
                .unwrap()
                .apply_cloud(&mut self.credentials, &bytes)?;
            binding.version = Some(version);
            binding.digest = Some(crate::cloud::digest(&bytes));
        } else if binding.digest.as_ref() != Some(&digest) {
            binding.version =
                Some(rt.block_on(client.upload(&vault_id, binding.version.as_deref(), local))?);
            binding.digest = Some(digest);
        }
        crate::cloud::save_binding(&path, &binding)?;
        Ok(json!({"synced":true}))
    }
}
fn mobile_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| "Could not start sync")?;
    let _ = RUNTIME.set(runtime);
    RUNTIME
        .get()
        .ok_or_else(|| "Could not initialize sync runtime".into())
}

fn client(r: &Value) -> Result<CloudClient, String> {
    CloudClient::with_token(
        string(r, "server")?,
        Zeroizing::new(string(r, "token")?.into()),
    )
}
fn string<'a>(r: &'a Value, key: &str) -> Result<&'a str, String> {
    r.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Missing {key}"))
}
fn id(r: &Value) -> Result<usize, String> {
    r.get("id")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0 && *n <= MAX_ITEM_ID)
        .map(|n| n as usize)
        .ok_or_else(|| "Invalid item ID".into())
}
fn wipe_json(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe_json),
        Value::Object(o) => o.values_mut().for_each(wipe_json),
        _ => {}
    }
}
pub fn wipe_response(value: &mut Value) {
    wipe_json(value);
}

#[cfg(test)]
#[path = "mobile_sync_tests.rs"]
mod sync_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn external_key_contents_unlock_without_desktop_paths() {
        let directory = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let material: [u8; 32] = rand::random();
        let key_path = external.path().join("external.key");
        fs::write(&key_path, material).unwrap();
        let mut vault = Vault::memory();
        vault.metadata.filename = "key-vault.enc".into();
        vault.store = VaultStore::File {
            directory: directory.path().into(),
            filename: "key-vault.enc".into(),
        };
        let mut key =
            VaultCredentials::from(PasswordType::Key(key_path.to_string_lossy().into_owned()));
        persistence::write_vault_with_key(&vault, &mut key).unwrap();
        let mut mobile = MobileVault::new(directory.path().into()).unwrap();
        mobile.call(&json!({"op":"unlock","vault":"key-vault.enc","key_file":passkey::encode(material)}).to_string()).unwrap();
        assert!(mobile.call(r#"{"op":"biometric_material"}"#).is_ok());
        assert!(mobile.call(&json!({"op":"unlock","vault":"key-vault.enc","key_file":passkey::encode([0;32])}).to_string()).is_err());
        assert!(mobile.call(r#"{"op":"list"}"#).is_err());
    }
    #[test]
    fn passkeys_survive_desktop_documents_backups_and_portable_exports() {
        let temp = tempfile::tempdir().unwrap();
        let mut api = MobileVault::new(temp.path().into()).unwrap();
        let created = api
            .call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
            .unwrap();
        let registration = json!({"op":"passkey_create","origin":"https://example.com","request":{"rp":{"id":"example.com","name":"Example"},"user":{"id":passkey::encode(b"alice"),"name":"alice","displayName":"Alice"},"challenge":passkey::encode([4;32]),"pubKeyCredParams":[{"type":"public-key","alg":-7}]}});
        let response = api.call(&registration.to_string()).unwrap();
        let raw = fs::read(temp.path().join(created["vault"].as_str().unwrap())).unwrap();
        assert!(
            !raw.windows(b"private_key".len())
                .any(|w| w == b"private_key")
        );
        let mut key = api.credentials.clone();
        let plain = Zeroizing::new(decrypt_file(&mut key, &raw).unwrap());
        let document = persistence::decode_document(&plain).unwrap();
        assert_eq!(document.items.len(), 1);
        let item = document.items.values().next().unwrap();
        let stored: Passkey = serde_json::from_str(&item.metadata.custom_fields[0].value).unwrap();
        assert_eq!(stored.credential_id, response["id"]);
        assert!(api.save_passkey(&stored).is_err());
        assert!(
            api.vault
                .as_ref()
                .unwrap()
                .browser_logins("https://example.com")
                .is_empty()
        );
        assert!(
            api.call(r#"{"op":"item","id":1}"#).unwrap()["fields"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let export = temp.path().join("portable.json");
        api.vault
            .as_ref()
            .unwrap()
            .export(export.to_string_lossy().into_owned(), false)
            .unwrap();
        let imported =
            import::import_json(&fs::read_to_string(export).unwrap(), "synthetic.json").unwrap();
        assert_eq!(
            imported[0].custom_fields[0].value,
            item.metadata.custom_fields[0].value
        );
        assert!(
            api.vault
                .as_ref()
                .unwrap()
                .export(
                    temp.path().join("lossy.csv").to_string_lossy().into_owned(),
                    false
                )
                .is_err()
        );
        let backup = temp.path().join("vault.pmbackup");
        api.vault
            .as_ref()
            .unwrap()
            .encrypted_backup(
                backup.to_string_lossy().into_owned(),
                &mut PasswordType::Password("Cedar-Lantern-Quartz-9274!".into()),
                false,
            )
            .unwrap();
        let backed = fs::read(backup).unwrap();
        let mut key =
            VaultCredentials::from(PasswordType::Password("Cedar-Lantern-Quartz-9274!".into()));
        let document =
            persistence::decode_document(&decrypt_file(&mut key, &backed[9..]).unwrap()).unwrap();
        assert_eq!(
            document
                .items
                .values()
                .next()
                .unwrap()
                .metadata
                .custom_fields[0]
                .value,
            item.metadata.custom_fields[0].value
        );
        api.lock();
        api.call(&json!({"op":"unlock","vault":created["vault"],"password":"Cedar-Lantern-Quartz-9274!"}).to_string()).unwrap();
        assert_eq!(
            api.call(r#"{"op":"passkeys"}"#)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let assertion = json!({"op":"passkey_get","id":1,"origin":"https://example.com","request":{"rpId":"example.com","challenge":passkey::encode([3;32])}});
        assert!(api.call(&assertion.to_string()).is_ok());
    }
    #[test]
    fn mobile_persists_existing_format_and_biometric_unlock_rejects_wrong_keys() {
        let temp = tempfile::tempdir().unwrap();
        let mut api = MobileVault::new(temp.path().into()).unwrap();
        let created = api
            .call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
            .unwrap();
        api.call(r#"{"op":"save","name":"Example","username":"alice","password":"synthetic-secret","url":"https://example.com"}"#).unwrap();
        let material = api.call(r#"{"op":"biometric_material"}"#).unwrap();
        api.lock();
        assert!(api.call(r#"{"op":"list"}"#).is_err());
        api.call(&json!({"op":"biometric_unlock","vault":created["vault"],"material":material["material"]}).to_string()).unwrap();
        assert_eq!(api.call(r#"{"op":"list"}"#).unwrap()["total"], 1);
        api.lock();
        let mut bad = passkey::decode(material["material"].as_str().unwrap()).unwrap();
        bad[0] ^= 1;
        assert!(api.call(&json!({"op":"biometric_unlock","vault":created["vault"],"material":passkey::encode(bad)}).to_string()).is_err());
        assert!(api.call(r#"{"op":"list"}"#).is_err());
        api.call(&json!({"op":"unlock","vault":created["vault"],"password":"Cedar-Lantern-Quartz-9274!"}).to_string()).unwrap();
        assert_eq!(
            api.call(r#"{"op":"login","origin":"https://evil.com","id":1}"#)
                .unwrap_err(),
            "No matching login"
        );
        api.touched = Instant::now() - Duration::from_secs(301);
        assert!(api.call(r#"{"op":"list"}"#).is_err());
    }
}
