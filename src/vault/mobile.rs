use super::*;
use crate::{
    cloud::{
        CloudClient, Resolution,
        engine::{self, Bind, Snapshot, SyncHost},
    },
    passkey::{self, Passkey},
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[path = "mobile_tools.rs"]
mod tools;

const LOCKED: &str = "Vault is locked";
/// Largest request accepted over the FFI boundary (encoded imports and backups).
const MAX_REQUEST_BYTES: usize = 180 * 1024 * 1024;
/// Largest encrypted vault handed back to the app as a snapshot.
const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;
/// Biometric material is a 32-byte key followed by the vault's authenticated
/// 38-byte format/KDF/salt prefix, so a re-keyed vault invalidates it.
const KEY_BYTES: usize = 32;
const HEADER_PREFIX_BYTES: usize = 38;

/// One vault per app process. The native bridge serializes all access, including
/// file replacement and sync. Adapters must also lock on background/screen lock.
pub struct MobileVault {
    directory: PathBuf,
    vault: Option<Vault>,
    credentials: VaultCredentials,
    touched: Instant,
    /// Identifies one unlock so sync reviews cannot cross sessions.
    session: Option<String>,
    /// True only when unlocked with the original password or key file, not biometrics.
    primary_unlock: bool,
    settings: tools::MobileSettings,
    import_review: Option<ImportReview>,
    cancellation: Option<&'static AtomicBool>,
}

/// An import preview the user must confirm against unchanged input and vault state.
struct ImportReview {
    token: String,
    revision: u64,
    digest: String,
    conflicts: ConflictPolicy,
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
        let settings = tools::MobileSettings::load(&directory)?;
        Ok(Self {
            directory,
            vault: None,
            credentials: VaultCredentials::Locked,
            touched: Instant::now(),
            session: None,
            primary_unlock: false,
            settings,
            import_review: None,
            cancellation: None,
        })
    }

    /// Android's lock signal is independent of the serialized JNI vault mutex.
    pub fn set_cancellation(&mut self, flag: &'static AtomicBool) {
        self.cancellation = Some(flag);
    }

    pub fn lock(&mut self) {
        self.vault = None;
        self.credentials.zeroize();
        self.session = None;
        self.import_review = None;
        self.primary_unlock = false;
    }

    /// Applies the idle timeout, then returns the open vault.
    fn open(&mut self) -> Result<&mut Vault, String> {
        if self.touched.elapsed() >= Duration::from_secs(self.settings.unlock_seconds) {
            self.lock();
        }
        self.touched = Instant::now();
        self.vault.as_mut().ok_or_else(|| LOCKED.into())
    }

    fn vault(&self) -> Result<&Vault, String> {
        self.vault.as_ref().ok_or_else(|| LOCKED.into())
    }

    /// Borrows the vault and its credentials together for mutations.
    fn unlocked(&mut self) -> Result<(&mut Vault, &mut VaultCredentials), String> {
        match &mut self.vault {
            Some(vault) => Ok((vault, &mut self.credentials)),
            None => Err(LOCKED.into()),
        }
    }

    fn path(&self, name: &str) -> Result<PathBuf, String> {
        validate_vault_filename(name).map_err(|e| e.to_string())?;
        Ok(self.directory.join(name))
    }

    fn read_vault_file(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        crate::file::read_bounded_file(&self.path(name)?, MAX_VAULT_BYTES)
            .map_err(|_| "Could not read vault".into())
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
        self.adopt(vault, key, primary);
        Ok(())
    }

    /// Replaces any open session with `vault`.
    fn adopt(&mut self, vault: Vault, key: VaultCredentials, primary: bool) {
        self.lock();
        self.vault = Some(vault);
        self.credentials = key;
        self.primary_unlock = primary;
        self.session = Some(hex::encode(rand::random::<[u8; 16]>()));
        self.touched = Instant::now();
    }

    /// Writes a new, empty vault and opens it as a primary unlock.
    fn create_with_key(&mut self, mut key: VaultCredentials) -> Result<Value, VaultError> {
        let mut vault = Vault::memory();
        let name = format!("{}.enc", hex::encode(vault.vault_id()));
        vault.store = VaultStore::File {
            directory: self.directory.clone(),
            filename: name.clone(),
        };
        vault.metadata.filename = name.clone();
        write_vault_with_key(&vault, &mut key)?;
        self.adopt(vault, key, true);
        Ok(json!({ "vault": name }))
    }

    fn passkeys(&self) -> Result<Vec<(usize, Passkey)>, String> {
        let mut result = Vec::new();
        for item in self.vault()?.active_items() {
            if let Some(field) = item.passkey_field() {
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
        let (vault, credentials) = self.unlocked()?;
        let added = vault
            .add_passkey_entry(entry, credentials)
            .map_err(|e| e.to_string())?;
        if !added {
            return Err("Passkey entry already exists; retry registration".into());
        }
        Ok(())
    }

    /// IDs of logins with a password that may be filled for `origin`.
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
        if input.len() > MAX_REQUEST_BYTES {
            return Err("Mobile request exceeds limit".into());
        }
        let mut request: Value =
            serde_json::from_str(input).map_err(|_| "Invalid mobile request")?;
        if request.get("op").and_then(Value::as_str) != Some("lock") && cancelled(self.cancellation)
        {
            wipe_json(&mut request);
            self.lock();
            return Err(LOCKED.into());
        }
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.dispatch(&request)));
        wipe_json(&mut request);
        if cancelled(self.cancellation) {
            if let Ok(Ok(mut value)) = result {
                wipe_json(&mut value);
            }
            self.lock();
            return Err(
                "Operation interrupted; vault locked. A remote change may have completed; inspect \
                 before retrying"
                    .into(),
            );
        }
        result.unwrap_or_else(|_| {
            self.lock();
            Err("Mobile operation failed; vault locked".into())
        })
    }

    fn dispatch(&mut self, r: &Value) -> Result<Value, String> {
        let op = string(r, "op")?;
        if let Some(result) = self.local_tool(op, r).map_err(|e| e.to_string())? {
            return Ok(result);
        }
        if let Some(result) = self.session_op(op, r)? {
            return Ok(result);
        }
        self.open()?;
        if let Some(result) = self.parity_tool(op, r).map_err(|e| e.to_string())? {
            return Ok(result);
        }
        self.vault_op(op, r)
    }

    /// Operations that work without an open vault.
    fn session_op(&mut self, op: &str, r: &Value) -> Result<Option<Value>, String> {
        Ok(Some(match op {
            "lock" => {
                if let Some(flag) = self.cancellation {
                    flag.store(false, Ordering::SeqCst);
                }
                self.lock();
                json!({})
            }
            "status" => json!({
                "unlocked": self.open().is_ok(),
                "unlock_seconds": self.settings.unlock_seconds,
                "clipboard_seconds": self.settings.clipboard_seconds,
            }),
            "vaults" => json!(self.vault_names()?),
            "unlock" => {
                self.lock();
                let name = string(r, "vault")?;
                let key = if let Some(encoded) = opt_str(r, "key_file") {
                    let data = Zeroizing::new(passkey::decode(encoded)?);
                    let encrypted = self.read_vault_file(name)?;
                    crate::encryption::credentials_from_keyfile_bytes(&encrypted, &data)?
                } else {
                    PasswordType::Password(string(r, "password")?.into()).into()
                };
                self.unlock(name, key, true)?;
                json!({})
            }
            "create" => {
                let password = string(r, "password")?;
                validate_new_password(password)?;
                let key = PasswordType::Password(password.into()).into();
                self.create_with_key(key).map_err(|e| e.to_string())?
            }
            "import_vault" => {
                let data = passkey::decode(string(r, "data")?)?;
                crate::encryption::validate_vault_header(&data)?;
                if data.len() as u64 > MAX_VAULT_BYTES {
                    return Err("Vault exceeds size limit".into());
                }
                let name = format!("{}.enc", hex::encode(rand::random::<[u8; 16]>()));
                crate::cloud::write_private(&self.path(&name)?, &data, false)?;
                json!({ "vault": name })
            }
            "biometric_unlock" => {
                self.lock();
                let name = string(r, "vault")?;
                let data = Zeroizing::new(passkey::decode(string(r, "material")?)?);
                let encrypted = self.read_vault_file(name)?;
                crate::encryption::validate_vault_header(&encrypted)?;
                if data.len() != KEY_BYTES + HEADER_PREFIX_BYTES
                    || data[KEY_BYTES..] != encrypted[..HEADER_PREFIX_BYTES]
                {
                    return Err("Biometric key is stale; use password or key file".into());
                }
                let key = crate::encryption::cached_credentials(
                    &encrypted,
                    data[..KEY_BYTES].try_into().map_err(|_| "Invalid key")?,
                )?;
                self.unlock(name, key, false)?;
                json!({})
            }
            "cloud_list" => {
                let client = client(r)?;
                json!(self.block_on(client.list())??)
            }
            "cloud_download" => {
                let id = string(r, "id")?.to_owned();
                let copy = flag(r, "copy");
                let name = self.run_sync(r, true, async |host| {
                    engine::download(host, &id, copy).await
                })?;
                json!({ "vault": name })
            }
            _ => return Ok(None),
        }))
    }

    /// Operations that require an open vault.
    fn vault_op(&mut self, op: &str, r: &Value) -> Result<Value, String> {
        match op {
            "list" => {
                let filter = SearchFilter {
                    query: opt_string(r, "query"),
                    ..Default::default()
                };
                Ok(json!(
                    self.vault()?
                        .management_list(filter)
                        .map_err(|e| e.to_string())?
                ))
            }
            "item" => {
                let detail = self
                    .vault()?
                    .management_item(id(r)?, true)
                    .map_err(|e| e.to_string())?;
                Ok(json!(detail))
            }
            "save" => self.save_login(r),
            "delete" => {
                let id = id(r)?;
                let (vault, credentials) = self.unlocked()?;
                vault
                    .delete_entry(Target::Id(id), credentials)
                    .map_err(|e| e.to_string())?;
                Ok(json!({}))
            }
            "generate" => Ok(json!({ "password": crate::password::generate_password(24) })),
            "otp" => {
                let (code, expires) = self
                    .vault()?
                    .current_totp(Target::Id(id(r)?))
                    .map_err(|e| e.to_string())?;
                Ok(json!({ "code": code, "expires_in": expires }))
            }
            "logins" => {
                let vault = self.vault()?;
                let logins: Vec<_> = self
                    .login_ids(string(r, "origin")?)
                    .into_iter()
                    .filter_map(|id| vault.item(id))
                    .map(|item| vault.summary(item))
                    .collect();
                Ok(json!(logins))
            }
            "hostname_logins" | "otp_logins" => {
                let otp_only = op == "otp_logins";
                let hostname_only = !otp_only || flag(r, "hostname_only");
                let choices: Vec<_> = self
                    .vault()?
                    .mobile_browser_choices(string(r, "origin")?, hostname_only, otp_only)
                    .into_iter()
                    .map(|(item, origin)| {
                        json!({
                            "id": item.id,
                            "name": item.name,
                            "username": item.username,
                            "origin": origin,
                            "has_totp": item.has_totp,
                        })
                    })
                    .collect();
                Ok(json!(choices))
            }
            "site_otp" => {
                let id = id(r)?;
                let origin = string(r, "origin")?;
                let vault = self.vault()?;
                let matches = if origin.starts_with("androidapp://") {
                    self.login_ids(origin).contains(&id)
                        && vault.item(id).is_some_and(|item| {
                            matches!(
                                item.authenticator.as_ref().map(|auth| &auth.state),
                                Some(AuthenticatorState::Totp(_))
                            )
                        })
                } else {
                    vault
                        .mobile_browser_choices(origin, false, true)
                        .iter()
                        .any(|(item, _)| item.id == id)
                };
                if !matches {
                    return Err("No matching authenticator".into());
                }
                let (code, expires) = vault
                    .current_totp(Target::Id(id))
                    .map_err(|e| e.to_string())?;
                Ok(json!({ "code": code, "expires_in": expires }))
            }
            "login" => {
                let id = id(r)?;
                if !self.login_ids(string(r, "origin")?).contains(&id) {
                    return Err("No matching login".into());
                }
                let item = self.vault()?.item(id).ok_or("No matching login")?;
                Ok(json!(BrowserLogin {
                    id,
                    revision: item.revision,
                    name: item.entry.name.clone(),
                    username: item.entry.username.clone(),
                    password: item.entry.password.clone(),
                    has_totp: item.authenticator.is_some(),
                }))
            }
            "snapshot" => {
                let path = self.vault()?.sync_path()?;
                let bytes = crate::file::read_bounded_file(&path, MAX_SNAPSHOT_BYTES).map_err(
                    |_| "Encrypted vault exceeds mobile transfer limit or could not be read",
                )?;
                Ok(json!({ "data": passkey::encode(bytes) }))
            }
            "biometric_material" => self.biometric_material(),
            "passkeys" => {
                let request = r.get("request");
                let passkeys: Vec<_> = self
                    .passkeys()?
                    .iter()
                    .filter(|(_, p)| request.is_none_or(|q| p.matches(q)))
                    .map(|(id, p)| {
                        json!({
                            "id": id,
                            "credential_id": p.credential_id,
                            "rp_id": p.rp_id,
                            "user_name": p.user_name,
                            "display_name": p.display_name,
                        })
                    })
                    .collect();
                Ok(json!(passkeys))
            }
            "passkey_create" => {
                let existing: Vec<_> = self.passkeys()?.into_iter().map(|(_, p)| p).collect();
                let hash = client_hash(r)?;
                let (p, response) = passkey::create(
                    &r["request"],
                    string(r, "origin")?,
                    hash.as_deref(),
                    &existing,
                )?;
                self.save_passkey(&p)?;
                Ok(response)
            }
            "passkey_get" => {
                let selected = id(r)?;
                let (_, p) = self
                    .passkeys()?
                    .into_iter()
                    .find(|(id, _)| *id == selected)
                    .ok_or("Passkey not found")?;
                p.authenticate(
                    &r["request"],
                    string(r, "origin")?,
                    client_hash(r)?.as_deref(),
                )
            }
            "sync" => {
                let message = self.run_sync(r, true, async |host| {
                    engine::sync(host, None, Bind::CreateIfMissing).await
                })?;
                Ok(json!({ "synced": true, "message": message }))
            }
            "sync_status" | "sync_check" | "sync_enabled" => self.sync_state(op, r),
            "cloud_conflicts" => {
                let review =
                    self.run_sync(r, true, async |host| engine::review(host, None).await)?;
                Ok(json!(review))
            }
            "cloud_resolve" => {
                let resolution = Resolution {
                    token: string(r, "review_token")?.to_owned(),
                    choices: serde_json::from_value(r["choices"].clone())
                        .map_err(|_| "Invalid conflict choices")?,
                };
                let resolved = self.run_sync(r, true, async |host| {
                    engine::resolve(host, None, resolution).await
                })?;
                Ok(json!({ "synced": resolved.synced, "message": resolved.message }))
            }
            _ => Err("Unsupported mobile operation".into()),
        }
    }

    fn vault_names(&self) -> Result<Vec<String>, String> {
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
        Ok(names)
    }

    /// Adds a login, or updates the password-bearing fields of an existing one.
    fn save_login(&mut self, r: &Value) -> Result<Value, String> {
        let name = string(r, "name")?;
        if name.trim().is_empty() {
            return Err("Name is required".into());
        }
        let username = opt_string(r, "username");
        let url = opt_string(r, "url");
        let password = string(r, "password")?;
        let notes = opt_str(r, "notes").map(SecretString::from);
        let history_limit = self.settings.history_limit;
        let (vault, credentials) = self.unlocked()?;
        if let Some(id) = r.get("id").and_then(Value::as_u64) {
            let update = EntryUpdate {
                target: Target::Id(id as usize),
                update: EntryChanges {
                    name: Some(name.into()),
                    username,
                    url,
                    notes,
                },
                password: Some(password.into()),
            };
            vault
                .update_entry_with_limit(update, credentials, history_limit)
                .map_err(|e| e.to_string())?;
        } else {
            let entry = TypedEntry {
                entry: crate::types::PasswordEntry {
                    name: name.into(),
                    username,
                    password: password.into(),
                    url,
                    notes,
                    copy: false,
                },
                kind: ItemKind::Login,
                additional_urls: vec![],
                custom_fields: vec![],
            };
            let added = vault
                .add_typed_entry(entry, credentials)
                .map_err(|e| e.to_string())?;
            if !added {
                return Err("An entry with this name and username already exists".into());
            }
        }
        Ok(json!({}))
    }

    fn biometric_material(&self) -> Result<Value, String> {
        if !self.primary_unlock {
            return Err(
                "Unlock with the original password or key file before enabling biometrics".into(),
            );
        }
        let vault = self.vault()?;
        let encrypted = crate::file::read_bounded_file(&vault.sync_path()?, MAX_VAULT_BYTES)
            .map_err(|_| "Could not read vault")?;
        let VaultCredentials::Session { encryption_key, .. } = &self.credentials else {
            return Err(LOCKED.into());
        };
        let mut material = Zeroizing::new(encryption_key.to_vec());
        material.extend_from_slice(&encrypted[..HEADER_PREFIX_BYTES]);
        Ok(json!({
            "material": passkey::encode(&*material),
            "vault": vault.metadata.filename,
        }))
    }

    /// Borrows this owner as the shared sync engine's host for one request.
    fn sync_host(&mut self, r: &Value, needs_client: bool) -> Result<MobileSync<'_>, String> {
        let client = if needs_client { Some(client(r)?) } else { None };
        let directory = self.directory.clone();
        Ok(MobileSync {
            owner: std::sync::Mutex::new(self),
            client,
            directory,
        })
    }

    /// Runs one engine operation; the app's lock signal aborts its network work.
    fn run_sync<T>(
        &mut self,
        r: &Value,
        needs_client: bool,
        operation: impl AsyncFnOnce(&MobileSync<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        let cancellation = self.cancellation;
        let host = self.sync_host(r, needs_client)?;
        block_on(cancellation, operation(&host))?
    }

    fn sync_state(&mut self, op: &str, r: &Value) -> Result<Value, String> {
        if op == "sync_enabled" {
            let enabled = r
                .get("enabled")
                .and_then(Value::as_bool)
                .ok_or("Sync state required")?;
            self.run_sync(r, true, async |host| {
                engine::set_enabled(host, None, enabled).await
            })?;
        }
        let check = op == "sync_check";
        let status = self.run_sync(r, check, async |host| engine::status(host, check).await)?;
        Ok(json!({
            "enabled": status.binding.as_ref().map_or(!status.recovery_copy, |b| b.enabled),
            "configured": status.binding.is_some(),
            "local_changed": status.local_changed,
            "remote": status.remote,
            "binding": status.binding,
        }))
    }

    fn block_on<T>(&self, future: impl std::future::Future<Output = T>) -> Result<T, String> {
        block_on(self.cancellation, future)
    }
}

/// Runs network work on the shared runtime; the app's lock signal aborts it.
fn block_on<T>(
    cancellation: Option<&AtomicBool>,
    future: impl std::future::Future<Output = T>,
) -> Result<T, String> {
    Ok(mobile_runtime()?.block_on(interruptible(cancellation, future))?)
}

/// Mobile host for the shared sync engine. The JNI mutex already serializes
/// access; this lock only lets the engine borrow the owner from async code.
struct MobileSync<'a> {
    owner: std::sync::Mutex<&'a mut MobileVault>,
    client: Option<CloudClient>,
    directory: PathBuf,
}

impl<'a> MobileSync<'a> {
    fn owner(&self) -> Result<std::sync::MutexGuard<'_, &'a mut MobileVault>, String> {
        self.owner
            .lock()
            .map_err(|_| "Mobile session failed".into())
    }
}

impl SyncHost for MobileSync<'_> {
    fn client(&self) -> impl std::future::Future<Output = Result<CloudClient, String>> + Send {
        let client = self
            .client
            .clone()
            .ok_or_else(|| "Missing server".to_owned());
        async move { client }
    }
    fn snapshot(&self) -> impl std::future::Future<Output = Result<Snapshot, String>> + Send {
        let snapshot = (|| {
            let owner = self.owner()?;
            let vault = owner.vault()?;
            let path = vault.sync_path()?;
            let bytes = crate::file::read_bounded_file(&path, crate::cloud::MAX_BYTES)
                .map_err(|_| "Could not read local snapshot")?;
            Ok(Snapshot {
                id: hex::encode(vault.vault_id()),
                session: owner.session.clone().ok_or(LOCKED)?,
                state: crate::cloud::binding(&path)?,
                bytes: bytes.to_vec(),
                path,
            })
        })();
        async move { snapshot }
    }
    fn with_unlocked<T: Send + 'static>(
        &self,
        session: String,
        apply: impl FnOnce(&mut Vault, &mut VaultCredentials) -> Result<T, String> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, String>> + Send {
        let result = (|| {
            let mut owner = self.owner()?;
            if owner.session.as_ref() != Some(&session) {
                return Err("Vault locked or switched during sync; nothing was applied".into());
            }
            let (vault, credentials) = owner.unlocked()?;
            apply(vault, credentials)
        })();
        async move { result }
    }
    fn directory(&self) -> PathBuf {
        self.directory.clone()
    }
}

fn mobile_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
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

fn client_hash(r: &Value) -> Result<Option<Vec<u8>>, String> {
    opt_str(r, "client_hash").map(passkey::decode).transpose()
}

fn string<'a>(r: &'a Value, key: &str) -> Result<&'a str, String> {
    opt_str(r, key).ok_or_else(|| format!("Missing {key}"))
}

fn opt_str<'a>(r: &'a Value, key: &str) -> Option<&'a str> {
    r.get(key).and_then(Value::as_str)
}

fn opt_string(r: &Value, key: &str) -> Option<String> {
    opt_str(r, key).map(str::to_owned)
}

/// A boolean option that defaults to `false`.
fn flag(r: &Value, key: &str) -> bool {
    bool_or(r, key, false)
}

fn bool_or(r: &Value, key: &str, default: bool) -> bool {
    r.get(key).and_then(Value::as_bool).unwrap_or(default)
}

/// Destructive operations require an explicit `"confirmed": true`.
fn confirmed(r: &Value) -> bool {
    r.get("confirmed") == Some(&Value::Bool(true))
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

fn cancelled(flag: Option<&AtomicBool>) -> bool {
    flag.is_some_and(|flag| flag.load(Ordering::SeqCst))
}

async fn interruptible<T>(
    flag: Option<&AtomicBool>,
    future: impl std::future::Future<Output = T>,
) -> Result<T, &'static str> {
    tokio::select! {
        result = future => Ok(result),
        _ = async {
            while !cancelled(flag) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        } => Err("Operation interrupted; inspect any remote change before retrying"),
    }
}

#[cfg(test)]
#[path = "mobile_sync_tests.rs"]
mod sync_tests;

#[cfg(test)]
mod tests {
    #[test]
    fn website_otp_supports_code_only_items_and_rejects_wrong_origins_and_hotp() {
        use super::*;
        let temp = tempfile::tempdir().unwrap();
        let mut api = MobileVault::new(temp.path().into()).unwrap();
        api.call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
            .unwrap();
        for (name, origin) in [
            ("Login", "https://accounts.example.com"),
            ("Code only", "https://accounts.example.com:8443"),
            ("HOTP", "https://accounts.example.com"),
        ] {
            api.call(&json!({"op":"save","name":name,"username":"synthetic-user","password":"","url":origin}).to_string()).unwrap();
        }
        let vault = api.vault.as_mut().unwrap();
        for id in [1, 2] {
            vault.set_test_totp(
                id,
                "otpauth://totp/Example?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            );
        }
        vault.set_test_totp(
            3,
            "otpauth://hotp/Example?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0",
        );
        let choices = api.call(r#"{"op":"otp_logins","origin":"https://accounts.example.com","hostname_only":true}"#).unwrap();
        assert_eq!(choices.as_array().unwrap().len(), 2);
        assert!(!choices.to_string().contains("GEZDGNBV"));
        assert_eq!(
            api.call(r#"{"op":"otp_logins","origin":"https://accounts.example.com"}"#)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(
            api.call(r#"{"op":"site_otp","origin":"https://accounts.example.com","id":2}"#)
                .is_err()
        );
        assert!(
            api.call(r#"{"op":"site_otp","origin":"https://evil.example.com","id":1}"#)
                .is_err()
        );
        assert!(
            api.call(r#"{"op":"site_otp","origin":"https://accounts.example.com","id":3}"#)
                .is_err()
        );
        let code = api
            .call(r#"{"op":"site_otp","origin":"https://accounts.example.com:8443","id":2}"#)
            .unwrap();
        assert_eq!(code["code"].as_str().unwrap().len(), 6);
        assert!((1..=30).contains(&code["expires_in"].as_u64().unwrap()));
        api.lock();
        assert!(
            api.call(r#"{"op":"site_otp","origin":"https://accounts.example.com","id":1}"#)
                .is_err()
        );
    }

    #[test]
    fn hostname_choices_require_unlock_and_do_not_relax_secret_origin_checks() {
        use super::*;
        let temp = tempfile::tempdir().unwrap();
        let mut api = MobileVault::new(temp.path().into()).unwrap();
        let request = r#"{"op":"hostname_logins","origin":"https://accounts.example.com"}"#;
        assert!(api.call(request).is_err());
        api.call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
            .unwrap();
        for (name, url) in [
            ("Default", "https://accounts.example.com/login"),
            ("Other port", "https://accounts.example.com:8443"),
            ("Other host", "https://example.com"),
            ("Lookalike", "https://accounts.example.com.evil.test"),
            ("HTTP", "http://accounts.example.com"),
            ("Wildcard", "https://*.example.com"),
            ("Deleted", "https://accounts.example.com"),
        ] {
            api.call(&json!({"op":"save","name":name,"username":"synthetic-user","password":"synthetic-secret","url":url}).to_string()).unwrap();
        }
        api.call(r#"{"op":"delete","id":7}"#).unwrap();
        let choices = api.call(request).unwrap();
        let entries = choices.as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["origin"], "https://accounts.example.com");
        assert_eq!(entries[1]["origin"], "https://accounts.example.com:8443");
        assert!(!choices.to_string().contains("synthetic-secret"));
        assert!(
            api.call(r#"{"op":"hostname_logins","origin":"http://accounts.example.com"}"#)
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty()
        );
        let exact = api
            .call(r#"{"op":"logins","origin":"https://accounts.example.com"}"#)
            .unwrap();
        assert!(
            exact
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["id"] == 1)
        );
        // Existing explicit wildcard rules remain supported by the exact-origin
        // path, but the alternate port must not be authorized there.
        assert!(
            exact
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["id"] != 2)
        );
        assert!(
            api.call(r#"{"op":"login","origin":"https://accounts.example.com","id":2}"#)
                .is_err()
        );
        assert!(
            api.call(r#"{"op":"login","origin":"https://accounts.example.com:8443","id":2}"#)
                .is_ok()
        );
        api.lock();
        assert!(api.call(request).is_err());
    }

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
        // Biometric sessions cannot re-export the key or replace/delete the vault.
        for request in [
            json!({"op":"biometric_material"}),
            json!({"op":"rekey","password":"Replacement-Lantern-Quartz-9274!"}),
            json!({"op":"delete_vault","confirmed":true}),
        ] {
            assert!(api.call(&request.to_string()).is_err(), "{request}");
        }
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
