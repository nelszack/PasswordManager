//! Android/iOS bridge over the shared vault. Vault management uses the same
//! typed `ServerCommand`s as the desktop service; only work that is genuinely
//! mobile (byte-based files, biometrics, passkeys, platform autofill, and
//! local settings) has its own request types.
use super::*;
use crate::{
    cloud::{
        Choice, CloudClient, Resolution,
        engine::{self, Bind, Snapshot, SyncHost},
    },
    operations::{self, Deferred, SessionAccess},
    passkey::{self, Passkey},
    protocol::{ResponseCode, ResponsePayload, RpcResponse},
    secret::SecretString,
    types::{ServerCommand, TotpCommand},
};
use serde::Deserialize;
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

/// One request from the app. The JSON envelope is process-local; never log it.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    // Available while locked.
    Lock,
    Status,
    Vaults,
    Unlock {
        vault: String,
        password: Option<SecretString>,
        key_file: Option<SecretString>,
    },
    BiometricUnlock {
        vault: String,
        material: SecretString,
    },
    Create {
        password: SecretString,
    },
    CreateKey {
        key_file: SecretString,
    },
    NewKeyFile,
    ImportVault {
        data: String,
    },
    RestoreBackup {
        data: SecretString,
        password: Option<SecretString>,
        key_file: Option<SecretString>,
    },
    SettingsGet,
    SettingsSave {
        settings: tools::MobileSettings,
    },
    Generate(tools::GeneratorOptions),
    Passcheck {
        password: SecretString,
    },
    CloudList {
        server: String,
        token: SecretString,
    },
    CloudDownload {
        server: String,
        token: SecretString,
        id: String,
        #[serde(default)]
        copy: bool,
    },
    // Require an unlocked vault.
    Vault {
        command: Box<ServerCommand>,
        expected_revision: Option<u64>,
        /// The user confirmed an irreversible command (see `confirmation`).
        #[serde(default)]
        confirmed: bool,
    },
    Logins {
        origin: String,
    },
    HostnameLogins {
        origin: String,
    },
    OtpLogins {
        origin: String,
        #[serde(default)]
        hostname_only: bool,
    },
    Login {
        id: usize,
        origin: String,
    },
    SiteOtp {
        id: usize,
        origin: String,
    },
    Snapshot,
    BiometricMaterial,
    Passkeys {
        request: Option<Value>,
    },
    PasskeyCreate {
        request: Value,
        origin: String,
        client_hash: Option<String>,
    },
    PasskeyGet {
        id: usize,
        request: Value,
        origin: String,
        client_hash: Option<String>,
    },
    Sync {
        server: String,
        token: SecretString,
    },
    SyncStatus,
    SyncCheck {
        server: String,
        token: SecretString,
    },
    SyncEnabled {
        server: String,
        token: SecretString,
        enabled: bool,
    },
    CloudConflicts {
        server: String,
        token: SecretString,
    },
    CloudResolve {
        server: String,
        token: SecretString,
        review_token: String,
        choices: Vec<Choice>,
    },
    ExportItems {
        format: Option<String>,
        #[serde(default)]
        confirmed: bool,
    },
    ImportItems {
        data: SecretString,
        conflicts: Option<ConflictPolicy>,
        preview: Option<bool>,
        review_token: Option<String>,
    },
    BackupCreate {
        password: Option<SecretString>,
        key_file: Option<SecretString>,
    },
    Rekey {
        password: Option<SecretString>,
        key_file: Option<SecretString>,
    },
    DeleteVault {
        #[serde(default)]
        confirmed: bool,
    },
    PurgeExpired,
}

impl Request {
    fn needs_unlock(&self) -> bool {
        !matches!(
            self,
            Self::Lock
                | Self::Status
                | Self::Vaults
                | Self::Unlock { .. }
                | Self::BiometricUnlock { .. }
                | Self::Create { .. }
                | Self::CreateKey { .. }
                | Self::NewKeyFile
                | Self::ImportVault { .. }
                | Self::RestoreBackup { .. }
                | Self::SettingsGet
                | Self::SettingsSave { .. }
                | Self::Generate(_)
                | Self::Passcheck { .. }
                | Self::CloudList { .. }
                | Self::CloudDownload { .. }
        )
    }
}

/// One vault per app process. The native bridge serializes all access, including
/// file replacement and sync. Adapters must also lock on background/screen lock.
pub struct MobileVault {
    directory: PathBuf,
    vault: Option<Vault>,
    credentials: VaultCredentials,
    touched: Instant,
    /// Identifies one unlock so reviews and late network replies cannot cross sessions.
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

    /// JSON is only a process-local FFI envelope. Never log requests or results.
    pub fn call(&mut self, input: &str) -> Result<Value, String> {
        if input.len() > MAX_REQUEST_BYTES {
            return Err("Mobile request exceeds limit".into());
        }
        let mut envelope: Value =
            serde_json::from_str(input).map_err(|_| "Invalid mobile request")?;
        let op = envelope
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        // Deserialization errors can echo rejected values; report only the operation.
        let request = Request::deserialize(&envelope)
            .map_err(|_| format!("Invalid or unsupported mobile request: {op}"));
        wipe_json(&mut envelope);
        let request = request?;
        if !matches!(request, Request::Lock) && cancelled(self.cancellation) {
            self.lock();
            return Err(LOCKED.into());
        }
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.dispatch(request)));
        if cancelled(self.cancellation) {
            if let Ok(Ok(mut value)) = result {
                wipe_json(&mut value);
            }
            self.lock();
            return Err(
                "Operation interrupted; vault locked. A remote change may have \
                        completed; inspect before retrying"
                    .into(),
            );
        }
        result.unwrap_or_else(|_| {
            self.lock();
            Err("Mobile operation failed; vault locked".into())
        })
    }

    fn dispatch(&mut self, request: Request) -> Result<Value, String> {
        if request.needs_unlock() {
            self.open()?;
        }
        match request {
            Request::Lock => {
                if let Some(flag) = self.cancellation {
                    flag.store(false, Ordering::SeqCst);
                }
                self.lock();
                Ok(json!({}))
            }
            Request::Status => Ok(json!({
                "unlocked": self.open().is_ok(),
                "unlock_seconds": self.settings.unlock_seconds,
                "clipboard_seconds": self.settings.clipboard_seconds,
            })),
            Request::Vaults => Ok(json!(self.vault_names()?)),
            Request::Unlock {
                vault,
                password,
                key_file,
            } => {
                self.lock();
                let key = match key_file {
                    Some(encoded) => {
                        let data = Zeroizing::new(passkey::decode(&encoded)?);
                        let encrypted = self.read_vault_file(&vault)?;
                        crate::encryption::credentials_from_keyfile_bytes(&encrypted, &data)?
                    }
                    None => {
                        PasswordType::Password(password.ok_or("Missing password")?.expose_owned())
                            .into()
                    }
                };
                self.unlock(&vault, key, true)?;
                Ok(json!({}))
            }
            Request::BiometricUnlock { vault, material } => {
                self.biometric_unlock(&vault, &material)?;
                Ok(json!({}))
            }
            Request::Create { password } => {
                validate_new_password(&password)?;
                let key = PasswordType::Password(password.expose_owned()).into();
                self.create_with_key(key).map_err(|e| e.to_string())
            }
            Request::CreateKey { key_file } => {
                let key = tools::new_credentials(None, Some(key_file))?;
                self.create_with_key(key).map_err(|e| e.to_string())
            }
            Request::NewKeyFile => Ok(tools::new_key_file()),
            Request::ImportVault { data } => {
                let data = passkey::decode(&data)?;
                crate::encryption::validate_vault_header(&data)?;
                if data.len() as u64 > MAX_VAULT_BYTES {
                    return Err("Vault exceeds size limit".into());
                }
                let name = format!("{}.enc", hex::encode(rand::random::<[u8; 16]>()));
                crate::cloud::write_private(&self.path(&name)?, &data, false)?;
                Ok(json!({ "vault": name }))
            }
            Request::RestoreBackup {
                data,
                password,
                key_file,
            } => self.restore_backup(&data, password, key_file),
            Request::SettingsGet => Ok(json!(self.settings)),
            Request::SettingsSave { settings } => {
                settings.save(&self.directory)?;
                self.settings = settings;
                Ok(json!(self.settings))
            }
            Request::Generate(options) => options.generate(&self.settings),
            Request::Passcheck { password } => Ok(json!({
                "assessment": crate::password::password_strength_output(&password),
            })),
            Request::CloudList { server, token } => {
                let client = client(&server, token)?;
                Ok(json!(block_on(self.cancellation, client.list())??))
            }
            Request::CloudDownload {
                server,
                token,
                id,
                copy,
            } => {
                let download = self.run_sync(Some(client(&server, token)?), async |host| {
                    engine::download(host, &id, copy).await
                })?;
                let name = download.install(&self.directory)?;
                Ok(json!({ "vault": name }))
            }
            Request::Vault {
                command,
                expected_revision,
                confirmed,
            } => self.run_command(*command, expected_revision, confirmed),
            Request::Logins { origin } => {
                let vault = self.vault()?;
                let logins: Vec<_> = self
                    .login_ids(&origin)
                    .into_iter()
                    .filter_map(|id| vault.item(id))
                    .map(|item| vault.summary(item))
                    .collect();
                Ok(json!(logins))
            }
            Request::HostnameLogins { origin } => self.browser_choices(&origin, true, false),
            Request::OtpLogins {
                origin,
                hostname_only,
            } => self.browser_choices(&origin, hostname_only, true),
            Request::Login { id, origin } => self.login(id, &origin),
            Request::SiteOtp { id, origin } => self.site_otp(id, &origin),
            Request::Snapshot => {
                let path = self.vault()?.sync_path()?;
                let bytes = crate::file::read_bounded_file(&path, MAX_SNAPSHOT_BYTES).map_err(
                    |_| "Encrypted vault exceeds mobile transfer limit or could not be read",
                )?;
                Ok(json!({ "data": passkey::encode(bytes) }))
            }
            Request::BiometricMaterial => self.biometric_material(),
            Request::Passkeys { request } => {
                let passkeys: Vec<_> = self
                    .passkeys()?
                    .iter()
                    .filter(|(_, p)| request.as_ref().is_none_or(|q| p.matches(q)))
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
            Request::PasskeyCreate {
                request,
                origin,
                client_hash,
            } => {
                let existing: Vec<_> = self.passkeys()?.into_iter().map(|(_, p)| p).collect();
                let hash = client_hash.as_deref().map(passkey::decode).transpose()?;
                let (p, response) = passkey::create(&request, &origin, hash.as_deref(), &existing)?;
                self.save_passkey(&p)?;
                Ok(response)
            }
            Request::PasskeyGet {
                id,
                request,
                origin,
                client_hash,
            } => {
                let (_, p) = self
                    .passkeys()?
                    .into_iter()
                    .find(|(passkey_id, _)| *passkey_id == id)
                    .ok_or("Passkey not found")?;
                let hash = client_hash.as_deref().map(passkey::decode).transpose()?;
                p.authenticate(&request, &origin, hash.as_deref())
            }
            Request::Sync { server, token } => {
                let message = self.run_sync(Some(client(&server, token)?), async |host| {
                    engine::sync(host, None, Bind::CreateIfMissing).await
                })?;
                Ok(json!({ "synced": true, "message": message }))
            }
            Request::SyncStatus => self.sync_status(None, false),
            Request::SyncCheck { server, token } => {
                self.sync_status(Some(client(&server, token)?), true)
            }
            Request::SyncEnabled {
                server,
                token,
                enabled,
            } => {
                let client = client(&server, token)?;
                self.run_sync(Some(client.clone()), async |host| {
                    engine::set_enabled(host, None, enabled, Bind::Enable).await
                })?;
                self.sync_status(Some(client), false)
            }
            Request::CloudConflicts { server, token } => {
                let review = self.run_sync(Some(client(&server, token)?), async |host| {
                    engine::review(host, None).await
                })?;
                Ok(json!(review))
            }
            Request::CloudResolve {
                server,
                token,
                review_token,
                choices,
            } => {
                let resolution = Resolution {
                    token: review_token,
                    choices,
                };
                let resolved = self.run_sync(Some(client(&server, token)?), async |host| {
                    engine::resolve(host, None, resolution).await
                })?;
                Ok(json!({ "synced": resolved.synced, "message": resolved.message }))
            }
            Request::ExportItems { format, confirmed } => {
                self.export_items(format.as_deref() != Some("csv"), confirmed)
            }
            Request::ImportItems {
                data,
                conflicts,
                preview,
                review_token,
            } => self.import_items(
                &data,
                conflicts.unwrap_or(ConflictPolicy::Skip),
                preview.unwrap_or(true),
                review_token,
            ),
            Request::BackupCreate { password, key_file } => {
                self.backup_create(tools::new_credentials(password, key_file)?)
            }
            Request::Rekey { password, key_file } => {
                self.rekey(tools::new_credentials(password, key_file)?)
            }
            Request::DeleteVault { confirmed } => self.delete_vault(confirmed),
            Request::PurgeExpired => {
                let days = self.settings.trash_days;
                let (vault, credentials) = self.unlocked()?;
                let removed = vault
                    .purge_expired_trash(days, credentials)
                    .map_err(|e| e.to_string())?;
                Ok(json!({ "removed": removed }))
            }
        }
    }

    /// Runs a shared vault command exactly as the desktop service would,
    /// including deferred network work, then returns its payload.
    fn run_command(
        &mut self,
        mut command: ServerCommand,
        expected_revision: Option<u64>,
        confirmed: bool,
    ) -> Result<Value, String> {
        if let Err(error) = mobile_command(&command) {
            command.zeroize();
            return Err(error.into());
        }
        let history_limit = self.settings.history_limit;
        let cancellation = self.cancellation;
        let (vault, credentials) = self.unlocked()?;
        if let Some(required) = confirmation(vault, &command)
            && !confirmed
        {
            command.zeroize();
            return Err(required.into());
        }
        // Saving an item without changes succeeds, as the app has always shown.
        let existing_update = matches!(&command, ServerCommand::Update(u) if vault.entry_id(&u.entry.target).is_some());
        if let Some(expected) = expected_revision
            && !operations::expected_revision_matches(Some(vault), &command, expected)
        {
            command.zeroize();
            return Err("Item changed since it was opened; reopen it before continuing".into());
        }
        let mut responses = Vec::new();
        let deferred = operations::execute_unlocked(
            &mut responses,
            command,
            vault,
            credentials,
            history_limit,
        );
        match deferred {
            Deferred::None => {}
            Deferred::Audit(pending, check_breaches) => match pending
                .finish(|| cancelled(cancellation))
            {
                Ok(snapshot) => {
                    let audit = block_on(cancellation, snapshot.audit(check_breaches))?;
                    let code = if audit.incomplete {
                        ResponseCode::Failure
                    } else {
                        ResponseCode::Success
                    };
                    responses.push(RpcResponse::new(code, ResponsePayload::Audit(audit.report)));
                }
                Err(_) => operations::respond_conflict(
                    "Vault changed or audit evaluation failed; run it again",
                    &mut responses,
                ),
            },
            Deferred::Duo(prepared) => {
                let host = self.host(None);
                block_on(
                    cancellation,
                    operations::finish_duo(*prepared, &host, &mut responses),
                )?;
            }
            Deferred::DuoEnrollment(prepared) => {
                let host = self.host(None);
                block_on(
                    cancellation,
                    operations::finish_duo_enrollment(*prepared, &host, &mut responses),
                )?;
            }
        }
        response_value(responses, existing_update)
    }

    fn vault_names(&self) -> Result<Vec<String>, String> {
        let names =
            crate::file::list_vault_files(&self.directory).map_err(|_| "Could not list vaults")?;
        Ok(names
            .into_iter()
            .filter(|name| validate_vault_filename(name).is_ok())
            .collect())
    }

    fn biometric_unlock(&mut self, name: &str, material: &str) -> Result<(), String> {
        self.lock();
        let data = Zeroizing::new(passkey::decode(material)?);
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
        self.unlock(name, key, false)
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

    fn browser_choices(
        &self,
        origin: &str,
        hostname_only: bool,
        otp_only: bool,
    ) -> Result<Value, String> {
        let choices: Vec<_> = self
            .vault()?
            .mobile_browser_choices(origin, hostname_only, otp_only)
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

    fn login(&self, id: usize, origin: &str) -> Result<Value, String> {
        if !self.login_ids(origin).contains(&id) {
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

    /// A time-based code for a login the platform has matched to `origin`.
    /// Counter-based codes are never consumed by autofill.
    fn site_otp(&self, id: usize, origin: &str) -> Result<Value, String> {
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

    /// Lends this owner to the shared sync engine and Duo completion for one request.
    fn host(&mut self, client: Option<CloudClient>) -> MobileHost<'_> {
        MobileHost {
            session: self.session.clone(),
            directory: self.directory.clone(),
            client,
            owner: std::sync::Mutex::new(self),
        }
    }

    /// Runs one sync-engine operation; the app's lock signal aborts its network work.
    fn run_sync<T>(
        &mut self,
        client: Option<CloudClient>,
        operation: impl AsyncFnOnce(&MobileHost<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        let cancellation = self.cancellation;
        let host = self.host(client);
        block_on(cancellation, operation(&host))?
    }

    fn sync_status(&mut self, client: Option<CloudClient>, check: bool) -> Result<Value, String> {
        let status = self.run_sync(client, async |host| engine::status(host, check).await)?;
        Ok(json!({
            "enabled": status.binding.as_ref().map_or(!status.recovery_copy, |b| b.enabled),
            "configured": status.binding.is_some(),
            "local_changed": status.local_changed,
            "remote": status.remote,
            "binding": status.binding,
        }))
    }
}

/// Vault commands the app may send. Session lifecycle and file paths belong to
/// the mobile requests above; clipboard copies belong to the app.
fn mobile_command(command: &ServerCommand) -> Result<(), &'static str> {
    use ServerCommand as C;
    let allowed = match command {
        C::List(_)
        | C::ManagementItem { .. }
        | C::Update(_)
        | C::History(_)
        | C::RestorePassword { .. }
        | C::Trash
        | C::RestoreTrash(_)
        | C::PurgeTrash(_)
        | C::Audit(_)
        | C::AuthenticatorData(_)
        | C::Duo(_)
        | C::Totp(TotpCommand::Set { .. } | TotpCommand::Remove { .. } | TotpCommand::Duo { .. }) => {
            true
        }
        C::Add {
            entry,
            copy_timeout,
        } => !entry.entry.copy && *copy_timeout == 0,
        C::Delete(target) => !matches!(target, Target::Vault { .. }),
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err("Unsupported mobile vault command")
    }
}

/// Irreversible commands the app must confirm with the user first, and why.
fn confirmation(vault: &Vault, command: &ServerCommand) -> Option<&'static str> {
    match command {
        ServerCommand::PurgeTrash(_) => Some("Confirm permanent deletion"),
        ServerCommand::AuthenticatorData(target)
            if vault
                .target_item(target)
                .and_then(|item| item.authenticator.as_ref())
                .is_some_and(|a| matches!(a.state, AuthenticatorState::Hotp { .. })) =>
        {
            Some("Confirm generation; HOTP advances its counter")
        }
        _ => None,
    }
}

/// Converts the shared command responses into the app's reply. Failures are
/// plain messages; an incomplete audit still returns its partial report. With
/// `existing_update`, "not found or unchanged" means the item was unchanged.
fn response_value(responses: Vec<RpcResponse>, existing_update: bool) -> Result<Value, String> {
    let response = responses
        .into_iter()
        .next()
        .ok_or("Vault command produced no response")?;
    if existing_update && response.code == ResponseCode::NotFound as i32 {
        return Ok(json!({ "changed": false }));
    }
    match response.payload {
        ResponsePayload::Message(message) if response.code != ResponseCode::Success as i32 => {
            Err(message)
        }
        payload => Ok(payload.into_json()),
    }
}

/// Mobile host for the shared sync engine and Duo completion. The JNI mutex
/// already serializes access; this lock only lets async code borrow the owner.
struct MobileHost<'a> {
    owner: std::sync::Mutex<&'a mut MobileVault>,
    /// The unlock session this request started in.
    session: Option<String>,
    client: Option<CloudClient>,
    directory: PathBuf,
}

impl<'a> MobileHost<'a> {
    fn owner(&self) -> Result<std::sync::MutexGuard<'_, &'a mut MobileVault>, String> {
        self.owner
            .lock()
            .map_err(|_| "Mobile session failed".into())
    }

    /// Runs `apply` only if `session` is still the open unlock.
    fn with_session<T>(
        &self,
        session: Option<&String>,
        apply: impl FnOnce(&mut Vault, &mut VaultCredentials) -> T,
    ) -> Result<T, String> {
        let mut owner = self.owner()?;
        if session.is_none() || owner.session.as_ref() != session {
            return Err("Vault locked or switched; nothing was applied".into());
        }
        let (vault, credentials) = owner.unlocked()?;
        Ok(apply(vault, credentials))
    }
}

impl SyncHost for MobileHost<'_> {
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
        let result = self.with_session(Some(&session), apply).and_then(|r| r);
        async move { result }
    }
    fn directory(&self) -> PathBuf {
        self.directory.clone()
    }
}

impl SessionAccess for MobileHost<'_> {
    fn with_unlocked<T: Send + 'static>(
        &self,
        apply: impl FnOnce(&mut Vault, &mut VaultCredentials) -> Result<T, VaultError> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<Result<T, VaultError>, String>> + Send {
        let result = self.with_session(self.session.as_ref(), apply);
        async move { result }
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

/// Runs network work on the shared runtime; the app's lock signal aborts it.
fn block_on<T>(
    cancellation: Option<&AtomicBool>,
    future: impl std::future::Future<Output = T>,
) -> Result<T, String> {
    Ok(mobile_runtime()?.block_on(interruptible(cancellation, future))?)
}

fn client(server: &str, token: SecretString) -> Result<CloudClient, String> {
    CloudClient::with_token(server, Zeroizing::new(token.expose_owned()))
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
pub(super) mod test_support {
    //! Builds the app's requests from typed commands, as the Kotlin layer does.
    use super::*;

    pub fn vault_command(api: &mut MobileVault, command: ServerCommand) -> Result<Value, String> {
        api.call(&json!({ "op": "vault", "command": command }).to_string())
    }

    /// A command the user confirmed in the app (see `confirmation`).
    pub fn confirmed_command(
        api: &mut MobileVault,
        command: ServerCommand,
    ) -> Result<Value, String> {
        api.call(&json!({ "op": "vault", "command": command, "confirmed": true }).to_string())
    }

    pub fn vault_command_at(
        api: &mut MobileVault,
        command: ServerCommand,
        revision: u64,
    ) -> Result<Value, String> {
        api.call(
            &json!({ "op": "vault", "command": command, "expected_revision": revision })
                .to_string(),
        )
    }

    pub fn save(
        api: &mut MobileVault,
        name: &str,
        username: &str,
        password: &str,
        url: &str,
    ) -> Result<Value, String> {
        let entry = TypedEntry {
            entry: crate::types::PasswordEntry {
                name: name.into(),
                username: Some(username.into()),
                password: password.into(),
                url: Some(url.into()),
                notes: None,
                copy: false,
            },
            kind: ItemKind::Login,
            additional_urls: vec![],
            custom_fields: vec![],
        };
        vault_command(
            api,
            ServerCommand::Add {
                entry,
                copy_timeout: 0,
            },
        )
    }

    pub fn update(
        api: &mut MobileVault,
        id: usize,
        name: &str,
        password: &str,
    ) -> Result<Value, String> {
        vault_command(api, ServerCommand::Update(change(id, name, password)))
    }

    pub fn change(id: usize, name: &str, password: &str) -> TypedUpdate {
        TypedUpdate::from(EntryUpdate {
            target: Target::Id(id),
            update: EntryChanges {
                name: Some(name.into()),
                ..Default::default()
            },
            password: Some(password.into()),
        })
    }

    pub fn list(api: &mut MobileVault) -> Result<Value, String> {
        vault_command(api, ServerCommand::List(SearchFilter::default()))
    }

    pub fn item(api: &mut MobileVault, id: usize) -> Result<Value, String> {
        vault_command(api, ServerCommand::ManagementItem { id, reveal: true })
    }

    pub fn delete(api: &mut MobileVault, id: usize) -> Result<Value, String> {
        vault_command(api, ServerCommand::Delete(Target::Id(id)))
    }
}

#[cfg(test)]
#[path = "mobile_sync_tests.rs"]
mod sync_tests;

#[cfg(test)]
mod tests {
    use super::test_support::*;

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
            save(&mut api, name, "synthetic-user", "", origin).unwrap();
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
            save(&mut api, name, "synthetic-user", "synthetic-secret", url).unwrap();
        }
        delete(&mut api, 7).unwrap();
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
        assert!(list(&mut mobile).is_err());
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
        let record = document.items.values().next().unwrap();
        let stored: Passkey =
            serde_json::from_str(&record.metadata.custom_fields[0].value).unwrap();
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
            item(&mut api, 1).unwrap()["fields"]
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
            record.metadata.custom_fields[0].value
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
            record.metadata.custom_fields[0].value
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
        save(
            &mut api,
            "Example",
            "alice",
            "synthetic-secret",
            "https://example.com",
        )
        .unwrap();
        let material = api.call(r#"{"op":"biometric_material"}"#).unwrap();
        api.lock();
        assert!(list(&mut api).is_err());
        api.call(&json!({"op":"biometric_unlock","vault":created["vault"],"material":material["material"]}).to_string()).unwrap();
        assert_eq!(list(&mut api).unwrap()["total"], 1);
        // Biometric sessions cannot re-export the key or replace/delete the vault.
        for request in [
            json!({"op":"biometric_material"}),
            json!({"op":"rekey","password":"Replacement-Lantern-Quartz-9274!"}),
            json!({"op":"delete_vault","confirmed":true}),
        ] {
            assert!(api.call(&request.to_string()).is_err(), "{request}");
        }
        assert_eq!(list(&mut api).unwrap()["total"], 1);
        api.lock();
        let mut bad = passkey::decode(material["material"].as_str().unwrap()).unwrap();
        bad[0] ^= 1;
        assert!(api.call(&json!({"op":"biometric_unlock","vault":created["vault"],"material":passkey::encode(bad)}).to_string()).is_err());
        assert!(list(&mut api).is_err());
        api.call(&json!({"op":"unlock","vault":created["vault"],"password":"Cedar-Lantern-Quartz-9274!"}).to_string()).unwrap();
        assert_eq!(
            api.call(r#"{"op":"login","origin":"https://evil.com","id":1}"#)
                .unwrap_err(),
            "No matching login"
        );
        api.touched = Instant::now() - Duration::from_secs(301);
        assert!(list(&mut api).is_err());
    }
}
