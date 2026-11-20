//! Mobile-only workflows: local settings, the generator, and byte-based file
//! transfers (the app owns document pickers; Rust never sees their paths).
use super::*;

const SETTINGS_FILE: &str = "mobile-settings.json";
/// Largest plaintext export, import, or backup exchanged with the app.
const MAX_TRANSFER_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_SYMBOLS: &str = "!@#$%^&*-_=+";
/// Encrypted backups start with a 9-byte container header.
const BACKUP_HEADER_BYTES: usize = 9;
/// Recovery copies saved by a credential change; the sync engine treats this
/// prefix as a copy that never syncs implicitly.
const REKEY_RECOVERY_PREFIX: &str = "rekey-recovery-";

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct MobileSettings {
    pub unlock_seconds: u64,
    pub clipboard_seconds: u64,
    pub history_limit: usize,
    pub trash_days: u64,
    pub generator_length: u8,
    pub passphrase_words: u8,
}

impl Default for MobileSettings {
    fn default() -> Self {
        Self {
            unlock_seconds: 300,
            clipboard_seconds: 30,
            history_limit: 10,
            trash_days: 0,
            generator_length: 24,
            passphrase_words: 6,
        }
    }
}

impl MobileSettings {
    pub fn load(directory: &Path) -> Result<Self, String> {
        let path = directory.join(SETTINGS_FILE);
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = crate::file::read_bounded_file(&path, 4096)
            .map_err(|_| "Could not read mobile settings")?;
        let settings: Self =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid mobile settings")?;
        settings.validate()?;
        Ok(settings)
    }

    pub fn save(&self, directory: &Path) -> Result<(), String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| "Could not encode settings")?;
        crate::cloud::write_private(&directory.join(SETTINGS_FILE), &bytes, true)
    }

    fn validate(&self) -> Result<(), String> {
        if !(15..=86400).contains(&self.unlock_seconds)
            || !(1..=300).contains(&self.clipboard_seconds)
            || self.history_limit > 1000
            || self.trash_days > 36500
            || self.generator_length == 0
            || !(1..=64).contains(&self.passphrase_words)
        {
            return Err("Settings outside supported limits".into());
        }
        Ok(())
    }
}

/// Generator options; anything omitted uses the saved mobile defaults.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct GeneratorOptions {
    passphrase: bool,
    words: Option<u64>,
    separator: Option<String>,
    length: Option<u64>,
    uppercase: bool,
    lowercase: bool,
    digits: bool,
    symbols_enabled: bool,
    symbols: Option<String>,
    exclude_ambiguous: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            passphrase: false,
            words: None,
            separator: None,
            length: None,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols_enabled: true,
            symbols: None,
            exclude_ambiguous: false,
        }
    }
}

impl GeneratorOptions {
    pub fn generate(&self, defaults: &MobileSettings) -> Result<Value, String> {
        let value = SecretString::from(self.value(defaults)?);
        Ok(json!({
            "password": value,
            "assessment": crate::password::password_strength_output(&value),
        }))
    }

    fn value(&self, defaults: &MobileSettings) -> Result<String, String> {
        if self.passphrase {
            let words = self.words.unwrap_or(defaults.passphrase_words.into());
            if !(1..=64).contains(&words) {
                return Err("Use 1 to 64 words".into());
            }
            let separator = self.separator.as_deref().unwrap_or("-");
            if separator.len() > 32 {
                return Err("Separator too long".into());
            }
            return crate::password::generate_passphrase(words as u8, separator);
        }
        let length = self.length.unwrap_or(defaults.generator_length.into());
        if !(1..=255).contains(&length) {
            return Err("Use a length from 1 to 255".into());
        }
        let options = crate::password::PasswordOptions {
            uppercase: self.uppercase,
            lowercase: self.lowercase,
            digits: self.digits,
            symbols: self
                .symbols_enabled
                .then(|| self.symbols.as_deref().unwrap_or(DEFAULT_SYMBOLS)),
            exclude_ambiguous: self.exclude_ambiguous,
        };
        crate::password::generate_password_with_options(length as u8, &options)
    }
}

pub(super) fn new_key_file() -> Value {
    let key = Zeroizing::new(rand::random::<[u8; 32]>());
    json!({ "data": passkey::encode(&key[..]) })
}

/// Credentials for a new vault, backup, or rekey: a fresh key file or a
/// password that meets the new-password policy.
pub(super) fn new_credentials(
    password: Option<SecretString>,
    key_file: Option<SecretString>,
) -> Result<VaultCredentials, String> {
    if let Some(encoded) = key_file {
        let bytes = Zeroizing::new(passkey::decode(&encoded)?);
        return crate::encryption::new_keyfile_credentials(&bytes);
    }
    let password = password.ok_or("Missing password")?;
    validate_new_password(&password)?;
    Ok(PasswordType::Password(password.expose_owned()).into())
}

/// Credentials that open existing encrypted bytes.
fn existing_credentials(
    password: Option<SecretString>,
    key_file: Option<SecretString>,
    encrypted: &[u8],
) -> Result<VaultCredentials, String> {
    if let Some(encoded) = key_file {
        let bytes = Zeroizing::new(passkey::decode(&encoded)?);
        return crate::encryption::credentials_from_keyfile_bytes(encrypted, &bytes);
    }
    let password = password.ok_or("Missing password")?;
    Ok(PasswordType::Password(password.expose_owned()).into())
}

fn transfer(bytes: &[u8], what: &str) -> Result<Value, String> {
    if bytes.len() > MAX_TRANSFER_BYTES {
        return Err(format!("{what} exceeds the 16 MiB mobile transfer limit"));
    }
    Ok(json!({ "data": passkey::encode(bytes) }))
}

impl MobileState {
    pub(super) fn restore_backup(
        &mut self,
        data: &str,
        password: Option<SecretString>,
        key_file: Option<SecretString>,
    ) -> Result<Value, String> {
        let bytes = Zeroizing::new(passkey::decode(data)?);
        if bytes.len() < BACKUP_HEADER_BYTES {
            return Err("Invalid backup".into());
        }
        let mut key = existing_credentials(password, key_file, &bytes[BACKUP_HEADER_BYTES..])?;
        let vault = backup::decode_backup(&bytes, &mut key, self.directory.clone())
            .map_err(|e| e.to_string())?;
        let name = vault.metadata.filename.clone();
        write_vault_with_key(&vault, &mut key).map_err(|e| e.to_string())?;
        self.lock();
        Ok(json!({ "vault": name }))
    }

    pub(super) fn export_items(&mut self, json: bool, confirmed: bool) -> Result<Value, String> {
        if !confirmed {
            return Err("Confirm plaintext export".into());
        }
        let bytes = self
            .vault()?
            .export_bytes(json)
            .map_err(|e| e.to_string())?;
        transfer(&bytes, "File")
    }

    /// Previews an import, or applies one only if it matches the last preview.
    pub(super) fn import_items(
        &mut self,
        data: &str,
        conflicts: ConflictPolicy,
        preview: bool,
        review_token: Option<String>,
    ) -> Result<Value, String> {
        let bytes = Zeroizing::new(passkey::decode(data)?);
        if bytes.len() > MAX_TRANSFER_BYTES {
            return Err("Import exceeds the 16 MiB mobile transfer limit".into());
        }
        let contents = std::str::from_utf8(&bytes).map_err(|_| "Import must be UTF-8")?;
        let digest = crate::cloud::digest(&bytes);
        let history_limit = self.settings.history_limit;
        let review = if preview {
            None
        } else {
            Some(
                self.import_review
                    .take()
                    .ok_or("Preview this import first")?,
            )
        };
        let (vault, credentials) = self.unlocked()?;
        if let Some(review) = review
            && (review_token.as_deref() != Some(review.token.as_str())
                || review.revision != vault.data.revision
                || review.digest != digest
                || review.conflicts != conflicts)
        {
            return Err("Import or vault changed; preview again".into());
        }
        let report = vault
            .import_contents(contents, conflicts, preview, history_limit, credentials)
            .map_err(|e| e.to_string())?;
        if !preview {
            return Ok(json!({ "report": report }));
        }
        let token = hex::encode(rand::random::<[u8; 32]>());
        self.import_review = Some(ImportReview {
            token: token.clone(),
            revision: vault.data.revision,
            digest,
            conflicts,
        });
        Ok(json!({ "report": report, "review_token": token }))
    }

    pub(super) fn backup_create(&mut self, mut key: VaultCredentials) -> Result<Value, String> {
        let bytes = self
            .vault()?
            .backup_bytes(&mut key, MAX_BACKUP_BYTES)
            .map_err(|e| e.to_string())?;
        transfer(&bytes, "File")
    }

    /// Re-encrypts with new credentials after saving a recovery copy, then locks.
    /// The copy is still encrypted with the old credentials; the app offers to
    /// delete it once the new ones have unlocked the vault.
    pub(super) fn rekey(&mut self, candidate: VaultCredentials) -> Result<Value, String> {
        if !self.primary_unlock {
            return Err(
                "Unlock with your original password or key file before changing credentials".into(),
            );
        }
        let vault = self.vault()?;
        let path = vault.sync_path()?;
        let recovery = self.directory.join(format!(
            "{}{}-{}.enc",
            REKEY_RECOVERY_PREFIX,
            hex::encode(vault.vault_id()),
            hex::encode(rand::random::<[u8; 8]>())
        ));
        let original = fs::read(&path).map_err(|_| "Could not read recovery snapshot")?;
        crate::cloud::write_private(&recovery, &original, false)?;
        let (vault, credentials) = self.unlocked()?;
        let result = vault.rekey_credentials(credentials, candidate);
        self.lock();
        result.map_err(|e| e.to_string())?;
        Ok(json!({ "locked": true }))
    }

    /// This vault's recovery copies from earlier credential changes. Copies
    /// from builds that did not record the vault identity are not attributed.
    /// The open vault is never listed, even when it is itself a recovery copy
    /// unlocked with the old credentials.
    fn rekey_recovery_paths(&self) -> Result<Vec<PathBuf>, String> {
        let vault = self.vault()?;
        let prefix = format!("{REKEY_RECOVERY_PREFIX}{}-", hex::encode(vault.vault_id()));
        let open = vault.sync_path()?;
        Ok(self
            .vault_names()?
            .into_iter()
            .filter(|name| name.starts_with(&prefix))
            .map(|name| self.directory.join(name))
            .filter(|path| path.file_name() != open.file_name())
            .collect())
    }

    pub(super) fn rekey_recovery(&self) -> Result<Value, String> {
        Ok(json!({ "copies": self.rekey_recovery_paths()?.len() }))
    }

    /// Deletes recovery copies still encrypted with old credentials. Requires
    /// the current credentials, so a biometric session cannot remove them.
    pub(super) fn delete_rekey_recovery(&mut self, confirmed: bool) -> Result<Value, String> {
        if !self.primary_unlock || !confirmed {
            return Err("Original credential and confirmation required".into());
        }
        let mut deleted = 0;
        for path in self.rekey_recovery_paths()? {
            fs::remove_file(&path).map_err(|_| "Could not remove recovery copy")?;
            remove_sync_checkpoint(&path)?;
            deleted += 1;
        }
        Ok(json!({ "deleted": deleted }))
    }

    /// Removes the local vault and its sync checkpoint (server and vault ID).
    pub(super) fn delete_vault(&mut self, confirmed: bool) -> Result<Value, String> {
        if !self.primary_unlock || !confirmed {
            return Err("Original credential and confirmation required".into());
        }
        let path = self.vault()?.sync_path()?;
        fs::remove_file(&path).map_err(|_| "Could not remove vault")?;
        self.lock();
        remove_sync_checkpoint(&path)?;
        Ok(json!({ "deleted": true }))
    }
}

/// Deletes the `<name>.sync.json` checkpoint beside a vault file, if any.
fn remove_sync_checkpoint(vault: &Path) -> Result<(), String> {
    match fs::remove_file(vault.with_extension("sync.json")) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Vault removed, but its sync settings could not be removed".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    const PASSWORD: &str = "Synthetic-Mobile-Tools-9274!";
    fn request(api: &mut MobileVault, value: Value) -> Value {
        api.call(&value.to_string()).unwrap()
    }
    fn command(api: &mut MobileVault, command: ServerCommand) -> Value {
        vault_command(api, command).unwrap()
    }
    fn fixture() -> (tempfile::TempDir, MobileVault, String) {
        let directory = tempfile::tempdir().unwrap();
        let mut api = MobileVault::new(directory.path().to_owned()).unwrap();
        let name = request(&mut api, json!({"op":"create","password":PASSWORD}))["vault"]
            .as_str()
            .unwrap()
            .to_owned();
        (directory, api, name)
    }
    fn field(name: &str, value: &str, secret: bool) -> CustomField {
        CustomField {
            name: name.into(),
            value: value.into(),
            secret,
        }
    }
    fn add(api: &mut MobileVault, name: &str, kind: ItemKind) -> usize {
        let entry = TypedEntry {
            entry: crate::types::PasswordEntry {
                name: name.into(),
                username: Some("user".into()),
                password: "old-secret".into(),
                url: Some("https://example.com".into()),
                notes: Some("synthetic notes".into()),
                copy: false,
            },
            kind,
            additional_urls: vec!["https://alt.example.com".into()],
            custom_fields: vec![
                field("environment", "test", false),
                field("private", "hidden-value", true),
            ],
        };
        command(
            api,
            ServerCommand::Add {
                entry,
                copy_timeout: 0,
            },
        );
        list(api).unwrap()["items"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["id"]
            .as_u64()
            .unwrap() as usize
    }
    #[test]
    fn cancellation_locks_the_owner_and_interrupts_pending_network_work() {
        static CANCEL: Cancellation = Cancellation::new();
        let (_directory, mut api, _) = fixture();
        api.set_cancellation(&CANCEL);
        CANCEL.signal();
        assert!(api.call(r#"{"op":"status"}"#).is_err());
        assert!(api.state().vault.is_none());
        request(&mut api, json!({"op":"lock"}));
        assert!(!Ticket::new(Some(&CANCEL)).cancelled());
        // A waiter is woken by the signal itself, not by polling, and a
        // request that started before a signal stays cancelled after `lock`.
        let flag = Cancellation::new();
        let ticket = Ticket::new(Some(&flag));
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(10));
                flag.signal();
                flag.clear();
            });
            let started = Instant::now();
            assert!(
                mobile_runtime()
                    .unwrap()
                    .block_on(interruptible(&ticket, std::future::pending::<()>()))
                    .is_err()
            );
            assert!(started.elapsed() < Duration::from_secs(5));
        });
        assert!(ticket.cancelled());
        assert!(!Ticket::new(Some(&flag)).cancelled());
    }
    #[test]
    fn deleting_a_vault_removes_its_sync_settings_and_rekey_copies_can_be_removed() {
        let (directory, mut api, name) = fixture();
        let vault = directory.path().join(&name);
        let checkpoint = vault.with_extension("sync.json");
        // An unrelated vault's checkpoint survives.
        let other = directory.path().join("other.sync.json");
        fs::write(&other, b"{}").unwrap();
        request(
            &mut api,
            json!({"op":"rekey","password":"Replacement-Mobile-Tools-9274!"}),
        );
        // A recovery copy from an older build cannot be attributed and is kept.
        let legacy = directory.path().join("rekey-recovery-0123.enc");
        fs::write(&legacy, b"legacy").unwrap();
        assert!(
            api.call(r#"{"op":"rekey_recovery"}"#).is_err(),
            "rekey locks the vault"
        );
        request(
            &mut api,
            json!({"op":"unlock","vault":name,"password":"Replacement-Mobile-Tools-9274!"}),
        );
        assert_eq!(
            request(&mut api, json!({"op":"rekey_recovery"}))["copies"],
            1
        );
        assert!(
            api.call(r#"{"op":"delete_rekey_recovery"}"#).is_err(),
            "deletion must be confirmed"
        );
        let copy = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(REKEY_RECOVERY_PREFIX)
                    && *path != legacy
            })
            .unwrap();
        // The copy still opens with the old password until it is deleted.
        let mut old = VaultCredentials::from(PasswordType::Password(PASSWORD.into()));
        assert!(decrypt_file(&mut old, &fs::read(&copy).unwrap()).is_some());
        // While the copy itself is the open vault, it is never listed or deleted.
        let copy_name = copy.file_name().unwrap().to_str().unwrap();
        request(
            &mut api,
            json!({"op":"unlock","vault":copy_name,"password":PASSWORD}),
        );
        assert_eq!(
            request(&mut api, json!({"op":"rekey_recovery"}))["copies"],
            0
        );
        assert_eq!(
            request(
                &mut api,
                json!({"op":"delete_rekey_recovery","confirmed":true})
            )["deleted"],
            0
        );
        assert!(copy.exists());
        request(
            &mut api,
            json!({"op":"unlock","vault":name,"password":"Replacement-Mobile-Tools-9274!"}),
        );
        assert_eq!(
            request(
                &mut api,
                json!({"op":"delete_rekey_recovery","confirmed":true})
            )["deleted"],
            1
        );
        assert!(!copy.exists() && legacy.exists());
        assert_eq!(
            request(&mut api, json!({"op":"rekey_recovery"}))["copies"],
            0
        );
        let binding = json!({
            "server_url": "https://sync.example.com",
            "vault_id": name.trim_end_matches(".enc"),
            "enabled": false,
        });
        fs::write(&checkpoint, binding.to_string()).unwrap();
        // A background sync of a disabled vault reports it without a network request.
        let skipped = request(
            &mut api,
            json!({"op":"sync","server":"https://127.0.0.1:9","token":"1".repeat(64),"if_enabled":true}),
        );
        assert_eq!(skipped["disabled"], true);
        // An explicit sync still refuses instead of reporting success.
        assert!(
            api.call(
                &json!({"op":"sync","server":"https://127.0.0.1:9","token":"1".repeat(64)})
                    .to_string()
            )
            .is_err()
        );
        assert!(
            !request(&mut api, json!({"op":"sync_status"}))["enabled"]
                .as_bool()
                .unwrap()
        );
        request(&mut api, json!({"op":"delete_vault","confirmed":true}));
        assert!(!vault.exists() && !checkpoint.exists() && other.exists());
        // Without a checkpoint, deletion still succeeds.
        let (_directory, mut api, _) = fixture();
        request(&mut api, json!({"op":"delete_vault","confirmed":true}));
    }
    #[test]
    fn typed_edit_history_trash_and_desktop_roundtrip_preserve_unrelated_data() {
        let (directory, mut api, name) = fixture();
        for kind in [
            ItemKind::Login,
            ItemKind::SecureNote,
            ItemKind::PaymentCard,
            ItemKind::Identity,
            ItemKind::Wifi,
            ItemKind::SoftwareLicense,
            ItemKind::SshKey,
            ItemKind::ApiSecret,
        ] {
            add(&mut api, &kind.to_string(), kind);
        }
        let entry = item(&mut api, 1).unwrap();
        assert_eq!(entry["fields"].as_array().unwrap().len(), 2);
        let revision = entry["revision"].as_u64().unwrap();
        vault_command_at(
            &mut api,
            ServerCommand::Update(change(1, "login", "new-secret")),
            revision,
        )
        .unwrap();
        // A stale draft cannot overwrite a newer item.
        assert!(
            vault_command_at(
                &mut api,
                ServerCommand::Update(change(1, "login", "stale-secret")),
                revision
            )
            .is_err()
        );
        assert_eq!(
            command(&mut api, ServerCommand::History(Target::Id(1)))["history"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        command(
            &mut api,
            ServerCommand::RestorePassword {
                target: Target::Id(1),
                revision: 1,
            },
        );
        assert_eq!(item(&mut api, 1).unwrap()["password"], "old-secret");
        delete(&mut api, 1).unwrap();
        assert_eq!(
            command(&mut api, ServerCommand::Trash)["trash"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        command(&mut api, ServerCommand::RestoreTrash(1));
        request(&mut api, json!({"op":"lock"}));
        let (_, desktop) = persistence::lookup_vault_in(
            directory.path(),
            &mut PasswordType::Password(PASSWORD.into()).into(),
            Some(&name),
        )
        .unwrap()
        .unwrap();
        assert_eq!(desktop.active_items().count(), 8);
        let restored = desktop.management_item(1, true).unwrap();
        assert_eq!(restored.urls.len(), 2);
        assert_eq!(restored.fields.len(), 2);
        assert!(restored.revision > revision);
    }
    #[test]
    fn app_requests_cannot_reach_lifecycle_clipboard_or_path_commands() {
        let (_directory, mut api, _) = fixture();
        add(&mut api, "Item", ItemKind::Login);
        for rejected in [
            ServerCommand::Kill,
            ServerCommand::Lock(true),
            ServerCommand::Export {
                path: "/tmp/export.json".into(),
                force: true,
            },
            ServerCommand::GetSecret(Target::Id(1)),
            ServerCommand::ManagementCopy { id: 1, timeout: 5 },
            ServerCommand::Totp(TotpCommand::Show {
                target: Target::Id(1),
                copy_timeout: Some(5),
            }),
        ] {
            assert!(vault_command(&mut api, rejected).is_err());
        }
        let mut copying = TypedEntry {
            entry: crate::types::PasswordEntry {
                name: "Copied".into(),
                username: None,
                password: "secret".into(),
                url: None,
                notes: None,
                copy: true,
            },
            kind: ItemKind::Login,
            additional_urls: vec![],
            custom_fields: vec![],
        };
        assert!(
            vault_command(
                &mut api,
                ServerCommand::Add {
                    entry: copying,
                    copy_timeout: 0,
                }
            )
            .is_err()
        );
        copying = TypedEntry {
            entry: crate::types::PasswordEntry {
                name: "Copied".into(),
                username: None,
                password: "secret".into(),
                url: None,
                notes: None,
                copy: false,
            },
            kind: ItemKind::Login,
            additional_urls: vec![],
            custom_fields: vec![],
        };
        assert!(
            vault_command(
                &mut api,
                ServerCommand::Add {
                    entry: copying,
                    copy_timeout: 10,
                }
            )
            .is_err()
        );
        assert_eq!(list(&mut api).unwrap()["total"], 1);
        // Malformed requests fail without echoing their values.
        let error = api
            .call(r#"{"op":"unlock","vault":"x.enc","password":7,"synthetic-secret":"value"}"#)
            .unwrap_err();
        assert!(!error.contains("synthetic-secret") && !error.contains("value"));
    }
    #[test]
    fn portable_import_review_rejects_changed_files_policies_revisions_and_locked_calls() {
        let (_directory, mut api, _) = fixture();
        add(&mut api, "Source", ItemKind::ApiSecret);
        let export = request(
            &mut api,
            json!({"op":"export_items","confirmed":true,"format":"json"}),
        )["data"]
            .as_str()
            .unwrap()
            .to_owned();
        let import = |preview: bool, conflicts: &str, token: &Value| json!({"op":"import_items","preview":preview,"conflicts":conflicts,"data":export,"review_token":token});
        assert!(
            api.call(&import(false, "skip", &Value::Null).to_string())
                .is_err()
        );
        let preview = request(&mut api, import(true, "keep-both", &Value::Null));
        assert_eq!(list(&mut api).unwrap()["total"], 1);
        assert!(
            api.call(&import(false, "replace", &preview["review_token"]).to_string())
                .is_err()
        );
        let preview = request(&mut api, import(true, "keep-both", &Value::Null));
        request(
            &mut api,
            import(false, "keep-both", &preview["review_token"]),
        );
        assert_eq!(list(&mut api).unwrap()["total"], 2);
        let preview = request(&mut api, import(true, "replace", &Value::Null));
        add(&mut api, "Another", ItemKind::Login);
        assert!(
            api.call(&import(false, "replace", &preview["review_token"]).to_string())
                .is_err()
        );
        request(&mut api, json!({"op":"lock"}));
        assert!(
            api.call(&json!({"op":"export_items","confirmed":true}).to_string())
                .is_err()
        );
        assert!(
            api.call(&json!({"op":"rekey","password":PASSWORD}).to_string())
                .is_err()
        );
        for locked in [
            ServerCommand::Trash,
            ServerCommand::History(Target::Id(1)),
            ServerCommand::List(SearchFilter::default()),
            ServerCommand::Audit(AuditOptions::default()),
            ServerCommand::AuthenticatorData(Target::Id(1)),
        ] {
            assert!(vault_command(&mut api, locked).is_err());
        }
    }
    #[test]
    fn purging_trash_needs_confirmation_and_unchanged_saves_succeed() {
        let (_directory, mut api, _) = fixture();
        let id = add(&mut api, "Unchanged", ItemKind::Login);
        let detail = item(&mut api, id).unwrap();
        let unchanged = |name: &str| {
            ServerCommand::Update(TypedUpdate::from(EntryUpdate {
                target: Target::Id(id),
                update: EntryChanges {
                    name: Some(name.into()),
                    ..Default::default()
                },
                password: None,
            }))
        };
        let name = detail["name"].as_str().unwrap().to_owned();
        assert_eq!(command(&mut api, unchanged(&name))["changed"], false);
        delete(&mut api, id).unwrap();
        assert!(
            vault_command(&mut api, unchanged(&name)).is_err(),
            "a trashed item is not found"
        );
        assert!(vault_command(&mut api, ServerCommand::PurgeTrash(None)).is_err());
        assert_eq!(
            command(&mut api, ServerCommand::Trash)["trash"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        confirmed_command(&mut api, ServerCommand::PurgeTrash(None)).unwrap();
        assert!(
            command(&mut api, ServerCommand::Trash)["trash"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn encrypted_backup_restore_and_keyfile_rekey_survive_process_restart() {
        let (directory, mut api, name) = fixture();
        let id = add(&mut api, "Backup", ItemKind::Login);
        command(
            &mut api,
            ServerCommand::Totp(TotpCommand::Set {
                target: Target::Id(id),
                configuration:
                    "otpauth://hotp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0".into(),
            }),
        );
        assert_eq!(
            item(&mut api, id).unwrap()["otp_mode"],
            "Hotp",
            "the mode is readable without consuming a code"
        );
        let next = || ServerCommand::AuthenticatorData(Target::Id(id));
        assert!(
            vault_command(&mut api, next()).is_err(),
            "HOTP advances its counter only when confirmed"
        );
        assert_eq!(
            confirmed_command(&mut api, next()).unwrap()["code"],
            "755224"
        );
        delete(&mut api, id).unwrap();
        let encrypted =
            request(&mut api, json!({"op":"backup_create","password":PASSWORD}))["data"]
                .as_str()
                .unwrap()
                .to_owned();
        assert!(
            !String::from_utf8_lossy(&passkey::decode(&encrypted).unwrap()).contains("old-secret")
        );
        let restored = request(
            &mut api,
            json!({"op":"restore_backup","password":PASSWORD,"data":encrypted}),
        )["vault"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(restored, name);
        request(
            &mut api,
            json!({"op":"unlock","vault":restored,"password":PASSWORD}),
        );
        command(&mut api, ServerCommand::RestoreTrash(id));
        assert_eq!(
            confirmed_command(&mut api, next()).unwrap()["code"],
            "287082"
        );
        let key = request(&mut api, json!({"op":"new_key_file"}))["data"]
            .as_str()
            .unwrap()
            .to_owned();
        request(&mut api, json!({"op":"rekey","key_file":key}));
        assert!(
            !request(&mut api, json!({"op":"status"}))["unlocked"]
                .as_bool()
                .unwrap()
        );
        assert!(
            api.call(&json!({"op":"unlock","vault":restored,"password":PASSWORD}).to_string())
                .is_err()
        );
        drop(api);
        let mut reopened = MobileVault::new(directory.path().to_owned()).unwrap();
        request(
            &mut reopened,
            json!({"op":"unlock","vault":restored,"key_file":key}),
        );
        assert_eq!(
            item(&mut reopened, id).unwrap()["fields"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(directory.path().read_dir().unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("rekey-recovery-")
        }));
        let created = request(&mut reopened, json!({"op":"create_key","key_file":key}))["vault"]
            .as_str()
            .unwrap()
            .to_owned();
        request(&mut reopened, json!({"op":"lock"}));
        request(
            &mut reopened,
            json!({"op":"unlock","vault":created,"key_file":key}),
        );
    }
    #[test]
    fn generation_search_audit_and_settings_use_shared_policies() {
        let (directory, mut api, _) = fixture();
        add(&mut api, "Account", ItemKind::Login);
        add(&mut api, "Notes", ItemKind::SecureNote);
        let generated = request(
            &mut api,
            json!({"op":"generate","length":35,"uppercase":false,"lowercase":false,"digits":true,"symbols_enabled":false}),
        );
        let value = generated["password"].as_str().unwrap();
        assert_eq!(value.len(), 35);
        assert!(value.bytes().all(|b| b.is_ascii_digit()));
        let phrase = request(
            &mut api,
            json!({"op":"generate","passphrase":true,"words":7,"separator":"."}),
        );
        assert_eq!(phrase["password"].as_str().unwrap().split('.').count(), 7);
        assert!(api.call(r#"{"op":"generate","length":256}"#).is_err());
        let mut filter = SearchFilter::default();
        filter.list.kind = Some(ItemKind::SecureNote);
        filter.list.sort = SortField::Name;
        assert_eq!(command(&mut api, ServerCommand::List(filter))["total"], 1);
        let audit = command(
            &mut api,
            ServerCommand::Audit(AuditOptions {
                require_totp: true,
                ..Default::default()
            }),
        );
        assert_eq!(audit["missing_totp"].as_array().unwrap().len(), 1);
        let mut settings = request(&mut api, json!({"op":"settings_get"}));
        settings["history_limit"] = json!(3);
        settings["unlock_seconds"] = json!(60);
        request(&mut api, json!({"op":"settings_save","settings":settings}));
        drop(api);
        let mut api = MobileVault::new(directory.path().to_owned()).unwrap();
        assert_eq!(
            request(&mut api, json!({"op":"settings_get"}))["history_limit"],
            3
        );
        let mut bad = settings;
        bad["unlock_seconds"] = json!(0);
        assert!(
            api.call(&json!({"op":"settings_save","settings":bad}).to_string())
                .is_err()
        );
    }
    #[test]
    fn recovery_rejects_tampering_wrong_keys_and_reserved_passkey_fields() {
        let (_directory, mut api, _) = fixture();
        add(&mut api, "Safe", ItemKind::Login);
        let mut forged = change(1, "Safe", "old-secret");
        forged.set_fields = vec![field(passkey::FIELD, "private-key", true)];
        assert!(vault_command(&mut api, ServerCommand::Update(forged)).is_err());
        let data = request(&mut api, json!({"op":"backup_create","password":PASSWORD}))["data"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            api.call(&json!({"op":"restore_backup","password":"wrong","data":data}).to_string())
                .is_err()
        );
        let mut bytes = passkey::decode(&data).unwrap();
        let end = bytes.len() - 1;
        bytes[end] ^= 1;
        assert!(
            api.call(
                &json!({"op":"restore_backup","password":PASSWORD,"data":passkey::encode(&bytes)})
                    .to_string()
            )
            .is_err()
        );
        assert_eq!(list(&mut api).unwrap()["total"], 1);
    }
}
