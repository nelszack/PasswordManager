//! Native mobile workflows over shared domain operations. No desktop paths or daemon.
use super::*;
use serde::de::DeserializeOwned;

const SETTINGS_FILE: &str = "mobile-settings.json";

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
fn decode<T: DeserializeOwned>(value: Value) -> Result<T, VaultError> {
    // JSON errors can echo invalid secret values. Expose a fixed message instead.
    serde_json::from_value(value)
        .map_err(|_| VaultError::InvalidInput("Invalid mobile options".into()))
}
fn require(condition: bool, message: &str) -> Result<(), VaultError> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn new_credentials(r: &Value) -> Result<VaultCredentials, VaultError> {
    if let Some(encoded) = r.get("key_file").and_then(Value::as_str) {
        let bytes = Zeroizing::new(passkey::decode(encoded)?);
        Ok(crate::encryption::new_keyfile_credentials(&bytes)?)
    } else {
        let password = string(r, "password")?;
        validate_new_password(password).map_err(VaultError::from)?;
        Ok(PasswordType::Password(password.into()).into())
    }
}
fn file_credentials(r: &Value, encrypted: &[u8]) -> Result<VaultCredentials, VaultError> {
    if let Some(encoded) = r.get("key_file").and_then(Value::as_str) {
        let bytes = Zeroizing::new(passkey::decode(encoded)?);
        Ok(crate::encryption::credentials_from_keyfile_bytes(
            encrypted, &bytes,
        )?)
    } else {
        Ok(PasswordType::Password(string(r, "password")?.into()).into())
    }
}
/// Largest plaintext export, import, or backup exchanged with the app.
const MAX_TRANSFER_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_SYMBOLS: &str = "!@#$%^&*-_=+";

impl MobileVault {
    /// Tools that work whether or not a vault is open.
    pub(super) fn local_tool(&mut self, op: &str, r: &Value) -> Result<Option<Value>, VaultError> {
        Ok(Some(match op {
            "settings_get" => json!(self.settings),
            "settings_save" => {
                let settings: MobileSettings =
                    decode(r.get("settings").cloned().ok_or("Settings required")?)?;
                settings.validate()?;
                let bytes =
                    serde_json::to_vec(&settings).map_err(|_| "Could not encode settings")?;
                crate::cloud::write_private(&self.directory.join(SETTINGS_FILE), &bytes, true)?;
                self.settings = settings;
                json!(self.settings)
            }
            "new_key_file" => {
                let key = Zeroizing::new(rand::random::<[u8; 32]>());
                json!({ "data": passkey::encode(&key[..]) })
            }
            "create_key" => {
                require(
                    r.get("key_file").is_some(),
                    "Choose the saved key file first",
                )?;
                let key = new_credentials(r)?;
                self.create_with_key(key)?
            }
            "restore_backup" => {
                let bytes = Zeroizing::new(passkey::decode(string(r, "data")?)?);
                require(bytes.len() >= 9, "Invalid backup")?;
                let mut key = file_credentials(r, &bytes[9..])?;
                let vault = backup::decode_backup(&bytes, &mut key, self.directory.clone())?;
                let name = vault.metadata.filename.clone();
                write_vault_with_key(&vault, &mut key)?;
                self.lock();
                json!({ "vault": name })
            }
            "generate" => {
                let value = SecretString::from(self.generate(r)?);
                json!({
                    "password": value,
                    "assessment": crate::password::password_strength_output(&value),
                })
            }
            "passcheck" => json!({
                "assessment": crate::password::password_strength_output(string(r, "password")?),
            }),
            _ => return Ok(None),
        }))
    }

    fn generate(&self, r: &Value) -> Result<String, VaultError> {
        if flag(r, "passphrase") {
            let words = u64_or(r, "words", self.settings.passphrase_words.into());
            require((1..=64).contains(&words), "Use 1 to 64 words")?;
            let separator = opt_str(r, "separator").unwrap_or("-");
            require(separator.len() <= 32, "Separator too long")?;
            return Ok(crate::password::generate_passphrase(
                words as u8,
                separator,
            )?);
        }
        let length = u64_or(r, "length", self.settings.generator_length.into());
        require((1..=255).contains(&length), "Use a length from 1 to 255")?;
        let symbols = bool_or(r, "symbols_enabled", true)
            .then(|| opt_str(r, "symbols").unwrap_or(DEFAULT_SYMBOLS));
        let options = crate::password::PasswordOptions {
            uppercase: bool_or(r, "uppercase", true),
            lowercase: bool_or(r, "lowercase", true),
            digits: bool_or(r, "digits", true),
            symbols,
            exclude_ambiguous: flag(r, "exclude_ambiguous"),
        };
        Ok(crate::password::generate_password_with_options(
            length as u8,
            &options,
        )?)
    }

    /// Tools that require an open vault and match desktop behavior.
    pub(super) fn parity_tool(&mut self, op: &str, r: &Value) -> Result<Option<Value>, VaultError> {
        let cancellation = self.cancellation;
        let history_limit = self.settings.history_limit;
        let vault = self.vault.as_mut().ok_or(VaultError::Locked)?;
        let credentials = &mut self.credentials;
        Ok(Some(match op {
            "search" => json!(vault.management_list(search_filter(r)?)?),
            "save_item" => json!({ "changed": save_item(vault, credentials, history_limit, r)? }),
            "history" => json!({ "history": vault.view_password_history(Target::Id(id(r)?))? }),
            "restore_password" => {
                let revision = r
                    .get("revision")
                    .and_then(Value::as_u64)
                    .ok_or("Revision required")?;
                let changed =
                    vault.restore_password(Target::Id(id(r)?), revision as usize, credentials)?;
                json!({ "changed": changed })
            }
            "trash" => {
                let trash: Vec<_> = vault
                    .view_trash()
                    .iter()
                    .map(|v| {
                        json!({
                            "id": v.entry.entry.id,
                            "name": v.entry.entry.name,
                            "username": v.entry.entry.username,
                            "deleted": v.deleted,
                        })
                    })
                    .collect();
                json!({ "trash": trash })
            }
            "restore_trash" => json!({ "changed": vault.restore_trashed(id(r)?, credentials)? }),
            "purge_trash" => {
                require(confirmed(r), "Confirm permanent deletion")?;
                let target = r.get("id").is_some().then(|| id(r)).transpose()?;
                json!({ "changed": vault.purge_trash(target, credentials)? })
            }
            "purge_expired" => {
                let removed = vault.purge_expired_trash(self.settings.trash_days, credentials)?;
                json!({ "removed": removed })
            }
            "set_otp" => {
                let bits =
                    vault.set_totp(Target::Id(id(r)?), string(r, "configuration")?, credentials)?;
                json!({ "bits": bits })
            }
            "remove_otp" => {
                json!({ "changed": vault.remove_totp(Target::Id(id(r)?), credentials)? })
            }
            "next_otp" => {
                require(
                    confirmed(r),
                    "Confirm generation; HOTP advances its counter",
                )?;
                let code = vault.current_otp(Target::Id(id(r)?), credentials)?;
                json!({
                    "code": &*code.code,
                    "expires_in": code.expires_in,
                    "counter": code.counter,
                })
            }
            "authenticator_info" => {
                let item = vault
                    .item(id(r)?)
                    .filter(|i| i.active())
                    .ok_or("Item not found")?;
                let mode = item.authenticator.as_ref().map(|a| match a.state {
                    AuthenticatorState::Totp(_) => "totp",
                    AuthenticatorState::Hotp { .. } => "hotp",
                });
                json!({ "mode": mode, "has_duo": item.duo.is_some() })
            }
            "audit" => {
                let snapshot = vault
                    .prepare_audit(&AuditOptions {
                        stale_days: r.get("stale_days").and_then(Value::as_u64),
                        require_totp: flag(r, "require_totp"),
                        check_breaches: false,
                    })
                    .finish(|| cancelled(cancellation))?;
                let outcome = block_on(cancellation, snapshot.audit(flag(r, "check_breaches")))?;
                json!(outcome.report)
            }
            "export_items" => {
                require(confirmed(r), "Confirm plaintext export")?;
                let bytes = vault.export_bytes(opt_str(r, "format") != Some("csv"))?;
                require(
                    bytes.len() <= MAX_TRANSFER_BYTES,
                    "File exceeds the 16 MiB mobile transfer limit",
                )?;
                json!({ "data": passkey::encode(&bytes) })
            }
            "import_items" => {
                let bytes = Zeroizing::new(passkey::decode(string(r, "data")?)?);
                require(
                    bytes.len() <= MAX_TRANSFER_BYTES,
                    "Import exceeds the 16 MiB mobile transfer limit",
                )?;
                let contents = std::str::from_utf8(&bytes).map_err(|_| "Import must be UTF-8")?;
                let conflicts: ConflictPolicy =
                    decode(r.get("conflicts").cloned().unwrap_or(json!("skip")))?;
                let preview = bool_or(r, "preview", true);
                let digest = crate::cloud::digest(&bytes);
                if !preview {
                    let review = self
                        .import_review
                        .take()
                        .ok_or("Preview this import first")?;
                    require(
                        opt_str(r, "review_token") == Some(review.token.as_str())
                            && review.revision == vault.data.revision
                            && review.digest == digest
                            && review.conflicts == conflicts,
                        "Import or vault changed; preview again",
                    )?;
                }
                let report = vault.import_contents(
                    contents,
                    conflicts,
                    preview,
                    history_limit,
                    credentials,
                )?;
                if preview {
                    let token = hex::encode(rand::random::<[u8; 32]>());
                    self.import_review = Some(ImportReview {
                        token: token.clone(),
                        revision: vault.data.revision,
                        digest,
                        conflicts,
                    });
                    json!({ "report": report, "review_token": token })
                } else {
                    json!({ "report": report })
                }
            }
            "backup_create" => {
                let mut key = new_credentials(r)?;
                let bytes = vault.backup_bytes(&mut key, MAX_BACKUP_BYTES)?;
                require(
                    bytes.len() <= MAX_TRANSFER_BYTES,
                    "File exceeds the 16 MiB mobile transfer limit",
                )?;
                json!({ "data": passkey::encode(&bytes) })
            }
            "rekey" => {
                require(
                    self.primary_unlock,
                    "Unlock with your original password or key file before changing credentials",
                )?;
                let candidate = new_credentials(r)?;
                // Preserve the original encrypted snapshot before replacing its key.
                let path = vault.sync_path()?;
                let original = fs::read(&path).map_err(|_| "Could not read recovery snapshot")?;
                let recovery = self.directory.join(format!(
                    "rekey-recovery-{}.enc",
                    hex::encode(rand::random::<[u8; 16]>())
                ));
                crate::cloud::write_private(&recovery, &original, false)?;
                let result = vault.rekey_credentials(credentials, candidate);
                self.lock();
                result?;
                json!({ "locked": true })
            }
            "delete_vault" => {
                require(
                    self.primary_unlock && confirmed(r),
                    "Original credential and confirmation required",
                )?;
                fs::remove_file(vault.sync_path()?).map_err(|_| "Could not remove vault")?;
                self.lock();
                json!({ "deleted": true })
            }
            "duo_enroll" | "duo_requests" | "duo_respond" | "duo_remove" => {
                duo(vault, credentials, op, r, cancellation)?
            }
            _ => return Ok(None),
        }))
    }
}

fn non_empty(r: &Value, key: &str) -> Option<String> {
    opt_str(r, key).filter(|s| !s.is_empty()).map(str::to_owned)
}

fn u64_or(r: &Value, key: &str, default: u64) -> u64 {
    r.get(key).and_then(Value::as_u64).unwrap_or(default)
}

fn search_filter(r: &Value) -> Result<SearchFilter, VaultError> {
    let mut filter = SearchFilter::default();
    filter.query = non_empty(r, "query");
    filter.name = non_empty(r, "name");
    filter.username = non_empty(r, "username");
    filter.url = non_empty(r, "url");
    filter.notes = opt_str(r, "notes")
        .filter(|s| !s.is_empty())
        .map(SecretString::from);
    filter.list = ListOptions {
        kind: r
            .get("kind")
            .filter(|v| !v.is_null())
            .map(|v| decode(v.clone()))
            .transpose()?,
        has_totp: r.get("has_totp").and_then(Value::as_bool),
        weak: flag(r, "weak"),
        stale_days: r.get("stale_days").and_then(Value::as_u64),
        sort: r
            .get("sort")
            .map(|v| decode(v.clone()))
            .transpose()?
            .unwrap_or_default(),
        descending: flag(r, "descending"),
    };
    Ok(filter)
}

/// Adds or replaces a typed item. Returns whether anything changed.
fn save_item(
    vault: &mut Vault,
    credentials: &mut VaultCredentials,
    history_limit: usize,
    r: &Value,
) -> Result<bool, VaultError> {
    let name = string(r, "name")?;
    require(
        !name.trim().is_empty() && name.len() <= 4096,
        "Name is required (maximum 4096 bytes)",
    )?;
    let kind: ItemKind = decode(r.get("kind").cloned().unwrap_or(json!("login")))?;
    let urls: Vec<String> = decode(r.get("urls").cloned().unwrap_or(json!([])))?;
    require(
        urls.len() <= 128 && urls.iter().all(|s| s.len() <= 8192),
        "Too many or oversized websites",
    )?;
    let mut fields: Vec<CustomField> = decode(r.get("fields").cloned().unwrap_or(json!([])))?;
    for field in &mut fields {
        field.name = field.name.trim().to_owned();
    }
    let mut names = HashSet::new();
    require(
        fields.len() <= 128
            && fields.iter().all(|f| {
                !f.name.is_empty()
                    && f.name.len() <= 128
                    && f.value.len() <= 1024 * 1024
                    && !f.name.eq_ignore_ascii_case(passkey::FIELD)
                    && names.insert(f.name.to_lowercase())
            }),
        "Invalid, duplicate, or reserved custom field",
    )?;
    let username = opt_string(r, "username");
    let notes = opt_str(r, "notes").map(SecretString::from);
    let password = string(r, "password")?;
    if r.get("id").is_none() {
        let entry = TypedEntry {
            entry: crate::types::PasswordEntry {
                name: name.into(),
                username,
                password: password.into(),
                url: urls.first().cloned(),
                notes,
                copy: false,
            },
            kind,
            additional_urls: urls.into_iter().skip(1).collect(),
            custom_fields: fields,
        };
        require(
            vault.add_typed_entry(entry, credentials)?,
            "An item with this name and username already exists",
        )?;
        return Ok(true);
    }
    let id = id(r)?;
    let existing = vault
        .item(id)
        .filter(|i| i.active())
        .ok_or("Item not found")?;
    require(
        !existing.is_passkey(),
        "Passkey records cannot be edited as ordinary items",
    )?;
    require(
        r.get("revision").and_then(Value::as_u64) == Some(existing.revision),
        "Item changed; reopen the editor before saving",
    )?;
    let update = TypedUpdate {
        entry: EntryUpdate {
            target: Target::Id(id),
            update: EntryChanges {
                name: Some(name.into()),
                username,
                url: urls.first().cloned(),
                notes,
            },
            password: Some(password.into()),
        },
        kind: Some(kind),
        add_url: urls.iter().skip(1).cloned().collect(),
        remove_url: vec![],
        clear_urls: true,
        set_fields: fields,
        remove_fields: vec![],
        clear_fields: true,
    };
    vault.update_typed_entry_with_limit(update, credentials, history_limit)
}

/// Duo Push enrollment, request review, decisions, and removal.
fn duo(
    vault: &mut Vault,
    credentials: &mut VaultCredentials,
    op: &str,
    r: &Value,
    cancellation: Option<&AtomicBool>,
) -> Result<Value, VaultError> {
    use crate::types::{DuoCommand, OtpMode};
    let target = Target::Id(id(r)?);
    let command = match op {
        "duo_enroll" => DuoCommand::Enroll {
            target,
            activation: string(r, "activation")?.into(),
            mode: Some(if opt_str(r, "mode") == Some("totp") {
                OtpMode::Totp
            } else {
                OtpMode::Hotp
            }),
            replace: flag(r, "replace"),
        },
        "duo_requests" => DuoCommand::Requests { target },
        "duo_respond" => DuoCommand::Respond {
            target,
            request_id: string(r, "request_id")?.into(),
            fingerprint: string(r, "fingerprint")?.into(),
            approve: r
                .get("approve")
                .and_then(Value::as_bool)
                .ok_or("Explicit decision required")?,
            code: opt_str(r, "code").unwrap_or("").into(),
        },
        _ => DuoCommand::Remove { target },
    };
    match op {
        "duo_enroll" => {
            let prepared =
                vault.prepare_duo_enrollment(command, bool_or(r, "push", true), credentials)?;
            let material = block_on(cancellation, prepared.enroll())??;
            let message = vault.finish_duo_enrollment(&prepared, material, credentials)?;
            Ok(json!({ "message": message }))
        }
        "duo_remove" => Ok(json!({ "message": vault.duo_command(&command, credentials)? })),
        _ => {
            let prepared = vault.prepare_duo_poll(command, credentials)?;
            let bytes = block_on(cancellation, prepared.request.execute())??;
            match vault.finish_duo_poll(&prepared.review, &bytes, credentials)? {
                DuoPollResult::Requests(requests) => Ok(json!({ "requests": requests })),
                DuoPollResult::Decision(request) => {
                    let body = block_on(cancellation, (*request).execute())??;
                    crate::duo::acknowledge(&body)?;
                    Ok(json!({ "message": "Duo decision accepted" }))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PASSWORD: &str = "Synthetic-Mobile-Tools-9274!";
    fn request(api: &mut MobileVault, value: Value) -> Value {
        api.call(&value.to_string()).unwrap()
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
    fn add(api: &mut MobileVault, name: &str, kind: &str) -> usize {
        request(
            api,
            json!({"op":"save_item","name":name,"kind":kind,"username":"user","password":"old-secret",
            "urls":["https://example.com","https://alt.example.com"],"notes":"synthetic notes",
            "fields":[{"name":"environment","value":"test","secret":false},{"name":"private","value":"hidden-value","secret":true}]}),
        );
        request(api, json!({"op":"list"}))["items"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["id"]
            .as_u64()
            .unwrap() as usize
    }
    #[test]
    fn cancellation_locks_the_owner_and_interrupts_pending_network_work() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static CANCEL: AtomicBool = AtomicBool::new(false);
        let (_directory, mut api, _) = fixture();
        api.set_cancellation(&CANCEL);
        CANCEL.store(true, Ordering::SeqCst);
        assert!(api.call(r#"{"op":"status"}"#).is_err());
        assert!(api.vault.is_none());
        request(&mut api, json!({"op":"lock"}));
        assert!(!CANCEL.load(Ordering::SeqCst));
        let flag = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(10));
                flag.store(true, Ordering::SeqCst);
            });
            assert!(
                mobile_runtime()
                    .unwrap()
                    .block_on(interruptible(Some(&flag), std::future::pending::<()>()))
                    .is_err()
            );
        });
    }
    #[test]
    fn typed_edit_history_trash_and_desktop_roundtrip_preserve_unrelated_data() {
        let (directory, mut api, name) = fixture();
        for kind in [
            "login",
            "secure-note",
            "payment-card",
            "identity",
            "wifi",
            "software-license",
            "ssh-key",
            "api-secret",
        ] {
            add(&mut api, kind, kind);
        }
        let mut entry = request(&mut api, json!({"op":"item","id":1}));
        assert_eq!(entry["fields"].as_array().unwrap().len(), 2);
        let revision = entry["revision"].clone();
        entry["op"] = json!("save_item");
        entry["password"] = json!("new-secret");
        request(&mut api, entry.clone());
        assert!(api.call(&entry.to_string()).is_err()); // stale draft cannot overwrite a newer item
        assert_eq!(
            request(&mut api, json!({"op":"history","id":1}))["history"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        request(
            &mut api,
            json!({"op":"restore_password","id":1,"revision":1}),
        );
        assert_eq!(
            request(&mut api, json!({"op":"item","id":1}))["password"],
            "old-secret"
        );
        request(&mut api, json!({"op":"delete","id":1}));
        assert_eq!(
            request(&mut api, json!({"op":"trash"}))["trash"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(api.call(r#"{"op":"purge_trash"}"#).is_err());
        request(&mut api, json!({"op":"restore_trash","id":1}));
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
        assert!(restored.revision > revision.as_u64().unwrap());
    }
    #[test]
    fn portable_import_review_rejects_changed_files_policies_revisions_and_locked_calls() {
        let (_directory, mut api, _) = fixture();
        add(&mut api, "Source", "api-secret");
        let export = request(
            &mut api,
            json!({"op":"export_items","confirmed":true,"format":"json"}),
        )["data"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            api.call(&json!({"op":"import_items","preview":false,"data":export}).to_string())
                .is_err()
        );
        let preview = request(
            &mut api,
            json!({"op":"import_items","preview":true,"conflicts":"keep-both","data":export}),
        );
        assert_eq!(request(&mut api, json!({"op":"list"}))["total"], 1);
        assert!(api.call(&json!({"op":"import_items","preview":false,"conflicts":"replace","data":export,"review_token":preview["review_token"]}).to_string()).is_err());
        let preview = request(
            &mut api,
            json!({"op":"import_items","preview":true,"conflicts":"keep-both","data":export}),
        );
        request(
            &mut api,
            json!({"op":"import_items","preview":false,"conflicts":"keep-both","data":export,"review_token":preview["review_token"]}),
        );
        assert_eq!(request(&mut api, json!({"op":"list"}))["total"], 2);
        let preview = request(
            &mut api,
            json!({"op":"import_items","preview":true,"conflicts":"replace","data":export}),
        );
        add(&mut api, "Another", "login");
        assert!(api.call(&json!({"op":"import_items","preview":false,"conflicts":"replace","data":export,"review_token":preview["review_token"]}).to_string()).is_err());
        request(&mut api, json!({"op":"lock"}));
        for op in [
            "trash",
            "history",
            "export_items",
            "search",
            "audit",
            "save_item",
            "next_otp",
            "rekey",
        ] {
            assert!(api.call(&json!({"op":op}).to_string()).is_err(), "{op}");
        }
    }
    #[test]
    fn encrypted_backup_restore_and_keyfile_rekey_survive_process_restart() {
        let (directory, mut api, name) = fixture();
        let id = add(&mut api, "Backup", "login");
        request(
            &mut api,
            json!({"op":"set_otp","id":id,"configuration":"otpauth://hotp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0"}),
        );
        assert!(
            api.call(&json!({"op":"next_otp","id":id}).to_string())
                .is_err()
        );
        assert_eq!(
            request(&mut api, json!({"op":"next_otp","id":id,"confirmed":true}))["code"],
            "755224"
        );
        request(&mut api, json!({"op":"delete","id":id}));
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
        request(&mut api, json!({"op":"restore_trash","id":id}));
        assert_eq!(
            request(&mut api, json!({"op":"next_otp","id":id,"confirmed":true}))["code"],
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
            request(&mut reopened, json!({"op":"item","id":id}))["fields"]
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
        add(&mut api, "Account", "login");
        add(&mut api, "Notes", "secure-note");
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
        assert_eq!(
            request(
                &mut api,
                json!({"op":"search","kind":"secure-note","username":"","notes":"","sort":"name"})
            )["total"],
            1
        );
        assert_eq!(
            request(&mut api, json!({"op":"audit","require_totp":true}))["missing_totp"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
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
        add(&mut api, "Safe", "login");
        let mut entry = request(&mut api, json!({"op":"item","id":1}));
        entry["op"] = json!("save_item");
        entry["fields"] = json!([{"name":passkey::FIELD,"value":"private-key","secret":true}]);
        assert!(api.call(&entry.to_string()).is_err());
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
        assert_eq!(request(&mut api, json!({"op":"list"}))["total"], 1);
    }
}
