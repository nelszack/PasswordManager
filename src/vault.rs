use crate::{
    clipboard::copy_in_background,
    encryption::{decrypt_file, try_encrypt_file, try_gen_master_key, try_gen_master_key_legacy},
    file::{data_dir, file_exists, set_private_perms},
    server::{ServerInfo, respond},
    types::{EntryUpdate, PasswordEntry, PasswordType, SearchFilter, Target},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    fs::{self, read},
    io::Write,
};
use tempfile::NamedTempFile;
use tokio::net::TcpStream;
use totp_rs::{Builder as TotpBuilder, Secret as TotpSecret, Totp, TotpError};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct VaultEntry {
    pub id: usize,
    pub name: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created: String,
    pub modified: String,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct PasswordRevision {
    pub entry_id: usize,
    pub password: String,
    pub changed: String,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct TrashedEntry {
    pub entry: VaultEntry,
    pub history: Vec<PasswordRevision>,
    pub deleted: String,
}

#[derive(Serialize, Deserialize, Default, PartialEq, Clone)]
pub struct TotpRecord {
    pub entry_id: usize,
    pub configuration: String,
}

impl std::fmt::Debug for TotpRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TotpRecord")
            .field("entry_id", &self.entry_id)
            .field("configuration", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct RecoveryData {
    pub password_history: Vec<PasswordRevision>,
    pub trash: Vec<TrashedEntry>,
    #[serde(default)]
    pub next_entry_id: usize,
    #[serde(default)]
    pub totp: Vec<TotpRecord>,
}

impl Zeroize for PasswordRevision {
    fn zeroize(&mut self) {
        self.entry_id.zeroize();
        self.password.zeroize();
        self.changed.zeroize();
        *self = Self::default();
    }
}

impl Zeroize for TrashedEntry {
    fn zeroize(&mut self) {
        self.entry.zeroize();
        self.history.zeroize();
        self.deleted.zeroize();
        *self = Self::default();
    }
}

impl Zeroize for TotpRecord {
    fn zeroize(&mut self) {
        self.entry_id.zeroize();
        self.configuration.zeroize();
        *self = Self::default();
    }
}

impl Zeroize for RecoveryData {
    fn zeroize(&mut self) {
        self.password_history.zeroize();
        self.trash.zeroize();
        self.next_entry_id.zeroize();
        self.totp.zeroize();
        *self = Self::default();
    }
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
    #[serde(alias = "enteries")]
    pub entries: Vec<VaultEntry>,
    pub metadata: VaultMetadata,
    #[serde(default)]
    pub recovery: RecoveryData,
}

fn filename_key_from_master(master_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("vault-filename-v1", master_key)
}

fn vault_filename_from_key(filename_key: &[u8; 32]) -> String {
    let hash = blake3::hash(filename_key);
    let short = &hash.as_bytes()[..16];
    format!("{}.enc", hex::encode(short))
}

fn try_get_filename(key_pass: &mut PasswordType, new: bool) -> Result<String, String> {
    let master_key = try_gen_master_key(key_pass, new)?;
    let filename_key = filename_key_from_master(&master_key);
    Ok(vault_filename_from_key(&filename_key))
}

#[cfg(test)]
fn get_filename(key_pass: &mut PasswordType, new: bool) -> String {
    try_get_filename(key_pass, new).expect("could not derive vault filename")
}

fn try_get_legacy_filename(key_pass: &mut PasswordType) -> Result<String, String> {
    let master_key = try_gen_master_key_legacy(key_pass)?;
    let filename_key = filename_key_from_master(&master_key);
    Ok(vault_filename_from_key(&filename_key))
}

pub fn create_vault(
    vlt: &mut Option<Vault>,
    server_info: &mut ServerInfo,
    lock: bool,
) -> Result<(), String> {
    let generated_key_path = match server_info.keypass.as_ref() {
        Some(PasswordType::Key(path)) if !data_dir().join(path).exists() => {
            Some(data_dir().join(path))
        }
        _ => None,
    };
    let fname = try_get_filename(server_info.keypass.as_mut().unwrap(), true)?;
    let file_path = data_dir().join(&fname);
    if file_exists(&file_path) {
        if let Some(path) = generated_key_path {
            let _ = fs::remove_file(path);
        }
        return Err("A vault file with this key already exists.".to_string());
    }
    *vlt = Some(Vault {
        entries: Vec::new(),
        metadata: VaultMetadata {
            filename: fname.clone(),
        },
        recovery: RecoveryData::default(),
    });
    if let Err(error) = write_vault(
        vlt.as_ref().expect("vault was just initialized"),
        server_info,
    ) {
        vlt.zeroize();
        if let Some(path) = generated_key_path {
            let _ = fs::remove_file(path);
        }
        return Err(error);
    }
    if lock {
        vlt.zeroize();
        server_info.zeroize();
    }
    Ok(())
}
fn write_vault(vlt: &Vault, key_pass: &mut ServerInfo) -> Result<(), String> {
    if key_pass.keypass.is_none() {
        // This permits detached in-memory vault values used by callers and tests;
        // the running server never mutates a vault without an active key.
        return Ok(());
    }
    let fname = vlt.metadata.filename.clone();
    let file_path = data_dir().join(&fname);
    let buf = rmp_serde::to_vec(&vlt).map_err(|e| format!("could not encode vault: {e}"))?;
    let txt = try_encrypt_file(key_pass.keypass.as_mut().unwrap(), &buf[..])?;
    let mut temporary = NamedTempFile::new_in(data_dir())
        .map_err(|e| format!("could not create vault temp file: {e}"))?;
    set_private_perms(temporary.path())
        .map_err(|e| format!("could not protect vault temp file: {e}"))?;
    temporary
        .write_all(&txt)
        .map_err(|e| format!("could not write encrypted vault: {e}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|e| format!("could not sync encrypted vault: {e}"))?;
    temporary
        .persist(&file_path)
        .map_err(|e| format!("could not atomically replace vault file: {}", e.error))?;
    Ok(())
}

fn unlock_vault(key_pass: &mut ServerInfo) -> Option<Vault> {
    let kp = key_pass.keypass.as_mut()?;
    if let PasswordType::Key(key) = kp
        && !data_dir().join(key).is_file()
    {
        return None;
    }
    let fname = try_get_filename(key_pass.keypass.as_mut().unwrap(), false).ok()?;
    let mut file_path = data_dir().join(&fname);
    if !file_path.exists() {
        let legacy_fname = try_get_legacy_filename(key_pass.keypass.as_mut().unwrap()).ok()?;
        file_path = data_dir().join(&legacy_fname);
        if !file_path.exists() {
            return None;
        }
    }
    let contents = read(file_path).ok()?;
    let dec = decrypt_file(key_pass.keypass.as_mut().unwrap(), &contents)?;
    let mut vault: Vault = rmp_serde::from_slice(&dec).ok()?;
    vault.ensure_next_entry_id().ok()?;
    key_pass.locked = false;
    Some(vault)
}

fn url_match_json(
    entries: &[VaultEntry],
    totp_records: &[TotpRecord],
    url: &str,
) -> Option<String> {
    let mut results = Vec::new();
    for e in entries {
        if let Some(u) = &e.url
            && hosts_match(u, url)
        {
            results.push(json!({
                "id": e.id,
                "username": e.username.clone().unwrap_or_else(|| "None".to_string()),
                "password": e.password,
                "name": e.name,
                "has_totp": totp_records.iter().any(|record| record.entry_id == e.id),
            }));
        }
    }
    if results.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&results).unwrap())
    }
}

fn hostname(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let authority = value
        .split_once("://")
        .map_or(value, |(_, remainder)| remainder)
        .split(['/', '?', '#'])
        .next()?;
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if host_port.starts_with('[') {
        host_port
            .split_once(']')
            .map_or(host_port, |(host, _)| host)
    } else {
        host_port
            .split_once(':')
            .map_or(host_port, |(host, _)| host)
    };
    let host = host.trim_matches(['[', ']']).trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn hosts_match(saved_url: &str, requested_url: &str) -> bool {
    let (Some(saved), Some(requested)) = (hostname(saved_url), hostname(requested_url)) else {
        return false;
    };
    if let Some(base) = saved.strip_prefix("*.") {
        // Wildcards must be rooted at a registrable domain, never a public
        // suffix such as "com", "co.uk", or "github.io".
        return psl::domain_str(base) == Some(base)
            && requested != base
            && requested.ends_with(&format!(".{base}"));
    }
    saved == requested
}

fn is_otpauth_uri(value: &str) -> bool {
    value
        .get(.."otpauth://".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("otpauth://"))
}

const MIN_COMPATIBLE_TOTP_SECRET_BYTES: usize = 10;

fn compatible_totp_from_url(value: &str) -> Result<Totp, String> {
    match Totp::from_url(value) {
        Ok(totp) => Ok(totp),
        Err(TotpError::SecretTooShort { bits }) if bits >= MIN_COMPATIBLE_TOTP_SECRET_BYTES * 8 => {
            let totp = Totp::from_url_unchecked(value)
                .map_err(|error| format!("invalid otpauth URI: {error}"))?;
            if !(6..=8).contains(&totp.digits()) {
                return Err(format!(
                    "invalid otpauth URI: unsupported digit count {}",
                    totp.digits()
                ));
            }
            if totp.step() == 0 {
                return Err("invalid otpauth URI: period cannot be zero".to_string());
            }
            Ok(totp)
        }
        Err(error) => Err(format!("invalid otpauth URI: {error}")),
    }
}

fn compatible_totp_from_secret(secret: TotpSecret) -> Result<Totp, String> {
    let secret_bytes = secret.as_ref().len();
    if secret_bytes < MIN_COMPATIBLE_TOTP_SECRET_BYTES {
        return Err(format!(
            "TOTP secret must be at least {} bits, got {} bits",
            MIN_COMPATIBLE_TOTP_SECRET_BYTES * 8,
            secret_bytes * 8
        ));
    }
    let builder = TotpBuilder::new().with_secret(secret);
    if secret_bytes < 16 {
        Ok(builder.build_noncompliant())
    } else {
        builder
            .build()
            .map_err(|error| format!("invalid TOTP configuration: {error}"))
    }
}

fn normalize_totp_configuration(value: &str) -> Result<(String, usize), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("TOTP configuration cannot be empty".to_string());
    }
    if trimmed.len() > 4096 {
        return Err("TOTP configuration is too long".to_string());
    }
    if is_otpauth_uri(trimmed) {
        let totp = compatible_totp_from_url(trimmed)?;
        return Ok((trimmed.to_string(), totp.secret().as_ref().len() * 8));
    }

    let mut normalized: String = trimmed
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '-')
        .flat_map(char::to_uppercase)
        .collect();
    let secret = match TotpSecret::try_from_base32(&normalized) {
        Ok(secret) => secret,
        Err(error) => {
            normalized.zeroize();
            return Err(format!("invalid Base32 TOTP secret: {error}"));
        }
    };
    let secret_bits = secret.as_ref().len() * 8;
    if let Err(error) = compatible_totp_from_secret(secret) {
        normalized.zeroize();
        return Err(error);
    }
    Ok((normalized, secret_bits))
}

fn parse_totp_configuration(value: &str) -> Result<Totp, String> {
    if is_otpauth_uri(value) {
        compatible_totp_from_url(value)
    } else {
        let secret = TotpSecret::try_from_base32(value)
            .map_err(|error| format!("invalid Base32 TOTP secret: {error}"))?;
        compatible_totp_from_secret(secret)
    }
}

fn normalized_header(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn csv_field(headers: &[String], record: &csv::StringRecord, aliases: &[&str]) -> Option<String> {
    headers
        .iter()
        .position(|header| aliases.contains(&header.as_str()))
        .and_then(|index| record.get(index))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn import_csv(contents: &str, path: &str) -> Result<Vec<VaultEntry>, String> {
    let mut reader = csv::Reader::from_reader(contents.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| format!("invalid CSV headers in {path:?}: {e}"))?
        .iter()
        .map(normalized_header)
        .collect();
    let mut entries = Vec::new();
    for row in reader.records() {
        let row = row.map_err(|e| format!("invalid CSV data in {path:?}: {e}"))?;
        let name = csv_field(&headers, &row, &["name", "title"])
            .or_else(|| csv_field(&headers, &row, &["url", "website", "loginuri"]))
            .ok_or_else(|| format!("an imported CSV row in {path:?} has no name or URL"))?;
        let password = csv_field(&headers, &row, &["password"])
            .ok_or_else(|| format!("an imported CSV row in {path:?} has no password"))?;
        let now = chrono::Local::now().to_string();
        entries.push(VaultEntry {
            id: 0,
            name,
            username: csv_field(&headers, &row, &["username", "loginusername", "login"]),
            password,
            url: csv_field(
                &headers,
                &row,
                &["url", "website", "loginuri", "formactionorigin"],
            ),
            notes: csv_field(&headers, &row, &["notes", "note", "extra", "comments"]),
            created: csv_field(&headers, &row, &["created", "timecreated"])
                .unwrap_or_else(|| now.clone()),
            modified: csv_field(
                &headers,
                &row,
                &["modified", "timemodified", "timepasswordchanged"],
            )
            .unwrap_or(now),
        });
    }
    Ok(entries)
}

fn json_text(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(serde_json::Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn import_json(contents: &str, path: &str) -> Result<Vec<VaultEntry>, String> {
    let root: serde_json::Value =
        serde_json::from_str(contents).map_err(|e| format!("invalid JSON in {path:?}: {e}"))?;
    let bitwarden = root.get("items").is_some();
    let values = if let Some(items) = root.get("items").and_then(serde_json::Value::as_array) {
        items
    } else {
        root.as_array().ok_or_else(|| {
            "JSON import must be an array or a Bitwarden object with items".to_string()
        })?
    };
    let mut entries = Vec::new();
    for value in values {
        if bitwarden && value.get("type").and_then(serde_json::Value::as_u64) != Some(1) {
            continue;
        }
        let login = value.get("login").unwrap_or(value);
        let url = json_text(value, &["url", "website"]).or_else(|| {
            login
                .get("uris")
                .and_then(serde_json::Value::as_array)
                .and_then(|uris| uris.first())
                .and_then(|uri| json_text(uri, &["uri"]))
        });
        let name = json_text(value, &["name", "title"])
            .or_else(|| url.clone())
            .ok_or_else(|| format!("an imported JSON item in {path:?} has no name or URL"))?;
        let password = json_text(login, &["password"])
            .or_else(|| json_text(value, &["password"]))
            .ok_or_else(|| format!("an imported JSON item in {path:?} has no password"))?;
        let now = chrono::Local::now().to_string();
        entries.push(VaultEntry {
            id: 0,
            name,
            username: json_text(login, &["username", "login"]),
            password,
            url,
            notes: json_text(value, &["notes", "note"]),
            created: json_text(value, &["created", "creationDate"]).unwrap_or_else(|| now.clone()),
            modified: json_text(value, &["modified", "revisionDate"]).unwrap_or(now),
        });
    }
    if entries.is_empty() {
        return Err(format!("no supported login entries were found in {path:?}"));
    }
    Ok(entries)
}

impl Vault {
    const MAX_PASSWORD_HISTORY: usize = 10;

    fn ensure_next_entry_id(&mut self) -> Result<(), String> {
        let highest_id = self
            .entries
            .iter()
            .map(|entry| entry.id)
            .chain(self.recovery.trash.iter().map(|trashed| trashed.entry.id))
            .max()
            .unwrap_or(0);
        if self.recovery.next_entry_id <= highest_id {
            self.recovery.next_entry_id = highest_id
                .checked_add(1)
                .ok_or_else(|| "entry ID space is exhausted".to_string())?;
        }
        if self.recovery.next_entry_id == 0 {
            self.recovery.next_entry_id = 1;
        }
        Ok(())
    }

    fn allocate_entry_id(&mut self) -> Result<usize, String> {
        self.ensure_next_entry_id()?;
        let id = self.recovery.next_entry_id;
        self.recovery.next_entry_id = id
            .checked_add(1)
            .ok_or_else(|| "entry ID space is exhausted".to_string())?;
        Ok(id)
    }

    fn entry_index(&self, target: &Target) -> Option<usize> {
        match target {
            Target::Id(id) => self.entries.iter().position(|entry| entry.id == *id),
            Target::Name(name) => self.entries.iter().position(|entry| entry.name == *name),
            Target::Url(_) | Target::Vault(_) => None,
        }
    }

    fn push_password_history(&mut self, entry_id: usize, password: String) {
        self.recovery.password_history.push(PasswordRevision {
            entry_id,
            password,
            changed: chrono::Local::now().to_string(),
        });
        let count = self
            .recovery
            .password_history
            .iter()
            .filter(|revision| revision.entry_id == entry_id)
            .count();
        if count > Self::MAX_PASSWORD_HISTORY
            && let Some(index) = self
                .recovery
                .password_history
                .iter()
                .position(|revision| revision.entry_id == entry_id)
        {
            let mut removed = self.recovery.password_history.remove(index);
            removed.zeroize();
        }
    }

    pub fn rekey(
        &mut self,
        server_info: &mut ServerInfo,
        mut new_key: PasswordType,
    ) -> Result<(), String> {
        if let PasswordType::Key(path) = &new_key
            && data_dir().join(path).exists()
        {
            return Err("the new key file already exists".to_string());
        }
        let old_filename = self.metadata.filename.clone();
        let new_filename = try_get_filename(&mut new_key, true)?;
        let new_path = data_dir().join(&new_filename);
        if new_path.exists() {
            if let PasswordType::Key(path) = &new_key {
                let _ = fs::remove_file(data_dir().join(path));
            }
            return Err("a vault already exists for the new password or key".to_string());
        }

        self.metadata.filename = new_filename.clone();
        let mut replacement = ServerInfo {
            locked: false,
            keypass: Some(new_key.clone()),
        };
        if let Err(error) = write_vault(self, &mut replacement) {
            replacement.zeroize();
            self.metadata.filename = old_filename;
            if let PasswordType::Key(path) = &new_key {
                let _ = fs::remove_file(data_dir().join(path));
            }
            return Err(error);
        }
        if let Err(error) = fs::remove_file(data_dir().join(&old_filename)) {
            replacement.zeroize();
            let _ = fs::remove_file(&new_path);
            if let PasswordType::Key(path) = &new_key {
                let _ = fs::remove_file(data_dir().join(path));
            }
            self.metadata.filename = old_filename;
            return Err(format!("could not replace the old vault: {error}"));
        }
        replacement.zeroize();
        if let Some(mut old_key) = server_info.keypass.replace(new_key) {
            old_key.zeroize();
        }
        Ok(())
    }

    pub async fn get_entry(&self, a: Target, stream: &mut TcpStream, http: bool) {
        match a {
            Target::Id(i) => {
                let Some(entry) = self.entries.iter().find(|entry| entry.id == i) else {
                    respond("Invalid id.", stream, http).await;
                    return;
                };
                respond(&format!("{:?}\n", entry), stream, http).await;
                copy_in_background(entry.password.clone(), 15);
            }
            Target::Name(name) => {
                if let Some(entry) = self.entries.iter().find(|entry| entry.name == name) {
                    respond(&format!("{:?}\n", entry), stream, http).await;
                    copy_in_background(entry.password.clone(), 15);
                } else {
                    respond("Not found.\n", stream, http).await;
                }
            }
            Target::Url(u) => {
                if let Some(json) = url_match_json(&self.entries, &self.recovery.totp, &u) {
                    respond(&json, stream, http).await;
                } else {
                    respond("Not found.\n", stream, http).await;
                }
            }
            Target::Vault(_) => respond("Invalid entry selector.", stream, http).await,
        }
    }

    pub fn add_entry(
        &mut self,
        info: PasswordEntry,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        if self
            .entries
            .iter()
            .any(|entry| entry.name == info.name && entry.username == info.username)
        {
            return Ok(false);
        }

        let next_entry_id_before = self.recovery.next_entry_id;
        let id = self.allocate_entry_id()?;
        let now = chrono::Local::now().to_string();
        self.entries.push(VaultEntry {
            id,
            name: info.name,
            username: info.username,
            password: info.password,
            url: info.url,
            notes: info.notes,
            created: now.clone(),
            modified: now,
        });
        if let Err(error) = write_vault(self, key_pass) {
            self.entries.pop();
            self.recovery.next_entry_id = next_entry_id_before;
            return Err(error);
        }
        Ok(true)
    }

    pub fn delete_entry(
        &mut self,
        target: Target,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        let index = self.entry_index(&target);
        let Some(index) = index else {
            return Ok(false);
        };

        let mut recovery_before = self.recovery.clone();
        let mut removed = self.entries.remove(index);
        let removed_id = removed.id;
        let mut history = Vec::new();
        for revision in std::mem::take(&mut self.recovery.password_history) {
            if revision.entry_id == removed_id {
                history.push(revision);
            } else {
                self.recovery.password_history.push(revision);
            }
        }
        self.recovery.trash.push(TrashedEntry {
            entry: removed.clone(),
            history,
            deleted: chrono::Local::now().to_string(),
        });
        if let Err(error) = write_vault(self, key_pass) {
            self.entries.insert(index, removed);
            self.recovery.zeroize();
            self.recovery = recovery_before;
            return Err(error);
        }
        removed.zeroize();
        recovery_before.zeroize();
        Ok(true)
    }

    pub fn update_entry(
        &mut self,
        change: EntryUpdate,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        let EntryUpdate {
            target,
            update,
            password,
        } = change;
        let index = self.entry_index(&target);
        let Some(index) = index else {
            return Ok(false);
        };

        let mut original = self.entries[index].clone();
        let mut recovery_before = self.recovery.clone();
        let old_password = (update.password
            && password
                .as_ref()
                .is_some_and(|new_password| *new_password != original.password))
        .then(|| original.password.clone());
        let modified = apply_update(&mut self.entries[index], update, password);
        if let Some(old_password) = old_password {
            self.push_password_history(original.id, old_password);
        }
        if modified && let Err(error) = write_vault(self, key_pass) {
            self.entries[index] = original;
            self.recovery.zeroize();
            self.recovery = recovery_before;
            return Err(error);
        }
        original.zeroize();
        recovery_before.zeroize();
        Ok(modified)
    }

    pub fn set_totp(
        &mut self,
        target: Target,
        configuration: &str,
        key_pass: &mut ServerInfo,
    ) -> Result<Option<usize>, String> {
        let Some(entry_index) = self.entry_index(&target) else {
            return Ok(None);
        };
        let (normalized, secret_bits) = normalize_totp_configuration(configuration)?;
        let entry_id = self.entries[entry_index].id;
        let mut recovery_before = self.recovery.clone();
        let mut modified_before = self.entries[entry_index].modified.clone();

        if let Some(record) = self
            .recovery
            .totp
            .iter_mut()
            .find(|record| record.entry_id == entry_id)
        {
            record.configuration.zeroize();
            record.configuration = normalized;
        } else {
            self.recovery.totp.push(TotpRecord {
                entry_id,
                configuration: normalized,
            });
        }
        self.entries[entry_index].modified = chrono::Local::now().to_string();

        if let Err(error) = write_vault(self, key_pass) {
            self.entries[entry_index].modified.zeroize();
            self.entries[entry_index].modified = modified_before;
            self.recovery.zeroize();
            self.recovery = recovery_before;
            return Err(error);
        }
        modified_before.zeroize();
        recovery_before.zeroize();
        Ok(Some(secret_bits))
    }

    pub fn remove_totp(
        &mut self,
        target: Target,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        let Some(entry_index) = self.entry_index(&target) else {
            return Ok(false);
        };
        let entry_id = self.entries[entry_index].id;
        let Some(record_index) = self
            .recovery
            .totp
            .iter()
            .position(|record| record.entry_id == entry_id)
        else {
            return Ok(false);
        };
        let mut recovery_before = self.recovery.clone();
        let mut modified_before = self.entries[entry_index].modified.clone();
        let mut removed = self.recovery.totp.remove(record_index);
        removed.zeroize();
        self.entries[entry_index].modified = chrono::Local::now().to_string();

        if let Err(error) = write_vault(self, key_pass) {
            self.entries[entry_index].modified.zeroize();
            self.entries[entry_index].modified = modified_before;
            self.recovery.zeroize();
            self.recovery = std::mem::take(&mut recovery_before);
            return Err(error);
        }
        modified_before.zeroize();
        recovery_before.zeroize();
        Ok(true)
    }

    fn totp_at(&self, target: &Target, timestamp: u64) -> Result<(String, u64), String> {
        let Some(entry_index) = self.entry_index(target) else {
            return Err("entry not found".to_string());
        };
        let entry_id = self.entries[entry_index].id;
        let record = self
            .recovery
            .totp
            .iter()
            .find(|record| record.entry_id == entry_id)
            .ok_or_else(|| "entry has no TOTP authenticator".to_string())?;
        let totp = parse_totp_configuration(&record.configuration)?;
        let ttl = totp.step() - (timestamp % totp.step());
        Ok((totp.generate(timestamp).to_string(), ttl))
    }

    pub fn current_totp(&self, target: Target) -> Result<(String, u64), String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_string())?
            .as_secs();
        self.totp_at(&target, timestamp)
    }

    pub async fn view_password_history(&self, target: Target, stream: &mut TcpStream, http: bool) {
        let Some(index) = self.entry_index(&target) else {
            respond("Entry not found.", stream, http).await;
            return;
        };
        let entry = &self.entries[index];
        let revisions: Vec<_> = self
            .recovery
            .password_history
            .iter()
            .filter(|revision| revision.entry_id == entry.id)
            .rev()
            .collect();
        if revisions.is_empty() {
            respond("No password history.", stream, http).await;
            return;
        }
        for (index, revision) in revisions.iter().enumerate() {
            respond(
                &format!("{}. changed {}\n", index + 1, revision.changed),
                stream,
                http,
            )
            .await;
        }
    }

    pub fn restore_password(
        &mut self,
        target: Target,
        revision: usize,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        let Some(entry_index) = self.entry_index(&target) else {
            return Ok(false);
        };
        let entry_id = self.entries[entry_index].id;
        let history_indices: Vec<_> = self
            .recovery
            .password_history
            .iter()
            .enumerate()
            .filter_map(|(index, item)| (item.entry_id == entry_id).then_some(index))
            .collect();
        let Some(history_index) = revision
            .checked_sub(1)
            .and_then(|offset| history_indices.iter().rev().nth(offset))
            .copied()
        else {
            return Err("invalid password-history revision".to_string());
        };
        let mut entries_before = self.entries.clone();
        let mut recovery_before = self.recovery.clone();
        let mut selected = self.recovery.password_history.remove(history_index);
        let current = std::mem::replace(&mut self.entries[entry_index].password, selected.password);
        selected.password = current;
        selected.changed = chrono::Local::now().to_string();
        self.recovery.password_history.push(selected);
        self.entries[entry_index].modified = chrono::Local::now().to_string();
        if let Err(error) = write_vault(self, key_pass) {
            self.entries.zeroize();
            self.entries = std::mem::take(&mut entries_before);
            self.recovery.zeroize();
            self.recovery = std::mem::take(&mut recovery_before);
            return Err(error);
        }
        entries_before.zeroize();
        recovery_before.zeroize();
        Ok(true)
    }

    pub async fn view_trash(&self, stream: &mut TcpStream, http: bool) {
        if self.recovery.trash.is_empty() {
            respond("Trash is empty.", stream, http).await;
            return;
        }
        for (index, item) in self.recovery.trash.iter().enumerate() {
            let totp = self.totp_marker(item.entry.id);
            respond(
                &format!(
                    "{}. {} {:?} deleted {}{}\n",
                    index + 1,
                    item.entry.name,
                    item.entry.username,
                    item.deleted,
                    totp
                ),
                stream,
                http,
            )
            .await;
        }
    }

    pub fn restore_trashed(
        &mut self,
        trash_id: usize,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        let Some(index) = trash_id
            .checked_sub(1)
            .filter(|index| *index < self.recovery.trash.len())
        else {
            return Ok(false);
        };
        let mut recovery_before = self.recovery.clone();
        let mut trashed = self.recovery.trash.remove(index);
        if self.entries.iter().any(|entry| {
            entry.name == trashed.entry.name && entry.username == trashed.entry.username
        }) {
            self.recovery.zeroize();
            self.recovery = std::mem::take(&mut recovery_before);
            trashed.zeroize();
            return Err(
                "an active entry with the same name and username already exists".to_string(),
            );
        }
        let restored_id = trashed.entry.id;
        if self.entries.iter().any(|entry| entry.id == restored_id) {
            self.recovery.zeroize();
            self.recovery = std::mem::take(&mut recovery_before);
            trashed.zeroize();
            return Err("an active entry already uses this stable ID".to_string());
        }
        for revision in &mut trashed.history {
            revision.entry_id = restored_id;
        }
        self.recovery.password_history.append(&mut trashed.history);
        self.entries.push(trashed.entry);
        if let Err(error) = write_vault(self, key_pass) {
            self.entries.pop().zeroize();
            self.recovery.zeroize();
            self.recovery = std::mem::take(&mut recovery_before);
            return Err(error);
        }
        recovery_before.zeroize();
        Ok(true)
    }

    pub fn purge_trash(
        &mut self,
        trash_id: Option<usize>,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        let mut recovery_before = self.recovery.clone();
        let changed = if let Some(id) = trash_id {
            let Some(index) = id
                .checked_sub(1)
                .filter(|index| *index < self.recovery.trash.len())
            else {
                return Ok(false);
            };
            let mut removed = self.recovery.trash.remove(index);
            let removed_id = removed.entry.id;
            removed.zeroize();
            self.remove_totp_records(&[removed_id]);
            true
        } else {
            let changed = !self.recovery.trash.is_empty();
            let removed_ids = self
                .recovery
                .trash
                .iter()
                .map(|trashed| trashed.entry.id)
                .collect::<Vec<_>>();
            self.recovery.trash.zeroize();
            self.remove_totp_records(&removed_ids);
            changed
        };
        if changed && let Err(error) = write_vault(self, key_pass) {
            self.recovery.zeroize();
            self.recovery = std::mem::take(&mut recovery_before);
            return Err(error);
        }
        recovery_before.zeroize();
        Ok(changed)
    }

    fn remove_totp_records(&mut self, entry_ids: &[usize]) {
        let mut retained = Vec::with_capacity(self.recovery.totp.len());
        for mut record in std::mem::take(&mut self.recovery.totp) {
            if entry_ids.contains(&record.entry_id) {
                record.zeroize();
            } else {
                retained.push(record);
            }
        }
        self.recovery.totp = retained;
    }

    fn totp_marker(&self, entry_id: usize) -> &'static str {
        if self
            .recovery
            .totp
            .iter()
            .any(|record| record.entry_id == entry_id)
        {
            " [TOTP]"
        } else {
            ""
        }
    }

    fn audit_report(&self) -> String {
        let mut weak = Vec::new();
        let mut passwords: HashMap<&str, Vec<&VaultEntry>> = HashMap::new();
        let mut identities: HashMap<(String, String), Vec<&VaultEntry>> = HashMap::new();
        for entry in &self.entries {
            if zxcvbn::zxcvbn(&entry.password, &[]).score() <= zxcvbn::Score::Two {
                weak.push(entry);
            }
            passwords.entry(&entry.password).or_default().push(entry);
            let identity = (
                entry
                    .url
                    .as_deref()
                    .and_then(hostname)
                    .unwrap_or_else(|| entry.name.to_ascii_lowercase()),
                entry.username.as_deref().unwrap_or("").to_ascii_lowercase(),
            );
            identities.entry(identity).or_default().push(entry);
        }
        let reused: Vec<_> = passwords
            .values()
            .filter(|entries| entries.len() > 1)
            .collect();
        let duplicates: Vec<_> = identities
            .values()
            .filter(|entries| entries.len() > 1)
            .collect();
        let mut report = format!(
            "Audit: {} weak entries, {} reused-password groups, {} duplicate-login groups.\n",
            weak.len(),
            reused.len(),
            duplicates.len()
        );
        for entry in weak {
            report.push_str(&format!(
                "Weak: {}. {} {:?}\n",
                entry.id, entry.name, entry.username
            ));
        }
        for entries in reused {
            let labels = entries
                .iter()
                .map(|entry| format!("{}. {}", entry.id, entry.name))
                .collect::<Vec<_>>()
                .join(", ");
            report.push_str(&format!("Reused password: {labels}\n"));
        }
        for entries in duplicates {
            let labels = entries
                .iter()
                .map(|entry| format!("{}. {}", entry.id, entry.name))
                .collect::<Vec<_>>()
                .join(", ");
            report.push_str(&format!("Duplicate login: {labels}\n"));
        }
        report
    }

    pub async fn audit(&self, stream: &mut TcpStream, http: bool) {
        respond(&self.audit_report(), stream, http).await;
    }

    pub async fn view_entries(&self, stream: &mut TcpStream, http: bool) {
        if self.entries.is_empty() {
            respond("No entries.", stream, http).await;
            return;
        }
        for entry in &self.entries {
            let totp = self.totp_marker(entry.id);
            respond(
                &format!(
                    "{}. {} {:?} {:?} {:?}{}\n",
                    entry.id, entry.name, entry.username, entry.url, entry.notes, totp
                ),
                stream,
                http,
            )
            .await;
        }
    }

    fn search_entries(&self, filter: &SearchFilter) -> Vec<&VaultEntry> {
        fn field_matches(value: Option<&str>, needle: Option<&str>) -> bool {
            needle.is_none_or(|needle| {
                value.is_some_and(|value| value.to_lowercase().contains(&needle.to_lowercase()))
            })
        }

        let query = filter.query.as_ref().map(|query| query.to_lowercase());
        self.entries
            .iter()
            .filter(|entry| {
                let query_matches = query.as_ref().is_none_or(|query| {
                    entry.name.to_lowercase().contains(query)
                        || entry
                            .username
                            .as_deref()
                            .is_some_and(|value| value.to_lowercase().contains(query))
                        || entry
                            .url
                            .as_deref()
                            .is_some_and(|value| value.to_lowercase().contains(query))
                        || entry
                            .notes
                            .as_deref()
                            .is_some_and(|value| value.to_lowercase().contains(query))
                });
                query_matches
                    && field_matches(Some(&entry.name), filter.name.as_deref())
                    && field_matches(entry.username.as_deref(), filter.username.as_deref())
                    && field_matches(entry.url.as_deref(), filter.url.as_deref())
                    && field_matches(entry.notes.as_deref(), filter.notes.as_deref())
            })
            .collect()
    }

    pub async fn search(&self, filter: SearchFilter, stream: &mut TcpStream, http: bool) {
        let entries = self.search_entries(&filter);
        if entries.is_empty() {
            respond("No matching entries.", stream, http).await;
            return;
        }
        for entry in entries {
            let totp = self.totp_marker(entry.id);
            respond(
                &format!(
                    "{}. {} {:?} {:?} {:?}{}\n",
                    entry.id, entry.name, entry.username, entry.url, entry.notes, totp
                ),
                stream,
                http,
            )
            .await;
        }
    }

    pub fn lock_vault(&self, key_pass: &mut ServerInfo) -> Result<(), String> {
        write_vault(self, key_pass)?;
        key_pass.zeroize();
        Ok(())
    }
    pub fn export(&self, path: String) -> Result<(), String> {
        println!("WARNING: Export writes passwords as plaintext. Delete the file after use.");
        if std::path::Path::new(&path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        {
            let encoded = serde_json::to_vec_pretty(&self.entries)
                .map_err(|e| format!("could not encode JSON export: {e}"))?;
            fs::write(&path, encoded)
                .map_err(|e| format!("could not create export file {path:?}: {e}"))?;
            set_private_perms(std::path::Path::new(&path))
                .map_err(|e| format!("could not protect export file {path:?}: {e}"))?;
            return Ok(());
        }
        let mut wtr = csv::Writer::from_path(&path)
            .map_err(|e| format!("could not create export file {path:?}: {e}"))?;
        set_private_perms(std::path::Path::new(&path))
            .map_err(|e| format!("could not protect export file {path:?}: {e}"))?;
        for i in &self.entries {
            wtr.serialize(i)
                .map_err(|e| format!("could not write export file {path:?}: {e}"))?;
        }
        wtr.flush()
            .map_err(|e| format!("could not finish export file {path:?}: {e}"))
    }
    pub fn import(&mut self, path: String) -> Result<(), String> {
        let contents = fs::read_to_string(&path)
            .map_err(|e| format!("could not open import file {path:?}: {e}"))?;
        let trimmed = contents.trim_start();
        let imported = if trimmed.starts_with('{') || trimmed.starts_with('[') {
            import_json(&contents, &path)?
        } else {
            import_csv(&contents, &path)?
        };
        for mut entry in imported {
            let duplicate = self.entries.iter().any(|existing| {
                existing.name == entry.name
                    && existing.username == entry.username
                    && existing.url == entry.url
            });
            if !duplicate {
                entry.id = self.allocate_entry_id()?;
                self.entries.push(entry);
            }
        }
        Ok(())
    }
}

fn apply_update(
    entry: &mut VaultEntry,
    update: crate::cli::UpdateArgs,
    password: Option<String>,
) -> bool {
    let mut modified = false;
    if let Some(name) = update.name {
        entry.name = name;
        modified = true;
    }
    if let Some(notes) = update.notes {
        entry.notes = Some(notes);
        modified = true;
    }
    if update.password
        && let Some(password) = password
    {
        entry.password = password;
        modified = true;
    }
    if let Some(url) = update.url {
        entry.url = Some(url);
        modified = true;
    }
    if let Some(username) = update.username {
        entry.username = Some(username);
        modified = true;
    }
    if modified {
        entry.modified = chrono::Local::now().to_string();
    }
    modified
}

pub trait VaultAccess {
    async fn get_entry(&self, a: Target, stream: &mut TcpStream, http: bool);
    fn add_entry(&mut self, info: PasswordEntry, key_pass: &mut ServerInfo)
    -> Result<bool, String>;
    fn delete_entry(&mut self, id: Target, key_pass: &mut ServerInfo) -> Result<bool, String>;
    fn update_entry(&mut self, add: EntryUpdate, key_pass: &mut ServerInfo)
    -> Result<bool, String>;
    async fn view_entries(&self, stream: &mut TcpStream, http: bool);
    fn lock_vault(&self, key_pass: &mut ServerInfo) -> Result<(), String>;
    fn unlock_vault(&mut self, key_pass: &mut ServerInfo) -> Result<(), String>;
    fn export(&self, path: String) -> Result<(), String>;
    fn import(&mut self, path: String) -> Result<(), String>;
}

impl VaultAccess for Option<Vault> {
    async fn get_entry(&self, a: Target, stream: &mut TcpStream, http: bool) {
        if let Some(vlt) = self {
            vlt.get_entry(a, stream, http).await
        }
    }
    fn add_entry(
        &mut self,
        info: PasswordEntry,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        match self {
            Some(vlt) => vlt.add_entry(info, key_pass),
            None => Err("vault is locked".to_string()),
        }
    }
    fn delete_entry(&mut self, id: Target, key_pass: &mut ServerInfo) -> Result<bool, String> {
        match self {
            Some(vlt) => vlt.delete_entry(id, key_pass),
            None => Err("vault is locked".to_string()),
        }
    }

    fn update_entry(
        &mut self,
        add: EntryUpdate,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        match self {
            Some(vlt) => vlt.update_entry(add, key_pass),
            None => Err("vault is locked".to_string()),
        }
    }
    async fn view_entries(&self, stream: &mut TcpStream, http: bool) {
        if let Some(vlt) = self {
            vlt.view_entries(stream, http).await;
        }
    }
    fn lock_vault(&self, key_pass: &mut ServerInfo) -> Result<(), String> {
        if let Some(vlt) = self {
            vlt.lock_vault(key_pass)?;
        }
        key_pass.zeroize();
        Ok(())
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
            None => Err("wrong master password, or no vault exists for this key".to_string()),
        }
    }
    fn export(&self, path: String) -> Result<(), String> {
        if let Some(vlt) = self {
            vlt.export(path)
        } else {
            Err("vault is locked".to_string())
        }
    }
    fn import(&mut self, path: String) -> Result<(), String> {
        if let Some(vlt) = self {
            vlt.import(path)
        } else {
            Err("vault is locked".to_string())
        }
    }
}
pub fn delete_vault(mut key: PasswordType) -> Result<(), String> {
    let data = data_dir();
    if let PasswordType::Key(key_path) = &key
        && !data.join(key_path).is_file()
    {
        return Err("key file does not exist or is not a regular file".to_string());
    }
    let filename = try_get_filename(&mut key, false)?;
    fs::remove_file(data.join(filename))
        .map_err(|e| format!("could not delete vault (is the key correct?): {e}"))?;
    if let PasswordType::Key(key) = key {
        fs::remove_file(data.join(key))
            .map_err(|e| format!("vault deleted, but could not delete its key file: {e}"))?;
    }
    Ok(())
}
#[cfg(test)]
mod test {
    #![allow(unused_must_use)]
    use super::*;
    use crate::cli::UpdateArgs;
    use crate::encryption::gen_master_key;
    use crate::file::init_test_data_dir;
    use chrono::FixedOffset;
    use std::{fs, path::Path, thread};

    fn time_close(time: String) -> bool {
        let thing =
            chrono::DateTime::<FixedOffset>::parse_from_str(&time, "%Y-%m-%d %H:%M:%S%.f %:z")
                .unwrap();
        let diff = chrono::Local::now().signed_duration_since(thing);
        diff.num_seconds() < 1
    }

    #[test]
    fn renamed_entries_field_preserves_compact_vault_format() {
        #[derive(Serialize)]
        struct LegacyVault {
            enteries: Vec<VaultEntry>,
            metadata: VaultMetadata,
        }

        let legacy = LegacyVault {
            enteries: vec![VaultEntry {
                id: 1,
                name: "example".to_string(),
                password: "secret".to_string(),
                ..VaultEntry::default()
            }],
            metadata: VaultMetadata {
                filename: "legacy.enc".to_string(),
            },
        };
        let encoded = rmp_serde::to_vec(&legacy).unwrap();
        let decoded: Vault = rmp_serde::from_slice(&encoded).unwrap();

        assert_eq!(decoded.entries[0].name, "example");
        assert_eq!(decoded.metadata.filename, "legacy.enc");
    }

    #[test]
    fn test_url_match_json_escapes_special_chars() {
        let entries = vec![VaultEntry {
            id: 1,
            name: String::from("site\"with\"quote"),
            username: Some(String::from("bob")),
            password: String::from("pa\"ss\\wrd"),
            url: Some(String::from("example.com")),
            notes: None,
            created: String::from("2026-01-01"),
            modified: String::from("2026-01-01"),
        }];
        let totp = vec![TotpRecord {
            entry_id: 1,
            configuration: "secret-never-exported".into(),
        }];
        let json = url_match_json(&entries, &totp, "example.com").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["password"], "pa\"ss\\wrd");
        assert_eq!(parsed[0]["name"], "site\"with\"quote");
        assert_eq!(parsed[0]["username"], "bob");
        assert_eq!(parsed[0]["id"], 1);
        assert_eq!(parsed[0]["has_totp"], true);
        assert!(!json.contains("secret-never-exported"));
    }
    #[test]
    fn test_url_match_json_no_match_returns_none() {
        let entries = vec![VaultEntry {
            id: 1,
            name: String::from("x"),
            username: None,
            password: String::from("p"),
            url: Some(String::from("other.com")),
            notes: None,
            created: String::from("2026-01-01"),
            modified: String::from("2026-01-01"),
        }];
        assert!(url_match_json(&entries, &[], "example.com").is_none());
    }

    #[test]
    fn test_url_match_json_rejects_substring_lookalike() {
        let entries = vec![VaultEntry {
            id: 1,
            name: String::from("lookalike"),
            username: Some(String::from("alice")),
            password: String::from("secret"),
            url: Some(String::from("https://notexample.com/login")),
            notes: None,
            created: String::from("2026-01-01"),
            modified: String::from("2026-01-01"),
        }];
        assert!(url_match_json(&entries, &[], "example.com").is_none());
    }

    #[test]
    fn test_hostname_ignores_scheme_path_port_and_case() {
        assert!(hosts_match("HTTPS://Example.COM:443/login", "example.com"));
    }
    #[test]
    fn test_domain_matching_is_exact_by_default() {
        assert!(!hosts_match("example.com", "login.example.com"));
        assert!(!hosts_match("mail.example.com", "example.com"));
    }
    #[test]
    fn test_explicit_wildcard_matches_only_subdomains() {
        assert!(hosts_match("*.example.com", "login.example.com"));
        assert!(!hosts_match("*.example.com", "example.com"));
        assert!(!hosts_match("*.github.io", "attacker.github.io"));
    }
    #[test]
    fn test_url_match_json_partial_match() {
        let entries = vec![VaultEntry {
            id: 2,
            name: String::from("x"),
            username: None,
            password: String::from("p"),
            url: Some(String::from("*.example.com")),
            notes: None,
            created: String::from("2026-01-01"),
            modified: String::from("2026-01-01"),
        }];
        let json = url_match_json(&entries, &[], "mail.example.com").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["id"], 2);
        assert_eq!(parsed[0]["has_totp"], false);
    }
    #[test]
    fn test_add_entry_returns_false_for_duplicate() {
        let mut vlt = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        let entry = PasswordEntry {
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
        assert!(vlt.add_entry(entry.clone(), &mut si).unwrap());
        assert!(!vlt.add_entry(entry, &mut si).unwrap());
    }
    #[test]
    fn test_delete_entry_returns_false_when_not_found() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        let mut si = ServerInfo {
            locked: true,
            keypass: None,
        };
        assert!(
            !vlt.delete_entry(Target::Name("nope".into()), &mut si)
                .unwrap()
        );
        assert!(
            vlt.delete_entry(Target::Name("test".into()), &mut si)
                .unwrap()
        );
    }
    #[test]
    fn test_update_entry_returns_false_when_not_found() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        let mut si = ServerInfo {
            locked: true,
            keypass: None,
        };
        let upd = EntryUpdate {
            target: Target::Name("nope".into()),
            update: UpdateArgs {
                name: Some("x".into()),
                username: None,
                password: false,
                generate_password: false,
                url: None,
                notes: None,
            },
            password: None,
        };
        assert!(!vlt.update_entry(upd, &mut si).unwrap());
    }
    #[test]
    fn test_add_entry() {
        let mut vault: Vault = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vault.add_entry(
            PasswordEntry {
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
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: vault.entries[0].created.clone(),
                modified: vault.entries[0].modified.clone(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData {
                next_entry_id: 2,
                ..RecoveryData::default()
            },
        };
        assert_eq!(vault, expected);
        assert!(time_close(vault.entries[0].created.clone()));
        assert!(time_close(vault.entries[0].modified.clone()));
    }
    #[test]
    fn test_delete_id() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        vlt.delete_entry(
            Target::Id(1),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert!(vlt.entries.is_empty());
        assert_eq!(vlt.recovery.trash.len(), 1);
        assert_eq!(vlt.recovery.trash[0].entry.name, "test");
    }
    #[test]
    fn test_delete_name() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        vlt.delete_entry(
            Target::Name("test".into()),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert!(vlt.entries.is_empty());
        assert_eq!(vlt.recovery.trash.len(), 1);
        assert_eq!(vlt.recovery.trash[0].entry.name, "test");
    }
    #[test]
    fn test_update_id() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        vlt.update_entry(
            EntryUpdate {
                target: Target::Id(1),
                update: UpdateArgs {
                    name: Some(String::from("test2")),
                    username: Some(String::from("test2")),
                    password: false,
                    generate_password: false,
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
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test2"),
                username: Some(String::from("test2")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: vlt.entries[0].created.clone(),
                modified: vlt.entries[0].modified.clone(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        assert_eq!(vlt, expected);
        assert!(time_close(vlt.entries[0].modified.clone()))
    }
    #[test]
    fn test_update_name() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        vlt.update_entry(
            EntryUpdate {
                target: Target::Name(String::from("test")),
                update: UpdateArgs {
                    name: Some(String::from("test2")),
                    username: Some(String::from("test2")),
                    password: false,
                    generate_password: false,
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
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test2"),
                username: Some(String::from("test2")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: vlt.entries[0].created.clone(),
                modified: vlt.entries[0].modified.clone(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        assert_eq!(vlt, expected);
        assert!(time_close(vlt.entries[0].modified.clone()))
    }
    #[test]
    fn test_export_import() {
        let file = NamedTempFile::new().unwrap();

        let vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData {
                next_entry_id: 2,
                ..RecoveryData::default()
            },
        };
        vlt.export(file.path().to_str().unwrap().to_string())
            .unwrap();
        let mut vlt1 = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt1.import(file.path().to_str().unwrap().to_string())
            .unwrap();
        assert_eq!(vlt, vlt1);
    }

    #[test]
    fn test_failed_import_does_not_partially_modify_vault() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "id,name,username,password,url,notes,created,modified").unwrap();
        writeln!(file, "2,valid,user,password,,,created,modified").unwrap();
        writeln!(file, "not-an-id,invalid,user,,,,created,modified").unwrap();

        let mut vault = Vault::default();
        assert!(vault.import(file.path().display().to_string()).is_err());
        assert!(vault.entries.is_empty());
    }

    #[test]
    fn test_imports_chrome_style_csv() {
        let csv =
            "name,url,username,password,note\nExample,https://example.com,alice,secret,personal\n";
        let entries = import_csv(csv, "chrome.csv").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Example");
        assert_eq!(entries[0].username.as_deref(), Some("alice"));
        assert_eq!(entries[0].notes.as_deref(), Some("personal"));
    }

    #[test]
    fn test_imports_bitwarden_json() {
        let json = r#"{
            "items": [{
                "type": 1,
                "name": "Example",
                "notes": "work",
                "login": {
                    "username": "alice",
                    "password": "secret",
                    "uris": [{"uri": "https://example.com/login"}]
                }
            }]
        }"#;
        let entries = import_json(json, "bitwarden.json").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].username.as_deref(), Some("alice"));
        assert_eq!(entries[0].url.as_deref(), Some("https://example.com/login"));
    }

    #[test]
    fn test_json_export_round_trip() {
        let file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        let vault = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: "Example".into(),
                username: Some("alice".into()),
                password: "secret".into(),
                url: Some("example.com".into()),
                notes: None,
                created: "created".into(),
                modified: "modified".into(),
            }],
            metadata: VaultMetadata::default(),
            recovery: RecoveryData::default(),
        };
        vault.export(file.path().display().to_string()).unwrap();
        let mut imported = Vault::default();
        imported.import(file.path().display().to_string()).unwrap();
        assert_eq!(imported.entries, vault.entries);
    }

    #[test]
    fn test_import_assigns_local_stable_ids() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "id,name,username,password,url,notes,created,modified").unwrap();
        writeln!(file, "99,first,user,password,,,created,modified").unwrap();

        let mut vault = Vault::default();
        vault.import(file.path().display().to_string()).unwrap();
        assert_eq!(vault.entries[0].id, 1);
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
            writeln!(
                tf,
                "1,example.com,bob,secret,,,2026-01-01 00:00:00,2026-01-01 00:00:00"
            )
            .unwrap();
            writeln!(
                tf,
                "2,test.org,alice,pw456,,,2026-01-02 00:00:00,2026-01-02 00:00:00"
            )
            .unwrap();
        }
        vlt.import(tf.path().to_str().unwrap().to_string()).unwrap();

        vlt.lock_vault(&mut server_info);

        let vlt1 = unlock_vault(&mut ServerInfo {
            locked: true,
            keypass: Some(pass),
        })
        .unwrap();
        assert_eq!(vlt1.entries.len(), 2);
        assert_eq!(vlt1.entries[0].name, "example.com");
        assert_eq!(vlt1.entries[1].name, "test.org");

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
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
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
        assert_eq!(vlt.entries, vlt1.entries);
        assert_eq!(vlt.metadata, vlt1.metadata);
        assert_eq!(vlt1.recovery.next_entry_id, 2);
    }
    #[test]
    fn test_lock_unlock_password() {
        init_test_data_dir();
        let filename = get_filename(
            &mut PasswordType::Password("test_password1234!".to_string()),
            true,
        );
        let vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
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
        assert_eq!(vlt.entries, vlt1.entries);
        assert_eq!(vlt.metadata, vlt1.metadata);
        assert_eq!(vlt1.recovery.next_entry_id, 2);
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
        )
        .unwrap();
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
                entries: Vec::new(),
                metadata: VaultMetadata { filename },
                recovery: RecoveryData::default(),
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
        )
        .unwrap();
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
        )
        .unwrap();
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
                entries: Vec::new(),
                metadata: VaultMetadata { filename },
                recovery: RecoveryData::default(),
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
        )
        .unwrap();
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
    fn test_rekey_replaces_vault_and_new_password_unlocks() {
        init_test_data_dir();
        let unique = format!("{:016x}", rand::random::<u64>());
        let mut server_info = ServerInfo {
            locked: false,
            keypass: Some(PasswordType::Password(format!("old-{unique}"))),
        };
        let mut vault = None;
        create_vault(&mut vault, &mut server_info, false).unwrap();
        let old_path = data_dir().join(&vault.as_ref().unwrap().metadata.filename);
        let new_password = PasswordType::Password(format!("new-{unique}"));
        vault
            .as_mut()
            .unwrap()
            .rekey(&mut server_info, new_password.clone())
            .unwrap();
        let new_path = data_dir().join(&vault.as_ref().unwrap().metadata.filename);
        assert!(!old_path.exists());
        assert!(new_path.exists());
        let mut unlock_info = ServerInfo {
            locked: true,
            keypass: Some(new_password),
        };
        assert!(unlock_vault(&mut unlock_info).is_some());
        fs::remove_file(new_path).unwrap();
    }
    #[test]
    fn test_add_duplicate_entry_name() {
        let mut vlt = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt.add_entry(
            PasswordEntry {
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
        let initial_len = vlt.entries.len();

        // Same name, different username -> allowed (multiple accounts per site)
        vlt.add_entry(
            PasswordEntry {
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
        assert_eq!(vlt.entries.len(), initial_len + 1);

        // Same name AND same username -> still blocked
        vlt.add_entry(
            PasswordEntry {
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
        assert_eq!(vlt.entries.len(), initial_len + 1);
    }
    #[test]
    fn test_add_multiple_entries_ids_sequential() {
        let mut vlt = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        for i in 0..5 {
            vlt.add_entry(
                PasswordEntry {
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
        for (i, entry) in vlt.entries.iter().enumerate() {
            assert_eq!(entry.id, i + 1);
        }
    }
    #[test]
    fn test_delete_entry_preserves_other_ids() {
        let mut vlt = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        for i in 0..5 {
            vlt.add_entry(
                PasswordEntry {
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
            Target::Id(2),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(
            vlt.entries.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![1, 3, 4, 5]
        );
    }
    #[test]
    fn test_update_password_changes() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        vlt.update_entry(
            EntryUpdate {
                target: Target::Id(1),
                update: UpdateArgs {
                    name: None,
                    username: None,
                    password: true,
                    generate_password: false,
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
        assert_eq!(vlt.entries[0].password, "newpass");
    }
    #[test]
    fn test_update_url_changes() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        vlt.update_entry(
            EntryUpdate {
                target: Target::Id(1),
                update: UpdateArgs {
                    name: None,
                    username: None,
                    password: false,
                    generate_password: false,
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
            vlt.entries[0].url,
            Some(String::from("https://example.com"))
        );
    }
    #[test]
    fn test_update_notes_changes() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        vlt.update_entry(
            EntryUpdate {
                target: Target::Id(1),
                update: UpdateArgs {
                    name: None,
                    username: None,
                    password: false,
                    generate_password: false,
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
        assert_eq!(vlt.entries[0].notes, Some(String::from("important notes")));
    }

    #[test]
    fn test_delete_entry_invalid_id_zero() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        let result = vlt.delete_entry(
            Target::Id(0),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert!(!result.unwrap());
    }

    #[test]
    fn test_delete_entry_invalid_id_out_of_bounds() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        let result = vlt.delete_entry(
            Target::Id(100),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert!(!result.unwrap());
    }

    #[test]
    fn test_update_entry_invalid_id_zero() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        let result = vlt.update_entry(
            EntryUpdate {
                target: Target::Id(0),
                update: UpdateArgs {
                    name: Some(String::from("new")),
                    username: None,
                    password: false,
                    generate_password: false,
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
        assert!(!result.unwrap());
    }

    #[test]
    fn test_update_entry_invalid_id_out_of_bounds() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        let result = vlt.update_entry(
            EntryUpdate {
                target: Target::Id(100),
                update: UpdateArgs {
                    name: Some(String::from("new")),
                    username: None,
                    password: false,
                    generate_password: false,
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
        assert!(!result.unwrap());
    }

    #[test]
    fn test_delete_entry_by_name_no_match() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        let initial_len = vlt.entries.len();
        vlt.delete_entry(
            Target::Name("nonexistent".into()),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.entries.len(), initial_len);
    }

    #[test]
    fn test_update_entry_by_name_no_match() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        let original_modified = vlt.entries[0].modified.clone();
        vlt.update_entry(
            EntryUpdate {
                target: Target::Name(String::from("nonexistent")),
                update: UpdateArgs {
                    name: Some(String::from("new")),
                    username: None,
                    password: false,
                    generate_password: false,
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
        assert_eq!(vlt.entries[0].name, "test");
        assert_eq!(vlt.entries[0].modified, original_modified);
    }

    #[test]
    fn test_delete_name_with_only_first_match() {
        let mut vlt = Vault {
            entries: vec![
                VaultEntry {
                    id: 1,
                    name: String::from("dup"),
                    username: Some(String::from("user1")),
                    password: String::from("pass1"),
                    url: None,
                    notes: None,
                    created: chrono::Local::now().to_string(),
                    modified: chrono::Local::now().to_string(),
                },
                VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        vlt.delete_entry(
            Target::Name("dup".into()),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.entries.len(), 1);
        assert_eq!(vlt.entries[0].id, 2);
        assert_eq!(vlt.entries[0].username, Some(String::from("user2")));
    }

    #[test]
    fn test_add_entry_with_all_fields() {
        let mut vlt: Vault = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt.add_entry(
            PasswordEntry {
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
        assert_eq!(vlt.entries.len(), 1);
        assert_eq!(vlt.entries[0].name, "full_entry");
        assert_eq!(vlt.entries[0].username, Some(String::from("admin")));
        assert_eq!(vlt.entries[0].password, "secret123");
        assert_eq!(
            vlt.entries[0].url,
            Some(String::from("https://example.com"))
        );
        assert_eq!(
            vlt.entries[0].notes,
            Some(String::from("important account"))
        );
    }

    #[test]
    fn test_add_entry_with_minimal_fields() {
        let mut vlt: Vault = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt.add_entry(
            PasswordEntry {
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
        assert_eq!(vlt.entries.len(), 1);
        assert_eq!(vlt.entries[0].name, "minimal");
        assert_eq!(vlt.entries[0].username, None);
        assert_eq!(vlt.entries[0].url, None);
        assert_eq!(vlt.entries[0].notes, None);
    }

    #[test]
    fn test_update_all_fields_at_once() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        let original_created = vlt.entries[0].created.clone();
        vlt.update_entry(
            EntryUpdate {
                target: Target::Id(1),
                update: UpdateArgs {
                    name: Some(String::from("new_name")),
                    username: Some(String::from("new_user")),
                    password: true,
                    generate_password: false,
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
        assert_eq!(vlt.entries[0].name, "new_name");
        assert_eq!(vlt.entries[0].username, Some(String::from("new_user")));
        assert_eq!(vlt.entries[0].password, "new_pass");
        assert_eq!(vlt.entries[0].url, Some(String::from("https://new.com")));
        assert_eq!(vlt.entries[0].notes, Some(String::from("new notes")));
        assert_eq!(vlt.entries[0].created, original_created);
    }

    #[test]
    fn test_update_no_changes() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
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
            recovery: RecoveryData::default(),
        };
        let original_modified = vlt.entries[0].modified.clone();
        thread::sleep(std::time::Duration::from_millis(10));
        vlt.update_entry(
            EntryUpdate {
                target: Target::Id(1),
                update: UpdateArgs {
                    name: None,
                    username: None,
                    password: false,
                    generate_password: false,
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
        assert_eq!(vlt.entries[0].modified, original_modified);
    }

    fn recovery_test_vault(entries: Vec<VaultEntry>) -> Vault {
        Vault {
            entries,
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        }
    }

    fn recovery_test_entry(id: usize, name: &str, username: &str, password: &str) -> VaultEntry {
        VaultEntry {
            id,
            name: name.into(),
            username: Some(username.into()),
            password: password.into(),
            url: Some("example.com".into()),
            notes: None,
            created: "created".into(),
            modified: "modified".into(),
        }
    }

    #[test]
    fn password_updates_create_restorable_history() {
        let mut vault = recovery_test_vault(vec![recovery_test_entry(1, "site", "alice", "old")]);
        let mut server_info = ServerInfo::default();
        vault
            .update_entry(
                EntryUpdate {
                    target: Target::Id(1),
                    update: UpdateArgs {
                        name: None,
                        username: None,
                        password: true,
                        generate_password: false,
                        url: None,
                        notes: None,
                    },
                    password: Some("new".into()),
                },
                &mut server_info,
            )
            .unwrap();
        assert_eq!(vault.recovery.password_history[0].password, "old");
        vault
            .restore_password(Target::Id(1), 1, &mut server_info)
            .unwrap();
        assert_eq!(vault.entries[0].password, "old");
        assert_eq!(vault.recovery.password_history[0].password, "new");
    }

    #[test]
    fn delete_restore_and_purge_use_encrypted_trash_state() {
        let mut vault = recovery_test_vault(vec![recovery_test_entry(1, "site", "alice", "pass")]);
        let mut server_info = ServerInfo::default();
        assert!(vault.delete_entry(Target::Id(1), &mut server_info).unwrap());
        assert!(vault.entries.is_empty());
        assert_eq!(vault.recovery.trash.len(), 1);
        assert!(vault.restore_trashed(1, &mut server_info).unwrap());
        assert_eq!(vault.entries[0].name, "site");
        assert!(vault.recovery.trash.is_empty());
        vault.delete_entry(Target::Id(1), &mut server_info).unwrap();
        assert!(vault.purge_trash(None, &mut server_info).unwrap());
        assert!(vault.recovery.trash.is_empty());
    }

    #[test]
    fn password_history_is_bounded() {
        let mut vault = recovery_test_vault(vec![recovery_test_entry(1, "site", "alice", "p0")]);
        for index in 1..=15 {
            let old = std::mem::replace(&mut vault.entries[0].password, format!("p{index}"));
            vault.push_password_history(1, old);
        }
        assert_eq!(
            vault.recovery.password_history.len(),
            Vault::MAX_PASSWORD_HISTORY
        );
        assert_eq!(vault.recovery.password_history[0].password, "p5");
    }

    #[test]
    fn stable_ids_survive_delete_add_and_restore() {
        let mut vault = recovery_test_vault(vec![
            recovery_test_entry(4, "first", "alice", "one"),
            recovery_test_entry(9, "second", "bob", "two"),
        ]);
        let mut server_info = ServerInfo::default();

        assert!(vault.delete_entry(Target::Id(4), &mut server_info).unwrap());
        assert_eq!(vault.entries[0].id, 9);
        vault
            .add_entry(
                PasswordEntry {
                    name: "third".into(),
                    username: Some("carol".into()),
                    password: "three".into(),
                    url: None,
                    notes: None,
                    copy: false,
                },
                &mut server_info,
            )
            .unwrap();
        assert_eq!(vault.entries[1].id, 10);

        assert!(vault.restore_trashed(1, &mut server_info).unwrap());
        assert_eq!(vault.entries[2].id, 4);
        assert_eq!(vault.recovery.next_entry_id, 11);

        vault
            .delete_entry(Target::Id(10), &mut server_info)
            .unwrap();
        vault.purge_trash(None, &mut server_info).unwrap();
        vault
            .add_entry(
                PasswordEntry {
                    name: "fourth".into(),
                    username: Some("dana".into()),
                    password: "four".into(),
                    url: None,
                    notes: None,
                    copy: false,
                },
                &mut server_info,
            )
            .unwrap();
        assert_eq!(vault.entries.last().unwrap().id, 11);
    }

    #[test]
    fn search_is_case_insensitive_combines_filters_and_excludes_passwords() {
        let mut first = recovery_test_entry(3, "GitHub", "Alice", "hidden-token");
        first.url = Some("https://github.com/login".into());
        first.notes = Some("Personal account".into());
        let mut second = recovery_test_entry(8, "GitLab", "alice-work", "different-secret");
        second.url = Some("https://gitlab.example".into());
        second.notes = Some("Work account".into());
        let vault = recovery_test_vault(vec![first, second]);

        let query_results = vault.search_entries(&SearchFilter {
            query: Some("ALICE".into()),
            ..SearchFilter::default()
        });
        assert_eq!(query_results.len(), 2);

        let filtered = vault.search_entries(&SearchFilter {
            name: Some("git".into()),
            url: Some("github.com".into()),
            notes: Some("personal".into()),
            ..SearchFilter::default()
        });
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, 3);

        let password_results = vault.search_entries(&SearchFilter {
            query: Some("hidden-token".into()),
            ..SearchFilter::default()
        });
        assert!(password_results.is_empty());
    }

    #[test]
    fn totp_matches_rfc_6238_sha1_vectors() {
        let raw = "GEZD GNBV-GY3TQOJQ GEZDGNBVGY3TQOJQ";
        let (normalized, bits) = normalize_totp_configuration(raw).unwrap();
        assert_eq!(normalized, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(bits, 160);
        let totp = parse_totp_configuration(&normalized).unwrap();
        assert_eq!(totp.generate(59).to_string(), "287082");

        let uri = "otpauth://totp/RFC?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30";
        let totp = parse_totp_configuration(uri).unwrap();
        assert_eq!(totp.generate(59).to_string(), "94287082");
    }

    #[test]
    fn totp_accepts_github_compatible_80_bit_secrets() {
        let github_secret = "GEZDGNBVGY3TQOJQ";
        let (normalized, bits) = normalize_totp_configuration(github_secret).unwrap();
        assert_eq!(bits, 80);
        let raw_totp = parse_totp_configuration(&normalized).unwrap();

        let uri = format!(
            "otpauth://totp/GitHub:test?secret={github_secret}&issuer=GitHub&algorithm=SHA1&digits=6&period=30"
        );
        let (normalized_uri, uri_bits) = normalize_totp_configuration(&uri).unwrap();
        assert_eq!(uri_bits, 80);
        let uri_totp = parse_totp_configuration(&normalized_uri).unwrap();
        assert_eq!(raw_totp.generate(59), uri_totp.generate(59));

        assert!(normalize_totp_configuration("GEZDGNBVGY3TQ").is_err());
    }

    #[test]
    fn totp_follows_trash_restore_and_is_erased_on_purge() {
        let mut vault =
            recovery_test_vault(vec![recovery_test_entry(7, "service", "alice", "password")]);
        let mut server_info = ServerInfo::default();
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

        assert_eq!(
            vault
                .set_totp(Target::Id(7), secret, &mut server_info)
                .unwrap(),
            Some(160)
        );
        assert_eq!(vault.totp_at(&Target::Id(7), 59).unwrap().0, "287082");

        vault.delete_entry(Target::Id(7), &mut server_info).unwrap();
        assert!(vault.totp_at(&Target::Id(7), 59).is_err());
        assert_eq!(vault.recovery.totp[0].entry_id, 7);
        vault.restore_trashed(1, &mut server_info).unwrap();
        assert_eq!(vault.totp_at(&Target::Id(7), 59).unwrap().0, "287082");

        vault.delete_entry(Target::Id(7), &mut server_info).unwrap();
        vault.purge_trash(None, &mut server_info).unwrap();
        assert!(vault.recovery.totp.is_empty());
    }

    #[test]
    fn totp_rejects_invalid_configuration_and_can_be_removed() {
        let mut vault =
            recovery_test_vault(vec![recovery_test_entry(1, "service", "alice", "password")]);
        let mut server_info = ServerInfo::default();
        assert!(
            vault
                .set_totp(Target::Id(1), "not base32!", &mut server_info)
                .is_err()
        );
        assert!(vault.recovery.totp.is_empty());

        vault
            .set_totp(
                Target::Id(1),
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                &mut server_info,
            )
            .unwrap();
        assert!(vault.remove_totp(Target::Id(1), &mut server_info).unwrap());
        assert!(vault.recovery.totp.is_empty());
        assert!(!vault.remove_totp(Target::Id(1), &mut server_info).unwrap());
    }

    #[test]
    fn old_recovery_data_defaults_to_no_totp_records() {
        #[derive(Serialize)]
        struct LegacyRecoveryData {
            password_history: Vec<PasswordRevision>,
            trash: Vec<TrashedEntry>,
            next_entry_id: usize,
        }

        let encoded = rmp_serde::to_vec(&LegacyRecoveryData {
            password_history: Vec::new(),
            trash: Vec::new(),
            next_entry_id: 12,
        })
        .unwrap();
        let decoded: RecoveryData = rmp_serde::from_slice(&encoded).unwrap();
        assert_eq!(decoded.next_entry_id, 12);
        assert!(decoded.totp.is_empty());
    }

    #[test]
    fn totp_secrets_are_redacted_and_omitted_from_plaintext_exports() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let mut vault =
            recovery_test_vault(vec![recovery_test_entry(1, "service", "alice", "password")]);
        vault
            .set_totp(Target::Id(1), secret, &mut ServerInfo::default())
            .unwrap();
        assert!(!format!("{:?}", vault.recovery.totp[0]).contains(secret));

        let file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        vault.export(file.path().display().to_string()).unwrap();
        let exported = fs::read_to_string(file.path()).unwrap();
        assert!(!exported.contains(secret));
    }

    #[test]
    fn audit_reports_weak_reused_and_duplicate_logins_without_passwords() {
        let vault = recovery_test_vault(vec![
            recovery_test_entry(1, "first", "alice", "secret"),
            recovery_test_entry(2, "second", "alice", "secret"),
        ]);
        let report = vault.audit_report();
        assert!(report.contains("2 weak entries"));
        assert!(report.contains("1 reused-password groups"));
        assert!(report.contains("1 duplicate-login groups"));
        assert!(!report.contains("secret"));
    }
}
