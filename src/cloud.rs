//! Encrypted snapshot transport and durable synchronization checkpoints.
//! No password or decrypted entry is sent to the server.
use crate::{
    config::SyncConfig,
    file::{config_dir, data_dir, read_bounded_file, set_private_perms, sync_parent},
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

pub use pm_contracts::cloud::Action;

pub const MAX_BYTES: u64 = 128 * 1024 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteVault {
    pub id: String,
    pub version: String,
    pub size: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub server_url: String,
    pub vault_id: String,
    pub version: Option<String>,
    pub digest: Option<String>,
    pub enabled: bool,
}
pub fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
pub fn validate_server_url(value: &str) -> Result<(), String> {
    let url = url::Url::parse(value)
        .map_err(|_| "Sync server must be a complete HTTPS URL".to_owned())?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if (url.scheme() != "https" && !(url.scheme() == "http" && local))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("Use an HTTPS server origin, or HTTP on localhost for testing; no credentials, path, query, or fragment".into());
    }
    Ok(())
}
pub fn write_private(path: &Path, bytes: &[u8], replace: bool) -> Result<(), String> {
    let parent = path.parent().ok_or("Missing parent directory")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut temp = NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    set_private_perms(temp.path()).map_err(|e| e.to_string())?;
    temp.write_all(bytes)
        .and_then(|_| temp.as_file().sync_all())
        .map_err(|e| e.to_string())?;
    if replace {
        temp.persist(path).map_err(|e| e.to_string())?;
    } else {
        temp.persist_noclobber(path).map_err(|e| e.to_string())?;
    }
    sync_parent(path).map_err(|e| format!("File saved but durability uncertain: {e}"))
}
fn binding_path(vault: &Path) -> PathBuf {
    vault.with_extension("sync.json")
}
pub fn binding(vault: &Path) -> Result<Option<Binding>, String> {
    let path = binding_path(vault);
    let bytes = match read_bounded_file(&path, 16 * 1024) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let state: Binding =
        serde_json::from_slice(&bytes).map_err(|e| format!("Invalid sync checkpoint: {e}"))?;
    validate_server_url(&state.server_url)?;
    if !valid_id(&state.vault_id) || state.version.as_ref().is_some_and(|v| !valid_id(v)) {
        return Err("Invalid vault identity/version in sync checkpoint".into());
    }
    Ok(Some(state))
}
pub fn save_binding(vault: &Path, state: &Binding) -> Result<(), String> {
    write_private(
        &binding_path(vault),
        &serde_json::to_vec(state).map_err(|e| e.to_string())?,
        true,
    )
}
pub(crate) fn verify_identity(vault: &Path, id: [u8; 16]) -> Result<(), String> {
    if let Some(state) = binding(vault)?
        && state.vault_id != hex::encode(id)
    {
        return Err("Downloaded vault identity does not match its sync binding".into());
    }
    Ok(())
}
pub fn install_token(token: &str) -> Result<(), String> {
    let token = token.trim();
    if token.len() != 64
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Device token must contain 64 lowercase hexadecimal characters".into());
    }
    write_private(&config_dir().join("sync-token"), token.as_bytes(), true)
}
pub fn read_token_file(path: &Path) -> Result<Zeroizing<String>, String> {
    let mut bytes = read_bounded_file(path, 128).map_err(|e| e.to_string())?;
    String::from_utf8(std::mem::take(&mut *bytes))
        .map(Zeroizing::new)
        .map_err(|_| "Device credential must be UTF-8".into())
}

/// Verify replacement credentials before changing an existing connection.
pub async fn connect_with_token(
    current: crate::config::Config,
    url: &str,
    token: &str,
    path: &Path,
) -> Result<crate::config::Config, String> {
    CloudClient::with_token(url, Zeroizing::new(token.trim().to_owned()))?
        .list()
        .await?;
    let previous_config = fs::read(path).map_err(|e| e.to_string())?;
    let token_path = config_dir().join("sync-token");
    let previous = match read_token_file(&token_path) {
        Ok(token) => Some(token),
        Err(_) if !token_path.exists() => None,
        Err(e) => return Err(e),
    };
    let saved = install_token(token).and_then(|()| {
        crate::config::try_update(
            current,
            crate::config::ConfigChanges {
                sync_server_url: Some(url.into()),
                ..Default::default()
            },
            path,
        )
    });
    if saved.is_err() {
        if let Some(previous) = previous {
            write_private(&token_path, previous.as_bytes(), true)?;
        } else if token_path.exists() {
            fs::remove_file(&token_path).map_err(|e| e.to_string())?;
        }
        // A directory-sync error can be reported after config replacement.
        write_private(path, &previous_config, true)?;
    }
    saved
}
#[derive(Clone)]
pub struct CloudClient {
    pub url: String,
    token: std::sync::Arc<Zeroizing<String>>,
    http: reqwest::Client,
}
impl CloudClient {
    pub fn new(config: &SyncConfig) -> Result<Self, String> {
        validate_server_url(&config.server_url)?;
        let token = read_token_file(&config_dir().join("sync-token"))
            .map_err(|e| format!("Read sync credential: {e}; run pm sync connect"))?;
        if token.len() != 64
            || !token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("Invalid saved device credential; run pm sync connect".into());
        }
        Self::with_token(&config.server_url, token)
    }
    pub fn with_token(url: &str, token: Zeroizing<String>) -> Result<Self, String> {
        validate_server_url(url)?;
        if token.len() != 64
            || !token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("Invalid sync device credential".into());
        }
        // The transport holds no credentials: authorization is attached per
        // request. Reuse pools while rereading tokens for every new CloudClient.
        static HTTP: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
        let http = if let Some(http) = HTTP.get() {
            http.clone()
        } else {
            let http = reqwest::Client::builder()
                .timeout(Duration::from_secs(35))
                .connect_timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .map_err(|e| e.to_string())?;
            let _ = HTTP.set(http);
            HTTP.get().expect("transport initialized").clone()
        };
        Ok(Self {
            url: url.trim_end_matches('/').into(),
            token: std::sync::Arc::new(token),
            http,
        })
    }
    fn request(&self, method: reqwest::Method, suffix: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{suffix}", self.url))
            .bearer_auth(self.token.as_str())
    }
    fn checked(response: reqwest::Response) -> Result<reqwest::Response, String> {
        match response.status().as_u16() {
            200..=299 => Ok(response),
            401 | 403 => Err("Sync device is unauthorized or revoked".into()),
            412 => Err(
                "Sync conflict: another device uploaded changes; both copies have been preserved"
                    .into(),
            ),
            507 => Err("Sync server storage quota reached".into()),
            code => Err(format!("Sync server returned HTTP {code}")),
        }
    }
    async fn read(mut response: reqwest::Response, limit: u64) -> Result<Vec<u8>, String> {
        if response.content_length().is_some_and(|n| n > limit) {
            return Err("Sync response exceeds size limit".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if chunk.len() as u64 > limit.saturating_sub(bytes.len() as u64) {
                return Err("Sync response exceeds size limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
    pub async fn list(&self) -> Result<Vec<RemoteVault>, String> {
        let response = Self::checked(
            self.request(reqwest::Method::GET, "/v1/vaults")
                .send()
                .await
                .map_err(|e| e.to_string())?,
        )?;
        let vaults: Vec<RemoteVault> =
            serde_json::from_slice(&Self::read(response, 1024 * 1024).await?)
                .map_err(|e| e.to_string())?;
        if vaults
            .iter()
            .any(|v| !valid_id(&v.id) || !valid_id(&v.version) || v.size == 0 || v.size > MAX_BYTES)
        {
            return Err("Invalid cloud vault metadata".into());
        }
        Ok(vaults)
    }
    pub async fn download(&self, id: &str) -> Result<(String, Vec<u8>), String> {
        if !valid_id(id) {
            return Err("Invalid cloud vault ID".into());
        }
        let response = Self::checked(
            self.request(reqwest::Method::GET, &format!("/v1/vaults/{id}"))
                .send()
                .await
                .map_err(|e| e.to_string())?,
        )?;
        let version = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim_matches('"').to_owned())
            .filter(|v| valid_id(v))
            .ok_or("Missing or invalid cloud version")?;
        let bytes = Self::read(response, MAX_BYTES).await?;
        crate::encryption::validate_vault_header(&bytes).map_err(str::to_owned)?;
        Ok((version, bytes))
    }
    pub async fn upload(
        &self,
        id: &str,
        version: Option<&str>,
        bytes: Vec<u8>,
    ) -> Result<String, String> {
        if !valid_id(id) || bytes.len() as u64 > MAX_BYTES || version.is_some_and(|v| !valid_id(v))
        {
            return Err("Invalid sync upload".into());
        }
        let mut request = self.request(reqwest::Method::PUT, &format!("/v1/vaults/{id}"));
        request = if let Some(version) = version {
            request.header(reqwest::header::IF_MATCH, format!("\"{version}\""))
        } else {
            request.header(reqwest::header::IF_NONE_MATCH, "*")
        };
        let response = Self::checked(
            request
                .body(bytes)
                .send()
                .await
                .map_err(|e| e.to_string())?,
        )?;
        let value: serde_json::Value = serde_json::from_slice(&Self::read(response, 4096).await?)
            .map_err(|e| e.to_string())?;
        value
            .get("version")
            .and_then(|v| v.as_str())
            .filter(|v| valid_id(v))
            .map(str::to_owned)
            .ok_or("Invalid upload acknowledgement".into())
    }
    pub async fn events(&self, since: &str) -> Result<String, String> {
        if !since.is_empty() && !valid_id(since) {
            return Err("Invalid event cursor".into());
        }
        let response = Self::checked(
            self.request(reqwest::Method::GET, &format!("/v1/events?since={since}"))
                .send()
                .await
                .map_err(|e| e.to_string())?,
        )?;
        let value: serde_json::Value = serde_json::from_slice(&Self::read(response, 4096).await?)
            .map_err(|e| e.to_string())?;
        value
            .get("generation")
            .and_then(|v| v.as_str())
            .filter(|v| valid_id(v))
            .map(str::to_owned)
            .ok_or("Invalid change notification".into())
    }
}

/// A new download never overwrites an existing local vault. Its encrypted
/// identity is checked at first unlock before any entries become available.
pub(crate) fn install_download(
    server_url: &str,
    id: &str,
    version: String,
    bytes: Vec<u8>,
    independent_copy: bool,
) -> Result<String, String> {
    for filename in crate::vault::list_vaults().map_err(|e| e.to_string())? {
        if let Some(state) = binding(&data_dir().join(&filename))?
            && state.vault_id == id
            && state.server_url == server_url
            && !independent_copy
        {
            return Err(format!(
                "Vault already exists locally as {filename}; unlock it and run pm sync now"
            ));
        }
    }
    let filename = format!("{}.enc", hex::encode(rand::random::<[u8; 16]>()));
    let path = data_dir().join(&filename);
    // Install identity binding first: a crash must never leave an unbound download.
    save_binding(
        &path,
        &Binding {
            server_url: server_url.to_owned(),
            vault_id: id.into(),
            version: Some(version),
            digest: Some(digest(&bytes)),
            enabled: !independent_copy,
        },
    )?;
    write_private(&path, &bytes, false)?;
    Ok(filename)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_origins_and_ids() {
        for url in [
            "https://sync-server.example.ts.net",
            "http://127.0.0.1:8788",
        ] {
            assert!(validate_server_url(url).is_ok());
        }
        for url in [
            "http://example.com",
            "https://user:secret@example.com",
            "https://example.com/path",
            "https://example.com?token=secret",
            "file:///etc/passwd",
        ] {
            assert!(validate_server_url(url).is_err());
        }
        assert!(valid_id(&"a".repeat(32)));
        assert!(!valid_id("../vault"));
    }
    #[test]
    fn bound_identity_must_match_after_decryption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("local.enc");
        let state = Binding {
            server_url: "https://example.com".into(),
            vault_id: hex::encode([1; 16]),
            version: None,
            digest: None,
            enabled: true,
        };
        save_binding(&path, &state).unwrap();
        assert!(verify_identity(&path, [1; 16]).is_ok());
        assert!(verify_identity(&path, [2; 16]).is_err());
        assert!(!path.exists());
    }
}
