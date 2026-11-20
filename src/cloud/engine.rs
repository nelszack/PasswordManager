//! One synchronization state machine for every client. A host supplies the
//! unlocked vault and its encrypted file; the engine owns comparison, conflict
//! review, recovery copies, and checkpoint updates. Network transfers never
//! hold the vault: every change is rechecked against the snapshot it came from.
use super::{
    Binding, CloudClient, ConflictReview, DIRECT_UPLOAD_BYTES, Fetched, MAX_BYTES, RemoteVault,
    Resolution, Uploaded, binding, digest, install_download, save_binding,
};
use crate::file::read_bounded_file;
use crate::vault::{Vault, VaultCredentials};
use std::{
    future::Future,
    path::{Path, PathBuf},
};

/// The encrypted vault file and checkpoint as seen by one unlock session.
pub(crate) struct Snapshot {
    pub path: PathBuf,
    /// Hex vault identity, shared by every copy of this vault.
    pub id: String,
    pub session: String,
    pub bytes: Vec<u8>,
    pub state: Option<Binding>,
}

pub(crate) trait SyncHost: Sync {
    fn client(&self) -> impl Future<Output = Result<CloudClient, String>> + Send;
    fn snapshot(&self) -> impl Future<Output = Result<Snapshot, String>> + Send;
    /// Runs `apply` on the unlocked vault only while `session` is still open.
    fn with_unlocked<T: Send + 'static>(
        &self,
        session: String,
        apply: impl FnOnce(&mut Vault, &mut VaultCredentials) -> Result<T, String> + Send + 'static,
    ) -> impl Future<Output = Result<T, String>> + Send;
    /// Where downloads and recovery copies are installed.
    fn directory(&self) -> PathBuf;
}

/// How a sync treats a vault that has no checkpoint yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Bind {
    /// Require an existing checkpoint.
    Existing,
    /// Connect an ordinary vault on first sync; recovery copies still need `Enable`.
    CreateIfMissing,
    /// Connect or re-enable explicitly.
    Enable,
}

/// Local copies that must not start syncing until the user enables them.
/// `conflict-` copies were written by earlier mobile builds.
const RECOVERY_PREFIXES: [&str; 4] = ["rekey-recovery-", "recovery-", "comparison-", "conflict-"];

pub(crate) fn recovery_copy(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| RECOVERY_PREFIXES.iter().any(|p| name.starts_with(p)))
}

fn new_binding(server_url: &str, vault_id: &str, enabled: bool) -> Binding {
    Binding {
        server_url: server_url.to_owned(),
        vault_id: vault_id.to_owned(),
        version: None,
        digest: None,
        enabled,
    }
}

async fn current<H: SyncHost>(host: &H, expected: Option<&str>) -> Result<Snapshot, String> {
    let snap = host.snapshot().await?;
    if expected.is_some_and(|session| session != snap.session) {
        return Err("Unlock session changed before sync could start".into());
    }
    Ok(snap)
}

/// A comparison fetch is required before declaring a conflict: independently
/// uploaded ciphertext may already be byte-for-byte equal to the local vault.
#[derive(Debug, PartialEq, Eq)]
enum SyncDecision {
    UpToDate,
    Upload,
    Download,
    Compare,
    Conflict,
    RemoteMissing,
}

fn sync_decision(local_changed: bool, base: Option<&str>, remote: Option<&str>) -> SyncDecision {
    let remote_changed = remote != base;
    if !local_changed && !remote_changed {
        return SyncDecision::UpToDate;
    }
    if remote.is_some() && (remote_changed || base.is_none()) {
        return if local_changed {
            SyncDecision::Compare
        } else {
            SyncDecision::Download
        };
    }
    if base.is_some() && remote.is_none() {
        SyncDecision::RemoteMissing
    } else {
        SyncDecision::Upload
    }
}

fn compare_snapshot(local_changed: bool, same_contents: bool) -> SyncDecision {
    if same_contents {
        SyncDecision::UpToDate
    } else if local_changed {
        SyncDecision::Conflict
    } else {
        SyncDecision::Download
    }
}

/// Fails if the vault file or its checkpoint changed since `snapshot`.
fn unchanged_since(path: &Path, bytes_digest: &str, state: Option<&Binding>) -> Result<(), String> {
    let current = read_bounded_file(path, MAX_BYTES).map_err(|e| e.to_string())?;
    if binding(path)?.as_ref() != state || digest(&current) != bytes_digest {
        return Err("Local vault or sync settings changed; review again".into());
    }
    Ok(())
}

/// A failed sync. `stuck` is set when retrying cannot succeed until the local
/// vault or the cloud version changes (a conflict, a missing cloud vault, or a
/// cloud snapshot this session cannot or must not apply).
#[derive(Debug)]
pub(crate) struct SyncError {
    pub message: String,
    pub stuck: Option<Stuck>,
}

/// The two copies a stuck sync compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Stuck {
    /// Cloud version, or `None` when the cloud vault is missing.
    pub remote: Option<String>,
    /// Digest of the local encrypted vault file.
    pub local: String,
}

impl From<String> for SyncError {
    fn from(message: String) -> Self {
        Self {
            message,
            stuck: None,
        }
    }
}
impl From<&str> for SyncError {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}

const REMOTE_MISSING: &str = "Cloud vault is missing; local vault preserved";
const CONFLICT: &str = "Sync conflict: local and cloud vaults both changed. Both copies are \
                        preserved; review the conflicts before synchronizing again.";

pub(crate) async fn sync<H: SyncHost>(
    host: &H,
    expected: Option<&str>,
    bind: Bind,
) -> Result<String, String> {
    sync_checked(host, expected, bind)
        .await
        .map_err(|error| error.message)
}

/// One request in the common cases: a conditional download (If-None-Match)
/// when only the cloud may have changed, or a conditional upload (If-Match)
/// when the local vault changed. A rejected upload downloads for comparison.
pub(crate) async fn sync_checked<H: SyncHost>(
    host: &H,
    expected: Option<&str>,
    bind: Bind,
) -> Result<String, SyncError> {
    let mut snap = current(host, expected).await?;
    let client = host.client().await?;
    let mut state = match snap.state.clone() {
        Some(state) => state,
        None if bind == Bind::Existing => {
            return Err("This vault is not connected to sync; run pm sync enable".into());
        }
        None if bind == Bind::CreateIfMissing && recovery_copy(&snap.path) => {
            return Err(
                "Recovery/comparison copy: enable sync explicitly before synchronizing".into(),
            );
        }
        None => new_binding(&client.url, &snap.id, true),
    };
    if state.server_url != client.url || state.vault_id != snap.id {
        return Err(
            "Sync binding belongs to a different server or vault; local copy preserved".into(),
        );
    }
    // The checkpoint a download must find unchanged on disk.
    let mut checkpoint = snap.state.clone();
    if bind == Bind::Enable && checkpoint.as_ref() != Some(&enabled(&state)) {
        state.enabled = true;
        save_binding(&snap.path, &state)?;
        checkpoint = Some(state.clone());
    }
    if !state.enabled {
        return Err("Sync is disabled for this vault".into());
    }
    let local_digest = digest(&snap.bytes);
    let local_changed = state.digest.as_deref() != Some(&local_digest);
    let stuck = |remote: Option<&str>, message: String| SyncError {
        message,
        stuck: Some(Stuck {
            remote: remote.map(str::to_owned),
            local: local_digest.clone(),
        }),
    };
    let fetched = if local_changed {
        // Large bodies check the version first instead of risking a doomed transfer.
        let attempt = if snap.bytes.len() > DIRECT_UPLOAD_BYTES {
            let remote = client.head(&snap.id).await?.map(|remote| remote.version);
            match sync_decision(true, state.version.as_deref(), remote.as_deref()) {
                SyncDecision::RemoteMissing => return Err(stuck(None, REMOTE_MISSING.into())),
                decision => decision == SyncDecision::Upload,
            }
        } else {
            true
        };
        if attempt {
            // The server compares the base version atomically before committing.
            match client
                .try_upload(
                    &snap.id,
                    state.version.as_deref(),
                    std::mem::take(&mut snap.bytes),
                )
                .await?
            {
                Uploaded::Committed(version) => {
                    state.version = Some(version);
                    state.digest = Some(local_digest.clone());
                    save_binding(&snap.path, &state)?;
                    return Ok("Uploaded encrypted vault changes".into());
                }
                // The cloud changed or vanished: compare before declaring a conflict.
                Uploaded::Stale => {}
            }
        }
        client.fetch(&snap.id, None).await?
    } else {
        client.fetch(&snap.id, state.version.as_deref()).await?
    };
    let (version, bytes) = match fetched {
        Fetched::NotModified => return Ok("Vault is up to date".into()),
        Fetched::Missing if state.version.is_none() && !local_changed => {
            return Ok("Vault is up to date".into());
        }
        Fetched::Missing => return Err(stuck(None, REMOTE_MISSING.into())),
        Fetched::Snapshot { version, bytes } => (version, bytes),
    };
    // A comparison is required before declaring a conflict: independently
    // uploaded ciphertext may already be byte-for-byte equal to the local vault.
    match compare_snapshot(local_changed, digest(&bytes) == local_digest) {
        SyncDecision::UpToDate => {
            state.version = Some(version);
            state.digest = Some(local_digest.clone());
            save_binding(&snap.path, &state)?;
            return Ok("Vault is up to date".into());
        }
        SyncDecision::Conflict => return Err(stuck(Some(&version), CONFLICT.into())),
        _ => {}
    }
    // The version arrived with these bytes, so a concurrent upload cannot mismatch them.
    state.version = Some(version.clone());
    state.digest = Some(digest(&bytes));
    let path = snap.path;
    let unchanged = local_digest.clone();
    let applied = host
        .with_unlocked(snap.session, move |vault, key| {
            unchanged_since(&path, &unchanged, checkpoint.as_ref())
                .map_err(|_| "Local vault changed during download; both copies preserved")?;
            // A snapshot that cannot be applied stays unapplicable until it changes.
            if let Err(error) = vault.apply_cloud(key, &bytes) {
                return Ok(Err(error));
            }
            save_binding(&path, &state)?;
            Ok(Ok("Downloaded and applied cloud changes".to_owned()))
        })
        .await?;
    applied.map_err(|message| stuck(Some(&version), message))
}

/// Whether both copies a stuck sync compared are still unchanged. Costs one
/// local read and one metadata request instead of a full download.
pub(crate) async fn still_stuck<H: SyncHost>(host: &H, stuck: &Stuck) -> Result<bool, String> {
    let snap = current(host, None).await?;
    if digest(&snap.bytes) != stuck.local {
        return Ok(false);
    }
    let remote = host.client().await?.head(&snap.id).await?;
    Ok(remote.map(|remote| remote.version) == stuck.remote)
}

pub(crate) struct Status {
    pub binding: Option<Binding>,
    pub local_changed: bool,
    /// Whether this unbound file is a recovery copy that must be enabled explicitly.
    pub recovery_copy: bool,
    /// The cloud head, when requested.
    pub remote: Option<RemoteVault>,
}

pub(crate) async fn status<H: SyncHost>(host: &H, check_remote: bool) -> Result<Status, String> {
    let snap = current(host, None).await?;
    let remote = if check_remote {
        host.client().await?.head(&snap.id).await?
    } else {
        None
    };
    Ok(Status {
        local_changed: snap.state.as_ref().and_then(|b| b.digest.as_deref())
            != Some(&digest(&snap.bytes)),
        recovery_copy: recovery_copy(&snap.path),
        binding: snap.state,
        remote,
    })
}

fn enabled(state: &Binding) -> Binding {
    Binding {
        enabled: true,
        ..state.clone()
    }
}

/// Turns sync on or off for this vault without transferring anything. A vault
/// without a checkpoint is refused for [`Bind::Existing`]; otherwise it gets a
/// new checkpoint (so a recovery copy can be marked disabled before any sync).
pub(crate) async fn set_enabled<H: SyncHost>(
    host: &H,
    expected: Option<&str>,
    enabled: bool,
    bind: Bind,
) -> Result<Binding, String> {
    let snap = current(host, expected).await?;
    let state = match snap.state.clone() {
        Some(mut state) => {
            if enabled && state.server_url != host.client().await?.url {
                return Err("Sync server differs from this vault's binding".into());
            }
            state.enabled = enabled;
            state
        }
        None if bind == Bind::Existing => {
            return Err("This vault is not connected to sync".into());
        }
        None => new_binding(&host.client().await?.url, &snap.id, enabled),
    };
    let saved = state.clone();
    host.with_unlocked(
        snap.session,
        move |_: &mut Vault, _: &mut VaultCredentials| {
            unchanged_since(&snap.path, &digest(&snap.bytes), snap.state.as_ref())?;
            save_binding(&snap.path, &saved)
        },
    )
    .await?;
    Ok(state)
}

/// A cloud vault fetched for installation as a new local file.
pub(crate) struct Download {
    url: String,
    id: String,
    version: String,
    bytes: Vec<u8>,
    independent_copy: bool,
}

impl Download {
    /// Installs into `directory` and returns the new filename. An independent
    /// copy is a `comparison-` file that never syncs until enabled.
    pub(crate) fn install(self, directory: &Path) -> Result<String, String> {
        let prefix = if self.independent_copy {
            "comparison-"
        } else {
            ""
        };
        install_download(
            directory,
            prefix,
            &self.url,
            &self.id,
            Some(self.version),
            self.bytes,
            self.independent_copy,
        )
    }
}

/// Downloads a cloud vault. The host installs it while it can still accept files.
pub(crate) async fn download<H: SyncHost>(
    host: &H,
    id: &str,
    independent_copy: bool,
) -> Result<Download, String> {
    let client = host.client().await?;
    let (version, bytes) = client.download(id).await?;
    Ok(Download {
        url: client.url,
        id: id.to_owned(),
        version,
        bytes,
        independent_copy,
    })
}

/// Binds consent to the exact two ciphertexts, connection, and unlock session.
fn review_token(snap: &Snapshot, server: &str, version: &str, bytes: &[u8]) -> String {
    digest(
        &serde_json::to_vec(&(
            &snap.session,
            &snap.id,
            server,
            digest(&snap.bytes),
            version,
            digest(bytes),
        ))
        .expect("strings serialize"),
    )
}

/// Downloads the cloud copy and lists the fields that differ.
pub(crate) async fn review<H: SyncHost>(
    host: &H,
    expected: Option<&str>,
) -> Result<ConflictReview, String> {
    let (snap, url, version, bytes) = fetch_for_review(host, expected).await?;
    let token = review_token(&snap, &url, &version, &bytes);
    let local_digest = digest(&snap.bytes);
    host.with_unlocked(snap.session, move |vault, credentials| {
        unchanged_since(&snap.path, &local_digest, snap.state.as_ref())?;
        let items = vault.cloud_conflicts(credentials, &bytes)?;
        Ok(ConflictReview { token, items })
    })
    .await
}

pub(crate) struct Resolved {
    pub message: String,
    /// Whether the follow-up sync after applying the resolution succeeded.
    pub synced: bool,
}

/// Applies reviewed choices, preserving both full encrypted copies first, then syncs.
pub(crate) async fn resolve<H: SyncHost>(
    host: &H,
    expected: Option<&str>,
    resolution: Resolution,
) -> Result<Resolved, String> {
    let (snap, url, version, bytes) = fetch_for_review(host, expected).await?;
    if resolution.token != review_token(&snap, &url, &version, &bytes) {
        return Err(
            "Local or cloud vault changed since review; refresh conflicts and choose again".into(),
        );
    }
    let directory = host.directory();
    let local_digest = digest(&snap.bytes);
    let session = snap.session.clone();
    let result = host
        .with_unlocked(session, move |vault, credentials| {
            unchanged_since(&snap.path, &local_digest, snap.state.as_ref())?;
            let merged = vault.merge_cloud(credentials, &bytes, &resolution.choices)?;
            // Preserve both complete encrypted snapshots, including history and
            // trash, before committing any decision. Recovery copies never auto-sync.
            let local_copy = install_download(
                &directory,
                "recovery-local-",
                &url,
                &snap.id,
                None,
                snap.bytes,
                true,
            )?;
            let remote_digest = digest(&bytes);
            let remote_copy = install_download(
                &directory,
                "recovery-cloud-",
                &url,
                &snap.id,
                Some(version.clone()),
                bytes,
                true,
            )?;
            vault
                .apply_prepared_cloud(credentials, merged)
                .map_err(|error| error.to_string())?;
            let mut state = snap.state.ok_or("Sync binding removed")?;
            // The remote remains the upload's CAS base. A concurrent upload
            // after review will cause normal sync to preserve both versions.
            state.version = Some(version);
            state.digest = Some(remote_digest);
            save_binding(&snap.path, &state)?;
            Ok(format!(
                "Resolution saved. Encrypted recovery copies: {local_copy} (local), \
                 {remote_copy} (cloud)."
            ))
        })
        .await?;
    Ok(match sync(host, expected, Bind::Existing).await {
        Ok(message) => Resolved {
            message: format!("{result}\n{message}"),
            synced: true,
        },
        Err(error) => Resolved {
            message: format!(
                "{result}\nSync pending: {error}. Review current state before retrying."
            ),
            synced: false,
        },
    })
}

async fn fetch_for_review<H: SyncHost>(
    host: &H,
    expected: Option<&str>,
) -> Result<(Snapshot, String, String, Vec<u8>), String> {
    let snap = current(host, expected).await?;
    let client = host.client().await?;
    let state = snap
        .state
        .as_ref()
        .ok_or("This vault is not connected to sync")?;
    if !state.enabled || state.server_url != client.url || state.vault_id != snap.id {
        return Err("Sync binding or connection changed; review again".into());
    }
    let (version, bytes) = client.download(&snap.id).await?;
    Ok((snap, client.url, version, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_and_comparison_copies_never_sync_implicitly() {
        for name in [
            "rekey-recovery-1.enc",
            "recovery-local-1.enc",
            "comparison-1-2.enc",
            "conflict-1-2.enc",
        ] {
            assert!(recovery_copy(Path::new(name)), "{name}");
        }
        assert!(!recovery_copy(Path::new("vault-1.enc")));
    }

    #[test]
    fn reconciliation_preserves_both_copies_until_a_comparison_is_known() {
        use SyncDecision::*;
        for (local_changed, base, remote, expected) in [
            (false, Some("a"), Some("a"), UpToDate),
            (true, Some("a"), Some("a"), Upload),
            (true, None, None, Upload),
            (false, Some("a"), Some("b"), Download),
            (true, Some("a"), Some("b"), Compare),
            (true, None, Some("a"), Compare),
            (true, Some("a"), None, RemoteMissing),
            (false, Some("a"), None, RemoteMissing),
        ] {
            assert_eq!(
                sync_decision(local_changed, base, remote),
                expected,
                "{local_changed} {base:?} {remote:?}"
            );
        }
        assert_eq!(compare_snapshot(true, true), UpToDate);
        assert_eq!(compare_snapshot(true, false), Conflict);
        assert_eq!(compare_snapshot(false, false), Download);
    }

    #[test]
    fn recovery_copies_are_recognized_by_name() {
        for name in [
            "rekey-recovery-a.enc",
            "recovery-local-a.enc",
            "recovery-cloud-a.enc",
            "comparison-a.enc",
        ] {
            assert!(recovery_copy(Path::new(name)), "{name}");
        }
        assert!(!recovery_copy(Path::new("0123.enc")));
    }
}
