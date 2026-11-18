//! One synchronization state machine for every client. A host supplies the
//! unlocked vault and its encrypted file; the engine owns comparison, conflict
//! review, recovery copies, and checkpoint updates. Network transfers never
//! hold the vault: every change is rechecked against the snapshot it came from.
use super::{
    Binding, CloudClient, ConflictReview, MAX_BYTES, RemoteVault, Resolution, binding, digest,
    install_download, save_binding,
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
const RECOVERY_PREFIXES: [&str; 3] = ["rekey-recovery-", "recovery-", "comparison-"];

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

pub(crate) async fn sync<H: SyncHost>(
    host: &H,
    expected: Option<&str>,
    bind: Bind,
) -> Result<String, String> {
    let snap = current(host, expected).await?;
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
    if bind == Bind::Enable {
        state.enabled = true;
        save_binding(&snap.path, &state)?;
    }
    if !state.enabled {
        return Err("Sync is disabled for this vault".into());
    }
    let remote = client.head(&snap.id).await?;
    let local_digest = digest(&snap.bytes);
    let local_changed = state.digest.as_deref() != Some(&local_digest);
    let remote_version = remote.as_ref().map(|v| v.version.clone());
    let decision = sync_decision(
        local_changed,
        state.version.as_deref(),
        remote_version.as_deref(),
    );
    match decision {
        SyncDecision::UpToDate => return Ok("Vault is up to date".into()),
        SyncDecision::RemoteMissing => {
            return Err("Cloud vault is missing; local vault preserved".into());
        }
        SyncDecision::Upload => {
            // The server compares the base version atomically before committing.
            let version = client
                .upload(&snap.id, state.version.as_deref(), snap.bytes)
                .await?;
            state.version = Some(version);
            state.digest = Some(local_digest);
            save_binding(&snap.path, &state)?;
            return Ok("Uploaded encrypted vault changes".into());
        }
        SyncDecision::Download | SyncDecision::Compare | SyncDecision::Conflict => {}
    }
    let remote = remote.ok_or("Cloud vault is missing; local vault preserved")?;
    let (version, bytes) = client.download(&snap.id).await?;
    match compare_snapshot(local_changed, bytes == snap.bytes) {
        SyncDecision::UpToDate => {
            state.version = Some(version);
            state.digest = Some(local_digest);
            save_binding(&snap.path, &state)?;
            return Ok("Vault is up to date".into());
        }
        SyncDecision::Conflict => {
            return Err(
                "Sync conflict: local and cloud vaults both changed. Both copies are preserved; \
                 review the conflicts before synchronizing again."
                    .into(),
            );
        }
        _ => {}
    }
    if version != remote.version {
        return Err("Cloud changed during download; retry sync".into());
    }
    state.version = Some(version);
    state.digest = Some(digest(&bytes));
    let path = snap.path;
    let checkpoint = snap.state;
    host.with_unlocked(snap.session, move |vault, key| {
        unchanged_since(&path, &local_digest, checkpoint.as_ref())
            .map_err(|_| "Local vault changed during download; both copies preserved")?;
        vault.apply_cloud(key, &bytes)?;
        save_binding(&path, &state)?;
        Ok("Downloaded and applied cloud changes".to_owned())
    })
    .await
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

/// Turns sync on or off for this vault without transferring anything.
pub(crate) async fn set_enabled<H: SyncHost>(
    host: &H,
    expected: Option<&str>,
    enabled: bool,
) -> Result<Binding, String> {
    let snap = current(host, expected).await?;
    let state = match snap.state {
        Some(mut state) => {
            if enabled && state.server_url != host.client().await?.url {
                return Err("Sync server differs from this vault's binding".into());
            }
            state.enabled = enabled;
            state
        }
        None => new_binding(&host.client().await?.url, &snap.id, enabled),
    };
    save_binding(&snap.path, &state)?;
    Ok(state)
}

/// Installs a cloud vault as a new local file and returns its filename.
pub(crate) async fn download<H: SyncHost>(
    host: &H,
    id: &str,
    independent_copy: bool,
) -> Result<String, String> {
    let client = host.client().await?;
    let (version, bytes) = client.download(id).await?;
    let prefix = if independent_copy { "comparison-" } else { "" };
    install_download(
        &host.directory(),
        prefix,
        &client.url,
        id,
        Some(version),
        bytes,
        independent_copy,
    )
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
