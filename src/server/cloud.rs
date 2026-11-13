//! Network transfers never hold the vault owner or extend its unlock timeout.
use super::*;
use crate::cloud::{Binding, CloudClient, binding, digest, save_binding};
use crate::config::try_read_config;
use crate::file::{config_dir, read_bounded_file};
use std::path::PathBuf;
static SYNC: Mutex<()> = Mutex::const_new(());
struct AbortTask(tokio::task::JoinHandle<()>);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Snapshot {
    path: PathBuf,
    id: String,
    session: String,
    bytes: Vec<u8>,
    state: Option<Binding>,
}
async fn snapshot(worker: &VaultWorker) -> Result<Snapshot, String> {
    worker
        .with_session(|session| {
            let vault = session.vault().ok_or("Unlock a vault first")?;
            let path = vault.sync_path()?;
            let state = binding(&path)?;
            let mut bytes =
                read_bounded_file(&path, crate::cloud::MAX_BYTES).map_err(|e| e.to_string())?;
            Ok(Snapshot {
                path,
                id: hex::encode(vault.vault_id()),
                session: session.session_id().ok_or("Vault locked")?,
                bytes: std::mem::take(&mut *bytes),
                state,
            })
        })
        .await?
}

#[derive(Debug, PartialEq, Eq)]
struct Probe {
    session: String,
    revision: u64,
    path: PathBuf,
    binding: Option<Binding>,
    configured_server: String,
    len: u64,
    modified: Option<std::time::SystemTime>,
    created: Option<std::time::SystemTime>,
    #[cfg(unix)]
    inode: u64,
}
async fn probe(worker: &VaultWorker, configured_server: String) -> Result<Probe, String> {
    worker
        .with_session(move |session| {
            let vault = session.vault().ok_or("Vault locked")?;
            let path = vault.sync_path()?;
            let metadata = std::fs::metadata(&path).map_err(|e| e.to_string())?;
            Ok(Probe {
                session: session.session_id().ok_or("Vault locked")?,
                revision: vault.vault_revision(),
                binding: binding(&path)?,
                configured_server,
                path,
                len: metadata.len(),
                modified: metadata.modified().ok(),
                created: metadata.created().ok(),
                #[cfg(unix)]
                inode: {
                    use std::os::unix::fs::MetadataExt;
                    metadata.ino()
                },
            })
        })
        .await?
}
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())?
}
async fn client() -> Result<CloudClient, String> {
    blocking(|| CloudClient::new(&try_read_config(&config_dir().join("config.toml"))?.sync)).await
}
pub(super) async fn command(
    worker: &VaultWorker,
    action: crate::cloud::Action,
    expected_session: Option<String>,
    stopping: Arc<AtomicBool>,
) -> Result<String, String> {
    let _guard = SYNC.lock().await;
    if stopping.load(Ordering::Acquire) {
        return Err("Server is stopping".into());
    }
    if expected_session.is_some() && worker.session_id() != expected_session {
        return Err("Unlock session changed before sync could start".into());
    }
    use crate::cloud::Action;
    let independent_copy = matches!(action, Action::PullCopy(_));
    match action {
        Action::List => {
            let client = client().await?;
            let list = client.list().await?;
            serde_json::to_string_pretty(&list).map_err(|e| e.to_string())
        }
        Action::Pull(id) | Action::PullCopy(id) => {
            let client = client().await?;
            let url = client.url.clone();
            let remote_id = id.clone();
            let (version, bytes) = client.download(&remote_id).await?;
            let filename = worker
                .with_session(move |_| {
                    if stopping.load(Ordering::Acquire) {
                        return Err("Server is stopping; download was not installed".into());
                    }
                    crate::cloud::install_download(
                        &url,
                        &id,
                        Some(version),
                        bytes,
                        independent_copy,
                    )
                })
                .await??;
            Ok(format!(
                "Downloaded encrypted vault as {filename}. Unlock it with its existing password or external key."
            ))
        }
        Action::Conflicts => review_or_resolve(worker, None, expected_session, stopping).await,
        Action::Resolve(resolution) => {
            review_or_resolve(worker, Some(resolution), expected_session, stopping).await
        }
        Action::Disable => {
            worker
                .with_session(move |session| {
                    if session.session_id() != expected_session {
                        return Err("Unlock session changed before disabling sync".into());
                    }
                    let path = session.vault().ok_or("Unlock a vault first")?.sync_path()?;
                    let mut state = binding(&path)?.ok_or("This vault is not connected to sync")?;
                    state.enabled = false;
                    save_binding(&path, &state)?;
                    Ok("Sync disabled for this vault".to_owned())
                })
                .await?
        }
        Action::Status => {
            let snapshot = snapshot(worker).await?;
            Ok(match snapshot.state {
                Some(s) => format!(
                    "Vault: {}\nServer: {}\nEnabled: {}\nRemote version: {}\nLocal changes: {}",
                    s.vault_id,
                    s.server_url,
                    s.enabled,
                    s.version.as_deref().unwrap_or("not uploaded"),
                    s.digest.as_deref() != Some(&digest(&snapshot.bytes))
                ),
                None => "This vault is not connected to sync. Run pm sync enable.".into(),
            })
        }
        action => {
            sync(
                worker,
                matches!(action, Action::Enable),
                matches!(action, Action::Check),
                expected_session,
            )
            .await
        }
    }
}
/// Bind consent to the exact two ciphertexts, connection, and unlock session.
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
async fn review_or_resolve(
    worker: &VaultWorker,
    resolution: Option<crate::cloud::Resolution>,
    expected_session: Option<String>,
    stopping: Arc<AtomicBool>,
) -> Result<String, String> {
    let snap = snapshot(worker).await?;
    if expected_session.as_ref() != Some(&snap.session) {
        return Err("Unlock session changed before conflict review".into());
    }
    let client = client().await?;
    let state = snap
        .state
        .as_ref()
        .ok_or("This vault is not connected to sync")?;
    if !state.enabled || state.server_url != client.url || state.vault_id != snap.id {
        return Err("Sync binding or connection changed; review again".into());
    }
    let (version, bytes) = client.download(&snap.id).await?;
    let token = review_token(&snap, &client.url, &version, &bytes);
    if resolution.as_ref().is_some_and(|r| r.token != token) {
        return Err(
            "Local or cloud vault changed since review; refresh conflicts and choose again".into(),
        );
    }
    let url = client.url.clone();
    let resolving = resolution.is_some();
    let result = worker.with_session(move |session| {
        if stopping.load(Ordering::Acquire) {
            return Err("Server is stopping; conflict resolution was not applied".into());
        }
        if session.session_id().as_ref() != Some(&snap.session) {
            return Err("Vault locked or switched during conflict review".into());
        }
        if binding(&snap.path)? != snap.state || digest(&read_bounded_file(&snap.path, crate::cloud::MAX_BYTES).map_err(|e| e.to_string())?) != digest(&snap.bytes) {
            return Err("Local vault or sync settings changed; review again".into());
        }
        session.with_unlocked(|vault, credentials| {
            let work = (|| -> Result<String, String> {
                let Some(resolution) = resolution else {
                    let items = vault.cloud_conflicts(credentials, &bytes)?;
                    return serde_json::to_string_pretty(&crate::cloud::ConflictReview { token, items }).map_err(|e| e.to_string());
                };
                let merged = vault.merge_cloud(credentials, &bytes, &resolution.choices)?;
                // Preserve both full encrypted snapshots, including history/trash,
                // before committing any decision. Recovery copies never auto-sync.
                let local_copy = crate::cloud::install_download(&url, &snap.id, None, snap.bytes, true)?;
                let remote_copy = crate::cloud::install_download(&url, &snap.id, Some(version.clone()), bytes.clone(), true)?;
                vault.apply_cloud(credentials, &merged)?;
                let mut state = snap.state.ok_or("Sync binding removed")?;
                // The remote remains the upload's CAS base. A concurrent upload
                // after review will cause normal sync to preserve both versions.
                state.version = Some(version);
                state.digest = Some(digest(&bytes));
                save_binding(&snap.path, &state)?;
                Ok(format!("Resolution saved. Encrypted recovery copies: {local_copy} (local), {remote_copy} (cloud)."))
            })();
            work.map_err(crate::vault::VaultError::Persistence)
        }).map_err(|e| e.to_string())
    }).await??;
    if !resolving {
        return Ok(result);
    }
    match sync(worker, false, false, expected_session).await {
        Ok(message) => {
            worker.set_cloud_warning(None).await;
            Ok(format!("{result}\n{message}"))
        }
        Err(error) => Ok(format!(
            "{result}\nSync pending: {error}. Review current state before retrying."
        )),
    }
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

async fn sync(
    worker: &VaultWorker,
    enable: bool,
    check: bool,
    expected_session: Option<String>,
) -> Result<String, String> {
    let snap = snapshot(worker).await?;
    if expected_session
        .as_ref()
        .is_some_and(|s| s != &snap.session)
    {
        return Err("Unlock session changed before sync could start".into());
    }
    let client = client().await?;
    let mut state = match snap.state {
        Some(s) => s,
        None if enable => Binding {
            server_url: client.url.clone(),
            vault_id: snap.id.clone(),
            version: None,
            digest: None,
            enabled: true,
        },
        None => return Err("This vault is not connected to sync; run pm sync enable".into()),
    };
    if state.server_url != client.url || state.vault_id != snap.id {
        return Err(
            "Sync binding belongs to a different server or vault; local copy preserved".into(),
        );
    }
    if enable {
        state.enabled = true;
        save_binding(&snap.path, &state)?;
    }
    if !state.enabled {
        return Err("Sync is disabled for this vault".into());
    }
    let remote_id = snap.id.clone();
    let c = client.clone();
    let remote = c.list().await?.into_iter().find(|v| v.id == remote_id);
    let local_digest = digest(&snap.bytes);
    let local_changed = state.digest.as_deref() != Some(&local_digest);
    let remote_version = remote.as_ref().map(|v| v.version.clone());
    let remote_changed = remote_version != state.version;
    if check {
        return Ok(format!(
            "Local changes: {local_changed}\nCloud changes: {remote_changed}\nCloud vault exists: {}",
            remote.is_some()
        ));
    }
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
        _ => {}
    }
    if matches!(decision, SyncDecision::Download | SyncDecision::Compare) {
        let remote = remote.expect("download decision requires a remote vault");
        let id = snap.id.clone();
        let c = client.clone();
        let (version, bytes) = c.download(&id).await?;
        let compared = compare_snapshot(local_changed, bytes == snap.bytes);
        if compared == SyncDecision::UpToDate {
            state.version = Some(version);
            state.digest = Some(local_digest);
            save_binding(&snap.path, &state)?;
            return Ok("Vault is up to date".into());
        }
        if compared == SyncDecision::Conflict {
            return Err("Sync conflict: local and cloud vaults both changed. Both copies are preserved; review them in Cloud sync or run pm sync conflicts.".into());
        }
        if version != remote.version {
            return Err("Cloud changed during download; retry sync".into());
        }
        state.version = Some(version);
        state.digest = Some(digest(&bytes));
        return worker
            .with_session(move |session| {
                if session.session_id().as_ref() != Some(&snap.session) {
                    return Err("Vault locked or switched during sync; update deferred".into());
                }
                if digest(
                    &read_bounded_file(&snap.path, crate::cloud::MAX_BYTES)
                        .map_err(|e| e.to_string())?,
                ) != local_digest
                {
                    return Err("Local vault changed during download; both copies preserved".into());
                }
                // Recheck binding so a concurrent disable/server switch cannot be undone.
                let current = binding(&snap.path)?.ok_or("Sync binding removed")?;
                if !current.enabled || current.server_url != state.server_url {
                    return Err("Sync settings changed during download".into());
                }
                session
                    .with_unlocked(|vault, key| {
                        vault
                            .apply_cloud(key, &bytes)
                            .map_err(crate::vault::VaultError::Persistence)
                    })
                    .map_err(|e| e.to_string())?;
                save_binding(&snap.path, &state)?;
                Ok("Downloaded and applied cloud changes".to_owned())
            })
            .await?;
    }
    // The server compares the base version atomically before committing.
    let id = snap.id;
    let base = state.version.clone();
    let bytes = snap.bytes;
    let version = client.upload(&id, base.as_deref(), bytes).await?;
    state.version = Some(version);
    state.digest = Some(local_digest);
    save_binding(&snap.path, &state)?;
    Ok("Uploaded encrypted vault changes".into())
}
pub(super) fn start(worker: VaultWorker, stopping: Arc<AtomicBool>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let wake = Arc::new(tokio::sync::Notify::new());
        let events_wake = wake.clone();
        let events_stop = stopping.clone();
        let events = AbortTask(tokio::spawn(async move {
            let mut generation = String::new();
            while !events_stop.load(Ordering::Acquire) {
                let result = async {
                    let c = client().await?;
                    let old = generation.clone();
                    c.events(&old).await
                }
                .await;
                match result {
                    Ok(next) => {
                        if next != generation {
                            generation = next;
                            events_wake.notify_one();
                        }
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                }
            }
        }));
        let mut last_probe = None;
        let mut last_remote = std::time::Instant::now() - Duration::from_secs(60);
        while !stopping.load(Ordering::Acquire) {
            let notified = tokio::select! {_=tokio::time::sleep(Duration::from_secs(2))=>false,_=wake.notified()=>true};
            let Ok(config) = try_read_config(&config_dir().join("config.toml")) else {
                last_probe = None;
                continue;
            };
            if !config.sync.automatic
                || config.sync.server_url.is_empty()
                || worker.session_id().is_none()
            {
                last_probe = None;
                continue;
            }
            let Ok(current) = probe(&worker, config.sync.server_url).await else {
                last_probe = None;
                continue;
            };
            if !current.binding.as_ref().is_some_and(|s| s.enabled) {
                last_probe = None;
                continue;
            }
            // A full snapshot is needed only for a change, notification, or
            // bounded remote recheck. The recheck also covers external writes
            // whose timestamps/size happen to match the previous file.
            if last_probe.as_ref() == Some(&current)
                && !notified
                && last_remote.elapsed() < Duration::from_secs(30)
            {
                continue;
            }
            let _guard = SYNC.lock().await;
            let result = sync(&worker, false, false, None).await;
            worker
                .set_cloud_warning(result.as_ref().err().map(|e| format!("Cloud sync: {e}")))
                .await;
            last_probe = Some(current);
            last_remote = std::time::Instant::now();
        }
        drop(events);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn idle_probe_tracks_file_binding_session_and_configuration_without_decryption() {
        crate::file::init_test_data_dir();
        let vault = Vault::from_entries(vec![], Some("probe.enc".into()));
        let path = vault.sync_path().unwrap();
        // Probing must work without opening or decoding the snapshot contents.
        std::fs::write(&path, b"synthetic ciphertext").unwrap();
        let session = VaultSession::unlock(
            vault,
            PasswordType::Session {
                encryption_key: [42; 32],
                salt: [7; 16],
                kdf: 1,
                memory_kib: 8192,
                iterations: 1,
                parallelism: 1,
            },
        );
        let worker = VaultWorker::start(
            session,
            Arc::new(AtomicU64::new(0)),
            Arc::new(Mutex::new(None)),
        );
        let first = probe(&worker, "https://one.example".into()).await.unwrap();
        assert_eq!(
            first,
            probe(&worker, "https://one.example".into()).await.unwrap()
        );
        assert_ne!(
            first,
            probe(&worker, "https://two.example".into()).await.unwrap()
        );
        std::fs::write(&path, b"a changed encrypted snapshot").unwrap();
        assert_ne!(
            first,
            probe(&worker, "https://one.example".into()).await.unwrap()
        );
        let changed = probe(&worker, "https://one.example".into()).await.unwrap();
        save_binding(
            &path,
            &Binding {
                server_url: "https://one.example".into(),
                vault_id: "b".repeat(32),
                version: None,
                digest: None,
                enabled: false,
            },
        )
        .unwrap();
        assert_ne!(
            changed,
            probe(&worker, "https://one.example".into()).await.unwrap()
        );
        worker
            .with_session(|session| *session = VaultSession::Locked)
            .await
            .unwrap();
        assert!(probe(&worker, "https://one.example".into()).await.is_err());
    }
}

#[cfg(test)]
mod decision_tests {
    use super::{SyncDecision::*, compare_snapshot, sync_decision};
    #[test]
    fn reconciliation_preserves_both_copies_until_a_comparison_is_known() {
        for (local, base, remote, expected) in [
            (false, Some("v1"), Some("v1"), UpToDate),
            (true, Some("v1"), Some("v1"), Upload),
            (false, Some("v1"), Some("v2"), Download),
            (true, Some("v1"), Some("v2"), Compare),
            (true, None, None, Upload),
            (true, Some("v1"), None, RemoteMissing),
            (false, Some("v1"), None, RemoteMissing),
            (true, None, Some("v1"), Compare),
        ] {
            assert_eq!(sync_decision(local, base, remote), expected);
        }
        assert_eq!(compare_snapshot(true, true), UpToDate);
        assert_eq!(compare_snapshot(true, false), Conflict);
        assert_eq!(compare_snapshot(false, false), Download);
    }
}
