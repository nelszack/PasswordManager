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
            let bytes = read_bounded_file(&path, crate::cloud::MAX_BYTES)
                .map_err(|e| e.to_string())?
                .to_vec();
            Ok(Snapshot {
                path,
                id: hex::encode(vault.vault_id()),
                session: session.session_id().ok_or("Vault locked")?,
                bytes,
                state,
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
            let list = blocking(move || client.list()).await?;
            serde_json::to_string_pretty(&list).map_err(|e| e.to_string())
        }
        Action::Pull(id) | Action::PullCopy(id) => {
            let client = client().await?;
            let url = client.url.clone();
            let remote_id = id.clone();
            let (version, bytes) = blocking(move || client.download(&remote_id)).await?;
            let filename = worker
                .with_session(move |_| {
                    if stopping.load(Ordering::Acquire) {
                        return Err("Server is stopping; download was not installed".into());
                    }
                    crate::cloud::install_download(&url, &id, version, bytes, independent_copy)
                })
                .await??;
            Ok(format!(
                "Downloaded encrypted vault as {filename}. Unlock it with its existing password or external key."
            ))
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
    let remote = blocking(move || Ok(c.list()?.into_iter().find(|v| v.id == remote_id))).await?;
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
    if !local_changed && !remote_changed {
        return Ok("Vault is up to date".into());
    }
    if let Some(remote) = remote
        && (remote_changed || state.version.is_none())
    {
        let id = snap.id.clone();
        let c = client.clone();
        let (version, bytes) = blocking(move || c.download(&id)).await?;
        if bytes == snap.bytes {
            state.version = Some(version);
            state.digest = Some(local_digest);
            save_binding(&snap.path, &state)?;
            return Ok("Vault is up to date".into());
        }
        if local_changed {
            return Err("Sync conflict: local and cloud vaults both changed. Both copies are preserved; automatic merging is not supported yet.".into());
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
                let mut edit = session.edit();
                let (key, vault) = edit.parts_mut();
                vault
                    .as_mut()
                    .ok_or("Vault locked")?
                    .apply_cloud(key, &bytes)?;
                save_binding(&snap.path, &state)?;
                Ok("Downloaded and applied cloud changes".to_owned())
            })
            .await?;
    }
    if state.version.is_some() && remote_version.is_none() {
        return Err("Cloud vault is missing; local vault preserved".into());
    }
    // The server compares the base version atomically before committing.
    let id = snap.id;
    let base = state.version.clone();
    let bytes = snap.bytes;
    let version = blocking(move || client.upload(&id, base.as_deref(), bytes)).await?;
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
                    blocking(move || c.events(&old)).await
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
        let mut last_digest = String::new();
        let mut last_remote = std::time::Instant::now() - Duration::from_secs(60);
        while !stopping.load(Ordering::Acquire) {
            let notified = tokio::select! {_=tokio::time::sleep(Duration::from_secs(2))=>false,_=wake.notified()=>true};
            let config = try_read_config(&config_dir().join("config.toml"));
            if !config.is_ok_and(|c| c.sync.automatic && !c.sync.server_url.is_empty()) {
                continue;
            }
            let Ok(snap) = snapshot(&worker).await else {
                continue;
            };
            if !snap.state.as_ref().is_some_and(|s| s.enabled) {
                continue;
            }
            let current = digest(&snap.bytes);
            if current == last_digest
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
            last_digest = current;
            last_remote = std::time::Instant::now();
        }
        drop(events);
    })
}
