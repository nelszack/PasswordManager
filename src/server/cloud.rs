//! Desktop host for the shared sync engine. Network transfers never hold the
//! vault owner or extend its unlock timeout.
use super::*;
use crate::cloud::engine::{self, Bind, Snapshot, SyncHost};
use crate::cloud::{Binding, CloudClient, binding};
use crate::config::try_read_config;
use crate::file::{config_dir, data_dir, read_bounded_file};
use crate::vault::VaultError;
use std::path::PathBuf;
static SYNC: Mutex<()> = Mutex::const_new(());
struct AbortTask(tokio::task::JoinHandle<()>);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct DesktopHost<'a> {
    worker: &'a VaultWorker,
    stopping: Arc<AtomicBool>,
}

impl SyncHost for DesktopHost<'_> {
    fn client(&self) -> impl std::future::Future<Output = Result<CloudClient, String>> + Send {
        client()
    }
    fn snapshot(&self) -> impl std::future::Future<Output = Result<Snapshot, String>> + Send {
        let snapshot = self.worker.with_session(|session| {
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
        });
        async move { snapshot.await? }
    }
    fn with_unlocked<T: Send + 'static>(
        &self,
        expected: String,
        apply: impl FnOnce(&mut Vault, &mut VaultCredentials) -> Result<T, String> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, String>> + Send {
        let stopping = self.stopping.clone();
        let applied = self.worker.with_session(move |session| {
            if stopping.load(Ordering::Acquire) {
                return Err("Server is stopping; the vault was not changed".into());
            }
            if session.session_id().as_ref() != Some(&expected) {
                return Err("Vault locked or switched during sync; nothing was applied".into());
            }
            session
                .with_unlocked(|vault, credentials| {
                    apply(vault, credentials).map_err(VaultError::Persistence)
                })
                .map_err(|e| e.to_string())
        });
        async move { applied.await? }
    }
    fn directory(&self) -> PathBuf {
        data_dir()
    }
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
) -> Result<ResponsePayload, String> {
    let _guard = SYNC.lock().await;
    if stopping.load(Ordering::Acquire) {
        return Err("Server is stopping".into());
    }
    if expected_session.is_some() && worker.session_id() != expected_session {
        return Err("Unlock session changed before sync could start".into());
    }
    let host = DesktopHost { worker, stopping };
    let expected = expected_session.as_deref();
    use crate::cloud::Action;
    let message = match action {
        Action::List => return Ok(ResponsePayload::CloudVaults(client().await?.list().await?)),
        Action::Pull(id) | Action::PullCopy(id) if !crate::cloud::valid_id(&id) => {
            return Err("Invalid cloud vault ID".into());
        }
        Action::Pull(id) => downloaded(engine::download(&host, &id, false).await?),
        Action::PullCopy(id) => downloaded(engine::download(&host, &id, true).await?),
        Action::Conflicts => {
            let expected = expected.ok_or("Unlock session changed before conflict review")?;
            return Ok(ResponsePayload::CloudConflicts(
                engine::review(&host, Some(expected)).await?,
            ));
        }
        Action::Resolve(resolution) => {
            let expected = expected.ok_or("Unlock session changed before conflict review")?;
            let resolved = engine::resolve(&host, Some(expected), resolution).await?;
            if resolved.synced {
                worker.set_cloud_warning(None).await;
            }
            resolved.message
        }
        Action::Disable => {
            engine::set_enabled(&host, expected, false).await?;
            "Sync disabled for this vault".to_owned()
        }
        Action::Status => {
            let status = engine::status(&host, false).await?;
            match status.binding {
                Some(s) => format!(
                    "Vault: {}\nServer: {}\nEnabled: {}\nRemote version: {}\nLocal changes: {}",
                    s.vault_id,
                    s.server_url,
                    s.enabled,
                    s.version.as_deref().unwrap_or("not uploaded"),
                    status.local_changed,
                ),
                None => "This vault is not connected to sync. Run pm sync enable.".into(),
            }
        }
        Action::Check => check(&host).await?,
        Action::Enable => engine::sync(&host, expected, Bind::Enable).await?,
        Action::Now => engine::sync(&host, expected, Bind::Existing).await?,
    };
    Ok(ResponsePayload::Message(message))
}

fn downloaded(filename: String) -> String {
    format!(
        "Downloaded encrypted vault as {filename}. Unlock it with its existing password or \
         external key."
    )
}

async fn check(host: &DesktopHost<'_>) -> Result<String, String> {
    let status = engine::status(host, true).await?;
    let state = status
        .binding
        .ok_or("This vault is not connected to sync; run pm sync enable")?;
    if !state.enabled {
        return Err("Sync is disabled for this vault".into());
    }
    let remote_changed = status.remote.as_ref().map(|v| &v.version) != state.version.as_ref();
    Ok(format!(
        "Local changes: {}\nCloud changes: {remote_changed}\nCloud vault exists: {}",
        status.local_changed,
        status.remote.is_some()
    ))
}
/// A disabled receiver owns no pending network request. Changes cancel the old
/// request before credentials for the next connection are loaded.
async fn event_loop<F, Fut>(
    mut enabled: tokio::sync::watch::Receiver<Option<String>>,
    wake: Arc<tokio::sync::Notify>,
    fetch: F,
) where
    F: Fn(String, String) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    let mut endpoint = None;
    let mut generation = String::new();
    loop {
        let current = enabled.borrow_and_update().clone();
        if current != endpoint {
            endpoint = current;
            generation.clear();
        }
        let Some(server) = endpoint.clone() else {
            if enabled.changed().await.is_err() {
                return;
            }
            continue;
        };
        let result = tokio::select! {
            changed = enabled.changed() => {
                if changed.is_err() { return; }
                continue;
            }
            result = fetch(server, generation.clone()) => result,
        };
        match result {
            Ok(next) => {
                if next != generation {
                    generation = next;
                    wake.notify_one();
                }
            }
            Err(_) => {
                tokio::select! {
                    changed = enabled.changed() => { if changed.is_err() { return; } }
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {}
                }
            }
        }
    }
}

pub(super) fn start(worker: VaultWorker, stopping: Arc<AtomicBool>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let wake = Arc::new(tokio::sync::Notify::new());
        let (events_enabled, enabled) = tokio::sync::watch::channel(None);
        let events = AbortTask(tokio::spawn(event_loop(
            enabled,
            wake.clone(),
            |url, generation| async move {
                let client = client().await?;
                if client.url != url {
                    return Err("Sync connection changed".into());
                }
                client.events(&generation).await
            },
        )));
        let mut last_probe = None;
        let mut last_remote = std::time::Instant::now() - Duration::from_secs(60);
        while !stopping.load(Ordering::Acquire) {
            let notified = tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(2)) => false,
                _ = wake.notified() => true,
            };
            let Ok(config) = try_read_config(&config_dir().join("config.toml")) else {
                events_enabled.send_if_modified(|current| current.take().is_some());
                last_probe = None;
                continue;
            };
            if !config.sync.automatic
                || config.sync.server_url.is_empty()
                || worker.session_id().is_none()
            {
                events_enabled.send_if_modified(|current| current.take().is_some());
                last_probe = None;
                continue;
            }
            let Ok(current) = probe(&worker, config.sync.server_url).await else {
                events_enabled.send_if_modified(|current| current.take().is_some());
                last_probe = None;
                continue;
            };
            if !current.binding.as_ref().is_some_and(|state| {
                state.enabled && state.server_url == current.configured_server.trim_end_matches('/')
            }) {
                events_enabled.send_if_modified(|current| current.take().is_some());
                last_probe = None;
                continue;
            }
            events_enabled.send_if_modified(|value| {
                let next = Some(current.configured_server.trim_end_matches('/').to_owned());
                if *value == next {
                    false
                } else {
                    *value = next;
                    true
                }
            });
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
            let host = DesktopHost {
                worker: &worker,
                stopping: stopping.clone(),
            };
            let result = engine::sync(&host, None, Bind::Existing).await;
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
    use crate::cloud::save_binding;

    #[tokio::test]
    async fn idle_probe_tracks_file_binding_session_and_configuration_without_decryption() {
        crate::file::init_test_data_dir();
        let vault = Vault::from_entries(vec![], Some("probe.enc".into()));
        let path = vault.sync_path().unwrap();
        // Probing must work without opening or decoding the snapshot contents.
        std::fs::write(&path, b"synthetic ciphertext").unwrap();
        let session = VaultSession::unlock(
            vault,
            VaultCredentials::Session {
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
mod event_tests {
    use super::*;

    #[tokio::test]
    async fn disabled_events_cancel_requests_and_connection_changes_reset_the_cursor() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (enabled, receiver) = tokio::sync::watch::channel(None);
            let (calls, mut started) = tokio::sync::mpsc::unbounded_channel();
            let wake = Arc::new(tokio::sync::Notify::new());
            let task = tokio::spawn(event_loop(receiver, wake.clone(), move |url, cursor| {
                let calls = calls.clone();
                async move {
                    struct Cancel(Option<tokio::sync::oneshot::Sender<()>>);
                    impl Drop for Cancel {
                        fn drop(&mut self) {
                            if let Some(sender) = self.0.take() {
                                let _ = sender.send(());
                            }
                        }
                    }
                    let (cancel, cancelled) = tokio::sync::oneshot::channel();
                    let _cancel = Cancel(Some(cancel));
                    calls.send((url, cursor.clone(), cancelled)).unwrap();
                    if cursor.is_empty() {
                        Ok("generation".into())
                    } else {
                        std::future::pending().await
                    }
                }
            }));
            tokio::task::yield_now().await;
            assert!(
                started.try_recv().is_err(),
                "disabled events must not load credentials or request events"
            );
            enabled.send(Some("first".into())).unwrap();
            let (url, cursor, _) = started.recv().await.unwrap();
            assert_eq!(url, "first");
            assert!(cursor.is_empty());
            let (_, cursor, cancelled) = started.recv().await.unwrap();
            assert_eq!(cursor, "generation");
            wake.notified().await;
            enabled.send(None).unwrap();
            cancelled.await.unwrap();
            tokio::task::yield_now().await;
            assert!(started.try_recv().is_err());
            enabled.send(Some("second".into())).unwrap();
            let (url, cursor, _) = started.recv().await.unwrap();
            assert_eq!(url, "second");
            assert!(
                cursor.is_empty(),
                "a new connection cannot reuse the old event cursor"
            );
            let (_, _, cancelled) = started.recv().await.unwrap();
            drop(enabled);
            cancelled.await.unwrap();
            task.await.unwrap();
        })
        .await
        .expect("event loop must respond to configuration changes");
    }
}
