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
                session: session.session_id().ok_or(crate::protocol::VAULT_LOCKED)?,
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

/// Installs on the owner queue, so shutdown, lock, and unlock cannot interleave.
async fn install(host: &DesktopHost<'_>, download: engine::Download) -> Result<String, String> {
    let stopping = host.stopping.clone();
    host.worker
        .with_session(move |_| {
            if stopping.load(Ordering::Acquire) {
                return Err("Server is stopping; download was not installed".into());
            }
            download.install(&data_dir())
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
            let vault = session.vault().ok_or(crate::protocol::VAULT_LOCKED)?;
            let path = vault.sync_path()?;
            let metadata = std::fs::metadata(&path).map_err(|e| e.to_string())?;
            Ok(Probe {
                session: session.session_id().ok_or(crate::protocol::VAULT_LOCKED)?,
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
        Action::Pull(id) => {
            downloaded(install(&host, engine::download(&host, &id, false).await?).await?)
        }
        Action::PullCopy(id) => {
            downloaded(install(&host, engine::download(&host, &id, true).await?).await?)
        }
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
            engine::set_enabled(&host, expected, false, Bind::Existing).await?;
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
                None if !crate::cloud::device_connected() => crate::cloud::NOT_CONNECTED.into(),
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
    let state = status.binding.ok_or(if crate::cloud::device_connected() {
        "This vault is not connected to sync; run pm sync enable"
    } else {
        crate::cloud::NOT_CONNECTED
    })?;
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

/// How often an idle, healthy loop rechecks the cloud.
const REMOTE_RECHECK: Duration = Duration::from_secs(30);
/// Upper bound for the backoff after repeated transient failures.
const MAX_BACKOFF: Duration = Duration::from_secs(15 * 60);
/// A stuck sync is retried in full at least this often, even when the cheap
/// check sees no change, in case a failure was misclassified.
const STUCK_FULL_RETRY: Duration = Duration::from_secs(30 * 60);

/// Failure memory for automatic sync. A stuck failure (conflict, undecryptable
/// or rolled-back cloud copy) cannot succeed until either copy changes, so it
/// is not repeated while both stay the same. Other failures back off.
#[derive(Default)]
struct Retry {
    failures: u32,
    stuck: Option<(engine::Stuck, std::time::Instant)>,
}

impl Retry {
    /// Minimum time between unprompted cloud checks.
    fn delay(&self) -> Duration {
        let factor = 1u32 << self.failures.min(10);
        REMOTE_RECHECK.saturating_mul(factor).min(MAX_BACKOFF)
    }
    fn record(&mut self, result: &Result<String, engine::SyncError>, now: std::time::Instant) {
        match result {
            Ok(_) => *self = Self::default(),
            Err(engine::SyncError {
                stuck: Some(stuck), ..
            }) => {
                self.failures = 0;
                self.stuck = Some((stuck.clone(), now));
            }
            Err(_) => {
                self.failures = self.failures.saturating_add(1);
                self.stuck = None;
            }
        }
    }
    /// The stuck state to verify cheaply instead of syncing again, if any.
    fn stuck(&self, now: std::time::Instant) -> Option<&engine::Stuck> {
        self.stuck
            .as_ref()
            .filter(|(_, since)| now.duration_since(*since) < STUCK_FULL_RETRY)
            .map(|(stuck, _)| stuck)
    }
}

#[cfg(unix)]
type FileIdentity = u64;
#[cfg(not(unix))]
type FileIdentity = ();

/// Rereads config.toml only when its metadata changes, off the async threads.
#[derive(Default)]
struct ConfigCache {
    stamp: Option<(u64, Option<std::time::SystemTime>, FileIdentity)>,
    sync: Option<crate::config::SyncConfig>,
}

impl ConfigCache {
    async fn load(&mut self, path: PathBuf) -> Option<crate::config::SyncConfig> {
        let known = self.stamp;
        let (stamp, sync) = blocking(move || {
            let stat = || {
                std::fs::metadata(&path).ok().map(|metadata| {
                    #[cfg(unix)]
                    let identity = {
                        use std::os::unix::fs::MetadataExt;
                        metadata.ino()
                    };
                    #[cfg(not(unix))]
                    let identity = ();
                    (metadata.len(), metadata.modified().ok(), identity)
                })
            };
            let stamp = stat();
            if stamp.is_some() && stamp == known {
                return Ok((stamp, None));
            }
            let sync = try_read_config(&path).ok().map(|c| c.sync);
            // Reading a missing file writes the defaults; record that file.
            Ok((stamp.or_else(stat), Some(sync)))
        })
        .await
        .ok()?;
        if let Some(sync) = sync {
            self.sync = sync;
        }
        self.stamp = stamp;
        self.sync.clone()
    }
}

/// Wait for a burst of local edits to finish before uploading.
const LOCAL_CHANGE_SETTLE: Duration = Duration::from_millis(250);

/// Resolve once the watched value differs from `seen` (recording it), or
/// never if the worker has stopped publishing.
async fn changed_from<T: Clone + PartialEq>(
    receiver: &mut tokio::sync::watch::Receiver<T>,
    seen: &mut T,
) {
    loop {
        if receiver.changed().await.is_err() {
            return std::future::pending().await;
        }
        let current = receiver.borrow_and_update().clone();
        if current != *seen {
            *seen = current;
            return;
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
        let mut last_remote = std::time::Instant::now();
        let mut retry = Retry::default();
        let mut config_cache = ConfigCache::default();
        // Edits, unlocks, and switches made through this server start a check
        // at once; the timer still catches changes made by other processes.
        let (mut sessions, mut revisions) = worker.changes();
        let mut seen_session = sessions.borrow_and_update().clone();
        let mut seen_revision = *revisions.borrow_and_update();
        while !stopping.load(Ordering::Acquire) {
            let notified = tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(2)) => false,
                _ = wake.notified() => true,
                _ = changed_from(&mut revisions, &mut seen_revision) => {
                    // Coalesce a burst of edits into one upload.
                    tokio::time::sleep(LOCAL_CHANGE_SETTLE).await;
                    seen_revision = *revisions.borrow_and_update();
                    false
                }
                _ = changed_from(&mut sessions, &mut seen_session) => false,
            };
            let Some(config) = config_cache.load(config_dir().join("config.toml")).await else {
                events_enabled.send_if_modified(|current| current.take().is_some());
                last_probe = None;
                continue;
            };
            if !config.automatic || config.server_url.is_empty() || worker.session_id().is_none() {
                events_enabled.send_if_modified(|current| current.take().is_some());
                last_probe = None;
                continue;
            }
            let Ok(current) = probe(&worker, config.server_url).await else {
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
            let local_changed = last_probe.as_ref() != Some(&current);
            if local_changed {
                // New local state deserves a prompt attempt and a fresh backoff.
                retry.failures = 0;
            } else if !notified && last_remote.elapsed() < retry.delay() {
                continue;
            }
            let _guard = SYNC.lock().await;
            let host = DesktopHost {
                worker: &worker,
                stopping: stopping.clone(),
            };
            let now = std::time::Instant::now();
            if !local_changed && let Some(stuck) = retry.stuck(now) {
                // Repeating the same download would fail the same way.
                let unchanged = engine::still_stuck(&host, stuck).await;
                last_remote = now;
                match unchanged {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(_) => {
                        retry.failures = retry.failures.saturating_add(1);
                        continue;
                    }
                }
            }
            let result = engine::sync_checked(&host, None, Bind::Existing).await;
            worker
                .set_cloud_warning(
                    result
                        .as_ref()
                        .err()
                        .map(|e| format!("Cloud sync: {}", e.message)),
                )
                .await;
            retry.record(&result, std::time::Instant::now());
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

    #[test]
    fn automatic_sync_backs_off_and_waits_for_a_change_when_stuck() {
        let start = std::time::Instant::now();
        let mut retry = Retry::default();
        assert_eq!(retry.delay(), REMOTE_RECHECK);
        let transient = Err(engine::SyncError::from("Sync request timed out"));
        let mut previous = retry.delay();
        for _ in 0..12 {
            retry.record(&transient, start);
            assert!(retry.delay() >= previous && retry.delay() <= MAX_BACKOFF);
            previous = retry.delay();
        }
        assert_eq!(retry.delay(), MAX_BACKOFF);
        assert!(retry.stuck(start).is_none());
        let stuck = engine::Stuck {
            remote: Some("a".repeat(32)),
            local: "b".repeat(64),
        };
        retry.record(
            &Err(engine::SyncError {
                message: "conflict".into(),
                stuck: Some(stuck.clone()),
            }),
            start,
        );
        assert_eq!(retry.delay(), REMOTE_RECHECK);
        assert_eq!(retry.stuck(start), Some(&stuck));
        // A full retry is still made occasionally in case of misclassification.
        assert!(retry.stuck(start + STUCK_FULL_RETRY).is_none());
        retry.record(&transient, start);
        assert!(retry.stuck(start).is_none());
        retry.record(&Ok("Vault is up to date".into()), start);
        assert_eq!(retry.delay(), REMOTE_RECHECK);
        assert!(retry.stuck.is_none());
    }

    #[tokio::test]
    async fn configuration_is_reread_only_after_the_file_changes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let mut cache = ConfigCache::default();
        let first = cache
            .load(path.clone())
            .await
            .expect("default configuration");
        assert!(cache.stamp.is_some());
        // Same metadata: the cached value is served without parsing.
        cache.sync = Some(crate::config::SyncConfig {
            server_url: "https://cached.example".into(),
            automatic: false,
        });
        assert_eq!(
            cache.load(path.clone()).await.unwrap().server_url,
            "https://cached.example"
        );
        // A replaced file is read again.
        let text = std::fs::read_to_string(&path).unwrap();
        let temporary = path.with_extension("replacement");
        std::fs::write(&temporary, text + "\n").unwrap();
        std::fs::rename(&temporary, &path).unwrap();
        assert_eq!(cache.load(path).await.unwrap(), first);
    }

    #[tokio::test]
    async fn local_change_wakes_only_for_a_different_value() {
        let (sender, mut receiver) = tokio::sync::watch::channel(Some(1u64));
        let mut seen = *receiver.borrow_and_update();
        // Every worker job republishes; an unchanged revision must not wake sync.
        sender.send_replace(Some(1));
        {
            let wait = changed_from(&mut receiver, &mut seen);
            tokio::pin!(wait);
            assert!(
                tokio::time::timeout(Duration::from_millis(50), &mut wait)
                    .await
                    .is_err()
            );
            sender.send_replace(Some(2));
            tokio::time::timeout(Duration::from_secs(1), &mut wait)
                .await
                .expect("a new revision wakes the sync loop");
        }
        assert_eq!(seen, Some(2));
        drop(sender);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                changed_from(&mut receiver, &mut seen)
            )
            .await
            .is_err(),
            "a stopped worker must not spin the loop"
        );
    }

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
