//! Android/iOS bridge over the shared vault. Vault management uses the same
//! typed `ServerCommand`s as the desktop service; only work that is genuinely
//! mobile (byte-based files, biometrics, passkeys, platform autofill, and
//! local settings) has its own request types.
use super::*;
use crate::{
    cloud::{
        Choice, CloudClient, Resolution,
        engine::{self, Bind, Snapshot, SyncHost},
    },
    operations::{self, Deferred, Stale, VaultHost},
    passkey::{self, Passkey, PasskeyIdentity},
    protocol::{ResponseCode, ResponsePayload, RpcResponse},
    secret::SecretString,
    types::{ServerCommand, TotpCommand},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, TryLockError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[path = "mobile_tools.rs"]
mod tools;

const LOCKED: &str = "Vault is locked";
const ITEM_CHANGED: &str = "Item changed since it was opened; reopen it before continuing";
const INTERRUPTED: &str = "Operation interrupted; vault locked. A remote change may have \
                           completed; inspect before retrying";
const SYNC_BUSY: &str = "A background sync is still running; try again shortly";
/// How long a request from the app waits for a running background sync.
const SYNC_TURN_WAIT: Duration = Duration::from_secs(15);
/// Largest request accepted over the FFI boundary (encoded imports and backups).
const MAX_REQUEST_BYTES: usize = 180 * 1024 * 1024;
/// Largest encrypted vault handed back to the app as a snapshot.
const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;
/// Biometric material is a 32-byte key followed by the vault's authenticated
/// 38-byte format/KDF/salt prefix, so a re-keyed vault invalidates it.
const KEY_BYTES: usize = 32;
const HEADER_PREFIX_BYTES: usize = 38;

/// File content sent with a request: raw bytes from [`MobileVault::call_binary`],
/// or the base64url `data` field of a JSON request, decoded before routing.
type Payload = Zeroizing<Vec<u8>>;

thread_local! {
    /// File content a handler returns, collected by the call on this thread.
    /// Handlers producing it run synchronously on the calling thread.
    static OUTGOING: std::cell::RefCell<Option<Payload>> = const { std::cell::RefCell::new(None) };
}

/// Return file content beside the reply instead of base64 inside it.
fn binary_reply(bytes: Payload) -> Value {
    OUTGOING.with(|slot| *slot.borrow_mut() = Some(bytes));
    json!({})
}

fn take_outgoing() -> Option<Payload> {
    OUTGOING.with(|slot| slot.borrow_mut().take())
}

/// One request from the app. The JSON envelope is process-local; never log it.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    // Available while locked.
    Lock,
    Status,
    Vaults,
    Unlock {
        vault: String,
        password: Option<SecretString>,
        key_file: Option<SecretString>,
    },
    BiometricUnlock {
        vault: String,
        material: SecretString,
    },
    Create {
        password: SecretString,
    },
    CreateKey {
        key_file: SecretString,
    },
    NewKeyFile,
    ImportVault {
        #[serde(skip)]
        data: Payload,
    },
    RestoreBackup {
        #[serde(skip)]
        data: Payload,
        password: Option<SecretString>,
        key_file: Option<SecretString>,
    },
    SettingsGet,
    SettingsSave {
        settings: tools::MobileSettings,
    },
    Generate(tools::GeneratorOptions),
    Passcheck {
        password: SecretString,
    },
    /// Per-type editor labels and suggested custom fields, shared with the desktop.
    ItemProfiles,
    CloudList {
        server: String,
        token: SecretString,
    },
    CloudDownload {
        server: String,
        token: SecretString,
        id: String,
        #[serde(default)]
        copy: bool,
    },
    // Require an unlocked vault.
    Vault {
        command: Box<ServerCommand>,
        expected_revision: Option<u64>,
        /// The user confirmed an irreversible command (see `confirmation`).
        #[serde(default)]
        confirmed: bool,
    },
    Logins {
        origin: String,
    },
    HostnameLogins {
        origin: String,
    },
    /// Logins for the site that already hold this password and, when one was
    /// captured, this username, so saving an unchanged sign-in adds no
    /// duplicate. The comparison happens here; only summaries are returned.
    SavedLogins {
        origin: String,
        #[serde(default)]
        hostname_only: bool,
        #[serde(default)]
        username: String,
        password: SecretString,
    },
    OtpLogins {
        origin: String,
        #[serde(default)]
        hostname_only: bool,
    },
    Login {
        id: usize,
        origin: String,
    },
    /// Roles of described form fields for card and identity autofill. Pure
    /// classification; available while locked.
    TypedFields {
        fields: Vec<String>,
    },
    /// Cards or identities to choose from (names only).
    TypedChoices {
        kind: ItemKind,
    },
    /// The chosen item's values for the form's roles.
    TypedValues {
        id: usize,
        kind: ItemKind,
        roles: Vec<String>,
    },
    SiteOtp {
        id: usize,
        origin: String,
    },
    Snapshot,
    BiometricMaterial,
    Passkeys {
        request: Option<Value>,
    },
    PasskeyCreate {
        request: Value,
        origin: String,
        client_hash: Option<String>,
    },
    PasskeyGet {
        id: usize,
        request: Value,
        origin: String,
        client_hash: Option<String>,
    },
    Sync {
        server: String,
        token: SecretString,
        /// Report a disabled vault as `{"synced": false, "disabled": true}`
        /// instead of failing, so background syncs need no status read first.
        #[serde(default)]
        if_enabled: bool,
        /// A follow-up sync after a change. It runs to completion even if the
        /// app locks meanwhile: it can upload only the encrypted snapshot taken
        /// while unlocked, and its apply step still needs that same session.
        #[serde(default)]
        background: bool,
    },
    SyncStatus,
    SyncCheck {
        server: String,
        token: SecretString,
    },
    SyncEnabled {
        server: String,
        token: SecretString,
        enabled: bool,
    },
    CloudConflicts {
        server: String,
        token: SecretString,
    },
    CloudResolve {
        server: String,
        token: SecretString,
        review_token: String,
        choices: Vec<Choice>,
    },
    ExportItems {
        format: Option<String>,
        #[serde(default)]
        confirmed: bool,
    },
    /// Attach a file chosen with the system picker (base64url content).
    AttachmentAdd {
        id: usize,
        name: String,
        #[serde(skip)]
        data: Payload,
        expected_revision: Option<u64>,
    },
    /// An attachment's content as base64url, for saving with the system picker.
    AttachmentData {
        id: usize,
        name: String,
    },
    ImportItems {
        #[serde(skip)]
        data: Payload,
        conflicts: Option<ConflictPolicy>,
        preview: Option<bool>,
        review_token: Option<String>,
    },
    BackupCreate {
        password: Option<SecretString>,
        key_file: Option<SecretString>,
    },
    Rekey {
        password: Option<SecretString>,
        key_file: Option<SecretString>,
    },
    /// Counts this vault's recovery copies still encrypted with old credentials.
    RekeyRecovery,
    DeleteRekeyRecovery {
        #[serde(default)]
        confirmed: bool,
    },
    DeleteVault {
        #[serde(default)]
        confirmed: bool,
    },
    PurgeExpired,
}

impl Request {
    fn needs_unlock(&self) -> bool {
        !matches!(
            self,
            Self::Lock
                | Self::Status
                | Self::Vaults
                | Self::Unlock { .. }
                | Self::BiometricUnlock { .. }
                | Self::Create { .. }
                | Self::CreateKey { .. }
                | Self::NewKeyFile
                | Self::ImportVault { .. }
                | Self::RestoreBackup { .. }
                | Self::SettingsGet
                | Self::SettingsSave { .. }
                | Self::Generate(_)
                | Self::Passcheck { .. }
                | Self::ItemProfiles
                | Self::CloudList { .. }
                | Self::CloudDownload { .. }
                | Self::TypedFields { .. }
        )
    }

    /// Requests that open a new unlock session.
    fn opens_session(&self) -> bool {
        matches!(
            self,
            Self::Unlock { .. }
                | Self::BiometricUnlock { .. }
                | Self::Create { .. }
                | Self::CreateKey { .. }
        )
    }
}

/// The app's lock signal. It is raised without the vault mutex, so it can wake
/// network waits at once. New requests are refused until the app sends `lock`;
/// requests already running when it was raised stay cancelled even after that
/// `lock` clears it.
pub struct Cancellation {
    raised: AtomicBool,
    generation: AtomicU64,
    notify: tokio::sync::Notify,
}

impl Cancellation {
    pub const fn new() -> Self {
        Self {
            raised: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            notify: tokio::sync::Notify::const_new(),
        }
    }

    /// Raised on background, screen-off, or an explicit lock in the app.
    pub fn signal(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.raised.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn clear(&self) {
        self.raised.store(false, Ordering::SeqCst);
    }
}

impl Default for Cancellation {
    fn default() -> Self {
        Self::new()
    }
}

/// One request's view of the lock signal.
#[derive(Clone, Copy)]
struct Ticket {
    flag: Option<&'static Cancellation>,
    generation: u64,
}

impl Ticket {
    fn new(flag: Option<&'static Cancellation>) -> Self {
        Self {
            flag,
            generation: flag.map_or(0, |f| f.generation.load(Ordering::SeqCst)),
        }
    }

    fn cancelled(&self) -> bool {
        self.flag.is_some_and(|f| {
            f.raised.load(Ordering::SeqCst)
                || f.generation.load(Ordering::SeqCst) != self.generation
        })
    }

    /// Completes once this request is cancelled; never without a signal.
    async fn wait(&self) {
        let Some(flag) = self.flag else {
            return std::future::pending().await;
        };
        loop {
            // Register before checking, so a signal in between still wakes us.
            let mut notified = std::pin::pin!(flag.notify.notified());
            notified.as_mut().enable();
            if self.cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// One vault per app process. Vault state has its own mutex, held only for
/// local work: sync, Duo, and breach-check network transfers run without it,
/// and anything they bring back is re-checked against the unlock session (and,
/// for sync, the file and checkpoint) they started from. Adapters must also
/// signal [`Cancellation`] on background/screen lock.
pub struct MobileVault {
    state: Arc<Mutex<MobileState>>,
    /// Serializes sync-engine operations that write checkpoints or files.
    sync: Mutex<()>,
    cancellation: Option<&'static Cancellation>,
}

/// Everything that requires the vault mutex.
struct MobileState {
    directory: PathBuf,
    /// The same locked/unlocked capability the desktop worker owns. Its
    /// session ID keeps reviews and late network replies from crossing unlocks.
    session: VaultSession,
    touched: Instant,
    /// Counts opened sessions, so a cancelled request locks only its own session.
    adoptions: u64,
    /// True only when unlocked with the original password or key file, not biometrics.
    primary_unlock: bool,
    settings: tools::MobileSettings,
    import_review: Option<ImportReview>,
}

/// An import preview the user must confirm against unchanged input and vault state.
struct ImportReview {
    token: String,
    revision: u64,
    digest: String,
    conflicts: ConflictPolicy,
}

/// A shared vault command after its vault step, waiting for deferred work.
struct PreparedCommand {
    reply: Option<RpcResponse>,
    deferred: Deferred,
    existing_update: bool,
    session: Option<String>,
}

impl Drop for MobileState {
    fn drop(&mut self) {
        self.lock();
    }
}

/// Locks the vault state. A panic while it was held may have interrupted a
/// change, so a poisoned state is locked before anyone uses it again.
fn guard(state: &Mutex<MobileState>) -> MutexGuard<'_, MobileState> {
    state.lock().unwrap_or_else(|poisoned| {
        state.clear_poison();
        let mut owner = poisoned.into_inner();
        owner.lock();
        owner
    })
}

impl Request {
    /// Where this request keeps its file content, for those that take one.
    fn payload_mut(&mut self) -> Option<&mut Payload> {
        match self {
            Self::ImportVault { data }
            | Self::RestoreBackup { data, .. }
            | Self::AttachmentAdd { data, .. }
            | Self::ImportItems { data, .. } => Some(data),
            _ => None,
        }
    }
}

impl MobileVault {
    pub fn new(directory: PathBuf) -> Result<Self, String> {
        if !directory.is_absolute() {
            return Err("Mobile storage path must be absolute".into());
        }
        fs::create_dir_all(&directory).map_err(|_| "Could not create mobile storage")?;
        crate::file::set_private_dir_perms(&directory)
            .map_err(|_| "Could not protect mobile storage")?;
        let settings = tools::MobileSettings::load(&directory)?;
        Ok(Self {
            state: Arc::new(Mutex::new(MobileState {
                directory,
                session: VaultSession::Locked,
                touched: Instant::now(),
                adoptions: 0,
                primary_unlock: false,
                settings,
                import_review: None,
            })),
            sync: Mutex::new(()),
            cancellation: None,
        })
    }

    /// Android's lock signal is independent of the vault mutex.
    pub fn set_cancellation(&mut self, flag: &'static Cancellation) {
        self.cancellation = Some(flag);
    }

    pub fn lock(&self) {
        self.state().lock();
    }

    fn state(&self) -> MutexGuard<'_, MobileState> {
        guard(&self.state)
    }

    /// Held for one sync-engine operation; never while holding the vault state.
    /// A background sync can hold it for a long upload and ignores the lock
    /// signal, so a request from the app stops waiting at the lock signal or
    /// after [`SYNC_TURN_WAIT`] instead of blocking its request thread. A
    /// background sync (`patient`) waits for the turn however long it takes.
    fn sync_turn(&self, ticket: &Ticket, patient: bool) -> Result<MutexGuard<'_, ()>, String> {
        let deadline = (!patient).then(|| Instant::now() + SYNC_TURN_WAIT);
        loop {
            match self.sync.try_lock() {
                Ok(turn) => return Ok(turn),
                Err(TryLockError::Poisoned(poisoned)) => {
                    self.sync.clear_poison();
                    return Ok(poisoned.into_inner());
                }
                Err(TryLockError::WouldBlock) => {
                    if ticket.cancelled() {
                        return Err(INTERRUPTED.into());
                    }
                    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        return Err(SYNC_BUSY.into());
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        }
    }

    /// JSON is only a process-local FFI envelope. Never log requests or results.
    /// Safe to call from several threads: local work is serialized by the vault
    /// mutex, and network work runs between its snapshot and apply steps.
    /// File content travels base64url-encoded in the JSON `data` field, both
    /// ways. [`Self::call_binary`] passes it as raw bytes instead.
    pub fn call(&self, input: &str) -> Result<Value, String> {
        let (mut value, outgoing) = self.call_inner(input, None)?;
        if let (Some(bytes), Value::Object(reply)) = (outgoing, &mut value) {
            reply.insert("data".into(), Value::String(passkey::encode(&*bytes)));
        }
        Ok(value)
    }

    /// Like [`Self::call`], with imports, backups and attachments as raw bytes
    /// beside a JSON request without `data`, and file content in replies
    /// returned the same way. Avoids base64 and the large text copies it
    /// causes on both sides of the FFI boundary.
    pub fn call_binary(
        &self,
        input: &str,
        data: Option<Payload>,
    ) -> Result<(Value, Option<Payload>), String> {
        if data
            .as_ref()
            .is_some_and(|bytes| bytes.len() > MAX_REQUEST_BYTES)
        {
            return Err("Mobile request exceeds limit".into());
        }
        self.call_inner(input, Some(data))
    }

    /// `binary` is the raw content of a [`Self::call_binary`] request, or
    /// `None` when content arrives as a JSON field.
    fn call_inner(
        &self,
        input: &str,
        binary: Option<Option<Payload>>,
    ) -> Result<(Value, Option<Payload>), String> {
        if input.len() > MAX_REQUEST_BYTES {
            return Err("Mobile request exceeds limit".into());
        }
        let mut envelope: Value =
            serde_json::from_str(input).map_err(|_| "Invalid mobile request")?;
        let op = envelope
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let invalid = || format!("Invalid or unsupported mobile request: {op}");
        // File content is taken out of the envelope before typed parsing,
        // so the request owns the decoded bytes and nothing is copied twice.
        let field = envelope.as_object_mut().and_then(|o| o.remove("data"));
        let payload = match (binary, field) {
            (Some(bytes), None) => bytes,
            (None, None) => None,
            (None, Some(Value::String(text))) => {
                let text = Zeroizing::new(text);
                Some(Zeroizing::new(
                    passkey::decode(&text).map_err(|_| invalid())?,
                ))
            }
            (_, Some(mut other)) => {
                wipe_json(&mut other);
                wipe_json(&mut envelope);
                return Err(invalid());
            }
        };
        // Deserialization errors can echo rejected values; report only the operation.
        let request = Request::deserialize(&envelope).map_err(|_| invalid());
        wipe_json(&mut envelope);
        let mut request = request?;
        match (request.payload_mut(), payload) {
            (Some(slot), Some(bytes)) => *slot = bytes,
            (None, None) => {}
            _ => return Err(invalid()),
        }
        let ticket = Ticket::new(self.cancellation);
        if matches!(request, Request::Lock) {
            if let Some(flag) = self.cancellation {
                flag.clear();
            }
            self.lock();
            return Ok((json!({}), None));
        }
        if ticket.cancelled() {
            self.lock();
            return Err(LOCKED.into());
        }
        // A background sync is not interrupted by the lock signal (see `Sync`).
        let ticket = if matches!(
            request,
            Request::Sync {
                background: true,
                ..
            }
        ) {
            Ticket::new(None)
        } else {
            ticket
        };
        let opens_session = request.opens_session();
        let adoptions = self.state().adoptions;
        drop(take_outgoing());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.dispatch(request, &ticket)
        }));
        // Taken whatever happened, so content never outlives its call.
        let outgoing = take_outgoing();
        if ticket.cancelled() {
            if let Ok(Ok(mut value)) = result {
                wipe_json(&mut value);
            }
            drop(outgoing);
            // A session another request opened after the app's `lock` is not ours to end.
            let mut state = self.state();
            if opens_session || state.adoptions == adoptions {
                state.lock();
            }
            return Err(INTERRUPTED.into());
        }
        match result {
            Ok(Ok(value)) => Ok((value, outgoing)),
            Ok(Err(error)) => Err(error),
            Err(_) => {
                self.lock();
                Err("Mobile operation failed; vault locked".into())
            }
        }
    }

    /// Routes network requests to handlers that release the vault between
    /// steps; everything else runs once under the vault mutex.
    fn dispatch(&self, request: Request, ticket: &Ticket) -> Result<Value, String> {
        match request {
            Request::Vault {
                command,
                expected_revision,
                confirmed,
            } => self.run_command(ticket, *command, expected_revision, confirmed),
            request @ (Request::CloudList { .. }
            | Request::CloudDownload { .. }
            | Request::Sync { .. }
            | Request::SyncStatus
            | Request::SyncCheck { .. }
            | Request::SyncEnabled { .. }
            | Request::CloudConflicts { .. }
            | Request::CloudResolve { .. }) => {
                if request.needs_unlock() {
                    self.state().open()?;
                }
                self.cloud_request(request, ticket)
            }
            // A sync running alongside would write the deleted vault's
            // checkpoint back, so deletion waits for the sync turn.
            request @ (Request::DeleteVault { .. } | Request::DeleteRekeyRecovery { .. }) => {
                let _turn = self.sync_turn(ticket, false)?;
                self.state().dispatch(request)
            }
            request => self.state().dispatch(request),
        }
    }

    fn cloud_request(&self, request: Request, ticket: &Ticket) -> Result<Value, String> {
        match request {
            Request::CloudList { server, token } => {
                let client = client(&server, token)?;
                Ok(json!(block_on(ticket, client.list())??))
            }
            Request::CloudDownload {
                server,
                token,
                id,
                copy,
            } => {
                let _turn = self.sync_turn(ticket, false)?;
                let download =
                    self.run_sync(ticket, Some(client(&server, token)?), async |host| {
                        engine::download(host, &id, copy).await
                    })?;
                // Installed under the vault mutex, so lock and unlock cannot interleave.
                let name = download.install(&self.state().directory)?;
                Ok(json!({ "vault": name }))
            }
            Request::Sync {
                server,
                token,
                if_enabled,
                background,
            } => {
                if if_enabled && !self.state().sync_enabled()? {
                    return Ok(json!({
                        "synced": false,
                        "disabled": true,
                        "message": "Sync is disabled for this vault",
                    }));
                }
                let _turn = self.sync_turn(ticket, background)?;
                let message =
                    self.run_sync(ticket, Some(client(&server, token)?), async |host| {
                        engine::sync(host, None, Bind::CreateIfMissing).await
                    })?;
                Ok(json!({ "synced": true, "message": message }))
            }
            Request::SyncStatus => self.sync_status(ticket, None, false),
            Request::SyncCheck { server, token } => {
                self.sync_status(ticket, Some(client(&server, token)?), true)
            }
            Request::SyncEnabled {
                server,
                token,
                enabled,
            } => {
                let client = client(&server, token)?;
                {
                    let _turn = self.sync_turn(ticket, false)?;
                    self.run_sync(ticket, Some(client.clone()), async |host| {
                        engine::set_enabled(host, None, enabled, Bind::Enable).await
                    })?;
                }
                self.sync_status(ticket, Some(client), false)
            }
            Request::CloudConflicts { server, token } => {
                let _turn = self.sync_turn(ticket, false)?;
                let review =
                    self.run_sync(ticket, Some(client(&server, token)?), async |host| {
                        engine::review(host, None).await
                    })?;
                Ok(json!(review))
            }
            Request::CloudResolve {
                server,
                token,
                review_token,
                choices,
            } => {
                let resolution = Resolution {
                    token: review_token,
                    choices,
                };
                let _turn = self.sync_turn(ticket, false)?;
                let resolved =
                    self.run_sync(ticket, Some(client(&server, token)?), async |host| {
                        engine::resolve(host, None, resolution).await
                    })?;
                Ok(json!({ "synced": resolved.synced, "message": resolved.message }))
            }
            _ => Err(MISROUTED.into()),
        }
    }

    /// Runs a shared vault command exactly as the desktop service would. Its
    /// deferred network or long CPU work runs after the vault mutex is
    /// released and may re-enter only the session that prepared it.
    fn run_command(
        &self,
        ticket: &Ticket,
        command: ServerCommand,
        expected_revision: Option<u64>,
        confirmed: bool,
    ) -> Result<Value, String> {
        let PreparedCommand {
            mut reply,
            deferred,
            existing_update,
            session,
        } = self
            .state()
            .prepare_command(command, expected_revision, confirmed)?;
        let host = self.host(ticket, None);
        block_on(
            ticket,
            operations::finish_deferred(deferred, &host, session, &mut reply),
        )?;
        response_value(reply, existing_update)
    }

    /// Lends the vault state to the shared sync engine or deferred work.
    fn host(&self, ticket: &Ticket, client: Option<CloudClient>) -> MobileHost<'_> {
        MobileHost {
            directory: self.state().directory.clone(),
            ticket: *ticket,
            client,
            owner: &self.state,
        }
    }

    /// Runs one sync-engine operation; the app's lock signal aborts its network work.
    fn run_sync<T>(
        &self,
        ticket: &Ticket,
        client: Option<CloudClient>,
        operation: impl AsyncFnOnce(&MobileHost<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        let host = self.host(ticket, client);
        block_on(ticket, operation(&host))?
    }

    fn sync_status(
        &self,
        ticket: &Ticket,
        client: Option<CloudClient>,
        check: bool,
    ) -> Result<Value, String> {
        let status = self.run_sync(ticket, client, async |host| {
            engine::status(host, check).await
        })?;
        Ok(json!({
            "enabled": status.binding.as_ref().map_or(!status.recovery_copy, |b| b.enabled),
            "configured": status.binding.is_some(),
            "local_changed": status.local_changed,
            "remote": status.remote,
            "binding": status.binding,
        }))
    }
}

const MISROUTED: &str = "Mobile request was routed incorrectly";

impl MobileState {
    fn lock(&mut self) {
        self.session.lock();
        self.import_review = None;
        self.primary_unlock = false;
    }

    /// Applies the idle timeout, then requires an open vault.
    fn open(&mut self) -> Result<(), String> {
        if self.touched.elapsed() >= Duration::from_secs(self.settings.unlock_seconds) {
            self.lock();
        }
        self.touched = Instant::now();
        self.vault().map(|_| ())
    }

    fn vault(&self) -> Result<&Vault, String> {
        self.session.vault().ok_or_else(|| LOCKED.into())
    }

    /// Runs a mutation with the vault and its credentials. A change that leaves
    /// the credentials unusable locks the session, as on the desktop.
    fn with_unlocked<T>(
        &mut self,
        action: impl FnOnce(&mut Vault, &mut VaultCredentials) -> Result<T, VaultError>,
    ) -> Result<T, String> {
        self.session
            .with_unlocked(action)
            .map_err(|error| match error {
                VaultError::Locked => LOCKED.into(),
                error => error.to_string(),
            })
    }

    fn session_id(&self) -> Option<String> {
        self.session.session_id()
    }

    fn path(&self, name: &str) -> Result<PathBuf, String> {
        validate_vault_filename(name).map_err(|e| e.to_string())?;
        Ok(self.directory.join(name))
    }

    fn read_vault_file(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        crate::file::read_bounded_file(&self.path(name)?, MAX_VAULT_BYTES)
            .map_err(|_| "Could not read vault".into())
    }

    fn unlock(
        &mut self,
        name: &str,
        mut key: VaultCredentials,
        primary: bool,
    ) -> Result<(), String> {
        self.lock();
        let (_, vault) = persistence::lookup_vault_in(&self.directory, &mut key, Some(name))
            .map_err(|e| e.to_string())?
            .ok_or("Vault not found")?;
        self.adopt(vault, key, primary).map_err(|e| e.to_string())
    }

    /// Replaces any open session with `vault`.
    fn adopt(
        &mut self,
        vault: Vault,
        key: VaultCredentials,
        primary: bool,
    ) -> Result<(), VaultError> {
        self.lock();
        self.session.install(vault, key)?;
        self.primary_unlock = primary;
        self.adoptions += 1;
        self.touched = Instant::now();
        Ok(())
    }

    /// Writes a new, empty vault and opens it as a primary unlock.
    fn create_with_key(&mut self, mut key: VaultCredentials) -> Result<Value, VaultError> {
        let mut vault = Vault::memory();
        let name = format!("{}.enc", hex::encode(vault.vault_id()));
        vault.store = VaultStore::File {
            directory: self.directory.clone(),
            filename: name.clone(),
        };
        vault.metadata.filename = name.clone();
        write_vault_with_key(&vault, &mut key)?;
        self.adopt(vault, key, true)?;
        Ok(json!({ "vault": name }))
    }

    /// Whether a sync of this vault would run: an explicit checkpoint setting,
    /// or for an unbound vault, anything but a recovery copy. Reads only the
    /// small checkpoint file, never the vault.
    fn sync_enabled(&self) -> Result<bool, String> {
        let path = self.vault()?.sync_path()?;
        Ok(crate::cloud::binding(&path)?
            .map_or_else(|| !engine::recovery_copy(&path), |binding| binding.enabled))
    }

    /// Runs one local request; the caller has applied the idle timeout.
    fn dispatch(&mut self, request: Request) -> Result<Value, String> {
        if request.needs_unlock() {
            self.open()?;
        }
        match request {
            request @ (Request::Status
            | Request::Vaults
            | Request::Unlock { .. }
            | Request::BiometricUnlock { .. }
            | Request::Create { .. }
            | Request::CreateKey { .. }
            | Request::NewKeyFile
            | Request::ImportVault { .. }
            | Request::RestoreBackup { .. }
            | Request::BiometricMaterial) => self.session_request(request),
            request @ (Request::SettingsGet
            | Request::SettingsSave { .. }
            | Request::Generate(_)
            | Request::Passcheck { .. }
            | Request::ItemProfiles) => self.settings_request(request),
            request @ (Request::Logins { .. }
            | Request::HostnameLogins { .. }
            | Request::SavedLogins { .. }
            | Request::OtpLogins { .. }
            | Request::Login { .. }
            | Request::SiteOtp { .. }
            | Request::TypedFields { .. }
            | Request::TypedChoices { .. }
            | Request::TypedValues { .. }) => self.autofill_request(request),
            request @ (Request::Passkeys { .. }
            | Request::PasskeyCreate { .. }
            | Request::PasskeyGet { .. }) => self.passkey_request(request),
            request => self.file_request(request),
        }
    }

    /// Vault files, unlocking, and the biometric key.
    fn session_request(&mut self, request: Request) -> Result<Value, String> {
        match request {
            Request::Status => Ok(json!({
                "unlocked": self.open().is_ok(),
                "unlock_seconds": self.settings.unlock_seconds,
                "clipboard_seconds": self.settings.clipboard_seconds,
                "leave_lock_seconds": self.settings.leave_lock_seconds,
            })),
            Request::Vaults => Ok(json!(self.vault_names()?)),
            Request::Unlock {
                vault,
                password,
                key_file,
            } => {
                self.lock();
                let key = match key_file {
                    Some(encoded) => {
                        let data = Zeroizing::new(passkey::decode(&encoded)?);
                        let encrypted = self.read_vault_file(&vault)?;
                        crate::encryption::credentials_from_keyfile_bytes(&encrypted, &data)?
                    }
                    None => {
                        PasswordType::Password(password.ok_or("Missing password")?.expose_owned())
                            .into()
                    }
                };
                self.unlock(&vault, key, true)?;
                Ok(json!({}))
            }
            Request::BiometricUnlock { vault, material } => {
                self.biometric_unlock(&vault, &material)?;
                Ok(json!({}))
            }
            Request::Create { password } => {
                validate_new_password(&password)?;
                let key = PasswordType::Password(password.expose_owned()).into();
                self.create_with_key(key).map_err(|e| e.to_string())
            }
            Request::CreateKey { key_file } => {
                let key = tools::new_credentials(None, Some(key_file))?;
                self.create_with_key(key).map_err(|e| e.to_string())
            }
            Request::NewKeyFile => Ok(tools::new_key_file()),
            Request::ImportVault { data } => {
                crate::encryption::validate_vault_header(&data)?;
                if data.len() as u64 > MAX_VAULT_BYTES {
                    return Err("Vault exceeds size limit".into());
                }
                let name = format!("{}.enc", hex::encode(rand::random::<[u8; 16]>()));
                crate::cloud::write_private(&self.path(&name)?, &data, false)?;
                Ok(json!({ "vault": name }))
            }
            Request::RestoreBackup {
                data,
                password,
                key_file,
            } => self.restore_backup(&data, password, key_file),
            Request::BiometricMaterial => self.biometric_material(),
            _ => Err(MISROUTED.into()),
        }
    }

    /// Device-local preferences and tools that never touch the vault.
    fn settings_request(&mut self, request: Request) -> Result<Value, String> {
        match request {
            Request::SettingsGet => Ok(json!(self.settings)),
            Request::SettingsSave { settings } => {
                settings.save(&self.directory)?;
                self.settings = settings;
                Ok(json!(self.settings))
            }
            Request::Generate(options) => options.generate(&self.settings),
            Request::Passcheck { password } => {
                let (score, rating) = crate::password::strength_rating(&password);
                Ok(json!({
                    "assessment": crate::password::password_strength_output(&password),
                    "score": score,
                    "rating": rating,
                    // The same rule vault creation applies, for live feedback.
                    "master_problem": crate::encryption::validate_new_password(&password).err(),
                }))
            }
            Request::ItemProfiles => Ok(crate::item_profile::profiles_json()),
            _ => Err(MISROUTED.into()),
        }
    }

    /// Platform autofill: logins and codes only for an origin the app verified.
    fn autofill_request(&mut self, request: Request) -> Result<Value, String> {
        match request {
            Request::Logins { origin } => {
                let vault = self.vault()?;
                let logins: Vec<_> = self
                    .login_ids(&origin)
                    .into_iter()
                    .filter_map(|id| vault.item(id))
                    .map(|item| vault.summary(item))
                    .collect();
                Ok(json!(logins))
            }
            Request::HostnameLogins { origin } => self.browser_choices(&origin, true, false),
            Request::SavedLogins {
                origin,
                hostname_only,
                username,
                password,
            } => {
                let vault = self.vault()?;
                let ids: std::collections::BTreeSet<usize> = if hostname_only {
                    vault
                        .mobile_browser_choices(&origin, true, false)
                        .into_iter()
                        .map(|(summary, _)| summary.id)
                        .collect()
                } else {
                    self.login_ids(&origin).into_iter().collect()
                };
                let saved: Vec<_> = ids
                    .into_iter()
                    .filter_map(|id| vault.item(id))
                    .filter(|item| super::browser::login_holds(item, &username, &password))
                    .map(|item| vault.summary(item))
                    .collect();
                Ok(json!(saved))
            }
            Request::OtpLogins {
                origin,
                hostname_only,
            } => self.browser_choices(&origin, hostname_only, true),
            Request::Login { id, origin } => self.login(id, &origin),
            Request::SiteOtp { id, origin } => self.site_otp(id, &origin),
            Request::TypedFields { fields } => {
                if fields.len() > 1000 || fields.iter().any(|f| f.len() > 4096) {
                    return Err("Too many or too long field descriptions".into());
                }
                Ok(json!(typed_fill::classify(&fields)))
            }
            Request::TypedChoices { kind } => Ok(json!(self.vault()?.typed_fill_choices(kind))),
            Request::TypedValues { id, kind, roles } => {
                if roles.len() > 64 {
                    return Err("Too many fields".into());
                }
                let values = self
                    .vault()?
                    .typed_fill_values(id, kind, &roles)
                    .map_err(|e| e.to_string())?;
                Ok(json!(values))
            }
            _ => Err(MISROUTED.into()),
        }
    }

    /// The platform credential provider's passkeys.
    fn passkey_request(&mut self, request: Request) -> Result<Value, String> {
        match request {
            Request::Passkeys { request } => {
                let passkeys: Vec<_> = self
                    .passkey_identities()?
                    .iter()
                    .filter(|(_, p)| request.as_ref().is_none_or(|q| p.matches(q)))
                    .map(|(id, p)| {
                        json!({
                            "id": id,
                            "credential_id": p.credential_id,
                            "rp_id": p.rp_id,
                            "user_name": p.user_name,
                            "display_name": p.display_name,
                        })
                    })
                    .collect();
                Ok(json!(passkeys))
            }
            Request::PasskeyCreate {
                request,
                origin,
                client_hash,
            } => {
                let existing: Vec<_> = self
                    .passkey_identities()?
                    .into_iter()
                    .map(|(_, p)| p)
                    .collect();
                let hash = client_hash.as_deref().map(passkey::decode).transpose()?;
                // The provider activity requires a fresh unlock (password or
                // biometric) before every passkey operation.
                let (p, response) =
                    passkey::create(&request, &origin, hash.as_deref(), &existing, true)?;
                self.save_passkey(&p)?;
                Ok(response)
            }
            Request::PasskeyGet {
                id,
                request,
                origin,
                client_hash,
            } => {
                let p = self.passkey(id)?;
                let hash = client_hash.as_deref().map(passkey::decode).transpose()?;
                p.authenticate(&request, &origin, hash.as_deref(), true)
            }
            _ => Err(MISROUTED.into()),
        }
    }

    /// Snapshots, transfers, credentials, and retention.
    fn file_request(&mut self, request: Request) -> Result<Value, String> {
        match request {
            Request::Snapshot => {
                let path = self.vault()?.sync_path()?;
                let bytes = crate::file::read_bounded_file(&path, MAX_SNAPSHOT_BYTES).map_err(
                    |_| "Encrypted vault exceeds mobile transfer limit or could not be read",
                )?;
                Ok(binary_reply(bytes))
            }
            Request::ExportItems { format, confirmed } => {
                self.export_items(format.as_deref() != Some("csv"), confirmed)
            }
            Request::AttachmentAdd {
                id,
                name,
                data,
                expected_revision,
            } => {
                let target = Target::Id(id);
                self.with_unlocked(|vault, credentials| {
                    if let Some(expected) = expected_revision
                        && vault.target_revision(&target) != Some(expected)
                    {
                        return Err(VaultError::Conflict(ITEM_CHANGED.into()));
                    }
                    vault.add_attachment(&target, &name, data, credentials)
                })?;
                Ok(json!({ "message": "Attachment added." }))
            }
            Request::AttachmentData { id, name } => {
                let data = self
                    .vault()?
                    .attachment_data(&Target::Id(id), &name)
                    .map_err(|e| e.to_string())?;
                Ok(binary_reply(data))
            }
            Request::ImportItems {
                data,
                conflicts,
                preview,
                review_token,
            } => self.import_items(
                &data,
                conflicts.unwrap_or(ConflictPolicy::Skip),
                preview.unwrap_or(true),
                review_token,
            ),
            Request::BackupCreate { password, key_file } => {
                self.backup_create(tools::new_credentials(password, key_file)?)
            }
            Request::Rekey { password, key_file } => {
                self.rekey(tools::new_credentials(password, key_file)?)
            }
            Request::RekeyRecovery => self.rekey_recovery(),
            Request::DeleteRekeyRecovery { confirmed } => self.delete_rekey_recovery(confirmed),
            Request::DeleteVault { confirmed } => self.delete_vault(confirmed),
            Request::PurgeExpired => {
                let days = self.settings.trash_days;
                let removed = self.with_unlocked(|vault, credentials| {
                    vault.purge_expired_trash(days, credentials)
                })?;
                Ok(json!({ "removed": removed }))
            }
            _ => Err(MISROUTED.into()),
        }
    }

    /// The vault step of a shared command, including the idle timeout. Any
    /// deferred work is returned for the caller to finish without the mutex.
    fn prepare_command(
        &mut self,
        mut command: ServerCommand,
        expected_revision: Option<u64>,
        confirmed: bool,
    ) -> Result<PreparedCommand, String> {
        self.open()?;
        if let Err(error) = mobile_command(&command) {
            command.zeroize();
            return Err(error.into());
        }
        let history_limit = self.settings.history_limit;
        let session = self.session_id();
        self.with_unlocked(|vault, credentials| {
            if let Some(required) = confirmation(vault, &command)
                && !confirmed
            {
                command.zeroize();
                return Err(VaultError::Validation(required.into()));
            }
            // Saving an item without changes succeeds, as the app has always shown.
            let existing_update = matches!(&command, ServerCommand::Update(u) if vault.entry_id(&u.entry.target).ok().flatten().is_some());
            if let Some(expected) = expected_revision
                && !operations::expected_revision_matches(Some(vault), &command, expected)
            {
                command.zeroize();
                return Err(VaultError::Conflict(ITEM_CHANGED.into()));
            }
            let mut reply = None;
            let deferred =
                operations::execute_unlocked(&mut reply, command, vault, credentials, history_limit);
            Ok(PreparedCommand {
                reply,
                deferred,
                existing_update,
                session,
            })
        })
    }

    fn vault_names(&self) -> Result<Vec<String>, String> {
        let names =
            crate::file::list_vault_files(&self.directory).map_err(|_| "Could not list vaults")?;
        Ok(names
            .into_iter()
            .filter(|name| validate_vault_filename(name).is_ok())
            .collect())
    }

    fn biometric_unlock(&mut self, name: &str, material: &str) -> Result<(), String> {
        self.lock();
        let data = Zeroizing::new(passkey::decode(material)?);
        let encrypted = self.read_vault_file(name)?;
        crate::encryption::validate_vault_header(&encrypted)?;
        if data.len() != KEY_BYTES + HEADER_PREFIX_BYTES
            || data[KEY_BYTES..] != encrypted[..HEADER_PREFIX_BYTES]
        {
            return Err("Biometric key is stale; use password or key file".into());
        }
        let key = crate::encryption::cached_credentials(
            &encrypted,
            data[..KEY_BYTES].try_into().map_err(|_| "Invalid key")?,
        )?;
        self.unlock(name, key, false)
    }

    fn biometric_material(&self) -> Result<Value, String> {
        if !self.primary_unlock {
            return Err(
                "Unlock with the original password or key file before enabling biometrics".into(),
            );
        }
        let vault = self.vault()?;
        let encrypted = crate::file::read_bounded_file(&vault.sync_path()?, MAX_VAULT_BYTES)
            .map_err(|_| "Could not read vault")?;
        let Some(VaultCredentials::Session { encryption_key, .. }) = self.session.credentials()
        else {
            return Err(LOCKED.into());
        };
        let mut material = Zeroizing::new(encryption_key.to_vec());
        material.extend_from_slice(&encrypted[..HEADER_PREFIX_BYTES]);
        Ok(json!({
            "material": passkey::encode(&*material),
            "vault": vault.metadata.filename,
        }))
    }

    /// IDs of logins with a password that may be filled for `origin`.
    fn login_ids(&self, origin: &str) -> Vec<usize> {
        let Some(vault) = self.session.vault() else {
            return vec![];
        };
        if origin.starts_with("https://") {
            return vault.site_login_ids(origin);
        }
        vault
            .active_items()
            .filter(|item| login_matches(vault, item, origin))
            .map(|item| item.entry.id)
            .collect()
    }

    /// Whether one item is a login matching `origin`, without scanning the vault.
    fn login_matches_id(&self, id: usize, origin: &str) -> bool {
        self.session.vault().is_some_and(|vault| {
            vault
                .item(id)
                .is_some_and(|item| item.active() && login_matches(vault, item, origin))
        })
    }

    fn browser_choices(
        &self,
        origin: &str,
        hostname_only: bool,
        otp_only: bool,
    ) -> Result<Value, String> {
        let choices: Vec<_> = self
            .vault()?
            .mobile_browser_choices(origin, hostname_only, otp_only)
            .into_iter()
            .map(|(item, origin)| {
                json!({
                    "id": item.id,
                    "name": item.name,
                    "username": item.username,
                    "origin": origin,
                    "has_totp": item.has_totp,
                })
            })
            .collect();
        Ok(json!(choices))
    }

    fn login(&self, id: usize, origin: &str) -> Result<Value, String> {
        if !self.login_matches_id(id, origin) {
            return Err("No matching login".into());
        }
        let item = self.vault()?.item(id).ok_or("No matching login")?;
        Ok(json!(BrowserLogin {
            id,
            revision: item.revision,
            name: item.entry.name.clone(),
            username: item.entry.username.clone(),
            password: item.entry.password.clone(),
            has_totp: item.authenticator.is_some(),
        }))
    }

    /// A time-based code for a login the platform has matched to `origin`.
    /// Counter-based codes are never consumed by autofill.
    fn site_otp(&self, id: usize, origin: &str) -> Result<Value, String> {
        let vault = self.vault()?;
        let matches = if origin.starts_with("androidapp://") {
            self.login_matches_id(id, origin)
                && vault.item(id).is_some_and(|item| {
                    matches!(
                        item.authenticator.as_ref().map(|auth| &auth.state),
                        Some(AuthenticatorState::Totp(_))
                    )
                })
        } else {
            vault
                .mobile_browser_choices(origin, false, true)
                .iter()
                .any(|(item, _)| item.id == id)
        };
        if !matches {
            return Err("No matching authenticator".into());
        }
        let (code, expires) = vault
            .current_totp(Target::Id(id))
            .map_err(|e| e.to_string())?;
        Ok(json!({ "code": code, "expires_in": expires }))
    }

    /// Public identities of stored passkeys. Private keys are neither parsed
    /// nor copied, and a damaged record is skipped instead of hiding the rest.
    fn passkey_identities(&self) -> Result<Vec<(usize, PasskeyIdentity)>, String> {
        let (result, skipped) = self.vault()?.passkey_identities();
        if skipped > 0 {
            // A count only: never log a record, identity, or key.
            eprintln!("pm-mobile: skipped {skipped} invalid stored passkey record(s)");
        }
        Ok(result)
    }

    /// One stored passkey with its signing key, fully validated before use.
    fn passkey(&self, id: usize) -> Result<Passkey, String> {
        self.vault()?.stored_passkey(id)
    }

    fn save_passkey(&mut self, p: &Passkey) -> Result<(), String> {
        self.with_unlocked(|vault, credentials| {
            vault
                .save_passkey(p, credentials)
                .map_err(VaultError::Persistence)
        })
    }
}

/// Vault commands the app may send. Session lifecycle and file paths belong to
/// the mobile requests above; clipboard copies belong to the app.
/// An active login with a password whose saved app or website matches `origin`.
fn login_matches(vault: &Vault, item: &Item, origin: &str) -> bool {
    if item.entry.password.is_empty() {
        return false;
    }
    if origin.starts_with("androidapp://") {
        item.metadata.kind == ItemKind::Login && item.urls().any(|url| url == origin)
    } else if origin.starts_with("https://") {
        vault
            .browser_login_revision(origin, item.entry.id)
            .is_some()
    } else {
        false
    }
}

fn mobile_command(command: &ServerCommand) -> Result<(), &'static str> {
    use ServerCommand as C;
    let allowed = match command {
        C::List(_)
        | C::ManagementItem { .. }
        | C::Update(_)
        | C::History(_)
        | C::RestorePassword { .. }
        | C::Trash
        | C::RestoreTrash(_)
        | C::PurgeTrash(_)
        | C::Audit(_)
        | C::AuthenticatorData(_)
        | C::Duo(_)
        | C::Totp(TotpCommand::Set { .. } | TotpCommand::Remove { .. } | TotpCommand::Duo { .. }) => {
            true
        }
        C::Add {
            entry,
            copy_timeout,
        } => !entry.entry.copy && *copy_timeout == 0,
        C::Delete(target) => !matches!(target, Target::Vault { .. }),
        // Adding and saving use the mobile byte requests instead of paths.
        C::Attachment(crate::types::AttachmentCommand::Remove { .. }) => true,
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err("Unsupported mobile vault command")
    }
}

/// Irreversible commands the app must confirm with the user first, and why.
fn confirmation(vault: &Vault, command: &ServerCommand) -> Option<&'static str> {
    match command {
        ServerCommand::PurgeTrash(_) => Some("Confirm permanent deletion"),
        ServerCommand::AuthenticatorData(target)
            if vault
                .target_item(target)
                .and_then(|item| item.authenticator.as_ref())
                .is_some_and(|a| matches!(a.state, AuthenticatorState::Hotp { .. })) =>
        {
            Some("Confirm generation; HOTP advances its counter")
        }
        _ => None,
    }
}

/// Converts the shared command reply into the app's reply. Failures are
/// plain messages; an incomplete audit still returns its partial report. With
/// `existing_update`, "not found or unchanged" means the item was unchanged.
fn response_value(reply: Option<RpcResponse>, existing_update: bool) -> Result<Value, String> {
    let response = reply.ok_or("Vault command produced no response")?;
    if existing_update && response.code == ResponseCode::NotFound as i32 {
        return Ok(json!({ "changed": false }));
    }
    let notice = response.notice;
    match response.payload {
        ResponsePayload::Message(message) if response.code != ResponseCode::Success as i32 => {
            Err(message)
        }
        // The app shows result messages, so the notice follows the message.
        ResponsePayload::Message(message) => Ok(Value::String(match notice {
            Some(notice) => format!("{message} {notice}"),
            None => message,
        })),
        payload => Ok(payload.into_json()),
    }
}

/// Mobile host for the shared sync engine and deferred work. Each step takes
/// the vault mutex only for itself, so network transfers never hold it.
struct MobileHost<'a> {
    owner: &'a Arc<Mutex<MobileState>>,
    /// The request's view of the app's lock signal.
    ticket: Ticket,
    client: Option<CloudClient>,
    directory: PathBuf,
}

impl VaultHost for MobileHost<'_> {
    fn with_session<T: Send + 'static>(
        &self,
        session: Option<String>,
        apply: impl FnOnce(&mut Vault, &mut VaultCredentials) -> Result<T, VaultError> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<Result<T, VaultError>, String>> + Send {
        let result = (|| {
            let mut owner = guard(self.owner);
            if session.is_none() || owner.session_id() != session {
                return Err(crate::server::SESSION_CHANGED.to_owned());
            }
            Ok(owner.session.with_unlocked(apply))
        })();
        async move { result }
    }

    fn staleness(&self, session: Option<String>, revision: Option<u64>) -> Stale {
        let (owner, ticket) = (Arc::clone(self.owner), self.ticket);
        Arc::new(move || {
            if ticket.cancelled() || session.is_none() {
                return true;
            }
            let owner = guard(&owner);
            owner.session_id() != session
                || revision.is_some_and(|revision| {
                    owner.session.vault().map(Vault::vault_revision) != Some(revision)
                })
        })
    }

    /// Runs on the calling thread, which the app already keeps off its UI.
    fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> operations::Blocking<T> {
        let result = work();
        Box::pin(async move { Some(result) })
    }
}

impl SyncHost for MobileHost<'_> {
    fn client(&self) -> impl std::future::Future<Output = Result<CloudClient, String>> + Send {
        let client = self
            .client
            .clone()
            .ok_or_else(|| "Missing server".to_owned());
        async move { client }
    }
    fn snapshot(&self) -> impl std::future::Future<Output = Result<Snapshot, String>> + Send {
        let snapshot = (|| {
            let owner = guard(self.owner);
            Snapshot::of(owner.vault()?, owner.session_id().ok_or(LOCKED)?)
        })();
        async move { snapshot }
    }
    fn directory(&self) -> PathBuf {
        self.directory.clone()
    }
}

fn mobile_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| "Could not start sync")?;
    let _ = RUNTIME.set(runtime);
    RUNTIME
        .get()
        .ok_or_else(|| "Could not initialize sync runtime".into())
}

/// Runs network work on the shared runtime; the app's lock signal aborts it.
fn block_on<T>(ticket: &Ticket, future: impl std::future::Future<Output = T>) -> Result<T, String> {
    Ok(mobile_runtime()?.block_on(interruptible(ticket, future))?)
}

fn client(server: &str, token: SecretString) -> Result<CloudClient, String> {
    CloudClient::with_token(server, Zeroizing::new(token.expose_owned()))
}

fn wipe_json(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe_json),
        Value::Object(o) => o.values_mut().for_each(wipe_json),
        _ => {}
    }
}

pub fn wipe_response(value: &mut Value) {
    wipe_json(value);
}

async fn interruptible<T>(
    ticket: &Ticket,
    future: impl std::future::Future<Output = T>,
) -> Result<T, &'static str> {
    tokio::select! {
        result = future => Ok(result),
        () = ticket.wait() => Err("Operation interrupted; inspect any remote change before retrying"),
    }
}

#[cfg(test)]
pub(super) mod test_support {
    //! Builds the app's requests from typed commands, as the Kotlin layer does.
    use super::*;

    pub fn vault_command(api: &mut MobileVault, command: ServerCommand) -> Result<Value, String> {
        api.call(&json!({ "op": "vault", "command": command }).to_string())
    }

    /// A command the user confirmed in the app (see `confirmation`).
    pub fn confirmed_command(
        api: &mut MobileVault,
        command: ServerCommand,
    ) -> Result<Value, String> {
        api.call(&json!({ "op": "vault", "command": command, "confirmed": true }).to_string())
    }

    pub fn vault_command_at(
        api: &mut MobileVault,
        command: ServerCommand,
        revision: u64,
    ) -> Result<Value, String> {
        api.call(
            &json!({ "op": "vault", "command": command, "expected_revision": revision })
                .to_string(),
        )
    }

    pub fn save(
        api: &mut MobileVault,
        name: &str,
        username: &str,
        password: &str,
        url: &str,
    ) -> Result<Value, String> {
        let entry = TypedEntry {
            entry: crate::types::PasswordEntry {
                name: name.into(),
                username: Some(username.into()),
                password: password.into(),
                url: Some(url.into()),
                notes: None,
                copy: false,
            },
            kind: ItemKind::Login,
            additional_urls: vec![],
            custom_fields: vec![],
            tags: vec![],
            favorite: false,
        };
        vault_command(
            api,
            ServerCommand::Add {
                entry,
                copy_timeout: 0,
            },
        )
    }

    pub fn update(
        api: &mut MobileVault,
        id: usize,
        name: &str,
        password: &str,
    ) -> Result<Value, String> {
        vault_command(api, ServerCommand::Update(change(id, name, password)))
    }

    pub fn change(id: usize, name: &str, password: &str) -> TypedUpdate {
        TypedUpdate::from(EntryUpdate {
            target: Target::Id(id),
            update: EntryChanges {
                name: Some(name.into()),
                ..Default::default()
            },
            password: Some(password.into()),
        })
    }

    pub fn list(api: &mut MobileVault) -> Result<Value, String> {
        vault_command(api, ServerCommand::List(SearchFilter::default()))
    }

    pub fn item(api: &mut MobileVault, id: usize) -> Result<Value, String> {
        vault_command(api, ServerCommand::ManagementItem { id, reveal: true })
    }

    pub fn delete(api: &mut MobileVault, id: usize) -> Result<Value, String> {
        vault_command(api, ServerCommand::Delete(Target::Id(id)))
    }
}

#[cfg(test)]
#[path = "mobile_sync_tests.rs"]
mod sync_tests;

#[cfg(test)]
mod tests {
    use super::test_support::*;

    #[test]
    fn waiting_for_a_background_sync_ends_at_the_lock_signal() {
        use super::*;
        let temp = tempfile::tempdir().unwrap();
        let api = MobileVault::new(temp.path().into()).unwrap();
        let flag: &'static Cancellation = Box::leak(Box::new(Cancellation::new()));
        // A background sync holds the turn through a long upload.
        let _background = api.sync.lock().unwrap();
        let ticket = Ticket::new(Some(flag));
        let started = Instant::now();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                flag.signal();
            });
            assert_eq!(
                api.sync_turn(&ticket, false).err().as_deref(),
                Some(INTERRUPTED)
            );
        });
        assert!(started.elapsed() < SYNC_TURN_WAIT);
    }

    #[test]
    fn website_otp_supports_code_only_items_and_rejects_wrong_origins_and_hotp() {
        use super::*;
        let temp = tempfile::tempdir().unwrap();
        let mut api = MobileVault::new(temp.path().into()).unwrap();
        api.call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
            .unwrap();
        for (name, origin) in [
            ("Login", "https://accounts.example.com"),
            ("Code only", "https://accounts.example.com:8443"),
            ("HOTP", "https://accounts.example.com"),
        ] {
            save(&mut api, name, "synthetic-user", "", origin).unwrap();
        }
        {
            let mut state = api.state();
            state
                .with_unlocked(|vault, _| {
                    for id in [1, 2] {
                        vault.set_test_totp(
                            id,
                            "otpauth://totp/Example?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                        );
                    }
                    vault.set_test_totp(
                        3,
                        "otpauth://hotp/Example?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0",
                    );
                    Ok(())
                })
                .unwrap();
        }
        let choices = api.call(r#"{"op":"otp_logins","origin":"https://accounts.example.com","hostname_only":true}"#).unwrap();
        assert_eq!(choices.as_array().unwrap().len(), 2);
        assert!(!choices.to_string().contains("GEZDGNBV"));
        assert_eq!(
            api.call(r#"{"op":"otp_logins","origin":"https://accounts.example.com"}"#)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(
            api.call(r#"{"op":"site_otp","origin":"https://accounts.example.com","id":2}"#)
                .is_err()
        );
        assert!(
            api.call(r#"{"op":"site_otp","origin":"https://evil.example.com","id":1}"#)
                .is_err()
        );
        assert!(
            api.call(r#"{"op":"site_otp","origin":"https://accounts.example.com","id":3}"#)
                .is_err()
        );
        let code = api
            .call(r#"{"op":"site_otp","origin":"https://accounts.example.com:8443","id":2}"#)
            .unwrap();
        assert_eq!(code["code"].as_str().unwrap().len(), 6);
        assert!((1..=30).contains(&code["expires_in"].as_u64().unwrap()));
        api.lock();
        assert!(
            api.call(r#"{"op":"site_otp","origin":"https://accounts.example.com","id":1}"#)
                .is_err()
        );
    }

    /// The exact JSON shapes the Android app sends (`VaultCommands.kt`).
    #[test]
    fn android_tag_and_favorite_requests_match_the_shared_contract() {
        use super::*;
        let temp = tempfile::tempdir().unwrap();
        let mut api = MobileVault::new(temp.path().into()).unwrap();
        api.call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
            .unwrap();
        let vault = |command: Value| json!({ "op": "vault", "command": command }).to_string();
        api.call(&vault(json!({ "operation": "add", "arguments": {
            "entry": { "entry": { "name": "Tagged", "username": null, "password": "synthetic",
                "url": null, "notes": null, "copy": false },
                "kind": "login", "additional_urls": [], "custom_fields": [],
                "tags": ["Work", "Cloud"], "favorite": false },
            "copy_timeout": 0 } })))
            .unwrap();
        save(
            &mut api,
            "Untagged",
            "user",
            "synthetic",
            "https://example.com",
        )
        .unwrap();
        // The favorite toggle sends only the mark.
        api.call(&vault(json!({ "operation": "update", "arguments": {
            "entry": { "target": { "Id": 1 }, "update": {} }, "kind": null,
            "add_url": [], "remove_url": [], "clear_urls": false, "set_fields": [],
            "remove_fields": [], "clear_fields": false, "favorite": true } })))
            .unwrap();
        let detail = item(&mut api, 1).unwrap();
        assert_eq!(detail["favorite"], true);
        assert_eq!(detail["tags"], json!(["Work", "Cloud"]));
        assert_eq!(detail["password"], "synthetic");
        // A full edit replaces the tags; an edit without tag fields keeps them.
        api.call(&vault(json!({ "operation": "update", "arguments": {
            "entry": { "target": { "Id": 1 }, "update": { "name": "Tagged", "username": null,
                "url": null, "notes": null }, "password": "synthetic" },
            "kind": "login", "add_url": [], "remove_url": [], "clear_urls": true,
            "set_fields": [], "remove_fields": [], "clear_fields": true,
            "add_tags": ["Home"], "remove_tags": [], "clear_tags": true, "favorite": true } })))
            .unwrap();
        assert_eq!(item(&mut api, 1).unwrap()["tags"], json!(["Home"]));
        update(&mut api, 1, "Tagged", "synthetic").unwrap();
        assert_eq!(item(&mut api, 1).unwrap()["tags"], json!(["Home"]));
        let favorites = api
            .call(&vault(json!({ "operation": "list", "arguments": {
                "query": null, "name": null, "username": null, "url": null, "notes": null,
                "list": { "kind": null, "has_totp": null, "weak": false, "stale_days": null,
                    "sort": "name", "descending": false, "tags": [], "favorite": true } } })))
            .unwrap();
        let items = favorites["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["name"], "Tagged");
        assert_eq!(items[0]["favorite"], true);
    }

    #[test]
    fn binary_calls_carry_file_content_beside_the_json_both_ways() {
        use super::*;
        let temp = tempfile::tempdir().unwrap();
        let mut api = MobileVault::new(temp.path().into()).unwrap();
        api.call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
            .unwrap();
        save(
            &mut api,
            "Holder",
            "user",
            "synthetic",
            "https://example.com",
        )
        .unwrap();
        let revision = item(&mut api, 1).unwrap()["revision"].as_u64().unwrap();
        let content = vec![0u8, 1, 2, 250, 255];
        let add = json!({ "op": "attachment_add", "id": 1, "name": "scan.png",
            "expected_revision": revision })
        .to_string();
        // Content must come from one place: bytes, or a JSON field, never neither or both.
        let invalid = |result: Result<(Value, Option<Payload>), String>| {
            assert!(
                result
                    .unwrap_err()
                    .contains("Invalid or unsupported mobile request")
            );
        };
        invalid(api.call_binary(&add, None));
        invalid(
            api.call_binary(
                &json!({ "op": "attachment_add", "id": 1, "name": "scan.png",
                "data": passkey::encode(&content) })
                .to_string(),
                Some(Zeroizing::new(content.clone())),
            ),
        );
        invalid(api.call_binary(r#"{"op":"status"}"#, Some(Zeroizing::new(vec![1]))));
        let (reply, outgoing) = api
            .call_binary(&add, Some(Zeroizing::new(content.clone())))
            .unwrap();
        assert!(outgoing.is_none());
        assert_eq!(reply["message"], "Attachment added.");
        // Content comes back as bytes, and the JSON call still encodes it.
        let (reply, outgoing) = api
            .call_binary(r#"{"op":"attachment_data","id":1,"name":"scan.png"}"#, None)
            .unwrap();
        assert_eq!(reply, json!({}));
        assert_eq!(*outgoing.unwrap(), content);
        let encoded = api
            .call(r#"{"op":"attachment_data","id":1,"name":"scan.png"}"#)
            .unwrap();
        assert_eq!(encoded["data"], passkey::encode(&content));
        // A round trip of the encrypted snapshot, imported as a separate vault file.
        let (_, snapshot) = api.call_binary(r#"{"op":"snapshot"}"#, None).unwrap();
        let (imported, _) = api
            .call_binary(r#"{"op":"import_vault"}"#, snapshot)
            .unwrap();
        assert!(imported["vault"].as_str().unwrap().ends_with(".enc"));
        // A failed request returns no content.
        api.lock();
        assert!(
            api.call_binary(r#"{"op":"attachment_data","id":1,"name":"scan.png"}"#, None)
                .is_err()
        );
        assert!(take_outgoing().is_none());
    }

    #[test]
    fn android_attachments_transfer_bytes_and_respect_revisions_and_limits() {
        use super::*;
        let temp = tempfile::tempdir().unwrap();
        let mut api = MobileVault::new(temp.path().into()).unwrap();
        api.call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
            .unwrap();
        save(
            &mut api,
            "Holder",
            "user",
            "synthetic",
            "https://example.com",
        )
        .unwrap();
        let content = passkey::encode([0u8, 1, 2, 250, 255]);
        let add = |revision: u64| {
            json!({ "op": "attachment_add", "id": 1, "name": "scan.png",
                "data": content, "expected_revision": revision })
            .to_string()
        };
        assert!(api.call(&add(99)).unwrap_err().contains("changed"));
        let revision = item(&mut api, 1).unwrap()["revision"].as_u64().unwrap();
        api.call(&add(revision)).unwrap();
        let detail = item(&mut api, 1).unwrap();
        assert_eq!(detail["attachments"][0]["name"], "scan.png");
        assert_eq!(detail["attachments"][0]["size"], 5);
        let data = api
            .call(r#"{"op":"attachment_data","id":1,"name":"SCAN.png"}"#)
            .unwrap();
        assert_eq!(data["data"], content);
        let oversized = passkey::encode(vec![0u8; attachments::MAX_ATTACHMENT_BYTES + 1]);
        assert!(
            api.call(
                &json!({ "op": "attachment_add", "id": 1, "name": "big", "data": oversized })
                    .to_string()
            )
            .is_err()
        );
        // Path-based commands are desktop-only; removal goes through the vault command.
        for command in [
            json!({ "Add": { "target": { "Id": 1 }, "path": "/etc/hosts", "name": null } }),
            json!({ "Save": { "target": { "Id": 1 }, "name": "scan.png",
                "path": "/tmp/out", "force": true } }),
        ] {
            assert!(
                vault_command(
                    &mut api,
                    serde_json::from_value(
                        json!({ "operation": "attachment", "arguments": command })
                    )
                    .unwrap()
                )
                .is_err()
            );
        }
        vault_command(
            &mut api,
            ServerCommand::Attachment(crate::types::AttachmentCommand::Remove {
                target: Target::Id(1),
                name: "scan.png".into(),
            }),
        )
        .unwrap();
        assert!(
            item(&mut api, 1).unwrap()["attachments"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        api.lock();
        assert!(
            api.call(r#"{"op":"attachment_data","id":1,"name":"scan.png"}"#)
                .is_err()
        );
    }

    #[test]
    fn android_card_and_identity_requests_classify_while_locked_and_fill_while_unlocked() {
        use super::*;
        let temp = tempfile::tempdir().unwrap();
        let mut api = MobileVault::new(temp.path().into()).unwrap();
        // Classification needs no vault.
        let roles = api
            .call(r#"{"op":"typed_fields","fields":["creditCardNumber","cc-csc","username"]}"#)
            .unwrap();
        assert_eq!(roles[0]["role"], "cc-number");
        assert_eq!(roles[0]["kind"], "payment-card");
        assert_eq!(roles[1]["role"], "cc-csc");
        assert!(roles[2].is_null());
        assert!(
            api.call(r#"{"op":"typed_choices","kind":"payment-card"}"#)
                .is_err()
        );
        api.call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
            .unwrap();
        vault_command(
            &mut api,
            ServerCommand::Add {
                entry: TypedEntry {
                    entry: PasswordEntry {
                        name: "Visa".into(),
                        username: Some("Alex Example".into()),
                        password: "4111111111111111".into(),
                        url: None,
                        notes: None,
                        copy: false,
                    },
                    kind: ItemKind::PaymentCard,
                    additional_urls: vec![],
                    custom_fields: vec![CustomField {
                        name: "Security code".into(),
                        value: "123".into(),
                        secret: true,
                    }],
                    tags: vec![],
                    favorite: false,
                },
                copy_timeout: 0,
            },
        )
        .unwrap();
        save(
            &mut api,
            "Login",
            "user",
            "synthetic",
            "https://example.com",
        )
        .unwrap();
        let choices = api
            .call(r#"{"op":"typed_choices","kind":"payment-card"}"#)
            .unwrap();
        assert_eq!(choices.as_array().unwrap().len(), 1);
        assert!(
            !choices.to_string().contains("4111"),
            "choices carry no secrets"
        );
        let values = api
            .call(r#"{"op":"typed_values","id":1,"kind":"payment-card","roles":["cc-number","cc-csc","cc-name"]}"#)
            .unwrap();
        assert_eq!(values["cc-number"], "4111111111111111");
        assert_eq!(values["cc-csc"], "123");
        assert_eq!(values["cc-name"], "Alex Example");
        assert!(
            api.call(r#"{"op":"typed_values","id":2,"kind":"payment-card","roles":["cc-number"]}"#)
                .is_err(),
            "a login is never filled as a card"
        );
        assert!(
            api.call(r#"{"op":"typed_choices","kind":"login"}"#)
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn hostname_choices_require_unlock_and_do_not_relax_secret_origin_checks() {
        use super::*;
        let temp = tempfile::tempdir().unwrap();
        let mut api = MobileVault::new(temp.path().into()).unwrap();
        let request = r#"{"op":"hostname_logins","origin":"https://accounts.example.com"}"#;
        assert!(api.call(request).is_err());
        api.call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
            .unwrap();
        for (name, url) in [
            ("Default", "https://accounts.example.com/login"),
            ("Other port", "https://accounts.example.com:8443"),
            ("Other host", "https://example.com"),
            ("Lookalike", "https://accounts.example.com.evil.test"),
            ("HTTP", "http://accounts.example.com"),
            ("Wildcard", "https://*.example.com"),
            ("Deleted", "https://accounts.example.com"),
        ] {
            save(&mut api, name, "synthetic-user", "synthetic-secret", url).unwrap();
        }
        delete(&mut api, 7).unwrap();
        let choices = api.call(request).unwrap();
        let entries = choices.as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["origin"], "https://accounts.example.com");
        assert_eq!(entries[1]["origin"], "https://accounts.example.com:8443");
        assert!(!choices.to_string().contains("synthetic-secret"));
        assert!(
            api.call(r#"{"op":"hostname_logins","origin":"http://accounts.example.com"}"#)
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty()
        );
        let exact = api
            .call(r#"{"op":"logins","origin":"https://accounts.example.com"}"#)
            .unwrap();
        assert!(
            exact
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["id"] == 1)
        );
        // Existing explicit wildcard rules remain supported by the exact-origin
        // path, but the alternate port must not be authorized there.
        assert!(
            exact
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["id"] != 2)
        );
        assert!(
            api.call(r#"{"op":"login","origin":"https://accounts.example.com","id":2}"#)
                .is_err()
        );
        assert!(
            api.call(r#"{"op":"login","origin":"https://accounts.example.com:8443","id":2}"#)
                .is_ok()
        );
        api.lock();
        assert!(api.call(request).is_err());
    }

    #[test]
    fn saved_logins_match_unchanged_sign_ins_without_returning_secrets() {
        use super::*;
        let temp = tempfile::tempdir().unwrap();
        let mut api = MobileVault::new(temp.path().into()).unwrap();
        let ids = |api: &MobileVault, request: &str| -> Vec<u64> {
            api.call(request)
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| {
                    assert!(!entry.to_string().contains("synthetic-secret"));
                    entry["id"].as_u64().unwrap()
                })
                .collect()
        };
        let exact = r#"{"op":"saved_logins","origin":"https://example.com","username":" Alex@Example.com ","password":"synthetic-secret"}"#;
        assert!(api.call(exact).is_err(), "requires an unlocked vault");
        api.call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
            .unwrap();
        save(
            &mut api,
            "Site",
            "alex@example.com",
            "synthetic-secret",
            "https://example.com",
        )
        .unwrap();
        save(
            &mut api,
            "Other",
            "sam@example.com",
            "synthetic-secret",
            "https://example.com",
        )
        .unwrap();
        save(
            &mut api,
            "Port",
            "alex@example.com",
            "synthetic-secret",
            "https://example.com:8443",
        )
        .unwrap();
        save(
            &mut api,
            "Elsewhere",
            "alex@example.com",
            "synthetic-secret",
            "https://other.test",
        )
        .unwrap();
        // Username case and surrounding space are ignored; port and host still apply.
        assert_eq!(ids(&api, exact), vec![1]);
        // A changed password is not "already saved".
        assert!(
            ids(
                &api,
                &exact.replace("synthetic-secret", "synthetic-secret2")
            )
            .is_empty()
        );
        // Without a captured username, any login holding the password matches.
        assert_eq!(
            ids(
                &api,
                r#"{"op":"saved_logins","origin":"https://example.com","password":"synthetic-secret"}"#
            ),
            vec![1, 2]
        );
        // Chrome's hostname-only forms consider every port on the host.
        assert_eq!(
            ids(
                &api,
                r#"{"op":"saved_logins","origin":"https://example.com","hostname_only":true,"username":"alex@example.com","password":"synthetic-secret"}"#
            ),
            vec![1, 3]
        );
    }

    use super::*;
    #[test]
    fn external_key_contents_unlock_without_desktop_paths() {
        let directory = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let material: [u8; 32] = rand::random();
        let key_path = external.path().join("external.key");
        fs::write(&key_path, material).unwrap();
        let mut vault = Vault::memory();
        vault.metadata.filename = "key-vault.enc".into();
        vault.store = VaultStore::File {
            directory: directory.path().into(),
            filename: "key-vault.enc".into(),
        };
        let mut key =
            VaultCredentials::from(PasswordType::Key(key_path.to_string_lossy().into_owned()));
        persistence::write_vault_with_key(&vault, &mut key).unwrap();
        let mut mobile = MobileVault::new(directory.path().into()).unwrap();
        mobile.call(&json!({"op":"unlock","vault":"key-vault.enc","key_file":passkey::encode(material)}).to_string()).unwrap();
        assert!(mobile.call(r#"{"op":"biometric_material"}"#).is_ok());
        assert!(mobile.call(&json!({"op":"unlock","vault":"key-vault.enc","key_file":passkey::encode([0;32])}).to_string()).is_err());
        assert!(list(&mut mobile).is_err());
    }
    #[test]
    fn passkeys_survive_desktop_documents_backups_and_portable_exports() {
        let temp = tempfile::tempdir().unwrap();
        let mut api = MobileVault::new(temp.path().into()).unwrap();
        let created = api
            .call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
            .unwrap();
        let registration = json!({"op":"passkey_create","origin":"https://example.com","request":{"rp":{"id":"example.com","name":"Example"},"user":{"id":passkey::encode(b"alice"),"name":"alice","displayName":"Alice"},"challenge":passkey::encode([4;32]),"pubKeyCredParams":[{"type":"public-key","alg":-7}]}});
        let response = api.call(&registration.to_string()).unwrap();
        let raw = fs::read(temp.path().join(created["vault"].as_str().unwrap())).unwrap();
        assert!(
            !raw.windows(b"private_key".len())
                .any(|w| w == b"private_key")
        );
        let mut key = api.state().session.credentials().unwrap().clone();
        let plain = decrypt_file(&mut key, &raw).unwrap();
        let document = persistence::decode_document(&plain).unwrap();
        assert_eq!(document.items.len(), 1);
        let record = document.items.values().next().unwrap();
        let stored: Passkey =
            serde_json::from_str(&record.metadata.custom_fields[0].value).unwrap();
        assert_eq!(stored.credential_id, response["id"]);
        assert!(api.state().save_passkey(&stored).is_err());
        assert!(
            api.state()
                .vault()
                .unwrap()
                .browser_logins("https://example.com")
                .is_empty()
        );
        assert!(
            item(&mut api, 1).unwrap()["fields"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let export = temp.path().join("portable.json");
        api.state()
            .vault()
            .unwrap()
            .export(export.to_string_lossy().into_owned(), false)
            .unwrap();
        let imported =
            import::import_json(&fs::read_to_string(export).unwrap(), "synthetic.json").unwrap();
        assert_eq!(
            imported[0].custom_fields[0].value,
            record.metadata.custom_fields[0].value
        );
        assert!(
            api.state()
                .vault()
                .unwrap()
                .export(
                    temp.path().join("lossy.csv").to_string_lossy().into_owned(),
                    false
                )
                .is_err()
        );
        let backup = temp.path().join("vault.pmbackup");
        api.state()
            .vault()
            .unwrap()
            .encrypted_backup(
                backup.to_string_lossy().into_owned(),
                &mut PasswordType::Password("Cedar-Lantern-Quartz-9274!".into()),
                false,
            )
            .unwrap();
        let backed = fs::read(backup).unwrap();
        let mut key =
            VaultCredentials::from(PasswordType::Password("Cedar-Lantern-Quartz-9274!".into()));
        let document =
            persistence::decode_document(&decrypt_file(&mut key, &backed[9..]).unwrap()).unwrap();
        assert_eq!(
            document
                .items
                .values()
                .next()
                .unwrap()
                .metadata
                .custom_fields[0]
                .value,
            record.metadata.custom_fields[0].value
        );
        api.lock();
        api.call(&json!({"op":"unlock","vault":created["vault"],"password":"Cedar-Lantern-Quartz-9274!"}).to_string()).unwrap();
        assert_eq!(
            api.call(r#"{"op":"passkeys"}"#)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let assertion = json!({"op":"passkey_get","id":1,"origin":"https://example.com","request":{"rpId":"example.com","challenge":passkey::encode([3;32])}});
        assert!(api.call(&assertion.to_string()).is_ok());
        // A damaged record is skipped by listing and registration and fails
        // only when it is the passkey being used.
        {
            let mut state = api.state();
            let damaged = TypedEntry {
                entry: crate::types::PasswordEntry {
                    name: "Damaged passkey".into(),
                    username: None,
                    password: "".into(),
                    url: Some("https://example.com".into()),
                    notes: None,
                    copy: false,
                },
                kind: ItemKind::Login,
                additional_urls: vec![],
                custom_fields: vec![CustomField {
                    name: passkey::FIELD.into(),
                    value: "not a passkey".into(),
                    secret: true,
                }],
                tags: vec![],
                favorite: false,
            };
            assert!(
                state
                    .with_unlocked(
                        |vault, credentials| vault.add_passkey_entry(damaged, credentials)
                    )
                    .unwrap()
            );
        }
        let listed = api.call(r#"{"op":"passkeys"}"#).unwrap();
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(listed[0]["id"], 1);
        assert!(api.call(&assertion.to_string()).is_ok());
        let mut damaged = assertion.clone();
        damaged["id"] = json!(2);
        assert!(api.call(&damaged.to_string()).is_err());
        let mut second = registration.clone();
        second["request"]["user"] =
            json!({"id":passkey::encode(b"bob"),"name":"bob","displayName":"Bob"});
        assert!(api.call(&second.to_string()).is_ok());
        let mut excluded = registration;
        excluded["request"]["excludeCredentials"] =
            json!([{"type":"public-key","id":response["id"]}]);
        assert_eq!(
            api.call(&excluded.to_string()).unwrap_err(),
            "CredentialExcluded"
        );
    }
    #[test]
    fn mobile_persists_existing_format_and_biometric_unlock_rejects_wrong_keys() {
        let temp = tempfile::tempdir().unwrap();
        let mut api = MobileVault::new(temp.path().into()).unwrap();
        let created = api
            .call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
            .unwrap();
        save(
            &mut api,
            "Example",
            "alice",
            "synthetic-secret",
            "https://example.com",
        )
        .unwrap();
        let material = api.call(r#"{"op":"biometric_material"}"#).unwrap();
        api.lock();
        assert!(list(&mut api).is_err());
        api.call(&json!({"op":"biometric_unlock","vault":created["vault"],"material":material["material"]}).to_string()).unwrap();
        assert_eq!(list(&mut api).unwrap()["total"], 1);
        // Biometric sessions cannot re-export the key or replace/delete the vault.
        for request in [
            json!({"op":"biometric_material"}),
            json!({"op":"rekey","password":"Replacement-Lantern-Quartz-9274!"}),
            json!({"op":"delete_vault","confirmed":true}),
        ] {
            assert!(api.call(&request.to_string()).is_err(), "{request}");
        }
        assert_eq!(list(&mut api).unwrap()["total"], 1);
        api.lock();
        let mut bad = passkey::decode(material["material"].as_str().unwrap()).unwrap();
        bad[0] ^= 1;
        assert!(api.call(&json!({"op":"biometric_unlock","vault":created["vault"],"material":passkey::encode(bad)}).to_string()).is_err());
        assert!(list(&mut api).is_err());
        api.call(&json!({"op":"unlock","vault":created["vault"],"password":"Cedar-Lantern-Quartz-9274!"}).to_string()).unwrap();
        assert_eq!(
            api.call(r#"{"op":"login","origin":"https://evil.com","id":1}"#)
                .unwrap_err(),
            "No matching login"
        );
        api.state().touched = Instant::now() - Duration::from_secs(301);
        assert!(list(&mut api).is_err());
    }
}
