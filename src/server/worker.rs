//! One owner for live vault state. Connections never borrow or lock the vault.
use super::*;
use crate::protocol::{
    OperationReceipt, OperationState, RequestEnvelope, ResponsePayload, RpcResponse,
};
use std::collections::VecDeque;
use tokio::sync::{oneshot, watch};

const QUEUE_CAPACITY: usize = 32;
const CONTROL_CAPACITY: usize = 8;
const RESULT_CAPACITY: usize = 256;
const RESULT_BYTES: usize = 64 * 1024;

type Action = Box<dyn FnOnce(&mut Owner) -> outcome::CommandOutcome + Send>;
struct Job {
    action: Action,
    reply: oneshot::Sender<outcome::CommandOutcome>,
    activity: bool,
}

struct Operation {
    id: String,
    vault_id: Option<[u8; 16]>,
    fingerprint: [u8; 32],
    receipt: OperationReceipt,
    reply: Option<RpcResponse>,
}
impl Drop for Operation {
    fn drop(&mut self) {
        if let Some(response) = self.reply.as_mut() {
            response.zeroize();
        }
    }
}

pub(super) struct Owner {
    pub session: VaultSession,
    operations: VecDeque<Operation>,
    fingerprint_key: Zeroizing<[u8; 32]>,
}
impl Owner {
    fn new(session: VaultSession) -> Self {
        Self {
            session,
            operations: VecDeque::new(),
            fingerprint_key: Zeroizing::new(rand::random()),
        }
    }
    fn clear_results(&mut self) {
        // Keep nonsecret receipts for reconciliation, but never retain unlocked
        // response material after a lock or a change of unlock session.
        for operation in &mut self.operations {
            if let Some(response) = operation.reply.as_mut() {
                response.zeroize();
            }
            operation.reply = None;
        }
    }
    fn receipt(&self, id: &str) -> OperationReceipt {
        self.operations
            .iter()
            .find(|op| op.id == id)
            .map(|op| op.receipt.clone())
            .unwrap_or_else(|| OperationReceipt {
                operation_id: id.to_owned(),
                state: OperationState::Unknown,
                revision: None,
            })
    }
    fn remember(&mut self, operation: Operation) -> Result<(), &'static str> {
        if self.operations.len() >= RESULT_CAPACITY {
            // In-flight effects must not fall out of the deduplication window.
            let Some(index) = self
                .operations
                .iter()
                .position(|op| op.receipt.state != OperationState::Pending)
            else {
                return Err("Too many operations awaiting reconciliation");
            };
            self.operations.remove(index);
        }
        self.operations.push_back(operation);
        Ok(())
    }
    fn complete(&mut self, id: &str, reply: &mut Option<RpcResponse>, external: bool) {
        let revision = self.session.vault().map(Vault::vault_revision);
        if let Some(operation) = self.operations.iter_mut().find(|op| op.id == id) {
            let code = reply.as_ref().map_or(0, |r| r.code);
            operation.receipt.state = if code == ResponseCode::Durability as i32 {
                OperationState::CommittedDurabilityUnknown
            } else if code == ResponseCode::Success as i32 {
                OperationState::Committed
            } else if external {
                OperationState::Unknown
            } else {
                OperationState::Failed
            };
            operation.receipt.revision = revision;
            // Retain small mutation results, particularly consumed HOTP codes.
            // Details/reports can be large and are recoverable through reads;
            // retain their receipt rather than multiplying secret snapshots.
            operation.reply = reply.as_mut().and_then(|response| {
                response.operation = Some(operation.receipt.clone());
                let size = match &response.payload {
                    ResponsePayload::Message(message) => message.len(),
                    ResponsePayload::Authenticator(code) => code.code.len() + code.mode.len(),
                    ResponsePayload::Vault(vault) => vault.vault_file.len(),
                    ResponsePayload::Operation(receipt) => receipt.operation_id.len(),
                    _ => return None,
                };
                (size + 512 <= RESULT_BYTES).then(|| {
                    let mut retained = response.clone();
                    // Deltas are disposable metadata, not part of retry receipts.
                    retained.changes = None;
                    retained
                })
            });
        }
    }
    fn execute(
        &mut self,
        state: ConnectionState,
        mut request: RequestEnvelope,
    ) -> outcome::CommandOutcome {
        if let Err(error) = request.validate() {
            return one(RpcResponse::message(ResponseCode::InvalidInput, error));
        }
        if let ServerCommand::OperationStatus(id) = &request.command {
            return one(RpcResponse::success(ResponsePayload::Operation(
                self.receipt(id),
            )));
        }
        if state.stopping.load(Ordering::Acquire) {
            return one(RpcResponse::message(
                ResponseCode::Failure,
                "Server is stopping.",
            ));
        }
        if request
            .expected_session
            .as_ref()
            .is_some_and(|expected| self.session.session_id().as_ref() != Some(expected))
        {
            return one(RpcResponse::message(
                ResponseCode::Conflict,
                "Unlock session changed; reopen the selection before continuing",
            ));
        }
        let operation_id = request.operation_id.take();
        let fingerprint = operation_id.as_ref().map(|_| {
            let mut bytes = crate::secret::SecretBuffer::default();
            rmp_serde::encode::write_named(
                &mut bytes,
                &(
                    &request.command,
                    request.expected_revision,
                    &request.expected_session,
                ),
            )
            .expect("commands serialize");
            *blake3::keyed_hash(&self.fingerprint_key, &bytes).as_bytes()
        });
        if let (Some(id), Some(fingerprint)) = (&operation_id, fingerprint) {
            if let Some(previous) = self.operations.iter().find(|op| op.id == *id) {
                if previous.vault_id.is_some()
                    && self.session.vault().is_some()
                    && previous.vault_id != self.session.vault().map(Vault::vault_id)
                {
                    return one(RpcResponse::message(
                        ResponseCode::Conflict,
                        "Operation belongs to a different vault",
                    ));
                }
                if previous.fingerprint != fingerprint {
                    return one(RpcResponse::message(
                        ResponseCode::Conflict,
                        "Operation ID was already used for different arguments",
                    ));
                }
                if previous.reply.is_none() {
                    return one(RpcResponse::success(ResponsePayload::Operation(
                        previous.receipt.clone(),
                    )));
                }
                return outcome::CommandOutcome {
                    reply: previous.reply.clone(),
                    effect: CommandEffect::None,
                    ..Default::default()
                };
            }
            let receipt = OperationReceipt {
                operation_id: id.clone(),
                state: OperationState::Pending,
                revision: None,
            };
            if let Err(error) = self.remember(Operation {
                id: id.clone(),
                vault_id: self.session.vault().map(Vault::vault_id),
                fingerprint,
                receipt,
                reply: None,
            }) {
                return one(RpcResponse::message(ResponseCode::Conflict, error));
            }
        }
        if let Some(expected) = request.expected_revision
            && !crate::operations::expected_revision_matches(
                self.session.vault(),
                &request.command,
                expected,
            )
        {
            let mut rejected = one(RpcResponse::message(
                ResponseCode::Conflict,
                "Item changed since it was opened; reopen it before continuing",
            ));
            // The session is unchanged: say so, so clients keep unsaved edits for
            // review rather than treating the conflict as a relock.
            rejected.session_id = self.session.session_id();
            if let Some(response) = rejected.reply.as_mut() {
                response.session_id = rejected.session_id.clone();
            }
            if let Some(id) = operation_id.as_ref() {
                self.complete(id, &mut rejected.reply, false);
            }
            return rejected;
        }
        let _ = self.session.with_unlocked(|vault, _| {
            vault.metadata.changes = None;
            Ok(())
        });
        let before = self.session.epoch();
        let mut result = execute_command(state, request.command, &mut self.session);
        if before != self.session.epoch() || self.session.is_locked() {
            self.clear_results();
        }
        result.session_id = self.session.session_id();
        if let Some(response) = result.reply.as_mut() {
            response.session_id = result.session_id.clone();
            response.vault_revision = self.session.vault().map(Vault::vault_revision);
            response.changes = self.session.vault().and_then(Vault::mutation_changes);
        }
        if let Some(id) = operation_id {
            if matches!(
                result.effect,
                CommandEffect::None | CommandEffect::StopServer
            ) {
                self.complete(&id, &mut result.reply, false);
            } else {
                let receipt = self.receipt(&id);
                if let Some(response) = result.reply.as_mut() {
                    response.operation = Some(receipt.clone());
                }
            }
        }
        result
    }
}
fn one(response: RpcResponse) -> outcome::CommandOutcome {
    outcome::CommandOutcome {
        reply: Some(response),
        effect: CommandEffect::None,
        ..Default::default()
    }
}

/// Passkey confirmation flags published with each session change.
fn passkey_flags_of(session: &VaultSession) -> u8 {
    if session.is_locked() {
        return 0;
    }
    let pin = session.passkey_pin(&crate::file::data_dir());
    u8::from(pin || session.password_check()) | (u8::from(pin) << 1)
}

/// Stores `value` and wakes receivers only when it differs from the current one.
fn publish<T: PartialEq>(sender: &watch::Sender<T>, value: T) {
    sender.send_if_modified(|current| {
        let changed = *current != value;
        if changed {
            *current = value;
        }
        changed
    });
}

#[derive(Clone)]
pub(super) struct VaultWorker {
    normal: mpsc::Sender<Job>,
    control: mpsc::Sender<Job>,
    locked: watch::Receiver<Option<String>>,
    revision: watch::Receiver<Option<u64>>,
    cloud_warning: Arc<Mutex<Option<String>>>,
    /// Passkey confirmation for the unlocked vault: bit 0 means it can
    /// confirm the person, bit 1 means a passkey PIN is set.
    passkey_flags: Arc<std::sync::atomic::AtomicU8>,
}
impl VaultWorker {
    /// Session and vault-revision receivers. The worker notifies only when a
    /// value changes; warnings are observed by subscribers' periodic checks.
    pub(super) fn changes(
        &self,
    ) -> (
        watch::Receiver<Option<String>>,
        watch::Receiver<Option<u64>>,
    ) {
        (self.locked.clone(), self.revision.clone())
    }
    pub fn start(
        session: VaultSession,
        timeout: Arc<AtomicU64>,
        background: Arc<Mutex<Option<String>>>,
    ) -> Self {
        let (normal_tx, mut normal) = mpsc::channel::<Job>(QUEUE_CAPACITY);
        let (control_tx, mut control) = mpsc::channel::<Job>(CONTROL_CAPACITY);
        let (locked_tx, locked) = watch::channel(session.session_id());
        let passkey_flags = Arc::new(std::sync::atomic::AtomicU8::new(passkey_flags_of(&session)));
        let flags = passkey_flags.clone();
        let (revision_tx, revision) = watch::channel(session.vault().map(Vault::vault_revision));
        tokio::spawn(async move {
            let mut owner = Some(Owner::new(session));
            let mut deadline: Option<tokio::time::Instant> = None;
            loop {
                let far_future =
                    tokio::time::Instant::now() + Duration::from_secs(365 * 24 * 60 * 60);
                let job = tokio::select! {
                    biased;
                    _=tokio::time::sleep_until(deadline.unwrap_or(far_future)),if deadline.is_some()=>{
                        let mut current=owner.take().expect("worker owns its session between jobs");
                        let result=tokio::task::spawn_blocking(move || {
                            let result=lock_session(&mut current.session);
                            current.clear_results();
                            (current,result)
                        }).await;
                        let Ok((returned,result))=result else { publish(&locked_tx, None); break };
                        owner=Some(returned);
                        let warning=result.err().map(|e|format!("Automatic lock cleanup warning: {e}"));
                        *background.lock().await=warning;
                        flags.store(0, Ordering::Release);
                        publish(&locked_tx, None);
                        deadline=None;
                        continue;
                    },
                    job=control.recv()=>match job {Some(job)=>job,None=>break},
                    job=normal.recv()=>match job {Some(job)=>job,None=>break},
                };
                let Job {
                    action,
                    reply,
                    activity,
                } = job;
                let mut current = owner.take().expect("worker owns its session between jobs");
                let result = tokio::task::spawn_blocking(move || {
                    let outcome = action(&mut current);
                    (current, outcome)
                })
                .await;
                let Ok((returned, outcome)) = result else {
                    let _ = reply.send(one(RpcResponse::message(
                        ResponseCode::Failure,
                        "Vault worker failed; session discarded",
                    )));
                    publish(&locked_tx, None);
                    break;
                };
                publish(
                    &revision_tx,
                    returned.session.vault().map(Vault::vault_revision),
                );
                let locked = returned.session.is_locked();
                flags.store(passkey_flags_of(&returned.session), Ordering::Release);
                publish(&locked_tx, returned.session.session_id());
                owner = Some(returned);
                if locked {
                    deadline = None;
                } else if activity {
                    let seconds = timeout.load(Ordering::Acquire);
                    // Configured seconds cover the full u64 range. A deadline
                    // beyond the monotonic clock's range cannot expire during
                    // this process, but must not panic and discard the worker.
                    deadline = (seconds > 0)
                        .then(|| {
                            tokio::time::Instant::now().checked_add(Duration::from_secs(seconds))
                        })
                        .flatten();
                }
                let _ = reply.send(outcome);
            }
            // Dropping owner discards all keys and vault data. Clipboard cleanup
            // is independent of whether shutdown can write the vault file.
            drop(owner);
            let _ = tokio::task::spawn_blocking(crate::clipboard::clear_owned).await;
        });
        Self {
            normal: normal_tx,
            control: control_tx,
            locked,
            revision,
            cloud_warning: Arc::new(Mutex::new(None)),
            passkey_flags,
        }
    }
    /// (can confirm a passkey request, a passkey PIN is set) for the unlocked vault.
    pub fn passkey_confirmation(&self) -> (bool, bool) {
        let flags = if self.session_id().is_some() {
            self.passkey_flags.load(Ordering::Acquire)
        } else {
            0
        };
        (flags & 1 != 0, flags & 2 != 0)
    }
    pub fn vault_revision(&self) -> Option<u64> {
        if self.session_id().is_none() {
            None
        } else {
            *self.revision.borrow()
        }
    }
    pub async fn cloud_warning(&self) -> Option<String> {
        self.cloud_warning.lock().await.clone()
    }
    pub async fn set_cloud_warning(&self, warning: Option<String>) {
        *self.cloud_warning.lock().await = warning;
    }
    #[cfg(test)]
    pub fn is_locked(&self) -> bool {
        self.session_id().is_none()
    }
    pub fn session_id(&self) -> Option<String> {
        if self.locked.has_changed().is_err() {
            None
        } else {
            self.locked.borrow().clone()
        }
    }
    async fn submit(
        &self,
        priority: bool,
        activity: bool,
        action: Action,
    ) -> outcome::CommandOutcome {
        let (reply, receive) = oneshot::channel();
        let job = Job {
            action,
            reply,
            activity,
        };
        let sender = if priority {
            &self.control
        } else {
            &self.normal
        };
        if sender.send(job).await.is_err() {
            return one(RpcResponse::message(
                ResponseCode::Failure,
                "Vault worker is unavailable",
            ));
        }
        receive.await.unwrap_or_else(|_| {
            one(RpcResponse::message(
                ResponseCode::Failure,
                "Vault worker stopped before replying",
            ))
        })
    }
    pub async fn execute(
        &self,
        state: ConnectionState,
        request: RequestEnvelope,
    ) -> outcome::CommandOutcome {
        let priority = matches!(
            request.command,
            ServerCommand::Lock(_) | ServerCommand::Kill | ServerCommand::OperationStatus(_)
        );
        let activity = request.command.extends_unlock();
        self.submit(
            priority,
            activity,
            Box::new(move |owner| owner.execute(state, request)),
        )
        .await
    }
    pub async fn with_session<T: Send + 'static>(
        &self,
        action: impl FnOnce(&mut VaultSession) -> T + Send + 'static,
    ) -> Result<T, String> {
        let (send, receive) = oneshot::channel();
        let outcome = self
            .submit(
                false,
                false,
                Box::new(move |owner| {
                    let result = action(&mut owner.session);
                    let _ = send.send(result);
                    outcome::CommandOutcome::default()
                }),
            )
            .await;
        receive.await.map_err(|_| {
            outcome
                .reply
                .as_ref()
                .map(RpcResponse::error_message)
                .unwrap_or_else(|| "Vault worker stopped before completing the operation".into())
        })
    }
    pub async fn finish_external(
        &self,
        mut result: outcome::CommandOutcome,
        operation_id: Option<String>,
    ) -> outcome::CommandOutcome {
        self.submit(
            false,
            false,
            Box::new(move |owner| {
                // Revalidate on the owner queue. A lock or another unlock while
                // network work was in flight must discard its old payload.
                if owner.session.session_id() != result.session_id {
                    result.reply = None;
                    outcome::respond_conflict(
                        "Unlock session changed; reopen the selection before continuing",
                        &mut result.reply,
                    );
                }
                if let Some(response) = result.reply.as_mut() {
                    response.session_id = result.session_id.clone();
                }
                if let Some(id) = operation_id {
                    owner.complete(&id, &mut result.reply, true);
                }
                result
            }),
        )
        .await
    }
    pub async fn lock(&self) -> outcome::CommandOutcome {
        self.submit(
            true,
            false,
            Box::new(|owner| {
                let result = lock_session(&mut owner.session);
                owner.clear_results();
                match result {
                    Ok(()) => one(RpcResponse::message(ResponseCode::Success, "Vault locked.")),
                    Err(error) => one(RpcResponse::message(
                        ResponseCode::Failure,
                        error.to_string(),
                    )),
                }
            }),
        )
        .await
    }
    pub fn system_lock_handler(
        &self,
        background: Arc<Mutex<Option<String>>>,
    ) -> Arc<dyn Fn() + Send + Sync> {
        let handle = self.clone();
        Arc::new(move || {
            let (reply, _) = oneshot::channel();
            let background = background.clone();
            let action = Box::new(move |owner: &mut Owner| {
                let result = lock_session(&mut owner.session);
                owner.clear_results();
                *background.blocking_lock() = result
                    .err()
                    .map(|e| format!("System lock cleanup warning: {e}"));
                outcome::CommandOutcome::default()
            });
            // OS callbacks are blocking monitor threads. Use a bounded control
            // mailbox and never take ownership of the session from this thread.
            let _ = handle.control.blocking_send(Job {
                action,
                reply,
                activity: false,
            });
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    fn live() -> VaultSession {
        VaultSession::unlock(
            Vault::memory(),
            VaultCredentials::Session {
                encryption_key: [42; 32],
                salt: [42; 16],
                kdf: 1,
                memory_kib: 8192,
                iterations: 1,
                parallelism: 1,
            },
        )
    }
    fn worker() -> VaultWorker {
        VaultWorker::start(
            live(),
            Arc::new(AtomicU64::new(1)),
            Arc::new(Mutex::new(None)),
        )
    }
    #[tokio::test]
    async fn maximum_inactivity_timeout_keeps_the_worker_available() {
        let worker = VaultWorker::start(
            live(),
            Arc::new(AtomicU64::new(u64::MAX)),
            Arc::new(Mutex::new(None)),
        );
        worker
            .submit(
                false,
                true,
                Box::new(|_| outcome::CommandOutcome::default()),
            )
            .await;
        assert!(
            !worker
                .with_session(|session| session.is_locked())
                .await
                .unwrap()
        );
        assert!(!worker.is_locked());
    }

    #[tokio::test]
    async fn status_receivers_wake_only_when_session_or_revision_changes() {
        let worker = VaultWorker::start(
            live(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(Mutex::new(None)),
        );
        let (mut sessions, mut revisions) = worker.changes();
        sessions.mark_unchanged();
        revisions.mark_unchanged();
        worker.with_session(|_| ()).await.unwrap();
        assert!(!sessions.has_changed().unwrap());
        assert!(!revisions.has_changed().unwrap());
        worker.with_session(VaultSession::lock).await.unwrap();
        assert!(sessions.has_changed().unwrap());
        assert!(revisions.has_changed().unwrap());
        assert_eq!(*sessions.borrow_and_update(), None);
        assert_eq!(*revisions.borrow_and_update(), None);
    }
    #[tokio::test]
    async fn lock_deadline_is_not_extended_by_passive_jobs() {
        let worker = worker();
        worker
            .submit(
                false,
                true,
                Box::new(|_| outcome::CommandOutcome::default()),
            )
            .await;
        let started = tokio::time::Instant::now();
        while started.elapsed() < Duration::from_millis(1150) {
            worker
                .submit(
                    true,
                    false,
                    Box::new(|_| outcome::CommandOutcome::default()),
                )
                .await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            worker
                .with_session(|session| session.is_locked())
                .await
                .unwrap()
        );
        assert!(worker.is_locked());
    }
    #[tokio::test]
    async fn queued_control_is_processed_before_ordinary_work() {
        let worker = worker();
        let (started, ready) = oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let handle = worker.clone();
        let blocked = tokio::spawn(async move {
            handle
                .with_session(move |_| {
                    started.send(()).unwrap();
                    wait.recv().unwrap();
                })
                .await
        });
        ready.await.unwrap();
        let order = Arc::new(StdMutex::new(Vec::new()));
        let handle = worker.clone();
        let normal_order = order.clone();
        let normal = tokio::spawn(async move {
            handle
                .submit(
                    false,
                    false,
                    Box::new(move |_| {
                        normal_order.lock().unwrap().push("normal");
                        outcome::CommandOutcome::default()
                    }),
                )
                .await
        });
        let handle = worker.clone();
        let control_order = order.clone();
        let control = tokio::spawn(async move {
            handle
                .submit(
                    true,
                    false,
                    Box::new(move |_| {
                        control_order.lock().unwrap().push("control");
                        outcome::CommandOutcome::default()
                    }),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while worker.normal.capacity() == QUEUE_CAPACITY
                || worker.control.capacity() == CONTROL_CAPACITY
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        release.send(()).unwrap();
        blocked.await.unwrap().unwrap();
        normal.await.unwrap();
        control.await.unwrap();
        assert_eq!(*order.lock().unwrap(), ["control", "normal"]);
    }
    #[test]
    fn locking_discards_cached_secrets_but_keeps_nonsecret_receipts() {
        let mut owner = Owner::new(live());
        owner
            .remember(Operation {
                id: "retained".into(),
                vault_id: None,
                fingerprint: [0; 32],
                receipt: OperationReceipt {
                    operation_id: "retained".into(),
                    state: OperationState::Committed,
                    revision: Some(1),
                },
                reply: Some(RpcResponse::success(ResponsePayload::Secret(
                    "synthetic-code".into(),
                ))),
            })
            .unwrap();
        owner.session.lock();
        owner.clear_results();
        assert!(owner.operations[0].reply.is_none());
        assert_eq!(owner.receipt("retained").state, OperationState::Committed);
    }
    #[test]
    fn in_flight_operations_are_never_evicted_and_external_errors_remain_unknown() {
        let mut owner = Owner::new(live());
        for i in 0..RESULT_CAPACITY {
            let id = format!("pending-{i}");
            owner
                .remember(Operation {
                    id: id.clone(),
                    vault_id: None,
                    fingerprint: [0; 32],
                    receipt: OperationReceipt {
                        operation_id: id,
                        state: OperationState::Pending,
                        revision: None,
                    },
                    reply: None,
                })
                .unwrap();
        }
        assert!(
            owner
                .remember(Operation {
                    id: "overflow".into(),
                    vault_id: None,
                    fingerprint: [0; 32],
                    receipt: OperationReceipt {
                        operation_id: "overflow".into(),
                        state: OperationState::Pending,
                        revision: None
                    },
                    reply: None
                })
                .is_err()
        );
        let mut reply = Some(RpcResponse::message(
            ResponseCode::Failure,
            "Duo response lost",
        ));
        owner.complete("pending-0", &mut reply, true);
        assert_eq!(owner.receipt("pending-0").state, OperationState::Unknown);
        let mut large = Some(RpcResponse::message(
            ResponseCode::Success,
            "x".repeat(RESULT_BYTES + 1),
        ));
        owner.complete("pending-1", &mut large, false);
        assert_eq!(owner.receipt("pending-1").state, OperationState::Committed);
        assert!(
            owner.operations[1].reply.is_none(),
            "large results retain only a receipt"
        );
        assert!(
            matches!(&large.as_ref().unwrap().payload,ResponsePayload::Message(message) if message.len()==RESULT_BYTES+1),
            "the original reply is still delivered intact"
        );
    }
}
