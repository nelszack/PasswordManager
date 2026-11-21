use super::outcome::{
    respond, respond_domain_error, respond_domain_error_with_context, respond_failed,
    respond_failure, respond_ok,
};
use super::*;
use crate::vault::unlock_selected_vault;

fn combined_lock_warning(
    background: &Mutex<Option<String>>,
    monitor: Option<&system_lock::Monitor>,
) -> Option<String> {
    let warnings = [
        background.blocking_lock().clone(),
        monitor.and_then(system_lock::Monitor::warning),
        super::ssh_agent::UNAVAILABLE.get().cloned(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    (!warnings.is_empty()).then(|| warnings.join("; "))
}

/// Installs an unlocked vault, then purges expired trash best-effort. Unlock
/// succeeds even when the purge cannot be saved; the failure (or uncertain
/// durability of a committed purge) is reported as a status warning instead.
pub(super) fn install_unlocked(
    state: &ConnectionState,
    session: &mut VaultSession,
    vault: Vault,
    credentials: VaultCredentials,
) -> Result<(), crate::vault::VaultError> {
    session.install(vault, credentials)?;
    let days = state.trash_retention_days;
    let warning = session
        .with_unlocked(|vault, credentials| vault.purge_expired_trash(days, credentials))
        .err()
        .map(|error| {
            if error.committed() {
                format!("Expired trash was purged, but the save may not be durable: {error}")
            } else {
                format!("Could not purge expired trash: {error}")
            }
        });
    if session.is_locked() {
        return Err(crate::vault::VaultError::Locked);
    }
    *state.background_error.blocking_lock() = warning;
    Ok(())
}

/// Refuses an attempt while the shared throttle is waiting.
fn throttled(state: &ConnectionState, responses: &mut Vec<RpcResponse>) -> bool {
    let wait = state
        .unlock_throttle
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .wait(std::time::Instant::now());
    if let Some(seconds) = wait {
        respond_failure(
            &format!("Too many incorrect attempts. Try again in {seconds} seconds."),
            responses,
        );
    }
    wait.is_some()
}

/// Records whether a password-checked attempt succeeded.
fn record_attempt(state: &ConnectionState, succeeded: bool) {
    let mut throttle = state
        .unlock_throttle
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if succeeded {
        throttle.succeeded();
    } else {
        throttle.failed(std::time::Instant::now());
    }
}

fn handle_command(
    responses: &mut Vec<RpcResponse>,
    state: ConnectionState,
    msg: ServerCommand,
    session: &mut VaultSession,
    effect: &mut CommandEffect,
) {
    if state.stopping.load(Ordering::Acquire) {
        let mut msg = msg;
        msg.zeroize();
        respond_failure("Server is stopping.", responses);
        return;
    }
    match msg {
        ServerCommand::Kill => {
            if !session.is_locked()
                && let Err(error) = lock_session(session)
            {
                respond_failed("Could not stop server safely", &error, responses);
                return;
            }
            state.stopping.store(true, Ordering::Release);
            respond("Server stopped.", responses);
            *effect = CommandEffect::StopServer;
        }
        ServerCommand::Lock(send) => {
            let was_locked = session.is_locked();
            match lock_session(session) {
                Ok(()) => {
                    *state.background_error.blocking_lock() = None;
                    if send {
                        respond(
                            if was_locked {
                                "Vault is already locked."
                            } else {
                                "Vault locked."
                            },
                            responses,
                        );
                    }
                }
                Err(error) => {
                    let message = format!("Vault locked with a cleanup warning: {error}");
                    *state.background_error.blocking_lock() = Some(message.clone());
                    if send {
                        respond_domain_error_with_context(&error, &message, responses);
                    }
                }
            }
        }
        ServerCommand::Unlock(mut info) => {
            if !session.is_locked() {
                info.zeroize();
                respond_failure(
                    "A vault is already unlocked. Lock it before unlocking another one.",
                    responses,
                );
                return;
            }
            if throttled(&state, responses) {
                info.zeroize();
                return;
            }
            let mut credentials = VaultCredentials::from(info.key);
            let result = unlock_selected_vault(&mut credentials, info.vault_file.as_deref())
                .and_then(|vault| install_unlocked(&state, session, vault, credentials));
            record_attempt(&state, result.is_ok());
            match result {
                Ok(()) => {
                    state
                        .inactivity_timeout
                        .store(info.timeout, Ordering::Release);
                    respond("Vault unlocked.", responses);
                }
                Err(error) => respond_failed("Unlock failed", &error, responses),
            }
        }
        ServerCommand::SshDecision { id, allow } => {
            if state.ssh_approvals.decide(&id, allow) {
                respond(
                    if allow {
                        "SSH signature allowed."
                    } else {
                        "SSH signature refused."
                    },
                    responses,
                );
            } else {
                respond_failure("That SSH request is no longer waiting.", responses);
            }
        }
        ServerCommand::PasskeyVerification { .. } => respond_failure(
            "Passkey confirmations are handled outside the vault worker",
            responses,
        ),
        ServerCommand::PasskeyDecision { id, secret } => {
            if session.is_locked() {
                respond_failure("Vault locked.", responses);
                return;
            }
            // Only a request from this unlock session can be answered here.
            if state.passkey_approvals.session_of(&id) != session.session_id() {
                respond_failure("That passkey request is no longer waiting.", responses);
                return;
            }
            let Some(secret) = secret else {
                state.passkey_approvals.decide(&id, false);
                respond("Passkey request refused.", responses);
                return;
            };
            // Same slowdown as wrong master passwords.
            if throttled(&state, responses) {
                return;
            }
            let confirmed = session.confirms_person(&crate::file::data_dir(), secret.expose());
            record_attempt(&state, confirmed);
            if !confirmed {
                respond_failure(
                    "That master password or passkey PIN is incorrect.",
                    responses,
                );
            } else if state.passkey_approvals.decide(&id, true) {
                respond("Passkey request confirmed.", responses);
            } else {
                respond_failure("That passkey request is no longer waiting.", responses);
            }
        }
        ServerCommand::SetPasskeyPin(pin) => {
            match session.set_passkey_pin(
                &crate::file::data_dir(),
                pin.as_ref().map(crate::secret::SecretString::expose),
            ) {
                Ok(()) if pin.is_some() => respond("Passkey PIN set.", responses),
                Ok(()) => respond("Passkey PIN removed.", responses),
                Err(error) => respond_failure(&error, responses),
            }
        }
        ServerCommand::Status => {
            let warning =
                combined_lock_warning(&state.background_error, state.system_lock.as_deref());
            let mut status = crate::protocol::ServerStatus::new(session.is_locked(), warning);
            status.ssh_requests = state.ssh_approvals.list();
            status.passkey_pin = session.passkey_pin(&crate::file::data_dir());
            status.passkey_verification = status.passkey_pin || session.password_check();
            status.passkey_requests = state
                .passkey_approvals
                .list_for(session.session_id().as_deref());
            respond_ok(ResponsePayload::Status(status), responses);
        }
        ServerCommand::Cloud(_) => respond_failure(
            "Sync commands are handled outside the vault worker",
            responses,
        ),
        ServerCommand::OperationStatus(_) => respond_failure(
            "Operation status is resolved by the vault worker.",
            responses,
        ),
        ServerCommand::New(key) => {
            if !session.is_locked()
                && let Err(error) = lock_session(session)
            {
                respond_domain_error(&error, responses);
                return;
            }
            let mut credentials = VaultCredentials::from(key);
            match create_vault(&mut None, &mut credentials, true) {
                Ok(()) => respond("Vault created.", responses),
                Err(error) => respond_domain_error(&error, responses),
            }
        }
        ServerCommand::Delete(Target::Vault {
            mut key,
            keep_key,
            vault_file,
        }) => {
            if throttled(&state, responses) {
                key.zeroize();
                return;
            }
            if let Err(error) = lock_session(session) {
                respond_domain_error(&error, responses);
                return;
            }
            match delete_vault(key, keep_key, vault_file.as_deref()) {
                Ok(()) => {
                    record_attempt(&state, true);
                    respond("Vault deleted.", responses)
                }
                Err(error) => {
                    record_attempt(&state, false);
                    respond_domain_error(&error, responses)
                }
            }
        }
        ServerCommand::RestoreBackup(mut request) => {
            if !session.is_locked() {
                respond_failure(
                    "Lock the current vault before restoring a backup.",
                    responses,
                );
            } else {
                match restore_encrypted_backup(&request.path, &mut request.key_pass) {
                    Ok(filename) => respond_ok(
                        ResponsePayload::Vault(crate::protocol::VaultReference {
                            vault_file: filename,
                        }),
                        responses,
                    ),
                    Err(error) => respond_failed("Backup restore failed", &error, responses),
                }
            }
            request.zeroize();
        }
        ServerCommand::Import(args) if args.new => {
            let result = if args.preview {
                Vault::default().import_with_options(
                    args.path,
                    args.conflicts,
                    true,
                    args.password_history_limit,
                    &mut ServerInfo::default(),
                )
            } else {
                if !session.is_locked()
                    && let Err(error) = lock_session(session)
                {
                    respond_domain_error(&error, responses);
                    return;
                }
                let Some(key) = args.key_pass else {
                    respond_failure(
                        "A password or key is required for a new imported vault.",
                        responses,
                    );
                    return;
                };
                let mut credentials = VaultCredentials::from(key);
                let mut vault = None;
                create_vault(&mut vault, &mut credentials, false).and_then(|()| {
                    vault
                        .as_mut()
                        .ok_or(crate::vault::VaultError::Locked)?
                        .import_with_options(
                            args.path,
                            args.conflicts,
                            false,
                            args.password_history_limit,
                            &mut credentials,
                        )
                })
            };
            match result {
                Ok(report) => respond_ok(ResponsePayload::ImportReport(report), responses),
                Err(error) => respond_failed("Import failed", &error, responses),
            }
        }
        mut msg => {
            if session.is_locked() {
                msg.zeroize();
                respond_failure("Vault locked.", responses);
                return;
            }
            // A passkey response reports user verification only after the
            // person confirmed this site in this unlock session.
            if let ServerCommand::BrowserPasskeyCreate {
                origin,
                verification,
                verified,
                ..
            }
            | ServerCommand::BrowserPasskeyGet {
                origin,
                verification,
                verified,
                ..
            } = &mut msg
                && let Some(token) = verification.take()
            {
                *verified =
                    state
                        .passkey_approvals
                        .redeem(&token, origin, session.session_id().as_deref());
                if !*verified {
                    respond_failure("The passkey confirmation expired; try again.", responses);
                    return;
                }
            }
            if let Err(error) = session.with_unlocked(|vault, key| {
                *effect = crate::operations::execute_unlocked(
                    responses,
                    msg,
                    vault,
                    key,
                    state.password_history_limit,
                )
                .into();
                Ok(())
            }) {
                respond_domain_error(&error, responses);
            }
        }
    }
}
/// Execute state work without a socket or an async response buffer.
pub(super) fn execute_command(
    state: ConnectionState,
    msg: ServerCommand,
    session: &mut crate::vault::VaultSession,
) -> outcome::CommandOutcome {
    let mut outcome = outcome::CommandOutcome::default();
    handle_command(
        &mut outcome.responses,
        state,
        msg,
        session,
        &mut outcome.effect,
    );
    outcome
}
