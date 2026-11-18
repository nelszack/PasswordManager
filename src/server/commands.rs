use super::outcome::{
    respond, respond_domain_error, respond_domain_error_with_context, respond_failure,
    respond_payload,
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
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    (!warnings.is_empty()).then(|| warnings.join("; "))
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
                respond_domain_error_with_context(
                    &error,
                    &format!("Could not stop server safely: {error}"),
                    responses,
                );
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
        ServerCommand::Unlock(info) => {
            if !session.is_locked() {
                respond_failure(
                    "A vault is already unlocked. Lock it before unlocking another one.",
                    responses,
                );
                return;
            }
            let mut credentials = VaultCredentials::from(info.key);
            let result = unlock_selected_vault(&mut credentials, info.vault_file.as_deref())
                .and_then(|mut vault| {
                    vault
                        .purge_expired_trash(state.trash_retention_days, &mut credentials)
                        .inspect_err(|_| {
                            let _ = lock_session(session);
                        })?;
                    session.install(vault, credentials)
                });
            match result {
                Ok(()) => {
                    state
                        .inactivity_timeout
                        .store(info.timeout, Ordering::Release);
                    *state.background_error.blocking_lock() = None;
                    respond("Vault unlocked.", responses);
                }
                Err(error) => respond_domain_error_with_context(
                    &error,
                    &format!("Unlock failed: {error}"),
                    responses,
                ),
            }
        }
        ServerCommand::Status => {
            let warning =
                combined_lock_warning(&state.background_error, state.system_lock.as_deref());
            respond_payload(
                ResponseCode::Success,
                ResponsePayload::Status(crate::protocol::ServerStatus::new(
                    session.is_locked(),
                    warning,
                )),
                responses,
            );
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
            key,
            keep_key,
            vault_file,
        }) => {
            if let Err(error) = lock_session(session) {
                respond_domain_error(&error, responses);
                return;
            }
            match delete_vault(key, keep_key, vault_file.as_deref()) {
                Ok(()) => respond("Vault deleted.", responses),
                Err(error) => respond_domain_error(&error, responses),
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
                    Ok(filename) => respond_payload(
                        ResponseCode::Success,
                        ResponsePayload::Vault(crate::protocol::VaultReference {
                            vault_file: filename,
                        }),
                        responses,
                    ),
                    Err(error) => respond_domain_error_with_context(
                        &error,
                        &format!("Backup restore failed: {error}"),
                        responses,
                    ),
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
                Ok(report) => respond_payload(
                    ResponseCode::Success,
                    ResponsePayload::ImportReport(report),
                    responses,
                ),
                Err(error) => respond_domain_error_with_context(
                    &error,
                    &format!("Import failed: {error}"),
                    responses,
                ),
            }
        }
        mut msg => {
            if session.is_locked() {
                msg.zeroize();
                respond_failure("Vault locked.", responses);
                return;
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
