use super::outcome::{
    respond, respond_conflict, respond_data, respond_domain_error,
    respond_domain_error_with_context, respond_domain_result, respond_failure, respond_not_found,
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
                handle_unlocked(
                    responses,
                    msg,
                    vault,
                    key,
                    state.password_history_limit,
                    effect,
                );
                Ok(())
            }) {
                respond_domain_error(&error, responses);
            }
        }
    }
}
fn handle_unlocked(
    responses: &mut Vec<RpcResponse>,
    msg: ServerCommand,
    vault: &mut Vault,
    server_info: &mut ServerInfo,
    password_history_limit: usize,
    effect: &mut CommandEffect,
) {
    match msg {
        ServerCommand::Rekey(new_key) => match vault.rekey(server_info, new_key) {
            Ok(()) => respond("Vault re-encrypted with the new key.", responses),
            Err(error) => respond_domain_error_with_context(
                &error,
                &format!(
                    "{}: {error}",
                    if error.committed() {
                        "Rekey committed with uncertain durability"
                    } else {
                        "Rekey failed before replacement"
                    }
                ),
                responses,
            ),
        },
        ServerCommand::Add {
            entry: info,
            copy_timeout,
        } => {
            let pass = Zeroizing::new(info.entry.copy.then(|| info.entry.password.clone()));
            match vault.add_typed_entry(info, server_info) {
                Ok(true) => {
                    respond("Item added.", responses);
                    if let Some(password) = pass.as_deref() {
                        copy_in_background(password.to_owned(), copy_timeout);
                    }
                }
                Ok(false) => respond_conflict("Item already exists.", responses),
                Err(error) => respond_domain_error_with_context(
                    &error,
                    &format!("Add failed: {error}"),
                    responses,
                ),
            }
        }
        ServerCommand::Delete(target) => match vault.delete_entry(target, server_info) {
            Ok(true) => respond("Entry moved to trash.", responses),
            Ok(false) => respond_not_found("Entry not found.", responses),
            Err(error) => respond_domain_error(&error, responses),
        },
        ServerCommand::History(target) => match vault.view_password_history(target) {
            Ok(rows) => respond_payload(
                ResponseCode::Success,
                ResponsePayload::History(crate::vault::HistoryPage {
                    history: rows.into_iter().map(str::to_owned).collect(),
                }),
                responses,
            ),
            Err(error) => respond_domain_error(&error, responses),
        },
        ServerCommand::RestorePassword { target, revision } => {
            match vault.restore_password(target, revision, server_info) {
                Ok(true) => respond("Password restored.", responses),
                Ok(false) => respond_not_found("Entry not found.", responses),
                Err(error) => respond_domain_error_with_context(
                    &error,
                    &format!("Password restore failed: {error}"),
                    responses,
                ),
            }
        }
        ServerCommand::Trash => {
            let trash = vault
                .view_trash()
                .into_iter()
                .map(|item| crate::vault::TrashSummary {
                    id: item.entry.entry.id,
                    name: item.entry.entry.name.clone(),
                    kind: item.entry.metadata.map_or(ItemKind::Login, |m| m.kind),
                    username: item.entry.entry.username.clone(),
                    deleted: item.deleted.to_owned(),
                    has_totp: item.entry.has_totp,
                })
                .collect();
            respond_payload(
                ResponseCode::Success,
                ResponsePayload::Trash(crate::vault::TrashPage { trash }),
                responses,
            );
        }
        ServerCommand::RestoreTrash(id) => match vault.restore_trashed(id, server_info) {
            Ok(true) => respond("Entry restored.", responses),
            Ok(false) => respond_not_found("Trash entry not found.", responses),
            Err(error) => respond_domain_error_with_context(
                &error,
                &format!("Restore failed: {error}"),
                responses,
            ),
        },
        ServerCommand::PurgeTrash(id) => match vault.purge_trash(id, server_info) {
            Ok(true) => respond("Trash purged.", responses),
            Ok(false) => respond_not_found("Trash entry not found.", responses),
            Err(error) => respond_domain_error_with_context(
                &error,
                &format!("Purge failed: {error}"),
                responses,
            ),
        },
        ServerCommand::Audit(options) => {
            {
                // Build the local findings and one-way password hashes while
                // the vault is available, then release the live state before
                // any network-backed breach checks begin.
                let audit_snapshot = vault.prepare_audit(&options);
                *effect = CommandEffect::Audit(audit_snapshot, options.check_breaches);
            }
        }
        ServerCommand::Duo(command) => {
            if matches!(
                &command,
                DuoCommand::Requests { .. } | DuoCommand::Respond { .. }
            ) {
                {
                    match vault.prepare_duo_poll(command, server_info) {
                        Ok(prepared) => *effect = CommandEffect::Duo(Box::new(prepared)),
                        Err(error) => respond_domain_error(&error, responses),
                    }
                }
            } else if matches!(&command, DuoCommand::Enroll { .. }) {
                {
                    match vault.prepare_duo_enrollment(command, true, server_info) {
                        Ok(prepared) => *effect = CommandEffect::DuoEnrollment(Box::new(prepared)),
                        Err(error) => respond_domain_error(&error, responses),
                    }
                }
            } else {
                let command = Zeroizing::new(command);
                {
                    respond_domain_result(vault.duo_command(&command, server_info), responses);
                }
            }
        }
        ServerCommand::Totp(command) => match command {
            TotpCommand::Watch {
                target,
                copy_timeout,
            } => match vault.current_totp(target) {
                Ok((code, ttl)) => {
                    let payload = crate::protocol::AuthenticatorResponse {
                        code: code.into(),
                        expires_in: Some(ttl),
                        counter: None,
                        mode: "totp".into(),
                    };
                    if let Some(timeout) = copy_timeout {
                        copy_in_background(payload.code.expose().to_owned(), timeout);
                    }
                    respond_payload(
                        ResponseCode::Success,
                        crate::protocol::ResponsePayload::Authenticator(payload),
                        responses,
                    );
                }
                Err(error) => respond_domain_error_with_context(
                    &error,
                    &format!(
                        "TOTP watch unavailable (requires a time-based authenticator): {error}"
                    ),
                    responses,
                ),
            },
            TotpCommand::Set {
                target,
                mut configuration,
            } => {
                let result = vault.set_totp(target, &configuration, server_info);
                configuration.zeroize();
                match result {
                    Ok(Some(bits)) if bits < 128 => respond(
                        &format!(
                            "Authenticator saved. Warning: provider supplied a {bits}-bit secret; RFC 4226 recommends at least 128 bits."
                        ),
                        responses,
                    ),
                    Ok(Some(_)) => respond("Authenticator saved.", responses),
                    Ok(None) => respond_not_found("Entry not found.", responses),
                    Err(error) => respond_domain_error_with_context(
                        &error,
                        &format!("Authenticator setup failed: {error}"),
                        responses,
                    ),
                }
            }
            TotpCommand::Duo {
                target,
                activation,
                mode,
            } => {
                let command = DuoCommand::Enroll {
                    target,
                    activation,
                    mode: Some(mode),
                    replace: false,
                };
                match vault.prepare_duo_enrollment(command, false, server_info) {
                    Ok(prepared) => *effect = CommandEffect::DuoEnrollment(Box::new(prepared)),
                    Err(error) => respond_domain_error_with_context(
                        &error,
                        &format!("Duo setup failed: {error}"),
                        responses,
                    ),
                }
            }
            TotpCommand::Show {
                target,
                copy_timeout,
            } => match vault.current_otp(target, server_info) {
                Ok(code) => {
                    if let Some(timeout) = copy_timeout {
                        copy_in_background(code.code.to_string(), timeout);
                    }
                    respond_payload(
                        ResponseCode::Success,
                        crate::protocol::ResponsePayload::Authenticator(
                            crate::protocol::AuthenticatorResponse {
                                code: code.code.to_string().into(),
                                expires_in: code.expires_in,
                                counter: code.counter,
                                mode: if code.counter.is_some() {
                                    "hotp"
                                } else {
                                    "totp"
                                }
                                .into(),
                            },
                        ),
                        responses,
                    );
                }
                Err(error) => respond_domain_error_with_context(
                    &error,
                    &format!("Authenticator unavailable: {error}"),
                    responses,
                ),
            },
            TotpCommand::Remove { target } => match vault.remove_totp(target, server_info) {
                Ok(true) => respond("Authenticator removed.", responses),
                Ok(false) => {
                    respond_not_found("Entry not found or has no authenticator.", responses)
                }
                Err(error) => respond_domain_error_with_context(
                    &error,
                    &format!("Authenticator removal failed: {error}"),
                    responses,
                ),
            },
        },
        ServerCommand::List(filter) => match vault.management_list(filter) {
            Ok(page) => respond_payload(
                ResponseCode::Success,
                crate::protocol::ResponsePayload::ItemPage(page),
                responses,
            ),
            Err(e) => respond_domain_error(&e, responses),
        },
        ServerCommand::ManagementItem { id, reveal } => match vault.management_item(id, reveal) {
            Ok(item) => respond_payload(
                ResponseCode::Success,
                crate::protocol::ResponsePayload::Item(item),
                responses,
            ),
            Err(e) => respond_domain_error(&e, responses),
        },
        ServerCommand::ManagementCopy { id, timeout } => {
            if timeout == 0 {
                respond_failure(
                    "Clipboard copying is disabled; configure a nonzero clipboard timeout.",
                    responses,
                );
            } else {
                match vault.get_secret(&Target::Id(id)) {
                    Ok(mut secret) => match crate::clipboard::try_copy_in_background(
                        std::mem::take(&mut *secret),
                        timeout,
                    ) {
                        Ok(()) => respond("Secret copied to clipboard.", responses),
                        Err(error) => {
                            respond_failure(&format!("Could not copy secret: {error}"), responses)
                        }
                    },
                    Err(error) => respond_domain_error(&error, responses),
                }
            }
        }
        ServerCommand::BrowserAutofill => {
            respond_payload(
                ResponseCode::Success,
                crate::protocol::ResponsePayload::Summaries(vault.browser_autofill()),
                responses,
            );
        }
        ServerCommand::BrowserDuoItems(origin) => {
            respond_payload(
                ResponseCode::Success,
                crate::protocol::ResponsePayload::Summaries(vault.browser_duo_items(&origin)),
                responses,
            );
        }
        ServerCommand::BrowserLogins(origin) => {
            respond_payload(
                ResponseCode::Success,
                crate::protocol::ResponsePayload::Summaries(vault.browser_logins(&origin)),
                responses,
            );
        }
        ServerCommand::BrowserLogin { domain, id } => match vault.browser_login(&domain, id) {
            Some(item) => respond_payload(
                ResponseCode::Success,
                crate::protocol::ResponsePayload::Login(item),
                responses,
            ),
            None => respond_not_found("Login item not found for this site.", responses),
        },
        ServerCommand::BrowserAutofillItem(id) => match vault.browser_autofill_item(id) {
            Some(item) => respond_payload(
                ResponseCode::Success,
                crate::protocol::ResponsePayload::Autofill(item),
                responses,
            ),
            None => respond_not_found("Autofill item not found.", responses),
        },
        ServerCommand::Get {
            target,
            copy_timeout,
            reveal_secrets,
        } => {
            match vault.target_detail(&target, reveal_secrets) {
                Ok(mut item) => {
                    // CLI secret-field reveal does not implicitly reveal the primary secret.
                    item.password = None;
                    if copy_timeout > 0
                        && let Ok(secret) = vault.get_secret(&target)
                    {
                        copy_in_background(secret.to_string(), copy_timeout);
                    }
                    respond_payload(
                        ResponseCode::Success,
                        crate::protocol::ResponsePayload::Item(item),
                        responses,
                    );
                }
                Err(e) => respond_domain_error(&e, responses),
            }
        }
        ServerCommand::GetField {
            target,
            name,
            copy_timeout,
        } => {
            if copy_timeout == Some(0) {
                respond_domain_error(
                    &crate::vault::VaultError::InvalidInput(
                        "Clipboard copying is disabled; configure a nonzero clipboard timeout."
                            .into(),
                    ),
                    responses,
                );
            } else {
                match vault.get_custom_field(&target, &name) {
                    Ok(mut value) => {
                        if let Some(timeout) = copy_timeout {
                            match crate::clipboard::try_copy_in_background(
                                std::mem::take(&mut *value),
                                timeout,
                            ) {
                                Ok(()) => respond("Custom field copied to clipboard.", responses),
                                Err(error) => respond_failure(
                                    &format!("Could not copy custom field: {error}"),
                                    responses,
                                ),
                            }
                        } else {
                            respond_data(&value, responses);
                        }
                    }
                    Err(error) => respond_domain_error(&error, responses),
                }
            }
        }
        ServerCommand::AuthenticatorData(target) => {
            respond_authenticator(vault.current_otp(target, server_info), responses);
        }
        ServerCommand::BrowserAuthenticatorData { domain, id } => {
            let result = (|| {
                if vault.browser_login_revision(&domain, id).is_none() {
                    return Err(crate::vault::VaultError::NotFound(
                        "Login item not found for this site.".into(),
                    ));
                }
                vault.current_otp(Target::Id(id), server_info)
            })();
            respond_authenticator(result, responses);
        }
        ServerCommand::GetSecret(target) => match vault.get_secret(&target) {
            Ok(secret) => respond_data(&secret, responses),
            Err(error) => respond_domain_error(&error, responses),
        },
        ServerCommand::Update(update) => {
            match vault.update_typed_entry_with_limit(update, server_info, password_history_limit) {
                Ok(true) => respond("Item updated.", responses),
                Ok(false) => respond_not_found("Item not found or unchanged.", responses),
                Err(error) => respond_domain_error_with_context(
                    &error,
                    &format!("Update failed: {error}"),
                    responses,
                ),
            }
        }
        ServerCommand::Export { path, force } => match vault.export(path, force) {
            Ok(()) => respond(
                "Export finished. WARNING: the export contains plaintext secrets.",
                responses,
            ),
            Err(e) => {
                respond_domain_error_with_context(&e, &format!("Export failed: {e}"), responses)
            }
        },
        ServerCommand::Backup(mut request) => {
            {
                let result = vault.encrypted_backup(
                    request.path.clone(),
                    &mut request.key_pass,
                    request.force,
                );
                match result {
                    Ok(()) => respond("Encrypted backup created.", responses),
                    Err(error) => respond_domain_error_with_context(
                        &error,
                        &format!("Backup failed: {error}"),
                        responses,
                    ),
                }
            }
            request.zeroize();
        }
        ServerCommand::Import(args) => {
            let result = vault.import_with_options(
                args.path,
                args.conflicts,
                args.preview,
                args.password_history_limit,
                server_info,
            );
            match result {
                Ok(report) => respond_payload(
                    ResponseCode::Success,
                    ResponsePayload::ImportReport(report),
                    responses,
                ),
                Err(error) => respond_domain_error(&error, responses),
            }
        }
        _ => unreachable!("session lifecycle operations handled before unlocked dispatch"),
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

fn respond_authenticator(
    result: Result<crate::vault::AuthenticatorCode, crate::vault::VaultError>,
    responses: &mut Vec<RpcResponse>,
) {
    match result {
        Ok(code) => {
            let payload = crate::protocol::AuthenticatorResponse {
                code: code.code.to_string().into(),
                expires_in: code.expires_in,
                counter: code.counter,
                mode: if code.counter.is_some() {
                    "hotp"
                } else {
                    "totp"
                }
                .into(),
            };
            respond_payload(
                ResponseCode::Success,
                crate::protocol::ResponsePayload::Authenticator(payload),
                responses,
            );
        }
        Err(error) => respond_domain_error(&error, responses),
    }
}
