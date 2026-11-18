//! Vault operations shared by the desktop service and the mobile bridge. Both
//! accept the same typed `ServerCommand`s and produce the same responses.
use crate::{
    clipboard::copy_in_background,
    protocol::{ResponseCode, ResponsePayload, RpcResponse},
    types::*,
    vault::{Vault, VaultCredentials},
};
use std::future::Future;
use zeroize::{Zeroize, Zeroizing};

/// Work that must finish after the vault is released (network or long CPU).
#[derive(Default)]
pub(crate) enum Deferred {
    #[default]
    None,
    Audit(crate::vault::PendingAudit, bool),
    Duo(Box<crate::vault::PreparedDuoPoll>),
    DuoEnrollment(Box<crate::vault::PreparedDuoEnrollment>),
}

/// Re-enters the session that started deferred work. Implementations must
/// refuse if that session was locked or replaced in the meantime.
pub(crate) trait SessionAccess: Sync {
    fn with_unlocked<T: Send + 'static>(
        &self,
        apply: impl FnOnce(&mut Vault, &mut VaultCredentials) -> Result<T, crate::vault::VaultError>
        + Send
        + 'static,
    ) -> impl Future<Output = Result<Result<T, crate::vault::VaultError>, String>> + Send;
}

/// Commands that a vault-owning client (not a lifecycle manager) may run.
pub(crate) fn expected_revision_matches(
    vault: Option<&Vault>,
    command: &ServerCommand,
    expected: u64,
) -> bool {
    let actual = vault.and_then(|vault| {
        command
            .revision_target()
            .and_then(|target| vault.target_revision(target))
            .or_else(|| command.target_id().and_then(|id| vault.revision(id)))
    });
    actual == Some(expected)
}

pub(crate) fn respond_payload(
    code: ResponseCode,
    payload: ResponsePayload,
    responses: &mut Vec<RpcResponse>,
) {
    responses.push(RpcResponse::new(code, payload));
}
pub(crate) fn respond_with_code(
    code: ResponseCode,
    message: &str,
    responses: &mut Vec<RpcResponse>,
) {
    responses.push(RpcResponse::message(code, message));
}
pub(crate) fn respond_data(message: &str, responses: &mut Vec<RpcResponse>) {
    respond_payload(
        ResponseCode::Success,
        ResponsePayload::Secret(message.into()),
        responses,
    );
}
pub(crate) fn respond(message: &str, responses: &mut Vec<RpcResponse>) {
    respond_with_code(ResponseCode::Success, message, responses);
}
pub(crate) fn respond_failure(message: &str, responses: &mut Vec<RpcResponse>) {
    respond_with_code(ResponseCode::Failure, message, responses);
}
pub(crate) fn respond_not_found(message: &str, responses: &mut Vec<RpcResponse>) {
    respond_with_code(ResponseCode::NotFound, message, responses);
}
pub(crate) fn respond_conflict(message: &str, responses: &mut Vec<RpcResponse>) {
    respond_with_code(ResponseCode::Conflict, message, responses);
}
fn domain_code(error: &crate::vault::VaultError) -> ResponseCode {
    use crate::vault::VaultError;
    match error {
        VaultError::NotFound(_) => ResponseCode::NotFound,
        VaultError::InvalidInput(_) | VaultError::Validation(_) => ResponseCode::InvalidInput,
        VaultError::Conflict(_) => ResponseCode::Conflict,
        VaultError::Locked | VaultError::Persistence(_) => ResponseCode::Failure,
        VaultError::Durability(_) => ResponseCode::Durability,
    }
}
pub(crate) fn respond_domain_error(
    error: &crate::vault::VaultError,
    responses: &mut Vec<RpcResponse>,
) {
    respond_domain_error_with_context(error, &error.to_string(), responses);
}
pub(crate) fn respond_domain_error_with_context(
    error: &crate::vault::VaultError,
    message: &str,
    responses: &mut Vec<RpcResponse>,
) {
    respond_with_code(domain_code(error), message, responses);
}
pub(crate) fn respond_domain_result(
    result: Result<String, crate::vault::VaultError>,
    responses: &mut Vec<RpcResponse>,
) {
    match result {
        Ok(output) => {
            let output = zeroize::Zeroizing::new(output);
            respond(&output, responses)
        }
        Err(error) => respond_domain_error(&error, responses),
    }
}

/// Runs one command against an unlocked vault. Network work (Duo, breach
/// checks) is returned as `Deferred` so the caller can release the vault first.
pub(crate) fn execute_unlocked(
    responses: &mut Vec<RpcResponse>,
    msg: ServerCommand,
    vault: &mut Vault,
    server_info: &mut VaultCredentials,
    password_history_limit: usize,
) -> Deferred {
    let mut deferred = Deferred::None;
    let effect = &mut deferred;
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
                *effect = Deferred::Audit(audit_snapshot, options.check_breaches);
            }
        }
        ServerCommand::Duo(command) => {
            if matches!(
                &command,
                DuoCommand::Requests { .. } | DuoCommand::Respond { .. }
            ) {
                {
                    match vault.prepare_duo_poll(command, server_info) {
                        Ok(prepared) => *effect = Deferred::Duo(Box::new(prepared)),
                        Err(error) => respond_domain_error(&error, responses),
                    }
                }
            } else if matches!(&command, DuoCommand::Enroll { .. }) {
                {
                    match vault.prepare_duo_enrollment(command, true, server_info) {
                        Ok(prepared) => *effect = Deferred::DuoEnrollment(Box::new(prepared)),
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
                    Ok(prepared) => *effect = Deferred::DuoEnrollment(Box::new(prepared)),
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
                        crate::protocol::ResponsePayload::Authenticator(authenticator_response(
                            code,
                        )),
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
    deferred
}

pub(crate) fn respond_authenticator(
    result: Result<crate::vault::AuthenticatorCode, crate::vault::VaultError>,
    responses: &mut Vec<RpcResponse>,
) {
    match result {
        Ok(code) => {
            let payload = authenticator_response(code);
            respond_payload(
                ResponseCode::Success,
                crate::protocol::ResponsePayload::Authenticator(payload),
                responses,
            );
        }
        Err(error) => respond_domain_error(&error, responses),
    }
}

pub(crate) fn authenticator_response(
    code: crate::vault::AuthenticatorCode,
) -> crate::protocol::AuthenticatorResponse {
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
    }
}

pub(crate) async fn finish_duo_enrollment(
    prepared: crate::vault::PreparedDuoEnrollment,
    session: &impl SessionAccess,
    responses: &mut Vec<RpcResponse>,
) {
    let material = match prepared.enroll().await {
        Ok(material) => material,
        Err(error) => {
            respond_domain_error_with_context(
                &error,
                &format!("Duo setup failed: {error}"),
                responses,
            );
            return;
        }
    };
    let result = session
        .with_unlocked(move |vault, key| vault.finish_duo_enrollment(&prepared, material, key))
        .await;
    match result {
        Ok(Ok(output)) => respond_domain_result(Ok(output), responses),
        Ok(Err(error)) => respond_domain_error_with_context(
            &error,
            &format!("Duo enrolled but saving failed: {error}. Check enrollment before retrying."),
            responses,
        ),
        Err(error) => respond_failure(&error, responses),
    }
}

pub(crate) async fn finish_duo(
    prepared: crate::vault::PreparedDuoPoll,
    session: &impl SessionAccess,
    responses: &mut Vec<RpcResponse>,
) {
    let crate::vault::PreparedDuoPoll { request, review } = prepared;
    let body = match request.execute().await {
        Ok(body) => body,
        Err(error) => {
            respond_domain_error(&error, responses);
            return;
        }
    };
    let result = session
        .with_unlocked(move |vault, key| vault.finish_duo_poll(&review, &body, key))
        .await;
    match result {
        Ok(Ok(crate::vault::DuoPollResult::Requests(output))) => respond_payload(
            ResponseCode::Success,
            ResponsePayload::DuoRequests(output),
            responses,
        ),
        Ok(Ok(crate::vault::DuoPollResult::Decision(request))) => {
            let result = (*request)
                .execute()
                .await
                .and_then(|body| crate::duo::acknowledge(&body));
            respond_domain_result(result.map(|_| "Duo decision accepted.".into()), responses);
        }
        Ok(Err(error)) => respond_domain_error(&error, responses),
        Err(error) => respond_failure(&error, responses),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acknowledgements_remain_messages_even_when_they_look_like_json() {
        let mut responses = Vec::new();
        respond_domain_result(Ok(r#"{"history":[]}"#.into()), &mut responses);
        assert!(matches!(
            &responses[0].payload,
            ResponsePayload::Message(message) if message == r#"{"history":[]}"#
        ));
    }
}
