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
    respond_ok(ResponsePayload::Secret(message.into()), responses);
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

pub(crate) fn respond_ok(payload: ResponsePayload, responses: &mut Vec<RpcResponse>) {
    respond_payload(ResponseCode::Success, payload, responses);
}
/// Report a domain failure prefixed with the operation that failed.
pub(crate) fn respond_failed(
    operation: &str,
    error: &crate::vault::VaultError,
    responses: &mut Vec<RpcResponse>,
) {
    respond_domain_error_with_context(error, &format!("{operation}: {error}"), responses);
}
fn respond_result<T>(
    result: Result<T, crate::vault::VaultError>,
    payload: impl FnOnce(T) -> ResponsePayload,
    responses: &mut Vec<RpcResponse>,
) {
    match result {
        Ok(value) => respond_ok(payload(value), responses),
        Err(error) => respond_domain_error(&error, responses),
    }
}
/// A mutation reports whether its target existed (and changed).
fn respond_change(
    result: Result<bool, crate::vault::VaultError>,
    done: &str,
    missing: &str,
    failed: Option<&str>,
    responses: &mut Vec<RpcResponse>,
) {
    match result {
        Ok(true) => respond(done, responses),
        Ok(false) => respond_not_found(missing, responses),
        Err(error) => match failed {
            Some(operation) => respond_failed(operation, &error, responses),
            None => respond_domain_error(&error, responses),
        },
    }
}
fn respond_found<T>(
    value: Option<T>,
    payload: impl FnOnce(T) -> ResponsePayload,
    missing: &str,
    responses: &mut Vec<RpcResponse>,
) {
    match value {
        Some(value) => respond_ok(payload(value), responses),
        None => respond_not_found(missing, responses),
    }
}
fn respond_copy(
    result: Result<(), String>,
    done: &str,
    subject: &str,
    responses: &mut Vec<RpcResponse>,
) {
    match result {
        Ok(()) => respond(done, responses),
        Err(error) => respond_failure(&format!("Could not copy {subject}: {error}"), responses),
    }
}
const CLIPBOARD_DISABLED: &str =
    "Clipboard copying is disabled; configure a nonzero clipboard timeout.";

/// Runs one command against an unlocked vault. Network work (Duo, breach
/// checks) is returned as `Deferred` so the caller can release the vault first.
pub(crate) fn execute_unlocked(
    responses: &mut Vec<RpcResponse>,
    msg: ServerCommand,
    vault: &mut Vault,
    server_info: &mut VaultCredentials,
    password_history_limit: usize,
) -> Deferred {
    match msg {
        ServerCommand::Rekey(new_key) => match vault.rekey(server_info, new_key) {
            Ok(()) => respond("Vault re-encrypted with the new key.", responses),
            Err(error) => respond_failed(
                if error.committed() {
                    "Rekey committed with uncertain durability"
                } else {
                    "Rekey failed before replacement"
                },
                &error,
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
                Err(error) => respond_failed("Add failed", &error, responses),
            }
        }
        ServerCommand::Delete(target) => respond_change(
            vault.delete_entry(target, server_info),
            "Entry moved to trash.",
            "Entry not found.",
            None,
            responses,
        ),
        ServerCommand::History(target) => respond_result(
            vault.view_password_history(target),
            |rows| {
                ResponsePayload::History(crate::vault::HistoryPage {
                    history: rows.into_iter().map(str::to_owned).collect(),
                })
            },
            responses,
        ),
        ServerCommand::RestorePassword { target, revision } => respond_change(
            vault.restore_password(target, revision, server_info),
            "Password restored.",
            "Entry not found.",
            Some("Password restore failed"),
            responses,
        ),
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
            respond_ok(
                ResponsePayload::Trash(crate::vault::TrashPage { trash }),
                responses,
            );
        }
        ServerCommand::RestoreTrash(id) => respond_change(
            vault.restore_trashed(id, server_info),
            "Entry restored.",
            "Trash entry not found.",
            Some("Restore failed"),
            responses,
        ),
        ServerCommand::PurgeTrash(id) => respond_change(
            vault.purge_trash(id, server_info),
            "Trash purged.",
            "Trash entry not found.",
            Some("Purge failed"),
            responses,
        ),
        // Build the local findings and one-way password hashes while the vault
        // is available, then release the live state before any network-backed
        // breach checks begin.
        ServerCommand::Audit(options) => {
            return Deferred::Audit(vault.prepare_audit(&options), options.check_breaches);
        }
        ServerCommand::Duo(command) => match &command {
            DuoCommand::Requests { .. } | DuoCommand::Respond { .. } => {
                match vault.prepare_duo_poll(command, server_info) {
                    Ok(prepared) => return Deferred::Duo(Box::new(prepared)),
                    Err(error) => respond_domain_error(&error, responses),
                }
            }
            DuoCommand::Enroll { .. } => {
                match vault.prepare_duo_enrollment(command, true, server_info) {
                    Ok(prepared) => return Deferred::DuoEnrollment(Box::new(prepared)),
                    Err(error) => respond_domain_error(&error, responses),
                }
            }
            _ => {
                let command = Zeroizing::new(command);
                respond_domain_result(vault.duo_command(&command, server_info), responses);
            }
        },
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
                    respond_ok(ResponsePayload::Authenticator(payload), responses);
                }
                Err(error) => respond_failed(
                    "TOTP watch unavailable (requires a time-based authenticator)",
                    &error,
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
                    Err(error) => respond_failed("Authenticator setup failed", &error, responses),
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
                    Ok(prepared) => return Deferred::DuoEnrollment(Box::new(prepared)),
                    Err(error) => respond_failed("Duo setup failed", &error, responses),
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
                    respond_ok(
                        ResponsePayload::Authenticator(authenticator_response(code)),
                        responses,
                    );
                }
                Err(error) => respond_failed("Authenticator unavailable", &error, responses),
            },
            TotpCommand::Remove { target } => respond_change(
                vault.remove_totp(target, server_info),
                "Authenticator removed.",
                "Entry not found or has no authenticator.",
                Some("Authenticator removal failed"),
                responses,
            ),
        },
        ServerCommand::List(filter) => respond_result(
            vault.management_list(filter),
            ResponsePayload::ItemPage,
            responses,
        ),
        ServerCommand::ManagementItem { id, reveal } => respond_result(
            vault.management_item(id, reveal),
            ResponsePayload::Item,
            responses,
        ),
        ServerCommand::ManagementCopy { id, timeout } => {
            if timeout == 0 {
                respond_failure(CLIPBOARD_DISABLED, responses);
            } else {
                match vault.get_secret(&Target::Id(id)) {
                    Ok(mut secret) => respond_copy(
                        crate::clipboard::try_copy_in_background(
                            std::mem::take(&mut *secret),
                            timeout,
                        ),
                        "Secret copied to clipboard.",
                        "secret",
                        responses,
                    ),
                    Err(error) => respond_domain_error(&error, responses),
                }
            }
        }
        ServerCommand::BrowserAutofill => respond_ok(
            ResponsePayload::Summaries(vault.browser_autofill()),
            responses,
        ),
        ServerCommand::BrowserDuoItems(origin) => respond_ok(
            ResponsePayload::Summaries(vault.browser_duo_items(&origin)),
            responses,
        ),
        ServerCommand::BrowserLogins(origin) => respond_ok(
            ResponsePayload::Summaries(vault.browser_logins(&origin)),
            responses,
        ),
        ServerCommand::BrowserLogin { domain, id } => respond_found(
            vault.browser_login(&domain, id),
            ResponsePayload::Login,
            "Login item not found for this site.",
            responses,
        ),
        ServerCommand::BrowserAutofillItem(id) => respond_found(
            vault.browser_autofill_item(id),
            ResponsePayload::Autofill,
            "Autofill item not found.",
            responses,
        ),
        ServerCommand::Get {
            target,
            copy_timeout,
            reveal_secrets,
        } => respond_result(
            vault.target_detail(&target, reveal_secrets),
            |mut item| {
                // CLI secret-field reveal does not implicitly reveal the primary secret.
                item.password = None;
                if copy_timeout > 0
                    && let Ok(secret) = vault.get_secret(&target)
                {
                    copy_in_background(secret.to_string(), copy_timeout);
                }
                ResponsePayload::Item(item)
            },
            responses,
        ),
        ServerCommand::GetField {
            target,
            name,
            copy_timeout,
        } => {
            if copy_timeout == Some(0) {
                respond_domain_error(
                    &crate::vault::VaultError::InvalidInput(CLIPBOARD_DISABLED.into()),
                    responses,
                );
            } else {
                match vault.get_custom_field(&target, &name) {
                    Ok(mut value) => match copy_timeout {
                        Some(timeout) => respond_copy(
                            crate::clipboard::try_copy_in_background(
                                std::mem::take(&mut *value),
                                timeout,
                            ),
                            "Custom field copied to clipboard.",
                            "custom field",
                            responses,
                        ),
                        None => respond_data(&value, responses),
                    },
                    Err(error) => respond_domain_error(&error, responses),
                }
            }
        }
        ServerCommand::AuthenticatorData(target) => {
            respond_authenticator(vault.current_otp(target, server_info), responses);
        }
        ServerCommand::BrowserAuthenticatorData { domain, id } => {
            let result = match vault.browser_login_revision(&domain, id) {
                Some(_) => vault.current_otp(Target::Id(id), server_info),
                None => Err(crate::vault::VaultError::NotFound(
                    "Login item not found for this site.".into(),
                )),
            };
            respond_authenticator(result, responses);
        }
        ServerCommand::GetSecret(target) => match vault.get_secret(&target) {
            Ok(secret) => respond_data(&secret, responses),
            Err(error) => respond_domain_error(&error, responses),
        },
        ServerCommand::Update(update) => respond_change(
            vault.update_typed_entry_with_limit(update, server_info, password_history_limit),
            "Item updated.",
            "Item not found or unchanged.",
            Some("Update failed"),
            responses,
        ),
        ServerCommand::Export { path, force } => match vault.export(path, force) {
            Ok(()) => respond(
                "Export finished. WARNING: the export contains plaintext secrets.",
                responses,
            ),
            Err(error) => respond_failed("Export failed", &error, responses),
        },
        ServerCommand::Backup(mut request) => {
            match vault.encrypted_backup(request.path.clone(), &mut request.key_pass, request.force)
            {
                Ok(()) => respond("Encrypted backup created.", responses),
                Err(error) => respond_failed("Backup failed", &error, responses),
            }
            request.zeroize();
        }
        ServerCommand::Import(args) => respond_result(
            vault.import_with_options(
                args.path,
                args.conflicts,
                args.preview,
                args.password_history_limit,
                server_info,
            ),
            ResponsePayload::ImportReport,
            responses,
        ),
        _ => unreachable!("session lifecycle operations handled before unlocked dispatch"),
    }
    Deferred::None
}

pub(crate) fn respond_authenticator(
    result: Result<crate::vault::AuthenticatorCode, crate::vault::VaultError>,
    responses: &mut Vec<RpcResponse>,
) {
    match result {
        Ok(code) => {
            let payload = authenticator_response(code);
            respond_ok(
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
            respond_failed("Duo setup failed", &error, responses);
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
        Ok(Ok(crate::vault::DuoPollResult::Requests(output))) => {
            respond_ok(ResponsePayload::DuoRequests(output), responses)
        }
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
