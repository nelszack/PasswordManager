//! Vault operations shared by the desktop service and the mobile bridge. Both
//! accept the same typed `ServerCommand`s and produce the same reply.
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
    /// Strength scoring for a weak-password list; the list itself is built
    /// on the vault queue once the scores are cached.
    WeakList(crate::vault::PendingScores, Box<SearchFilter>),
    Duo(Box<crate::vault::PreparedDuoPoll>),
    DuoEnrollment(Box<crate::vault::PreparedDuoEnrollment>),
}

/// A vault owner (the desktop worker queue or the mobile vault mutex) that
/// deferred work and cloud sync re-enter after running outside its lock.
pub(crate) trait VaultHost: Sync {
    /// Runs `apply` on the unlocked vault only while `session` is still the
    /// open unlock. The outer error means it was locked, replaced, or stopped.
    fn with_session<T: Send + 'static>(
        &self,
        session: Option<String>,
        apply: impl FnOnce(&mut Vault, &mut VaultCredentials) -> Result<T, crate::vault::VaultError>
        + Send
        + 'static,
    ) -> impl Future<Output = Result<Result<T, crate::vault::VaultError>, String>> + Send;

    /// A predicate that turns true once `session` is no longer open or, when
    /// given, the vault is no longer at `revision`. It never waits for the
    /// owner, so long work can poll it.
    fn staleness(&self, session: Option<String>, revision: Option<u64>) -> Stale;

    /// Runs CPU-heavy work outside the owner; None if it could not run. The
    /// future is boxed: an opaque one trips rustc's higher-ranked `Send` check
    /// in the server's connection task.
    fn blocking<T: Send + 'static>(&self, work: impl FnOnce() -> T + Send + 'static)
    -> Blocking<T>;
}

/// See [`VaultHost::blocking`].
pub(crate) type Blocking<T> = std::pin::Pin<Box<dyn Future<Output = Option<T>> + Send>>;

/// See [`VaultHost::staleness`].
pub(crate) type Stale = std::sync::Arc<dyn Fn() -> bool + Send + Sync>;

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
    reply: &mut Option<RpcResponse>,
) {
    *reply = Some(RpcResponse::new(code, payload));
}
pub(crate) fn respond_with_code(
    code: ResponseCode,
    message: &str,
    reply: &mut Option<RpcResponse>,
) {
    *reply = Some(RpcResponse::message(code, message));
}
pub(crate) fn respond_data(message: &str, reply: &mut Option<RpcResponse>) {
    respond_ok(ResponsePayload::Secret(message.into()), reply);
}
pub(crate) fn respond(message: &str, reply: &mut Option<RpcResponse>) {
    respond_with_code(ResponseCode::Success, message, reply);
}
pub(crate) fn respond_failure(message: &str, reply: &mut Option<RpcResponse>) {
    respond_with_code(ResponseCode::Failure, message, reply);
}
pub(crate) fn respond_not_found(message: &str, reply: &mut Option<RpcResponse>) {
    respond_with_code(ResponseCode::NotFound, message, reply);
}
pub(crate) fn respond_conflict(message: &str, reply: &mut Option<RpcResponse>) {
    respond_with_code(ResponseCode::Conflict, message, reply);
}
fn domain_code(error: &crate::vault::VaultError) -> ResponseCode {
    use crate::vault::VaultError;
    match error {
        VaultError::NotFound(_) => ResponseCode::NotFound,
        VaultError::InvalidInput(_) | VaultError::Validation(_) | VaultError::WrongKey => {
            ResponseCode::InvalidInput
        }
        VaultError::Conflict(_) => ResponseCode::Conflict,
        VaultError::Locked | VaultError::Persistence(_) => ResponseCode::Failure,
        VaultError::Durability(_) => ResponseCode::Durability,
    }
}
pub(crate) fn respond_domain_error(
    error: &crate::vault::VaultError,
    reply: &mut Option<RpcResponse>,
) {
    respond_domain_error_with_context(error, &error.to_string(), reply);
}
pub(crate) fn respond_domain_error_with_context(
    error: &crate::vault::VaultError,
    message: &str,
    reply: &mut Option<RpcResponse>,
) {
    respond_with_code(domain_code(error), message, reply);
}
pub(crate) fn respond_domain_result(
    result: Result<String, crate::vault::VaultError>,
    reply: &mut Option<RpcResponse>,
) {
    match result {
        Ok(output) => {
            let output = zeroize::Zeroizing::new(output);
            respond(&output, reply)
        }
        Err(error) => respond_domain_error(&error, reply),
    }
}

pub(crate) fn respond_ok(payload: ResponsePayload, reply: &mut Option<RpcResponse>) {
    respond_payload(ResponseCode::Success, payload, reply);
}
/// Report a domain failure prefixed with the operation that failed.
pub(crate) fn respond_failed(
    operation: &str,
    error: &crate::vault::VaultError,
    reply: &mut Option<RpcResponse>,
) {
    respond_domain_error_with_context(error, &format!("{operation}: {error}"), reply);
}
fn respond_result<T>(
    result: Result<T, crate::vault::VaultError>,
    payload: impl FnOnce(T) -> ResponsePayload,
    reply: &mut Option<RpcResponse>,
) {
    match result {
        Ok(value) => respond_ok(payload(value), reply),
        Err(error) => respond_domain_error(&error, reply),
    }
}
/// A mutation reports whether its target existed (and changed).
fn respond_change(
    result: Result<bool, crate::vault::VaultError>,
    done: &str,
    missing: &str,
    failed: Option<&str>,
    reply: &mut Option<RpcResponse>,
) {
    match result {
        Ok(true) => respond(done, reply),
        Ok(false) => respond_not_found(missing, reply),
        Err(error) => match failed {
            Some(operation) => respond_failed(operation, &error, reply),
            None => respond_domain_error(&error, reply),
        },
    }
}
fn respond_found<T>(
    value: Option<T>,
    payload: impl FnOnce(T) -> ResponsePayload,
    missing: &str,
    reply: &mut Option<RpcResponse>,
) {
    match value {
        Some(value) => respond_ok(payload(value), reply),
        None => respond_not_found(missing, reply),
    }
}
fn respond_copy(
    result: Result<(), String>,
    done: &str,
    subject: &str,
    reply: &mut Option<RpcResponse>,
) {
    match result {
        Ok(()) => respond(done, reply),
        Err(error) => respond_failure(&format!("Could not copy {subject}: {error}"), reply),
    }
}
const CLIPBOARD_DISABLED: &str =
    "Clipboard copying is disabled; configure a nonzero clipboard timeout.";

/// Runs one command against an unlocked vault. Network work (Duo, breach
/// checks) is returned as `Deferred` so the caller can release the vault first.
pub(crate) fn execute_unlocked(
    reply: &mut Option<RpcResponse>,
    msg: ServerCommand,
    vault: &mut Vault,
    server_info: &mut VaultCredentials,
    password_history_limit: usize,
) -> Deferred {
    match msg {
        msg @ (ServerCommand::Add { .. }
        | ServerCommand::Delete(..)
        | ServerCommand::History(..)
        | ServerCommand::RestorePassword { .. }
        | ServerCommand::Update(..)
        | ServerCommand::Get { .. }
        | ServerCommand::GetField { .. }
        | ServerCommand::GetSecret(..)) => {
            item_command(reply, msg, vault, server_info, password_history_limit);
            Deferred::None
        }
        msg @ (ServerCommand::List(..)
        | ServerCommand::ManagementItem { .. }
        | ServerCommand::ManagementCopy { .. }
        | ServerCommand::Audit(..)) => management_command(reply, msg, vault),
        msg @ (ServerCommand::Totp(..)
        | ServerCommand::Duo(..)
        | ServerCommand::AuthenticatorData(..)
        | ServerCommand::BrowserAuthenticatorData { .. }) => {
            authenticator_command(reply, msg, vault, server_info)
        }
        msg @ (ServerCommand::BrowserCopy { .. }
        | ServerCommand::BrowserCopyItem { .. }
        | ServerCommand::CopyGenerated { .. }) => {
            browser_copy(reply, msg, vault, server_info);
            Deferred::None
        }
        msg @ (ServerCommand::BrowserAutofill
        | ServerCommand::BrowserDuoItems(..)
        | ServerCommand::BrowserLogins(..)
        | ServerCommand::BrowserLogin { .. }
        | ServerCommand::BrowserLoginSaved { .. }
        | ServerCommand::BrowserAutofillItem(..)) => {
            browser_command(reply, msg, vault);
            Deferred::None
        }
        msg @ (ServerCommand::BrowserPasskeys { .. }
        | ServerCommand::BrowserPasskeyCreate { .. }
        | ServerCommand::BrowserPasskeyGet { .. }) => {
            passkey_command(reply, msg, vault, server_info);
            Deferred::None
        }
        ServerCommand::Attachment(command) => {
            attachment_command(reply, command, vault, server_info);
            Deferred::None
        }
        msg @ (ServerCommand::Trash
        | ServerCommand::RestoreTrash(..)
        | ServerCommand::PurgeTrash(..)
        | ServerCommand::Rekey(..)
        | ServerCommand::Export { .. }
        | ServerCommand::Backup(..)
        | ServerCommand::Import(..)) => {
            recovery_command(reply, msg, vault, server_info);
            Deferred::None
        }
        _ => unreachable!("session lifecycle operations handled before unlocked dispatch"),
    }
}

/// Browser WebAuthn. The origin was derived by the native host from the
/// browser's sender metadata.
fn passkey_command(
    reply: &mut Option<RpcResponse>,
    msg: ServerCommand,
    vault: &mut Vault,
    server_info: &mut VaultCredentials,
) {
    let parse = |request: &str| crate::passkey::parse(request);
    // `verified` is set by the service only after redeeming a confirmation
    // token; clients cannot set it.
    let result = match msg {
        ServerCommand::BrowserPasskeys { origin, request } => parse(&request)
            .and_then(|request| vault.browser_passkeys(&origin, &request))
            .map(ResponsePayload::Passkeys),
        ServerCommand::BrowserPasskeyCreate {
            origin,
            request,
            verified,
            ..
        } => parse(&request)
            .and_then(|request| {
                vault.browser_passkey_create(&origin, &request, server_info, verified)
            })
            .map(|value| ResponsePayload::PasskeyCredential(value.to_string())),
        ServerCommand::BrowserPasskeyGet {
            origin,
            id,
            request,
            verified,
            ..
        } => parse(&request)
            .and_then(|request| vault.browser_passkey_get(&origin, id, &request, verified))
            .map(|value| ResponsePayload::PasskeyCredential(value.to_string())),
        _ => unreachable!("dispatched by execute_unlocked"),
    };
    match result {
        Ok(payload) => respond_ok(payload, reply),
        Err(error) => respond_failure(&format!("Passkey request failed: {error}"), reply),
    }
}

/// Add, save, or remove an item's file attachments.
fn attachment_command(
    reply: &mut Option<RpcResponse>,
    command: AttachmentCommand,
    vault: &mut Vault,
    server_info: &mut VaultCredentials,
) {
    use crate::vault::attachments;
    match command {
        AttachmentCommand::Add { target, path, name } => {
            let name = name.unwrap_or_else(|| attachments::default_name(&path));
            match attachments::read_attachment_file(&path)
                .and_then(|data| vault.add_attachment(&target, &name, data, server_info))
            {
                Ok(()) => respond("Attachment added.", reply),
                Err(error) => respond_failed("Attachment failed", &error, reply),
            }
        }
        AttachmentCommand::Save {
            target,
            name,
            path,
            force,
        } => match vault.save_attachment(&target, &name, &path, force) {
            Ok(()) => respond("Attachment saved.", reply),
            Err(error) => respond_failed("Saving the attachment failed", &error, reply),
        },
        AttachmentCommand::Remove { target, name } => {
            match vault.remove_attachment(&target, &name, server_info) {
                Ok(()) => respond("Attachment removed.", reply),
                Err(error) => respond_failed("Removing the attachment failed", &error, reply),
            }
        }
    }
}

/// Edit, read, and copy individual items.
fn item_command(
    reply: &mut Option<RpcResponse>,
    msg: ServerCommand,
    vault: &mut Vault,
    server_info: &mut VaultCredentials,
    password_history_limit: usize,
) {
    match msg {
        ServerCommand::Add {
            entry: info,
            copy_timeout,
        } => {
            let pass = Zeroizing::new(info.entry.copy.then(|| info.entry.password.clone()));
            let name = info.entry.name.clone();
            match vault.add_typed_entry(info, server_info) {
                Ok(true) => {
                    // Say what happened to the copy, including a failure.
                    let copied = match pass.as_deref().filter(|p| !p.is_empty()) {
                        Some(password) if copy_timeout > 0 => {
                            Some(crate::clipboard::try_copy_in_background(
                                password.to_owned(),
                                copy_timeout,
                            ))
                        }
                        _ => None,
                    };
                    let message = match copied {
                        None => format!("Added \u{201c}{name}\u{201d}."),
                        Some(Ok(())) => format!(
                            "Added \u{201c}{name}\u{201d}. Its password is copied; the clipboard clears in {copy_timeout} seconds."
                        ),
                        Some(Err(error)) => format!(
                            "Added \u{201c}{name}\u{201d}, but its password could not be copied: {}.",
                            crate::clipboard::describe_error(&error)
                        ),
                    };
                    respond(&message, reply);
                }
                Ok(false) => respond_conflict("Item already exists.", reply),
                Err(error) => respond_failed("Add failed", &error, reply),
            }
        }
        ServerCommand::Delete(target) => respond_change(
            vault.delete_entry(target, server_info),
            "Item moved to trash.",
            "Item not found.",
            None,
            reply,
        ),
        ServerCommand::History(target) => respond_result(
            vault.view_password_history(target),
            |rows| {
                ResponsePayload::History(crate::vault::HistoryPage {
                    history: rows.into_iter().map(str::to_owned).collect(),
                })
            },
            reply,
        ),
        ServerCommand::RestorePassword { target, revision } => respond_change(
            vault.restore_password(target, revision, server_info),
            "Password restored.",
            "Item not found.",
            Some("Password restore failed"),
            reply,
        ),
        ServerCommand::Update(update) => respond_change(
            vault.update_typed_entry_with_limit(update, server_info, password_history_limit),
            "Item updated.",
            "Item not found or unchanged.",
            Some("Update failed"),
            reply,
        ),
        ServerCommand::Get {
            target,
            copy_timeout,
            reveal_secrets,
        } => {
            respond_result(
                vault.target_detail(&target, reveal_secrets),
                |mut item| {
                    // CLI secret-field reveal does not implicitly reveal the primary secret.
                    item.password = None;
                    ResponsePayload::Item(item)
                },
                reply,
            );
            // Report the copy's real outcome instead of assuming it worked.
            if copy_timeout > 0
                && reply.as_ref().is_some_and(|response| response.code == 0)
                && let Ok(secret) = vault.get_secret(&target)
            {
                let outcome = if secret.is_empty() {
                    Err("this item has nothing to copy".to_owned())
                } else {
                    crate::clipboard::try_copy_in_background(secret.to_string(), copy_timeout)
                };
                if let Some(response) = reply.as_mut() {
                    response.notice = Some(match outcome {
                        Ok(()) => {
                            format!("Copied; the clipboard clears in {copy_timeout} seconds.")
                        }
                        Err(error) => format!("Could not copy: {error}"),
                    });
                }
            }
        }
        ServerCommand::GetField {
            target,
            name,
            copy_timeout,
        } => {
            if copy_timeout == Some(0) {
                respond_domain_error(
                    &crate::vault::VaultError::InvalidInput(CLIPBOARD_DISABLED.into()),
                    reply,
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
                            reply,
                        ),
                        None => respond_data(&value, reply),
                    },
                    Err(error) => respond_domain_error(&error, reply),
                }
            }
        }
        ServerCommand::GetSecret(target) => match vault.get_secret(&target) {
            Ok(secret) => respond_data(&secret, reply),
            Err(error) => respond_domain_error(&error, reply),
        },
        _ => unreachable!("dispatched by execute_unlocked"),
    }
}

/// Management listings, item details, copies, and audits.
fn management_command(
    reply: &mut Option<RpcResponse>,
    msg: ServerCommand,
    vault: &mut Vault,
) -> Deferred {
    match msg {
        ServerCommand::List(filter) => {
            if let Some(pending) = vault.prepare_weak_list(&filter) {
                return Deferred::WeakList(pending, Box::new(filter));
            }
            respond_result(
                vault.management_list(filter),
                ResponsePayload::ItemPage,
                reply,
            )
        }
        ServerCommand::ManagementItem { id, reveal } => respond_result(
            vault.management_item(id, reveal),
            ResponsePayload::Item,
            reply,
        ),
        ServerCommand::ManagementCopy { id, timeout } => {
            if timeout == 0 {
                respond_failure(CLIPBOARD_DISABLED, reply);
            } else {
                match vault.get_secret(&Target::Id(id)) {
                    Ok(mut secret) => respond_copy(
                        crate::clipboard::try_copy_in_background(
                            std::mem::take(&mut *secret),
                            timeout,
                        ),
                        "Secret copied to clipboard.",
                        "secret",
                        reply,
                    ),
                    Err(error) => respond_domain_error(&error, reply),
                }
            }
        }
        // Build the local findings and one-way password hashes while the vault
        // is available, then release the live state before any network-backed
        // breach checks begin.
        ServerCommand::Audit(options) => {
            return Deferred::Audit(vault.prepare_audit(&options), options.check_breaches);
        }
        _ => unreachable!("dispatched by execute_unlocked"),
    }
    Deferred::None
}

/// TOTP/HOTP codes and Duo enrollment and push requests.
fn authenticator_command(
    reply: &mut Option<RpcResponse>,
    msg: ServerCommand,
    vault: &mut Vault,
    server_info: &mut VaultCredentials,
) -> Deferred {
    match msg {
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
                    respond_ok(ResponsePayload::Authenticator(payload), reply);
                }
                Err(error) => respond_failed(
                    "TOTP watch unavailable (requires a time-based authenticator)",
                    &error,
                    reply,
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
                            "Authenticator saved. Note: this site issued a short {bits}-bit authenticator key (128 bits is recommended); codes still work and nothing needs to change."
                        ),
                        reply,
                    ),
                    Ok(Some(_)) => respond("Authenticator saved.", reply),
                    Ok(None) => respond_not_found("Item not found.", reply),
                    Err(error) => respond_failed("Authenticator setup failed", &error, reply),
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
                    Err(error) => respond_failed("Duo setup failed", &error, reply),
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
                        reply,
                    );
                }
                Err(error) => respond_failed("Authenticator unavailable", &error, reply),
            },
            TotpCommand::Remove { target } => respond_change(
                vault.remove_totp(target, server_info),
                "Authenticator removed.",
                "Item not found, or it has no authenticator.",
                Some("Authenticator removal failed"),
                reply,
            ),
        },
        ServerCommand::Duo(command) => match &command {
            DuoCommand::Requests { .. } | DuoCommand::Respond { .. } => {
                match vault.prepare_duo_poll(command, server_info) {
                    Ok(prepared) => return Deferred::Duo(Box::new(prepared)),
                    Err(error) => respond_domain_error(&error, reply),
                }
            }
            DuoCommand::Enroll { .. } => {
                match vault.prepare_duo_enrollment(command, true, server_info) {
                    Ok(prepared) => return Deferred::DuoEnrollment(Box::new(prepared)),
                    Err(error) => respond_domain_error(&error, reply),
                }
            }
            _ => {
                let command = Zeroizing::new(command);
                respond_domain_result(vault.duo_command(&command, server_info), reply);
            }
        },
        ServerCommand::AuthenticatorData(target) => {
            respond_authenticator(vault.current_otp(target, server_info), reply);
        }
        ServerCommand::BrowserAuthenticatorData { domain, id } => {
            let result = match vault.browser_login_revision(&domain, id) {
                Some(_) => vault.current_otp(Target::Id(id), server_info),
                None => Err(crate::vault::VaultError::NotFound(
                    "Login item not found for this site.".into(),
                )),
            };
            respond_authenticator(result, reply);
        }
        _ => unreachable!("dispatched by execute_unlocked"),
    }
    Deferred::None
}

/// Popup copies: the value goes from the vault to the timed clipboard helper.
fn browser_copy(
    reply: &mut Option<RpcResponse>,
    msg: ServerCommand,
    vault: &mut Vault,
    server_info: &mut VaultCredentials,
) {
    use crate::types::{BrowserCopyField, OtpMode};
    let (value, subject, timeout) = match msg {
        ServerCommand::CopyGenerated { value, timeout } => {
            (Ok(value.expose_owned()), "Password", timeout)
        }
        ServerCommand::BrowserCopyItem { id, field, timeout } => {
            use crate::types::{BrowserCopyField, OtpMode};
            let detail = vault.target_detail(&Target::Id(id), false);
            let kind = detail.as_ref().map(|item| item.kind).unwrap_or_default();
            let profile = crate::item_profile::profile(kind);
            let nonempty = |value: String, missing: &str| {
                if value.is_empty() {
                    Err(missing.to_owned())
                } else {
                    Ok(value)
                }
            };
            let (value, subject) = match field {
                BrowserCopyField::Username => (
                    detail
                        .as_ref()
                        .map_err(|error| error.to_string())
                        .and_then(|item| {
                            nonempty(
                                item.username.clone().unwrap_or_default(),
                                "This item has no username.",
                            )
                        }),
                    profile.owner.split(" (").next().unwrap_or(profile.owner),
                ),
                BrowserCopyField::Password => (
                    vault
                        .get_secret(&Target::Id(id))
                        .map(|secret| secret.to_string())
                        .map_err(|error| error.to_string())
                        .and_then(|secret| nonempty(secret, "This item has nothing to copy.")),
                    profile.secret_name(),
                ),
                BrowserCopyField::Totp => (
                    match detail.as_ref().ok().and_then(|item| item.otp_mode) {
                        Some(OtpMode::Totp) => vault
                            .current_otp(Target::Id(id), server_info)
                            .map(|code| code.code.to_string())
                            .map_err(|error| error.to_string()),
                        Some(OtpMode::Hotp) => Err("Counter-based codes are shown in the desktop \
                                                   app, so each code is used once."
                            .to_owned()),
                        None => Err("This item has no one-time code.".to_owned()),
                    },
                    "One-time code",
                ),
            };
            (value, subject, timeout)
        }
        ServerCommand::BrowserCopy {
            domain,
            id,
            field,
            timeout,
        } => {
            let value = match vault.browser_login(&domain, id) {
                None => Err("Login item not found for this site.".to_owned()),
                Some(login) => match field {
                    BrowserCopyField::Username => login
                        .username
                        .filter(|name| !name.is_empty())
                        .ok_or_else(|| "This login has no username.".to_owned()),
                    BrowserCopyField::Password => {
                        let password = login.password.expose_owned();
                        if password.is_empty() {
                            Err("This login has no password.".to_owned())
                        } else {
                            Ok(password)
                        }
                    }
                    BrowserCopyField::Totp => {
                        let mode = vault
                            .target_detail(&Target::Id(id), false)
                            .ok()
                            .and_then(|item| item.otp_mode);
                        match mode {
                            Some(OtpMode::Totp) => vault
                                .current_otp(Target::Id(id), server_info)
                                .map(|code| code.code.to_string())
                                .map_err(|error| error.to_string()),
                            Some(OtpMode::Hotp) => Err("Counter-based codes are filled on the \
                                                        page so each code is used once."
                                .to_owned()),
                            None => Err("This login has no one-time code.".to_owned()),
                        }
                    }
                },
            };
            let subject = match field {
                BrowserCopyField::Username => "Username",
                BrowserCopyField::Password => "Password",
                BrowserCopyField::Totp => "One-time code",
            };
            (value, subject, timeout)
        }
        _ => unreachable!("dispatched by execute_unlocked"),
    };
    match value {
        _ if timeout == 0 => respond_failure(CLIPBOARD_DISABLED, reply),
        Err(message) => respond_not_found(&message, reply),
        Ok(value) => respond_copy(
            crate::clipboard::try_copy_in_background(value, timeout),
            &format!("{subject} copied. The clipboard clears in {timeout} seconds."),
            &subject.to_lowercase(),
            reply,
        ),
    }
}

/// Browser-extension summaries and site-bound logins.
fn browser_command(reply: &mut Option<RpcResponse>, msg: ServerCommand, vault: &mut Vault) {
    match msg {
        ServerCommand::BrowserAutofill => {
            respond_ok(ResponsePayload::Summaries(vault.browser_autofill()), reply)
        }
        ServerCommand::BrowserDuoItems(origin) => respond_ok(
            ResponsePayload::Summaries(vault.browser_duo_items(&origin)),
            reply,
        ),
        ServerCommand::BrowserLogins(origin) => respond_ok(
            ResponsePayload::Summaries(vault.browser_logins(&origin)),
            reply,
        ),
        ServerCommand::BrowserLoginSaved {
            domain,
            username,
            password,
        } => respond_ok(
            ResponsePayload::Summaries(vault.browser_saved_logins(&domain, &username, &password)),
            reply,
        ),
        ServerCommand::BrowserLogin { domain, id } => respond_found(
            vault.browser_login(&domain, id),
            ResponsePayload::Login,
            "Login item not found for this site.",
            reply,
        ),
        ServerCommand::BrowserAutofillItem(id) => respond_found(
            vault.browser_autofill_item(id),
            ResponsePayload::Autofill,
            "Autofill item not found.",
            reply,
        ),
        _ => unreachable!("dispatched by execute_unlocked"),
    }
}

/// Trash, re-encryption, and file import, export, and backup.
fn recovery_command(
    reply: &mut Option<RpcResponse>,
    msg: ServerCommand,
    vault: &mut Vault,
    server_info: &mut VaultCredentials,
) {
    match msg {
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
                reply,
            );
        }
        ServerCommand::RestoreTrash(id) => respond_change(
            vault.restore_trashed(id, server_info),
            "Item restored.",
            "No trashed item has that ID.",
            Some("Restore failed"),
            reply,
        ),
        ServerCommand::PurgeTrash(id) => respond_change(
            vault.purge_trash(id, server_info),
            "Trash purged.",
            "No trashed item has that ID.",
            Some("Purge failed"),
            reply,
        ),
        ServerCommand::Rekey(new_key) => match vault.rekey(server_info, new_key) {
            Ok(()) => respond("Vault re-encrypted with the new key.", reply),
            Err(error) => respond_failed(
                if error.committed() {
                    "Rekey committed with uncertain durability"
                } else {
                    "Rekey failed before replacement"
                },
                &error,
                reply,
            ),
        },
        ServerCommand::Export { path, force } => match vault.export(path, force) {
            Ok(()) => respond(
                "Export finished. WARNING: the export contains plaintext secrets.",
                reply,
            ),
            Err(error) => respond_failed("Export failed", &error, reply),
        },
        ServerCommand::Backup(mut request) => {
            match vault.encrypted_backup(request.path.clone(), &mut request.key_pass, request.force)
            {
                Ok(()) => respond("Encrypted backup created.", reply),
                Err(error) => respond_failed("Backup failed", &error, reply),
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
            reply,
        ),
        _ => unreachable!("dispatched by execute_unlocked"),
    }
}

pub(crate) fn respond_authenticator(
    result: Result<crate::vault::AuthenticatorCode, crate::vault::VaultError>,
    reply: &mut Option<RpcResponse>,
) {
    match result {
        Ok(code) => {
            let payload = authenticator_response(code);
            respond_ok(
                crate::protocol::ResponsePayload::Authenticator(payload),
                reply,
            );
        }
        Err(error) => respond_domain_error(&error, reply),
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

async fn finish_duo_enrollment(
    prepared: crate::vault::PreparedDuoEnrollment,
    host: &impl VaultHost,
    session: Option<String>,
    reply: &mut Option<RpcResponse>,
) {
    let material = match prepared.enroll().await {
        Ok(material) => material,
        Err(error) => {
            respond_failed("Duo setup failed", &error, reply);
            return;
        }
    };
    let result = host
        .with_session(session, move |vault, key| {
            vault.finish_duo_enrollment(&prepared, material, key)
        })
        .await;
    // Duo has consumed the activation by now, so a failure to save must say
    // so, including when the vault locked or the server began stopping.
    let saving_failed = |error: &dyn std::fmt::Display| {
        format!("Duo enrolled but saving failed: {error}. Check enrollment before retrying.")
    };
    match result {
        Ok(Ok(output)) => respond_domain_result(Ok(output), reply),
        Ok(Err(error)) => respond_domain_error_with_context(&error, &saving_failed(&error), reply),
        Err(error) => respond_failure(&saving_failed(&error), reply),
    }
}

pub(crate) async fn finish_duo(
    prepared: crate::vault::PreparedDuoPoll,
    host: &impl VaultHost,
    session: Option<String>,
    reply: &mut Option<RpcResponse>,
) {
    let crate::vault::PreparedDuoPoll { request, review } = prepared;
    let body = match request.execute().await {
        Ok(body) => body,
        Err(error) => {
            respond_domain_error(&error, reply);
            return;
        }
    };
    let result = host
        .with_session(session, move |vault, key| {
            vault.finish_duo_poll(&review, &body, key)
        })
        .await;
    match result {
        Ok(Ok(crate::vault::DuoPollResult::Requests(output))) => {
            respond_ok(ResponsePayload::DuoRequests(output), reply)
        }
        Ok(Ok(crate::vault::DuoPollResult::Decision(request))) => {
            let result = (*request)
                .execute()
                .await
                .and_then(|body| crate::duo::acknowledge(&body));
            respond_domain_result(result.map(|_| "Duo decision accepted.".into()), reply);
        }
        Ok(Err(error)) => respond_domain_error(&error, reply),
        Err(error) => respond_failure(&error, reply),
    }
}

/// Reports `error` after a command already ran. When the command left the
/// credentials unusable, the session locked after it produced its result; that
/// result may record a committed change, so it is kept (with the more severe
/// code, as Durability outranks every failure) instead of being replaced.
pub(crate) fn report_beside_result(
    error: &crate::vault::VaultError,
    reply: &mut Option<RpcResponse>,
) {
    let Some(mut ran) = reply.take() else {
        respond_domain_error(error, reply);
        return;
    };
    let mut lock = None;
    respond_domain_error(error, &mut lock);
    let Some(lock) = lock else {
        *reply = Some(ran);
        return;
    };
    ran.code = ran.code.max(lock.code);
    match (&mut ran.payload, lock.payload) {
        (ResponsePayload::Message(message), ResponsePayload::Message(locked)) => {
            message.push('\n');
            message.push_str(&locked);
        }
        (payload, locked) => *payload = locked,
    }
    *reply = Some(ran);
}

/// Completes deferred network or CPU work for the unlock `session` that
/// started it. Results are discarded if that session was locked or replaced,
/// and audits also if the vault changed meanwhile.
pub(crate) async fn finish_deferred(
    work: Deferred,
    host: &impl VaultHost,
    session: Option<String>,
    reply: &mut Option<RpcResponse>,
) {
    match work {
        Deferred::None => {}
        Deferred::Duo(prepared) => finish_duo(*prepared, host, session, reply).await,
        Deferred::DuoEnrollment(prepared) => {
            finish_duo_enrollment(*prepared, host, session, reply).await;
        }
        Deferred::Audit(pending, check_breaches) => {
            // Check the captured session/revision between scores so locking and
            // edits remain responsive.
            let stale = host.staleness(session.clone(), Some(pending.revision));
            let check = stale.clone();
            // `ok()` keeps borrowed error types out of the blocking result.
            let scored = host.blocking(move || pending.finish(|| check()).ok()).await;
            let Some(Some(snapshot)) = scored else {
                respond_conflict(
                    "Vault changed or audit evaluation failed; run it again",
                    reply,
                );
                return;
            };
            let audit = snapshot.audit(check_breaches).await;
            // Breach lookups take network time; an edit or sync meanwhile would
            // make this report describe passwords that are no longer stored.
            if stale() {
                respond_conflict("Vault changed while the audit ran; run it again", reply);
                return;
            }
            let code = if audit.incomplete {
                ResponseCode::Failure
            } else {
                ResponseCode::Success
            };
            respond_payload(code, ResponsePayload::Audit(audit.report), reply);
        }
        Deferred::WeakList(pending, filter) => {
            // Edits during scoring only leave a few cold scores for the list
            // to compute on the owner; a lock or switch discards the work.
            let stale = host.staleness(session.clone(), None);
            let scored = host
                .blocking(move || pending.finish(|| stale()).is_ok())
                .await;
            if scored != Some(true) {
                respond_conflict(
                    "Vault was locked or changed while checking password strength; run it again",
                    reply,
                );
                return;
            }
            match host
                .with_session(session, move |vault, _| vault.management_list(*filter))
                .await
            {
                Ok(result) => respond_result(result, ResponsePayload::ItemPage, reply),
                Err(error) => respond_failure(&error, reply),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lock_after_a_committed_change_keeps_the_commit() {
        let mut reply = Some(RpcResponse::message(
            ResponseCode::Durability,
            "Item updated; the save may not be durable.",
        ));
        report_beside_result(&crate::vault::VaultError::Locked, &mut reply);
        let response = reply.unwrap();
        assert_eq!(response.code, ResponseCode::Durability as i32);
        let ResponsePayload::Message(message) = &response.payload else {
            panic!("message payload expected");
        };
        assert!(message.starts_with("Item updated"));
        assert!(message.ends_with("vault is locked"));

        let mut reply = None;
        report_beside_result(&crate::vault::VaultError::Locked, &mut reply);
        assert_eq!(reply.unwrap().code, ResponseCode::Failure as i32);
    }

    #[test]
    fn acknowledgements_remain_messages_even_when_they_look_like_json() {
        let mut reply = None;
        respond_domain_result(Ok(r#"{"history":[]}"#.into()), &mut reply);
        assert!(matches!(
            &reply.unwrap().payload,
            ResponsePayload::Message(message) if message == r#"{"history":[]}"#
        ));
    }
}
