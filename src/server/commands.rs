use super::outcome::{
    respond, respond_conflict, respond_data, respond_domain_error,
    respond_domain_error_with_context, respond_domain_result, respond_failure, respond_not_found,
    respond_payload,
};
use super::*;
use crate::vault::{available, unlock_selected_vault};

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
    responses: &mut Vec<crate::protocol::RpcResponse>,
    state: ConnectionState,
    msg: ServerCommand,
    session: &mut crate::vault::VaultSession,
    effect: &mut CommandEffect,
) {
    // Kill marks shutdown while owning the session. Requests accepted before
    // the listener stops must not mutate files or unlock the vault afterward.
    if state.stopping.load(Ordering::Acquire) {
        let mut msg = msg;
        msg.zeroize();
        respond_failure("Server is stopping.", responses);
        return;
    }
    let mut edit = session.edit();
    let (server_info, vlt) = edit.parts_mut();
    let ConnectionState {
        instance_lock: _instance_lock,
        kill_tx: _,
        token: _,
        inactivity_timeout,
        stopping,
        background_error,
        system_lock,
        password_history_limit,
        trash_retention_days,
    } = state;
    if (server_info.locked || vlt.is_none())
        && !matches!(
            &msg,
            ServerCommand::Kill
                | ServerCommand::Lock(_)
                | ServerCommand::Unlock(_)
                | ServerCommand::Status
                | ServerCommand::New(_)
                | ServerCommand::Delete(Target::Vault { .. })
                | ServerCommand::RestoreBackup(_)
                | ServerCommand::Import(_)
                | ServerCommand::OperationStatus(_)
        )
    {
        let mut msg = msg;
        msg.zeroize();
        respond_failure("Vault locked.", responses);
        return;
    }
    match msg {
        ServerCommand::Kill => {
            if !server_info.locked
                && let Err(error) = lock_vlt(vlt, server_info)
            {
                respond_domain_error_with_context(
                    &error,
                    &format!("Could not stop server safely: {error}"),
                    responses,
                );
                return;
            }
            stopping.store(true, Ordering::Release);
            respond("Server stopped.", responses);
            *effect = CommandEffect::StopServer;
        }
        ServerCommand::Lock(send) => {
            let was_locked = server_info.locked;
            // Retry clipboard cleanup even when the vault was already locked.
            match lock_vlt(vlt, server_info) {
                Ok(()) => {
                    *background_error.blocking_lock() = None;
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
                    *background_error.blocking_lock() = Some(message.clone());
                    if send {
                        respond_domain_error_with_context(&error, &message, responses);
                    }
                }
            }
        }
        ServerCommand::Unlock(info) => {
            if server_info.locked {
                if let Some(mut old) = server_info.keypass.take() {
                    old.zeroize();
                }
                server_info.keypass = Some(info.key);
                match unlock_selected_vault(server_info, info.vault_file.as_deref())
                    .map(|vault| *vlt = Some(vault))
                {
                    Ok(()) => {
                        let expired = if let Some(vault) = vlt.as_mut() {
                            vault.purge_expired_trash(trash_retention_days, server_info)
                        } else {
                            Ok(0)
                        };
                        if let Err(error) = expired {
                            let _ = lock_vlt(vlt, server_info);
                            respond_domain_error_with_context(
                                &error,
                                &format!("Unlock failed while applying trash retention: {error}"),
                                responses,
                            );
                            return;
                        }
                        inactivity_timeout.store(info.timeout, Ordering::Release);
                        *background_error.blocking_lock() = None;
                        respond("Vault unlocked.", responses);
                    }
                    Err(e) => {
                        server_info.zeroize();
                        respond_domain_error_with_context(
                            &e,
                            &format!("Unlock failed: {}", e),
                            responses,
                        )
                    }
                }
            } else {
                respond_failure(
                    "A vault is already unlocked. Lock it before unlocking another one.",
                    responses,
                );
            }
        }
        ServerCommand::Status => {
            let warning = combined_lock_warning(&background_error, system_lock.as_deref());
            respond_payload(
                ResponseCode::Success,
                crate::protocol::ResponsePayload::Status(crate::protocol::ServerStatus::new(
                    server_info.locked,
                    warning,
                )),
                responses,
            );
        }
        ServerCommand::OperationStatus(_) => respond_failure(
            "Operation status is resolved by the vault worker.",
            responses,
        ),
        ServerCommand::New(key_path) => {
            if !server_info.locked
                && let Err(error) = lock_vlt(vlt, server_info)
            {
                respond_domain_error_with_context(
                    &error,
                    &format!("Could not lock current vault: {error}"),
                    responses,
                );
                return;
            }
            if let Some(mut old) = server_info.keypass.take() {
                old.zeroize();
            }
            server_info.keypass = Some(key_path);
            match create_vault(vlt, server_info, true) {
                Ok(()) => respond("Vault created.", responses),
                Err(e) => respond_domain_error(&e, responses),
            }
        }
        ServerCommand::Rekey(new_key) => {
            if let Some(vault) = vlt.as_mut() {
                match vault.rekey(server_info, new_key) {
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
                }
            } else {
                respond_failure("Vault unavailable.", responses);
            }
        }
        ServerCommand::Add {
            entry: info,
            copy_timeout,
        } => {
            let pass = Zeroizing::new(info.entry.copy.then(|| info.entry.password.clone()));
            match available(vlt).and_then(|vault| vault.add_typed_entry(info, server_info)) {
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
        ServerCommand::Delete(id) => match id {
            Target::Vault {
                key,
                keep_key,
                vault_file,
            } => {
                if let Err(error) = lock_vlt(vlt, server_info) {
                    respond_domain_error_with_context(
                        &error,
                        &format!("Delete failed while locking vault: {error}"),
                        responses,
                    );
                    return;
                }
                match delete_vault(key, keep_key, vault_file.as_deref()) {
                    Ok(()) => respond("Vault deleted.", responses),
                    Err(e) => respond_domain_error_with_context(
                        &e,
                        &format!("Delete failed: {e}"),
                        responses,
                    ),
                }
            }
            _ if !server_info.locked => {
                match available(vlt).and_then(|vault| vault.delete_entry(id, server_info)) {
                    Ok(true) => respond("Entry moved to trash.", responses),
                    Ok(false) => respond_not_found("Entry not found.", responses),
                    Err(error) => respond_domain_error_with_context(
                        &error,
                        &format!("Delete failed: {error}"),
                        responses,
                    ),
                }
            }
            _ => respond_failure("Vault locked.", responses),
        },
        ServerCommand::History(target) => {
            if let Some(vault) = vlt.as_ref() {
                match vault.view_password_history(target) {
                    Ok(rows) => respond_payload(
                        ResponseCode::Success,
                        ResponsePayload::History(crate::vault::HistoryPage {
                            history: rows.into_iter().map(str::to_owned).collect(),
                        }),
                        responses,
                    ),
                    Err(error) => respond_domain_error(&error, responses),
                }
            }
        }
        ServerCommand::RestorePassword { target, revision } => {
            if let Some(vault) = vlt.as_mut() {
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
        }
        ServerCommand::Trash => {
            if let Some(vault) = vlt.as_ref() {
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
        }
        ServerCommand::RestoreTrash(id) => {
            if let Some(vault) = vlt.as_mut() {
                match vault.restore_trashed(id, server_info) {
                    Ok(true) => respond("Entry restored.", responses),
                    Ok(false) => respond_not_found("Trash entry not found.", responses),
                    Err(error) => respond_domain_error_with_context(
                        &error,
                        &format!("Restore failed: {error}"),
                        responses,
                    ),
                }
            }
        }
        ServerCommand::PurgeTrash(id) => {
            if let Some(vault) = vlt.as_mut() {
                match vault.purge_trash(id, server_info) {
                    Ok(true) => respond("Trash purged.", responses),
                    Ok(false) => respond_not_found("Trash entry not found.", responses),
                    Err(error) => respond_domain_error_with_context(
                        &error,
                        &format!("Purge failed: {error}"),
                        responses,
                    ),
                }
            }
        }
        ServerCommand::Audit(options) => {
            if let Some(vault) = vlt.as_ref() {
                // Build the local findings and one-way password hashes while
                // the vault is available, then release the live state before
                // any network-backed breach checks begin.
                let audit_snapshot = vault.audit_snapshot(&options);
                *effect = CommandEffect::Audit(audit_snapshot, options.check_breaches);
            }
        }
        ServerCommand::Duo(command) => {
            if matches!(
                &command,
                DuoCommand::Requests { .. } | DuoCommand::Respond { .. }
            ) {
                if let Some(vault) = vlt.as_mut() {
                    match vault.prepare_duo_poll(command, server_info) {
                        Ok(prepared) => *effect = CommandEffect::Duo(Box::new(prepared)),
                        Err(error) => respond_domain_error(&error, responses),
                    }
                }
            } else if matches!(&command, DuoCommand::Enroll { .. }) {
                if let Some(vault) = vlt.as_mut() {
                    match vault.prepare_duo_enrollment(command, true, server_info) {
                        Ok(prepared) => *effect = CommandEffect::DuoEnrollment(Box::new(prepared)),
                        Err(error) => respond_domain_error(&error, responses),
                    }
                }
            } else {
                let command = Zeroizing::new(command);
                if let Some(vault) = vlt.as_mut() {
                    respond_domain_result(vault.duo_command(&command, server_info), responses);
                }
            }
        }
        ServerCommand::Totp(mut command) => {
            if let Some(vault) = vlt.as_mut() {
                match command {
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
                            Ok(prepared) => {
                                *effect = CommandEffect::DuoEnrollment(Box::new(prepared))
                            }
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
                    TotpCommand::Remove { target } => {
                        match vault.remove_totp(target, server_info) {
                            Ok(true) => respond("Authenticator removed.", responses),
                            Ok(false) => respond_not_found(
                                "Entry not found or has no authenticator.",
                                responses,
                            ),
                            Err(error) => respond_domain_error_with_context(
                                &error,
                                &format!("Authenticator removal failed: {error}"),
                                responses,
                            ),
                        }
                    }
                }
            } else {
                command.zeroize();
                respond_failure("Vault unavailable.", responses);
            }
        }
        ServerCommand::View(options) => {
            match vlt
                .as_ref()
                .ok_or(crate::vault::VaultError::Locked)
                .and_then(|v| {
                    v.management_list(SearchFilter {
                        list: options,
                        ..Default::default()
                    })
                }) {
                Ok(page) => respond_payload(
                    ResponseCode::Success,
                    crate::protocol::ResponsePayload::ItemPage(page),
                    responses,
                ),
                Err(e) => respond_domain_error(&e, responses),
            }
        }
        ServerCommand::ManagementList(filter) => {
            match vlt
                .as_ref()
                .ok_or(crate::vault::VaultError::Locked)
                .and_then(|v| v.management_list(filter))
            {
                Ok(page) => respond_payload(
                    ResponseCode::Success,
                    crate::protocol::ResponsePayload::ItemPage(page),
                    responses,
                ),
                Err(e) => respond_domain_error(&e, responses),
            }
        }
        ServerCommand::ManagementItem { id, reveal } => {
            match vlt
                .as_ref()
                .ok_or(crate::vault::VaultError::Locked)
                .and_then(|v| v.management_item(id, reveal))
            {
                Ok(item) => respond_payload(
                    ResponseCode::Success,
                    crate::protocol::ResponsePayload::Item(item),
                    responses,
                ),
                Err(e) => respond_domain_error(&e, responses),
            }
        }
        ServerCommand::ManagementCopy { id, timeout } => {
            if timeout == 0 {
                respond_failure(
                    "Clipboard copying is disabled; configure a nonzero clipboard timeout.",
                    responses,
                );
            } else {
                match vlt
                    .as_ref()
                    .ok_or(crate::vault::VaultError::Locked)
                    .and_then(|vault| vault.get_secret(&Target::Id(id)))
                {
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
            if let Some(vault) = vlt.as_ref() {
                respond_payload(
                    ResponseCode::Success,
                    crate::protocol::ResponsePayload::Summaries(vault.browser_autofill()),
                    responses,
                );
            }
        }
        ServerCommand::BrowserDuoItems(origin) => {
            if let Some(vault) = vlt.as_ref() {
                respond_payload(
                    ResponseCode::Success,
                    crate::protocol::ResponsePayload::Summaries(vault.browser_duo_items(&origin)),
                    responses,
                );
            }
        }
        ServerCommand::BrowserLogins(origin) => {
            if let Some(vault) = vlt.as_ref() {
                respond_payload(
                    ResponseCode::Success,
                    crate::protocol::ResponsePayload::Summaries(vault.browser_logins(&origin)),
                    responses,
                );
            }
        }
        ServerCommand::BrowserLogin { domain, id } => {
            match vlt.as_ref().and_then(|v| v.browser_login(&domain, id)) {
                Some(item) => respond_payload(
                    ResponseCode::Success,
                    crate::protocol::ResponsePayload::Login(item),
                    responses,
                ),
                None => respond_not_found("Login item not found for this site.", responses),
            }
        }
        ServerCommand::BrowserAutofillItem(id) => {
            match vlt.as_ref().and_then(|v| v.browser_autofill_item(id)) {
                Some(item) => respond_payload(
                    ResponseCode::Success,
                    crate::protocol::ResponsePayload::Autofill(item),
                    responses,
                ),
                None => respond_not_found("Autofill item not found.", responses),
            }
        }
        ServerCommand::Search(filter) => {
            match vlt
                .as_ref()
                .ok_or(crate::vault::VaultError::Locked)
                .and_then(|v| v.management_list(filter))
            {
                Ok(page) => respond_payload(
                    ResponseCode::Success,
                    crate::protocol::ResponsePayload::ItemPage(page),
                    responses,
                ),
                Err(e) => respond_domain_error(&e, responses),
            }
        }
        ServerCommand::Get {
            target,
            copy_timeout,
            reveal_secrets,
        } => {
            match vlt
                .as_ref()
                .ok_or(crate::vault::VaultError::Locked)
                .and_then(|v| v.target_detail(&target, reveal_secrets))
            {
                Ok(mut item) => {
                    // CLI secret-field reveal does not implicitly reveal the primary secret.
                    item.password = None;
                    if copy_timeout > 0
                        && let Some(vault) = vlt.as_ref()
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
                match vlt
                    .as_ref()
                    .ok_or(crate::vault::VaultError::Locked)
                    .and_then(|vault| vault.get_custom_field(&target, &name))
                {
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
            respond_authenticator(
                available(vlt).and_then(|vault| vault.current_otp(target, server_info)),
                responses,
            );
        }
        ServerCommand::BrowserAuthenticatorData { domain, id } => {
            let result = available(vlt).and_then(|vault| {
                if vault.browser_login_revision(&domain, id).is_none() {
                    return Err(crate::vault::VaultError::NotFound(
                        "Login item not found for this site.".into(),
                    ));
                }
                vault.current_otp(Target::Id(id), server_info)
            });
            respond_authenticator(result, responses);
        }
        ServerCommand::GetSecret(target) => {
            match vlt
                .as_ref()
                .ok_or(crate::vault::VaultError::Locked)
                .and_then(|vault| vault.get_secret(&target))
            {
                Ok(secret) => respond_data(&secret, responses),
                Err(error) => respond_domain_error(&error, responses),
            }
        }
        ServerCommand::Update(update) => {
            match available(vlt).and_then(|vault| {
                vault.update_typed_entry_with_limit(update, server_info, password_history_limit)
            }) {
                Ok(true) => respond("Item updated.", responses),
                Ok(false) => respond_not_found("Item not found or unchanged.", responses),
                Err(error) => respond_domain_error_with_context(
                    &error,
                    &format!("Update failed: {error}"),
                    responses,
                ),
            }
        }
        ServerCommand::Export { path, force } => {
            match available(vlt).and_then(|vault| vault.export(path, force)) {
                Ok(()) => respond(
                    "Export finished. WARNING: the export contains plaintext secrets.",
                    responses,
                ),
                Err(e) => {
                    respond_domain_error_with_context(&e, &format!("Export failed: {e}"), responses)
                }
            }
        }
        ServerCommand::Backup(mut request) => {
            if let Some(vault) = vlt.as_ref() {
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
            } else {
                respond_failure("Vault unavailable.", responses);
            }
            request.zeroize();
        }
        ServerCommand::RestoreBackup(mut request) => {
            if !server_info.locked {
                respond_failure(
                    "Lock the current vault before restoring a backup.",
                    responses,
                );
            } else {
                match restore_encrypted_backup(&request.path, &mut request.key_pass) {
                    Ok(filename) => respond_payload(
                        ResponseCode::Success,
                        crate::protocol::ResponsePayload::Vault(crate::protocol::VaultReference {
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
        ServerCommand::Import(args) => {
            let ImportRequest {
                path,
                new,
                key_pass,
                preview,
                conflicts,
                password_history_limit,
            } = args;
            if new && preview {
                let mut preview_vault = Vault::default();
                let result = preview_vault.import_with_options(
                    path,
                    conflicts,
                    true,
                    password_history_limit,
                    &mut ServerInfo::default(),
                );
                match result {
                    Ok(report) => respond_payload(
                        ResponseCode::Success,
                        crate::protocol::ResponsePayload::ImportReport(report),
                        responses,
                    ),
                    Err(error) => respond_domain_error_with_context(
                        &error,
                        &format!("Import preview failed: {error}"),
                        responses,
                    ),
                }
                preview_vault.zeroize();
                return;
            }
            if !new {
                if server_info.locked {
                    respond_failure("Vault locked.", responses);
                    return;
                }
                match available(vlt).and_then(|vault| {
                    vault.import_with_options(
                        path,
                        conflicts,
                        preview,
                        password_history_limit,
                        server_info,
                    )
                }) {
                    Ok(report) => respond_payload(
                        ResponseCode::Success,
                        crate::protocol::ResponsePayload::ImportReport(report),
                        responses,
                    ),
                    Err(error) => respond_domain_error_with_context(
                        &error,
                        &format!("Import failed: {error}"),
                        responses,
                    ),
                }
                return;
            }

            if !server_info.locked
                && let Err(error) = lock_vlt(vlt, server_info)
            {
                respond_domain_error_with_context(
                    &error,
                    &format!("Import failed while locking vault: {error}"),
                    responses,
                );
                return;
            }
            if let Some(mut old) = server_info.keypass.take() {
                old.zeroize();
            }
            let Some(key_pass) = key_pass else {
                respond_failure(
                    "A password or key is required for a new imported vault.",
                    responses,
                );
                return;
            };
            *server_info = ServerInfo {
                locked: true,
                keypass: Some(key_pass),
            };
            let error = create_vault(vlt, server_info, false).err();

            match error {
                Some(e) => respond_domain_error_with_context(
                    &e,
                    &format!("Import failed: {}", e),
                    responses,
                ),
                None => match available(vlt).and_then(|vault| {
                    vault.import_with_options(
                        path,
                        conflicts,
                        preview,
                        password_history_limit,
                        server_info,
                    )
                }) {
                    Ok(report) => {
                        vlt.zeroize();
                        server_info.zeroize();
                        respond_payload(
                            ResponseCode::Success,
                            crate::protocol::ResponsePayload::ImportReport(report),
                            responses,
                        )
                    }
                    Err(e) => {
                        let _ = lock_vlt(vlt, server_info);
                        respond_domain_error_with_context(
                            &e,
                            &format!("Import failed: {e}"),
                            responses,
                        );
                    }
                },
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
