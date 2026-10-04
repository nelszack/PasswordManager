use super::outcome::{
    respond, respond_conflict, respond_domain_error, respond_domain_error_with_context,
    respond_domain_result, respond_failure, respond_not_found,
};
use super::*;
use crate::vault::{available, unlock_selected_vault};

fn handle_command(
    responses: &mut Vec<BufferedResponse>,
    state: ConnectionState,
    msg: ServerCommand,
    session: &mut crate::vault::VaultSession,
    effect: &mut CommandEffect,
) {
    let mut add_label = "Item";
    let mut update_label = "Item";
    let mut update_missing = "Item not found or unchanged.";
    let msg = match msg {
        ServerCommand::Add(entry) => {
            add_label = "Entry";
            ServerCommand::AddTypedWithOptions {
                entry: TypedEntry {
                    entry,
                    kind: ItemKind::Login,
                    additional_urls: vec![],
                    custom_fields: vec![],
                },
                copy_timeout: 10,
            }
        }
        ServerCommand::AddTyped(entry) => ServerCommand::AddTypedWithOptions {
            entry,
            copy_timeout: 10,
        },
        ServerCommand::Update(entry) => {
            update_label = "Entry";
            update_missing = "Entry not found.";
            ServerCommand::UpdateTyped(TypedUpdate {
                entry,
                kind: None,
                add_url: vec![],
                remove_url: vec![],
                clear_urls: false,
                set_fields: vec![],
                remove_fields: vec![],
                clear_fields: false,
            })
        }
        ServerCommand::Get(target) => ServerCommand::GetDetails {
            target,
            copy_timeout: 15,
            reveal_secrets: false,
        },
        ServerCommand::GetWithOptions {
            target,
            copy_timeout,
        } => ServerCommand::GetDetails {
            target,
            copy_timeout,
            reveal_secrets: false,
        },
        other => other,
    };
    let (server_info, vlt) = session.parts_mut();
    let ConnectionState {
        session: session_handle,
        kill_tx: _,
        token: _,
        lock_generation,
        inactivity_timeout,
        background_error,
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
                | ServerCommand::StatusData
                | ServerCommand::New(_)
                | ServerCommand::Delete(Target::Vault { .. })
                | ServerCommand::RestoreBackup(_)
                | ServerCommand::Import(_)
        )
    {
        let mut msg = msg;
        msg.zeroize();
        respond_failure("Vault locked.", responses);
        return;
    }
    if !server_info.locked
        && !matches!(
            &msg,
            ServerCommand::Kill
                | ServerCommand::Lock(_)
                | ServerCommand::Unlock(_)
                | ServerCommand::Status
                | ServerCommand::StatusData
        )
    {
        let generation = lock_generation.fetch_add(1, Ordering::AcqRel) + 1;
        schedule_auto_lock(
            inactivity_timeout.load(Ordering::Acquire),
            generation,
            Arc::clone(&lock_generation),
            Arc::clone(&session_handle),
            Arc::clone(&background_error),
        );
    }
    match msg {
        ServerCommand::Add(_)
        | ServerCommand::AddTyped(_)
        | ServerCommand::Update(_)
        | ServerCommand::Get(_)
        | ServerCommand::GetWithOptions { .. } => unreachable!("legacy commands are normalized"),
        ServerCommand::Kill => {
            lock_generation.fetch_add(1, Ordering::AcqRel);
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
            respond("Server stopped.", responses);
            *effect = CommandEffect::StopServer;
        }
        ServerCommand::Lock(send) => {
            lock_generation.fetch_add(1, Ordering::AcqRel);
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
                        let generation = lock_generation.fetch_add(1, Ordering::AcqRel) + 1;
                        schedule_auto_lock(
                            info.timeout,
                            generation,
                            Arc::clone(&lock_generation),
                            session_handle,
                            Arc::clone(&background_error),
                        );
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
            let warning = background_error.blocking_lock().clone();
            respond(
                &status_message(server_info.locked, warning.as_deref()),
                responses,
            );
        }
        ServerCommand::StatusData => {
            let warning = background_error.blocking_lock().clone();
            let status = crate::protocol::ServerStatus::new(server_info.locked, warning);
            respond(
                &serde_json::to_string(&status).expect("status is serializable"),
                responses,
            );
        }
        ServerCommand::New(key_path) => {
            lock_generation.fetch_add(1, Ordering::AcqRel);
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
        ServerCommand::AddTypedWithOptions {
            entry: info,
            copy_timeout,
        } => {
            let pass = Zeroizing::new(info.entry.copy.then(|| info.entry.password.clone()));
            match available(vlt).and_then(|vault| vault.add_typed_entry(info, server_info)) {
                Ok(true) => {
                    respond(&format!("{add_label} added."), responses);
                    if let Some(password) = pass.as_deref() {
                        copy_in_background(password.to_owned(), copy_timeout);
                    }
                }
                Ok(false) => respond_conflict(&format!("{add_label} already exists."), responses),
                Err(error) => respond_domain_error_with_context(
                    &error,
                    &format!("Add failed: {error}"),
                    responses,
                ),
            }
        }
        ServerCommand::Delete(id) => match id {
            Target::Vault { key, keep_key } => {
                lock_generation.fetch_add(1, Ordering::AcqRel);
                if let Err(error) = lock_vlt(vlt, server_info) {
                    respond_domain_error_with_context(
                        &error,
                        &format!("Delete failed while locking vault: {error}"),
                        responses,
                    );
                    return;
                }
                match delete_vault(key, keep_key) {
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
                respond_domain_result(
                    vault
                        .view_password_history(target)
                        .map(|rows| presentation::history(&rows)),
                    responses,
                );
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
                respond(&presentation::trash(&vault.view_trash()), responses);
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
        ServerCommand::Totp(mut command) => {
            if let Some(vault) = vlt.as_mut() {
                match command {
                    TotpCommand::Set {
                        target,
                        mut configuration,
                    } => {
                        let result = vault.set_totp(target, &configuration, server_info);
                        configuration.zeroize();
                        match result {
                            Ok(Some(bits)) if bits < 128 => respond(
                                &format!(
                                    "TOTP authenticator saved. Warning: provider supplied a {bits}-bit secret; RFC 4226 recommends at least 128 bits."
                                ),
                                responses,
                            ),
                            Ok(Some(_)) => respond("TOTP authenticator saved.", responses),
                            Ok(None) => respond_not_found("Entry not found.", responses),
                            Err(error) => respond_domain_error_with_context(
                                &error,
                                &format!("TOTP setup failed: {error}"),
                                responses,
                            ),
                        }
                    }
                    TotpCommand::Show {
                        target,
                        copy_timeout,
                    } => match vault.current_totp(target) {
                        Ok((mut code, ttl)) => {
                            respond(&format!("TOTP: {code} ({ttl}s remaining)"), responses);
                            if let Some(timeout) = copy_timeout {
                                copy_in_background(code.clone(), timeout);
                            }
                            code.zeroize();
                        }
                        Err(error) => respond_domain_error_with_context(
                            &error,
                            &format!("TOTP unavailable: {error}"),
                            responses,
                        ),
                    },
                    TotpCommand::Remove { target } => {
                        match vault.remove_totp(target, server_info) {
                            Ok(true) => respond("TOTP authenticator removed.", responses),
                            Ok(false) => respond_not_found(
                                "Entry not found or has no TOTP authenticator.",
                                responses,
                            ),
                            Err(error) => respond_domain_error_with_context(
                                &error,
                                &format!("TOTP removal failed: {error}"),
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
            respond_domain_result(
                vlt.as_ref()
                    .ok_or(crate::vault::VaultError::Locked)
                    .and_then(|vault| {
                        vault
                            .view_entries(options)
                            .map(|entries| presentation::entries(&entries))
                    }),
                responses,
            );
        }
        ServerCommand::BrowserAutofill => {
            if let Some(vault) = vlt.as_ref() {
                let items = zeroize::Zeroizing::new(vault.browser_autofill_json());
                respond(&items, responses);
            }
        }
        ServerCommand::BrowserLogins(domain) => {
            if let Some(vault) = vlt.as_ref().filter(|_| !server_info.locked) {
                respond(&vault.browser_logins_json(&domain), responses);
            } else {
                respond_failure("Vault locked.", responses);
            }
        }
        ServerCommand::BrowserLogin { domain, id } => {
            if let Some(vault) = vlt.as_ref().filter(|_| !server_info.locked) {
                if let Some(item) = vault.browser_login_json(&domain, id) {
                    let item = Zeroizing::new(item);
                    respond(&item, responses);
                } else {
                    respond_not_found("Login item not found for this site.", responses);
                }
            } else {
                respond_failure("Vault locked.", responses);
            }
        }
        ServerCommand::BrowserAutofillItem(id) => {
            if let Some(vault) = vlt.as_ref() {
                let item = vault.browser_autofill_item_json(id).ok_or_else(|| {
                    crate::vault::VaultError::NotFound("Autofill item not found.".into())
                });
                respond_domain_result(item, responses);
            }
        }
        ServerCommand::Search(filter) => {
            if let Some(vault) = vlt.as_ref() {
                respond_domain_result(
                    vault
                        .search(filter)
                        .map(|entries| presentation::entries(&entries)),
                    responses,
                );
            }
        }
        ServerCommand::GetDetails {
            target,
            copy_timeout,
            reveal_secrets,
        } => {
            match vlt
                .as_ref()
                .ok_or(crate::vault::VaultError::Locked)
                .and_then(|vault| vault.get_entry(&target))
            {
                Ok(crate::vault::EntryOutput::Details(view)) => {
                    respond(
                        &presentation::entry_details_with_secrets(&view, reveal_secrets),
                        responses,
                    );
                    if !view.entry.password.is_empty() {
                        copy_in_background(view.entry.password.clone(), copy_timeout);
                    }
                }
                Ok(crate::vault::EntryOutput::SiteLogins(output)) => respond(&output, responses),
                Err(error) => respond_domain_error(&error, responses),
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
                            respond(&value, responses);
                        }
                    }
                    Err(error) => respond_domain_error(&error, responses),
                }
            }
        }
        ServerCommand::GetSecret(target) => {
            match vlt
                .as_ref()
                .ok_or(crate::vault::VaultError::Locked)
                .and_then(|vault| vault.get_secret(&target))
            {
                Ok(secret) => respond(&secret, responses),
                Err(error) => respond_domain_error(&error, responses),
            }
        }
        ServerCommand::UpdateTyped(update) => {
            match available(vlt).and_then(|vault| {
                vault.update_typed_entry_with_limit(update, server_info, password_history_limit)
            }) {
                Ok(true) => respond(&format!("{update_label} updated."), responses),
                Ok(false) => respond_not_found(update_missing, responses),
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
                match restore_encrypted_backup(&request.path, &mut request.key_pass, request.force)
                {
                    Ok(filename) => respond(
                        &format!(
                            "Encrypted backup restored as {filename}. Unlock it with the backup password/key."
                        ),
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
                    Ok(report) => respond(&report.to_string(), responses),
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
                    Ok(report) => respond(&report.to_string(), responses),
                    Err(error) => respond_domain_error_with_context(
                        &error,
                        &format!("Import failed: {error}"),
                        responses,
                    ),
                }
                return;
            }

            lock_generation.fetch_add(1, Ordering::AcqRel);
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
                        respond(&report.to_string(), responses)
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
