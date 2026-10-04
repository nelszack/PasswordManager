use super::*;

#[allow(clippy::needless_borrow)]
pub(super) async fn handle_command(
    mut stream: &mut TcpStream,
    state: ConnectionState,
    msg: ServerCommand,
    mut server_info: tokio::sync::OwnedMutexGuard<ServerInfo>,
    mut vlt: tokio::sync::OwnedMutexGuard<Option<Vault>>,
    effect: &mut CommandEffect,
) {
    let ConnectionState {
        server_info: server_info_handle,
        vlt: vlt_handle,
        kill_tx: _,
        token: _,
        lock_generation,
        inactivity_timeout,
        background_error,
        password_history_limit,
        trash_retention_days,
    } = state;
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
            Arc::clone(&server_info_handle),
            Arc::clone(&vlt_handle),
            Arc::clone(&background_error),
        );
    }
    match msg {
        ServerCommand::Kill => {
            lock_generation.fetch_add(1, Ordering::AcqRel);
            if !server_info.locked
                && let Err(error) = lock_vlt(&mut vlt, &mut server_info)
            {
                respond_domain_error_with_context(
                    &error,
                    &format!("Could not stop server safely: {error}"),
                    &mut stream,
                )
                .await;
                return;
            }
            respond("Server stopped.", &mut stream).await;
            *effect = CommandEffect::StopServer;
        }
        ServerCommand::Lock(send) => {
            lock_generation.fetch_add(1, Ordering::AcqRel);
            let was_locked = server_info.locked;
            // Retry clipboard cleanup even when the vault was already locked.
            match lock_vlt(&mut vlt, &mut server_info) {
                Ok(()) => {
                    *background_error.lock().await = None;
                    if send {
                        respond(
                            if was_locked {
                                "Vault is already locked."
                            } else {
                                "Vault locked."
                            },
                            &mut stream,
                        )
                        .await;
                    }
                }
                Err(error) => {
                    let message = format!("Vault locked with a cleanup warning: {error}");
                    *background_error.lock().await = Some(message.clone());
                    if send {
                        respond_domain_error_with_context(&error, &message, &mut stream).await;
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
                match vlt.unlock_vault_selected(&mut server_info, info.vault_file.as_deref()) {
                    Ok(()) => {
                        let expired = if let Some(vault) = vlt.as_mut() {
                            vault.purge_expired_trash(trash_retention_days, &mut server_info)
                        } else {
                            Ok(0)
                        };
                        if let Err(error) = expired {
                            let _ = lock_vlt(&mut vlt, &mut server_info);
                            respond_domain_error_with_context(
                                &error,
                                &format!("Unlock failed while applying trash retention: {error}"),
                                &mut stream,
                            )
                            .await;
                            return;
                        }
                        inactivity_timeout.store(info.timeout, Ordering::Release);
                        let generation = lock_generation.fetch_add(1, Ordering::AcqRel) + 1;
                        schedule_auto_lock(
                            info.timeout,
                            generation,
                            Arc::clone(&lock_generation),
                            server_info_handle,
                            vlt_handle,
                            Arc::clone(&background_error),
                        );
                        *background_error.lock().await = None;
                        respond("Vault unlocked.", &mut stream).await;
                    }
                    Err(e) => {
                        server_info.zeroize();
                        respond_domain_error_with_context(
                            &e,
                            &format!("Unlock failed: {}", e),
                            &mut stream,
                        )
                        .await
                    }
                }
            } else {
                respond_failure(
                    "A vault is already unlocked. Lock it before unlocking another one.",
                    &mut stream,
                )
                .await;
            }
        }
        ServerCommand::Status => {
            let warning = background_error.lock().await.clone();
            respond(
                &status_message(server_info.locked, warning.as_deref()),
                &mut stream,
            )
            .await;
        }
        ServerCommand::StatusData => {
            let warning = background_error.lock().await.clone();
            let status = crate::protocol::ServerStatus::new(server_info.locked, warning);
            respond(
                &serde_json::to_string(&status).expect("status is serializable"),
                &mut stream,
            )
            .await;
        }
        ServerCommand::New(key_path) => {
            lock_generation.fetch_add(1, Ordering::AcqRel);
            if !server_info.locked
                && let Err(error) = lock_vlt(&mut vlt, &mut server_info)
            {
                respond_domain_error_with_context(
                    &error,
                    &format!("Could not lock current vault: {error}"),
                    &mut stream,
                )
                .await;
                return;
            }
            if let Some(mut old) = server_info.keypass.take() {
                old.zeroize();
            }
            server_info.keypass = Some(key_path);
            match create_vault(&mut vlt, &mut server_info, true) {
                Ok(()) => respond("Vault created.", &mut stream).await,
                Err(e) => respond_domain_error(&e, &mut stream).await,
            }
        }
        ServerCommand::Rekey(new_key) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_mut() {
                match vault.rekey(&mut server_info, new_key) {
                    Ok(()) => respond("Vault re-encrypted with the new key.", &mut stream).await,
                    Err(error) => {
                        respond_domain_error_with_context(
                            &error,
                            &format!(
                                "{}: {error}",
                                if error.committed() {
                                    "Rekey committed with uncertain durability"
                                } else {
                                    "Rekey failed before replacement"
                                }
                            ),
                            &mut stream,
                        )
                        .await
                    }
                }
            } else {
                respond_failure("Vault unavailable.", &mut stream).await;
            }
        }
        ServerCommand::Add(info) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else {
                let mut pass = info.copy.then(|| info.password.clone());
                match vlt.add_entry(info, &mut server_info) {
                    Ok(true) => {
                        respond("Entry added.", &mut stream).await;
                        if let Some(p) = pass.as_deref() {
                            copy_in_background(p.to_owned(), 10);
                        }
                    }
                    Ok(false) => respond_conflict("Entry already exists.", &mut stream).await,
                    Err(error) => {
                        respond_domain_error_with_context(
                            &error,
                            &format!("Add failed: {error}"),
                            &mut stream,
                        )
                        .await
                    }
                }
                if let Some(p) = pass.as_mut() {
                    p.zeroize();
                }
            }
        }
        ServerCommand::AddTyped(info) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else {
                let mut pass = info.entry.copy.then(|| info.entry.password.clone());
                match vlt.add_typed_entry(info, &mut server_info) {
                    Ok(true) => {
                        respond("Item added.", &mut stream).await;
                        if let Some(password) = pass.as_deref() {
                            copy_in_background(password.to_owned(), 10);
                        }
                    }
                    Ok(false) => respond_conflict("Item already exists.", &mut stream).await,
                    Err(error) => {
                        respond_domain_error_with_context(
                            &error,
                            &format!("Add failed: {error}"),
                            &mut stream,
                        )
                        .await
                    }
                }
                if let Some(password) = pass.as_mut() {
                    password.zeroize();
                }
            }
        }
        ServerCommand::AddTypedWithOptions {
            entry: info,
            copy_timeout,
        } => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else {
                let mut pass = info.entry.copy.then(|| info.entry.password.clone());
                match vlt.add_typed_entry(info, &mut server_info) {
                    Ok(true) => {
                        respond("Item added.", &mut stream).await;
                        if let Some(password) = pass.as_deref() {
                            copy_in_background(password.to_owned(), copy_timeout);
                        }
                    }
                    Ok(false) => respond_conflict("Item already exists.", &mut stream).await,
                    Err(error) => {
                        respond_domain_error_with_context(
                            &error,
                            &format!("Add failed: {error}"),
                            &mut stream,
                        )
                        .await
                    }
                }
                if let Some(password) = pass.as_mut() {
                    password.zeroize();
                }
            }
        }
        ServerCommand::Delete(id) => match id {
            Target::Vault { key, keep_key } => {
                lock_generation.fetch_add(1, Ordering::AcqRel);
                if let Err(error) = lock_vlt(&mut vlt, &mut server_info) {
                    respond_domain_error_with_context(
                        &error,
                        &format!("Delete failed while locking vault: {error}"),
                        &mut stream,
                    )
                    .await;
                    return;
                }
                match delete_vault(key, keep_key) {
                    Ok(()) => respond("Vault deleted.", &mut stream).await,
                    Err(e) => {
                        respond_domain_error_with_context(
                            &e,
                            &format!("Delete failed: {e}"),
                            &mut stream,
                        )
                        .await
                    }
                }
            }
            _ if !server_info.locked => match vlt.delete_entry(id, &mut server_info) {
                Ok(true) => respond("Entry moved to trash.", &mut stream).await,
                Ok(false) => respond_not_found("Entry not found.", &mut stream).await,
                Err(error) => {
                    respond_domain_error_with_context(
                        &error,
                        &format!("Delete failed: {error}"),
                        &mut stream,
                    )
                    .await
                }
            },
            _ => respond_failure("Vault locked.", &mut stream).await,
        },
        ServerCommand::History(target) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_ref() {
                respond_domain_result(
                    vault
                        .view_password_history(target)
                        .map(|rows| presentation::history(&rows)),
                    &mut stream,
                )
                .await;
            }
        }
        ServerCommand::RestorePassword { target, revision } => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_mut() {
                match vault.restore_password(target, revision, &mut server_info) {
                    Ok(true) => respond("Password restored.", &mut stream).await,
                    Ok(false) => respond_not_found("Entry not found.", &mut stream).await,
                    Err(error) => {
                        respond_domain_error_with_context(
                            &error,
                            &format!("Password restore failed: {error}"),
                            &mut stream,
                        )
                        .await
                    }
                }
            }
        }
        ServerCommand::Trash => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_ref() {
                respond(&presentation::trash(&vault.view_trash()), &mut stream).await;
            }
        }
        ServerCommand::RestoreTrash(id) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_mut() {
                match vault.restore_trashed(id, &mut server_info) {
                    Ok(true) => respond("Entry restored.", &mut stream).await,
                    Ok(false) => respond_not_found("Trash entry not found.", &mut stream).await,
                    Err(error) => {
                        respond_domain_error_with_context(
                            &error,
                            &format!("Restore failed: {error}"),
                            &mut stream,
                        )
                        .await
                    }
                }
            }
        }
        ServerCommand::PurgeTrash(id) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_mut() {
                match vault.purge_trash(id, &mut server_info) {
                    Ok(true) => respond("Trash purged.", &mut stream).await,
                    Ok(false) => respond_not_found("Trash entry not found.", &mut stream).await,
                    Err(error) => {
                        respond_domain_error_with_context(
                            &error,
                            &format!("Purge failed: {error}"),
                            &mut stream,
                        )
                        .await
                    }
                }
            }
        }
        ServerCommand::Audit(options) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_ref() {
                // Build the local findings and one-way password hashes while
                // the vault is available, then release the live state before
                // any network-backed breach checks begin.
                let audit_snapshot = vault.audit_snapshot(&options);
                *effect = CommandEffect::Audit(audit_snapshot, options.check_breaches);
            }
        }
        ServerCommand::Totp(mut command) => {
            if server_info.locked {
                command.zeroize();
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_mut() {
                match command {
                    TotpCommand::Set {
                        target,
                        mut configuration,
                    } => {
                        let result = vault.set_totp(target, &configuration, &mut server_info);
                        configuration.zeroize();
                        match result {
                            Ok(Some(bits)) if bits < 128 => {
                                respond(
                                    &format!(
                                        "TOTP authenticator saved. Warning: provider supplied a {bits}-bit secret; RFC 4226 recommends at least 128 bits."
                                    ),
                                    &mut stream
)
                                .await
                            }
                            Ok(Some(_)) => {
                                respond("TOTP authenticator saved.", &mut stream).await
                            }
                            Ok(None) => {
                                respond_not_found("Entry not found.", &mut stream).await
                            }
                            Err(error) => {
                                respond_domain_error_with_context(&error, &format!("TOTP setup failed: {error}"), &mut stream)
                                .await
                            }
                        }
                    }
                    TotpCommand::Show {
                        target,
                        copy_timeout,
                    } => match vault.current_totp(target) {
                        Ok((mut code, ttl)) => {
                            respond(&format!("TOTP: {code} ({ttl}s remaining)"), &mut stream).await;
                            if let Some(timeout) = copy_timeout {
                                copy_in_background(code.clone(), timeout);
                            }
                            code.zeroize();
                        }
                        Err(error) => {
                            respond_domain_error_with_context(
                                &error,
                                &format!("TOTP unavailable: {error}"),
                                &mut stream,
                            )
                            .await
                        }
                    },
                    TotpCommand::Remove { target } => {
                        match vault.remove_totp(target, &mut server_info) {
                            Ok(true) => respond("TOTP authenticator removed.", &mut stream).await,
                            Ok(false) => {
                                respond_not_found(
                                    "Entry not found or has no TOTP authenticator.",
                                    &mut stream,
                                )
                                .await
                            }
                            Err(error) => {
                                respond_domain_error_with_context(
                                    &error,
                                    &format!("TOTP removal failed: {error}"),
                                    &mut stream,
                                )
                                .await
                            }
                        }
                    }
                }
            } else {
                command.zeroize();
                respond_failure("Vault unavailable.", &mut stream).await;
            }
        }
        ServerCommand::View(options) => {
            if !server_info.locked {
                respond_domain_result(
                    vlt.as_ref()
                        .ok_or(crate::vault::VaultError::Locked)
                        .and_then(|vault| {
                            vault
                                .view_entries(options)
                                .map(|entries| presentation::entries(&entries))
                        }),
                    &mut stream,
                )
                .await;
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::BrowserAutofill => {
            if !server_info.locked {
                if let Some(vault) = vlt.as_ref() {
                    let items = zeroize::Zeroizing::new(vault.browser_autofill_json());
                    respond(&items, &mut stream).await;
                }
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::BrowserLogins(domain) => {
            if let Some(vault) = vlt.as_ref().filter(|_| !server_info.locked) {
                respond(&vault.browser_logins_json(&domain), &mut stream).await;
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::BrowserLogin { domain, id } => {
            if let Some(vault) = vlt.as_ref().filter(|_| !server_info.locked) {
                if let Some(item) = vault.browser_login_json(&domain, id) {
                    let item = Zeroizing::new(item);
                    respond(&item, &mut stream).await;
                } else {
                    respond_not_found("Login item not found for this site.", &mut stream).await;
                }
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::BrowserAutofillItem(id) => {
            if !server_info.locked {
                if let Some(vault) = vlt.as_ref() {
                    let item = vault.browser_autofill_item_json(id).ok_or_else(|| {
                        crate::vault::VaultError::NotFound("Autofill item not found.".into())
                    });
                    respond_domain_result(item, &mut stream).await;
                }
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::Search(filter) => {
            if !server_info.locked {
                if let Some(vault) = vlt.as_ref() {
                    respond_domain_result(
                        vault
                            .search(filter)
                            .map(|entries| presentation::entries(&entries)),
                        &mut stream,
                    )
                    .await;
                }
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::Get(a) => {
            if !server_info.locked {
                deliver_entry(
                    vlt.as_ref()
                        .ok_or(crate::vault::VaultError::Locked)
                        .and_then(|vault| vault.get_entry(&a)),
                    15,
                    &mut stream,
                )
                .await;
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::GetWithOptions {
            target,
            copy_timeout,
        } => {
            if !server_info.locked {
                if let Some(vault) = vlt.as_ref() {
                    deliver_entry(vault.get_entry(&target), copy_timeout, &mut stream).await;
                }
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::GetDetails {
            target,
            copy_timeout,
            reveal_secrets,
        } => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else {
                match vlt
                    .as_ref()
                    .ok_or(crate::vault::VaultError::Locked)
                    .and_then(|vault| vault.get_entry(&target))
                {
                    Ok(crate::vault::EntryOutput::Details(view)) => {
                        respond(
                            &presentation::entry_details_with_secrets(&view, reveal_secrets),
                            &mut stream,
                        )
                        .await;
                        if !view.entry.password.is_empty() {
                            copy_in_background(view.entry.password.clone(), copy_timeout);
                        }
                    }
                    Ok(crate::vault::EntryOutput::SiteLogins(output)) => {
                        respond(&output, &mut stream).await
                    }
                    Err(error) => respond_domain_error(&error, &mut stream).await,
                }
            }
        }
        ServerCommand::GetField {
            target,
            name,
            copy_timeout,
        } => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if copy_timeout == Some(0) {
                respond_domain_error(
                    &crate::vault::VaultError::InvalidInput(
                        "Clipboard copying is disabled; configure a nonzero clipboard timeout."
                            .into(),
                    ),
                    &mut stream,
                )
                .await;
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
                                Ok(()) => {
                                    respond("Custom field copied to clipboard.", &mut stream).await
                                }
                                Err(error) => {
                                    respond_failure(
                                        &format!("Could not copy custom field: {error}"),
                                        &mut stream,
                                    )
                                    .await
                                }
                            }
                        } else {
                            respond(&value, &mut stream).await;
                        }
                    }
                    Err(error) => respond_domain_error(&error, &mut stream).await,
                }
            }
        }
        ServerCommand::GetSecret(target) => {
            if !server_info.locked {
                match vlt
                    .as_ref()
                    .ok_or(crate::vault::VaultError::Locked)
                    .and_then(|vault| vault.get_secret(&target))
                {
                    Ok(secret) => respond(&secret, &mut stream).await,
                    Err(error) => respond_domain_error(&error, &mut stream).await,
                }
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::Update(a) => {
            if !server_info.locked {
                match vlt.update_entry_with_limit(a, &mut server_info, password_history_limit) {
                    Ok(true) => respond("Entry updated.", &mut stream).await,
                    Ok(false) => respond_not_found("Entry not found.", &mut stream).await,
                    Err(error) => {
                        respond_domain_error_with_context(
                            &error,
                            &format!("Update failed: {error}"),
                            &mut stream,
                        )
                        .await
                    }
                }
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::UpdateTyped(update) => {
            if !server_info.locked {
                match vlt.update_typed_entry_with_limit(
                    update,
                    &mut server_info,
                    password_history_limit,
                ) {
                    Ok(true) => respond("Item updated.", &mut stream).await,
                    Ok(false) => {
                        respond_not_found("Item not found or unchanged.", &mut stream).await
                    }
                    Err(error) => {
                        respond_domain_error_with_context(
                            &error,
                            &format!("Update failed: {error}"),
                            &mut stream,
                        )
                        .await
                    }
                }
            } else {
                respond_failure("Vault locked.", &mut stream).await;
            }
        }
        ServerCommand::Export { path, force } => match vlt.export(path, force) {
            Ok(()) => {
                respond(
                    "Export finished. WARNING: the export contains plaintext secrets.",
                    &mut stream,
                )
                .await
            }
            Err(e) => {
                respond_domain_error_with_context(&e, &format!("Export failed: {e}"), &mut stream)
                    .await
            }
        },
        ServerCommand::Backup(mut request) => {
            if server_info.locked {
                respond_failure("Vault locked.", &mut stream).await;
            } else if let Some(vault) = vlt.as_ref() {
                let result = vault.encrypted_backup(
                    request.path.clone(),
                    &mut request.key_pass,
                    request.force,
                );
                match result {
                    Ok(()) => respond("Encrypted backup created.", &mut stream).await,
                    Err(error) => {
                        respond_domain_error_with_context(
                            &error,
                            &format!("Backup failed: {error}"),
                            &mut stream,
                        )
                        .await
                    }
                }
            } else {
                respond_failure("Vault unavailable.", &mut stream).await;
            }
            request.zeroize();
        }
        ServerCommand::RestoreBackup(mut request) => {
            if !server_info.locked {
                respond_failure(
                    "Lock the current vault before restoring a backup.",
                    &mut stream,
                )
                .await;
            } else {
                match restore_encrypted_backup(
                    &request.path,
                    &mut request.key_pass,
                    request.force,
                ) {
                    Ok(filename) => {
                        respond(
                            &format!(
                                "Encrypted backup restored as {filename}. Unlock it with the backup password/key."
                            ),
                            &mut stream
)
                        .await
                    }
                    Err(error) => {
                        respond_domain_error_with_context(&error, &format!("Backup restore failed: {error}"), &mut stream)
                        .await
                    }
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
                    Ok(report) => respond(&report.to_string(), &mut stream).await,
                    Err(error) => {
                        respond_domain_error_with_context(
                            &error,
                            &format!("Import preview failed: {error}"),
                            &mut stream,
                        )
                        .await
                    }
                }
                preview_vault.zeroize();
                return;
            }
            if !new {
                if server_info.locked {
                    respond_failure("Vault locked.", &mut stream).await;
                    return;
                }
                match vlt.import_with_options(
                    path,
                    conflicts,
                    preview,
                    password_history_limit,
                    &mut server_info,
                ) {
                    Ok(report) => respond(&report.to_string(), &mut stream).await,
                    Err(error) => {
                        respond_domain_error_with_context(
                            &error,
                            &format!("Import failed: {error}"),
                            &mut stream,
                        )
                        .await
                    }
                }
                return;
            }

            lock_generation.fetch_add(1, Ordering::AcqRel);
            if !server_info.locked
                && let Err(error) = lock_vlt(&mut vlt, &mut server_info)
            {
                respond_domain_error_with_context(
                    &error,
                    &format!("Import failed while locking vault: {error}"),
                    &mut stream,
                )
                .await;
                return;
            }
            if let Some(mut old) = server_info.keypass.take() {
                old.zeroize();
            }
            let Some(key_pass) = key_pass else {
                respond_failure(
                    "A password or key is required for a new imported vault.",
                    &mut stream,
                )
                .await;
                return;
            };
            *server_info = ServerInfo {
                locked: true,
                keypass: Some(key_pass),
            };
            let error = create_vault(&mut vlt, &mut server_info, false).err();

            match error {
                Some(e) => {
                    respond_domain_error_with_context(
                        &e,
                        &format!("Import failed: {}", e),
                        &mut stream,
                    )
                    .await
                }
                None => match vlt.import_with_options(
                    path,
                    conflicts,
                    preview,
                    password_history_limit,
                    &mut server_info,
                ) {
                    Ok(report) => {
                        vlt.zeroize();
                        server_info.zeroize();
                        respond(&report.to_string(), &mut stream).await
                    }
                    Err(e) => {
                        let _ = lock_vlt(&mut vlt, &mut server_info);
                        respond_domain_error_with_context(
                            &e,
                            &format!("Import failed: {e}"),
                            &mut stream,
                        )
                        .await;
                    }
                },
            }
        }
    }
}
