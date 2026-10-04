use super::*;

impl Vault {
    pub fn add_entry(
        &mut self,
        info: PasswordEntry,
        key_pass: &mut VaultCredentials,
    ) -> Result<bool, VaultError> {
        self.add_typed_entry(
            TypedEntry {
                entry: info,
                kind: ItemKind::Login,
                additional_urls: Vec::new(),
                custom_fields: Vec::new(),
            },
            key_pass,
        )
    }

    pub fn add_typed_entry(
        &mut self,
        request: TypedEntry,
        key_pass: &mut VaultCredentials,
    ) -> Result<bool, VaultError> {
        let TypedEntry {
            entry: info,
            kind,
            additional_urls,
            custom_fields,
        } = request;
        let mut info = Zeroizing::new(info);
        let mut custom_fields = Zeroizing::new(custom_fields);
        info.url = info
            .url
            .take()
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty());
        let mut normalized_urls = Vec::new();
        for url in additional_urls {
            let url = url.trim();
            if !url.is_empty()
                && info.url.as_deref() != Some(url)
                && !normalized_urls.iter().any(|saved| saved == url)
            {
                normalized_urls.push(url.to_string());
            }
        }
        if self
            .entries
            .iter()
            .any(|entry| entry.name == info.name && entry.username == info.username)
        {
            return Ok(false);
        }

        let id = self.next_entry_id()?;
        self.transaction(TransactionScope::Entry(id), key_pass, |vault| {
            let id = vault.allocate_entry_id()?;
            let now = chrono::Local::now().to_string();
            let password_changed = (!info.password.is_empty()).then(|| now.clone());
            vault.entries.push(VaultEntry {
                id,
                name: std::mem::take(&mut info.name),
                username: info.username.take(),
                password: std::mem::take(&mut info.password),
                url: info.url.take(),
                notes: info.notes.take(),
                created: now.clone(),
                modified: now,
            });
            let metadata_added =
                kind != ItemKind::Login || !normalized_urls.is_empty() || !custom_fields.is_empty();
            if metadata_added {
                vault.recovery.entry_metadata.push(EntryMetadata {
                    entry_id: id,
                    kind,
                    additional_urls: normalized_urls,
                    password_changed,
                    custom_fields: std::mem::take(&mut *custom_fields),
                });
            }
            Ok((true, true))
        })
    }

    pub fn delete_entry(
        &mut self,
        target: Target,
        key_pass: &mut VaultCredentials,
    ) -> Result<bool, VaultError> {
        let Some(index) = self.entry_index(&target) else {
            return Ok(false);
        };
        let id = self.entries[index].id;
        self.transaction(TransactionScope::Entry(id), key_pass, |vault| {
            let entry = vault.entries.remove(index);
            let history = vault.take_history_records(id);
            vault.recovery.trash.push(TrashedEntry {
                entry,
                history,
                deleted: chrono::Local::now().to_string(),
            });
            Ok((true, true))
        })
    }

    pub fn update_entry_with_limit(
        &mut self,
        change: EntryUpdate,
        key_pass: &mut VaultCredentials,
        password_history_limit: usize,
    ) -> Result<bool, VaultError> {
        self.update_typed_entry_with_limit(
            TypedUpdate {
                entry: change,
                kind: None,
                add_url: Vec::new(),
                remove_url: Vec::new(),
                clear_urls: false,
                set_fields: Vec::new(),
                remove_fields: Vec::new(),
                clear_fields: false,
            },
            key_pass,
            password_history_limit,
        )
    }

    pub fn update_typed_entry_with_limit(
        &mut self,
        change: TypedUpdate,
        key_pass: &mut VaultCredentials,
        password_history_limit: usize,
    ) -> Result<bool, VaultError> {
        let TypedUpdate {
            entry: change,
            kind,
            add_url,
            remove_url,
            clear_urls,
            set_fields,
            remove_fields,
            clear_fields,
        } = change;
        let EntryUpdate {
            target,
            update,
            password,
        } = change;
        let mut password = Zeroizing::new(password);
        let set_fields = Zeroizing::new(set_fields);
        let index = self.entry_index(&target);
        let Some(index) = index else {
            return Ok(false);
        };

        let id = self.entries[index].id;
        self.transaction(TransactionScope::Entry(id), key_pass, |vault| {
            let original = Zeroizing::new(vault.entries[index].clone());
            let password_changed = password
                .as_ref()
                .is_some_and(|new_password| *new_password != original.password);
            let old_password = password_changed.then(|| original.password.clone());
            let metadata_modified = vault.apply_metadata_update(
                original.id,
                MetadataUpdate {
                    kind,
                    add_urls: &add_url,
                    remove_urls: &remove_url,
                    clear_urls,
                    primary_url: update.url.as_deref(),
                    password_changed,
                    set_fields: &set_fields,
                    remove_fields: &remove_fields,
                    clear_fields,
                },
            );
            let mut modified = apply_update(&mut vault.entries[index], update, password.take());
            if clear_urls {
                modified |= vault.entries[index].url.take().is_some();
            } else if vault.entries[index]
                .url
                .as_ref()
                .is_some_and(|url| remove_url.iter().any(|removed| removed == url))
            {
                vault.entries[index].url = None;
                modified = true;
            }
            if modified || metadata_modified {
                vault.entries[index].modified = chrono::Local::now().to_string();
            }
            if let Some(old_password) = old_password {
                vault.push_password_history_with_limit(
                    original.id,
                    old_password,
                    password_history_limit,
                );
            }
            Ok((modified || metadata_modified, modified || metadata_modified))
        })
    }

    pub(super) fn apply_metadata_update(
        &mut self,
        entry_id: usize,
        update: MetadataUpdate<'_>,
    ) -> bool {
        let requested = update.kind.is_some()
            || !update.add_urls.is_empty()
            || !update.remove_urls.is_empty()
            || update.clear_urls
            || update.password_changed
            || !update.set_fields.is_empty()
            || !update.remove_fields.is_empty()
            || update.clear_fields;
        if !requested {
            return false;
        }
        let index = if let Some(index) = self
            .recovery
            .entry_metadata
            .iter()
            .position(|record| record.entry_id == entry_id)
        {
            index
        } else {
            self.recovery.entry_metadata.push(EntryMetadata {
                entry_id,
                ..EntryMetadata::default()
            });
            self.recovery.entry_metadata.len() - 1
        };
        let record = &mut self.recovery.entry_metadata[index];
        let before = Zeroizing::new(record.clone());
        if let Some(kind) = update.kind {
            record.kind = kind;
        }
        if update.clear_urls {
            record.additional_urls.clear();
        }
        record
            .additional_urls
            .retain(|url| !update.remove_urls.iter().any(|removed| removed == url));
        if let Some(primary) = update.primary_url {
            record.additional_urls.retain(|url| url != primary);
        }
        for url in update.add_urls {
            let url = url.trim();
            if !url.is_empty() && !record.additional_urls.iter().any(|saved| saved == url) {
                record.additional_urls.push(url.to_string());
            }
        }
        if update.password_changed {
            record.password_changed = Some(chrono::Local::now().to_string());
        }
        if update.clear_fields {
            record.custom_fields.zeroize();
            record.custom_fields.clear();
        }
        for name in update.remove_fields {
            let name = name.trim();
            let mut retained = Vec::with_capacity(record.custom_fields.len());
            for mut field in std::mem::take(&mut record.custom_fields) {
                if field.name.eq_ignore_ascii_case(name) {
                    field.zeroize();
                } else {
                    retained.push(field);
                }
            }
            record.custom_fields = retained;
        }
        for field in update.set_fields {
            if let Some(existing) = record
                .custom_fields
                .iter_mut()
                .find(|existing| existing.name.eq_ignore_ascii_case(&field.name))
            {
                existing.zeroize();
                *existing = field.clone();
            } else {
                record.custom_fields.push(field.clone());
            }
        }
        *record != *before
    }
}

pub(super) fn apply_update(
    entry: &mut VaultEntry,
    update: EntryChanges,
    password: Option<String>,
) -> bool {
    let mut modified = false;
    if let Some(name) = update.name {
        entry.name = name;
        modified = true;
    }
    if let Some(notes) = update.notes {
        entry.notes.zeroize();
        entry.notes = (!notes.is_empty()).then_some(notes);
        modified = true;
    }
    if let Some(password) = password {
        entry.password.zeroize();
        entry.password = password;
        modified = true;
    }
    if let Some(url) = update.url {
        entry.url = Some(url);
        modified = true;
    }
    if let Some(username) = update.username {
        entry.username = (!username.is_empty()).then_some(username);
        modified = true;
    }
    if modified {
        entry.modified = chrono::Local::now().to_string();
    }
    modified
}
