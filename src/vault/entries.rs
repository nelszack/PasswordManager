use super::*;

impl Vault {
    pub fn add_entry(
        &mut self,
        info: PasswordEntry,
        key: &mut VaultCredentials,
    ) -> Result<bool, VaultError> {
        self.add_typed_entry(
            TypedEntry {
                entry: info,
                kind: ItemKind::Login,
                additional_urls: vec![],
                custom_fields: vec![],
            },
            key,
        )
    }
    pub fn add_typed_entry(
        &mut self,
        request: TypedEntry,
        key: &mut VaultCredentials,
    ) -> Result<bool, VaultError> {
        let TypedEntry {
            entry: info,
            kind,
            additional_urls,
            custom_fields,
        } = request;
        let mut info = Zeroizing::new(info);
        if self
            .active_entries()
            .any(|entry| entry.name == info.name && entry.username == info.username)
        {
            return Ok(false);
        }
        info.url = info
            .url
            .take()
            .map(|u| u.trim().to_owned())
            .filter(|u| !u.is_empty());
        let mut urls = Vec::new();
        for url in additional_urls {
            let url = url.trim();
            if !url.is_empty() && info.url.as_deref() != Some(url) && !urls.iter().any(|s| s == url)
            {
                urls.push(url.to_owned());
            }
        }
        let id = self.next_entry_id()?;
        self.transaction(TransactionScope::Entry(id), key, |vault| {
            let id = vault.allocate_entry_id()?;
            let now = Timestamp::now();
            let metadata = EntryMetadata {
                kind,
                additional_urls: urls,
                password_changed: (!info.password.is_empty()).then(|| now.clone()),
                custom_fields,
            };
            let entry = VaultEntry {
                id,
                name: std::mem::take(&mut info.name),
                username: info.username.take(),
                password: std::mem::take(&mut info.password),
                url: info.url.take(),
                notes: info.notes.take(),
                created: now.clone(),
                modified: now,
            };
            vault
                .data
                .items
                .insert(ItemId::from_public(id)?, Item::new(entry, metadata));
            Ok((true, true))
        })
    }
    pub fn delete_entry(
        &mut self,
        target: Target,
        key: &mut VaultCredentials,
    ) -> Result<bool, VaultError> {
        let Some(id) = self.entry_id(&target) else {
            return Ok(false);
        };
        self.transaction(TransactionScope::Entry(id), key, |v| {
            let item = v.item_mut(id).expect("selected item");
            item.lifecycle = Lifecycle::Trashed {
                deleted_at: Timestamp::now(),
            };
            Ok((true, true))
        })
    }
    pub fn update_entry_with_limit(
        &mut self,
        entry: EntryUpdate,
        key: &mut VaultCredentials,
        limit: usize,
    ) -> Result<bool, VaultError> {
        self.update_typed_entry_with_limit(
            TypedUpdate {
                entry,
                kind: None,
                add_url: vec![],
                remove_url: vec![],
                clear_urls: false,
                set_fields: vec![],
                remove_fields: vec![],
                clear_fields: false,
            },
            key,
            limit,
        )
    }
    pub fn update_typed_entry_with_limit(
        &mut self,
        change: TypedUpdate,
        key: &mut VaultCredentials,
        limit: usize,
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
        let mut change = Zeroizing::new(change);
        let Some(id) = self.entry_id(&change.target) else {
            return Ok(false);
        };
        self.transaction(TransactionScope::Entry(id), key, |vault| {
            let changed_password = change
                .password
                .as_ref()
                .is_some_and(|p| p.as_str() != vault.item(id).unwrap().entry.password.as_str());
            if changed_password {
                let old = vault.item(id).unwrap().entry.password.clone();
                vault.push_password_history_with_limit(id, old, limit);
            }
            let entry = &mut vault.item_mut(id).unwrap().entry;
            // A full replacement clears the previous primary before applying
            // the new one. A clear without a replacement still removes it.
            let mut changed = clear_urls && entry.url.take().is_some();
            let update = std::mem::take(&mut change.update);
            changed |= apply_update(entry, update, change.password.take());
            if !clear_urls && entry.url.as_ref().is_some_and(|u| remove_url.contains(u)) {
                entry.url = None;
                changed = true;
            }
            let primary_url = entry.url.clone();
            let metadata_changed = vault.apply_metadata_update(
                id,
                MetadataUpdate {
                    kind,
                    add_urls: &add_url,
                    remove_urls: &remove_url,
                    clear_urls,
                    primary_url: primary_url.as_deref(),
                    password_changed: changed_password,
                    set_fields: &set_fields,
                    remove_fields: &remove_fields,
                    clear_fields,
                },
            );
            if changed || metadata_changed {
                vault.item_mut(id).unwrap().entry.modified = Timestamp::now();
            }
            Ok((changed || metadata_changed, changed || metadata_changed))
        })
    }
    fn apply_metadata_update(&mut self, id: usize, update: MetadataUpdate<'_>) -> bool {
        let Some(item) = self.item_mut(id) else {
            return false;
        };
        let record = &mut item.metadata;
        let before = record.clone();
        if let Some(kind) = update.kind {
            record.kind = kind;
        }
        if update.clear_urls {
            record.additional_urls.clear();
        }
        let primary_url = update.primary_url.map(str::trim);
        record
            .additional_urls
            .retain(|u| !update.remove_urls.contains(u) && primary_url != Some(u.as_str()));
        for url in update.add_urls {
            let url = url.trim();
            if !url.is_empty()
                && primary_url != Some(url)
                && !record.additional_urls.iter().any(|saved| saved == url)
            {
                record.additional_urls.push(url.into());
            }
        }
        if update.password_changed {
            record.password_changed = Some(Timestamp::now());
        }
        if update.clear_fields {
            record.custom_fields.clear();
        }
        record.custom_fields.retain(|f| {
            !update
                .remove_fields
                .iter()
                .any(|n| f.name.eq_ignore_ascii_case(n.trim()))
        });
        for field in update.set_fields {
            if let Some(old) = record
                .custom_fields
                .iter_mut()
                .find(|f| f.name.eq_ignore_ascii_case(&field.name))
            {
                *old = field.clone();
            } else {
                record.custom_fields.push(field.clone());
            }
        }
        *record != before
    }
}
pub(super) fn apply_update(
    entry: &mut VaultEntry,
    mut update: EntryChanges,
    password: Option<SecretString>,
) -> bool {
    let mut changed = false;
    if let Some(value) = update.name.take()
        && entry.name != value
    {
        entry.name = value;
        changed = true;
    }
    if let Some(value) = update.username.take() {
        let value = (!value.is_empty()).then_some(value);
        if entry.username != value {
            entry.username = value;
            changed = true;
        }
    }
    if let Some(value) = update.url.take()
        && entry.url.as_ref() != Some(&value)
    {
        entry.url = Some(value);
        changed = true;
    }
    if let Some(value) = update.notes.take() {
        let value = (!value.is_empty()).then_some(value);
        if entry.notes != value {
            entry.notes = value;
            changed = true;
        }
    }
    if let Some(value) = password
        && entry.password != value
    {
        entry.password = value;
        changed = true;
    }
    if changed {
        entry.modified = Timestamp::now();
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Vault, VaultCredentials, usize) {
        let mut vault = Vault::memory();
        let mut credentials = VaultCredentials::default();
        vault
            .add_typed_entry(
                TypedEntry {
                    entry: PasswordEntry {
                        name: "URL fixture".into(),
                        username: None,
                        password: "secret".into(),
                        url: Some("https://primary.test".into()),
                        notes: None,
                        copy: false,
                    },
                    kind: ItemKind::Login,
                    additional_urls: vec!["https://additional.test".into()],
                    custom_fields: vec![],
                },
                &mut credentials,
            )
            .unwrap();
        let id = vault.entry_id(&Target::Name("URL fixture".into())).unwrap();
        (vault, credentials, id)
    }

    fn change(id: usize) -> TypedUpdate {
        TypedUpdate {
            entry: EntryUpdate {
                target: Target::Id(id),
                update: EntryChanges::default(),
                password: None,
            },
            kind: None,
            add_url: vec![],
            remove_url: vec![],
            clear_urls: false,
            set_fields: vec![],
            remove_fields: vec![],
            clear_fields: false,
        }
    }

    #[test]
    fn full_url_replacement_keeps_primary_and_clearing_still_removes_all_urls() {
        let (mut vault, mut credentials, id) = fixture();
        let mut replacement = change(id);
        replacement.clear_urls = true;
        replacement.entry.update.url = Some("https://new.test".into());
        replacement.add_url = vec!["https://new.test".into(), "https://extra.test".into()];
        assert!(
            vault
                .update_typed_entry_with_limit(replacement, &mut credentials, 10)
                .unwrap()
        );
        assert_eq!(
            vault.item(id).unwrap().entry.url.as_deref(),
            Some("https://new.test")
        );
        assert_eq!(
            vault.metadata(id).unwrap().additional_urls,
            vec!["https://extra.test"]
        );
        assert_eq!(
            vault.management_item(id, false).unwrap().urls,
            vec!["https://new.test", "https://extra.test"]
        );

        let mut clear = change(id);
        clear.clear_urls = true;
        assert!(
            vault
                .update_typed_entry_with_limit(clear, &mut credentials, 10)
                .unwrap()
        );
        assert!(vault.item(id).unwrap().entry.url.is_none());
        assert!(vault.metadata(id).unwrap().additional_urls.is_empty());
    }

    #[test]
    fn additional_urls_never_duplicate_the_existing_or_replaced_primary() {
        let (mut vault, mut credentials, id) = fixture();
        let mut duplicate = change(id);
        duplicate.add_url = vec![" https://primary.test ".into()];
        assert!(
            !vault
                .update_typed_entry_with_limit(duplicate, &mut credentials, 10)
                .unwrap()
        );
        assert_eq!(
            vault.metadata(id).unwrap().additional_urls,
            vec!["https://additional.test"]
        );

        let mut promote = change(id);
        promote.entry.update.url = Some("https://additional.test".into());
        promote.add_url = vec!["https://additional.test".into()];
        assert!(
            vault
                .update_typed_entry_with_limit(promote, &mut credentials, 10)
                .unwrap()
        );
        assert_eq!(
            vault.item(id).unwrap().entry.url.as_deref(),
            Some("https://additional.test")
        );
        assert!(vault.metadata(id).unwrap().additional_urls.is_empty());
    }
}
