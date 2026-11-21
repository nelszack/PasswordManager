use super::*;
impl Vault {
    pub(super) fn summary(&self, item: &Item) -> ItemSummary {
        ItemSummary {
            id: item.entry.id,
            revision: item.revision,
            name: item.entry.name.clone(),
            username: item.entry.username.clone(),
            kind: item.metadata.kind,
            urls: item.urls().map(str::to_owned).collect(),
            has_totp: item.authenticator.is_some(),
            has_duo: item.duo.is_some(),
            tags: item.metadata.tags.clone(),
            favorite: item.metadata.favorite,
        }
    }
    pub fn management_list(&self, filter: SearchFilter) -> Result<ItemPage, VaultError> {
        let items = self.apply_list_options(self.search_items(&filter), &filter.list);
        let total = items.len();
        let items = items.into_iter().map(|item| self.summary(item)).collect();
        Ok(ItemPage { items, total })
    }
    pub fn management_item(&self, id: usize, reveal: bool) -> Result<ItemDetail, VaultError> {
        let item = self
            .item(id)
            .filter(|i| i.active())
            .ok_or_else(|| VaultError::NotFound(format!("no item has ID {id}")))?;
        let e = &item.entry;
        Ok(ItemDetail {
            id,
            revision: item.revision,
            name: e.name.clone(),
            username: e.username.clone(),
            kind: item.metadata.kind,
            urls: item.urls().map(str::to_owned).collect(),
            notes: e.notes.clone(),
            password: reveal.then(|| e.password.clone()),
            has_secret: !e.password.is_empty(),
            fields: item
                .metadata
                .custom_fields
                .iter()
                .filter(|f| !item_rules::is_reserved_field(&f.name))
                .map(|f| ItemField {
                    name: f.name.clone(),
                    secret: f.secret,
                    value: (!f.secret || reveal).then(|| f.value.clone()),
                })
                .collect(),
            has_totp: item.authenticator.is_some(),
            has_duo: item.duo.is_some(),
            otp_mode: item.authenticator.as_ref().map(|a| match a.state {
                AuthenticatorState::Totp(_) => crate::types::OtpMode::Totp,
                AuthenticatorState::Hotp { .. } => crate::types::OtpMode::Hotp,
            }),
            is_passkey: item.is_passkey(),
            tags: item.metadata.tags.clone(),
            favorite: item.metadata.favorite,
            attachments: item.attachments.iter().map(Attachment::info).collect(),
            created: e.created.to_string(),
            modified: e.modified.to_string(),
        })
    }
    pub fn target_detail(&self, target: &Target, reveal: bool) -> Result<ItemDetail, VaultError> {
        let id = self.require_target(target)?.entry.id;
        self.management_item(id, reveal)
    }
}

impl Vault {
    pub(crate) fn mutation_changes(&self) -> Option<pm_contracts::vault::ItemChanges> {
        let (base_revision, revision, ids) = self.metadata.changes.as_ref()?;
        let mut changes = pm_contracts::vault::ItemChanges {
            base_revision: *base_revision,
            revision: *revision,
            items: Vec::new(),
            removed: Vec::new(),
        };
        // Include the envelope/removal IDs and each URL's MessagePack prefix,
        // not just string contents: many short URLs can otherwise exceed the cap.
        let mut bytes = 128usize.saturating_add(ids.len().saturating_mul(16));
        for &id in ids {
            let item = self.item(id);
            if let Some(item) = item {
                bytes = bytes
                    .saturating_add(item.entry.name.len())
                    .saturating_add(item.entry.username.as_ref().map_or(0, String::len))
                    .saturating_add(
                        item.urls()
                            .map(|url| url.len().saturating_add(8))
                            .sum::<usize>(),
                    )
                    .saturating_add(512);
                if bytes > 64 * 1024 {
                    return None;
                }
            }
            match item.filter(|item| item.active()) {
                Some(item) => changes.items.push(self.summary(item)),
                None => changes.removed.push(id),
            }
        }
        Some(changes)
    }
}
