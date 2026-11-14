use super::*;

pub(super) enum TransactionScope {
    Entry(usize),
    Items(HashSet<ItemId>),
}

impl Vault {
    /// Stage only affected complete items. The live aggregate is untouched until
    /// atomic replacement commits, so errors and panics need no rollback engine.
    pub(super) fn transaction<T>(
        &mut self,
        scope: TransactionScope,
        key: &mut VaultCredentials,
        mutate: impl FnOnce(&mut Vault) -> Result<(bool, T), VaultError>,
    ) -> Result<T, VaultError> {
        let selected = match scope {
            TransactionScope::Entry(id) => HashSet::from([ItemId::from_public(id)?]),
            TransactionScope::Items(ids) => ids,
        };
        let mut staged = Vault {
            data: VaultData {
                vault_id: self.data.vault_id,
                items: selected
                    .iter()
                    .filter_map(|id| self.data.items.get(id).map(|item| (*id, item.clone())))
                    .collect(),
                next_item_id: self.data.next_item_id,
                revision: self.data.revision,
            },
            store: VaultStore::Memory,
            metadata: self.metadata.clone(),
        };
        let (changed, result) = mutate(&mut staged)?;
        if !changed {
            return Ok(result);
        }
        staged.data.revision = self
            .data
            .revision
            .checked_add(1)
            .filter(|value| *value <= MAX_ITEM_ID)
            .ok_or_else(|| VaultError::Conflict("vault revision exhausted".into()))?;
        for (id, item) in &mut staged.data.items {
            let old = self.data.items.get(id);
            if let Some(old) = old {
                if old.entry.password == item.entry.password {
                    item.strength = old.strength.clone();
                }
                if old.entry.url == item.entry.url
                    && old.metadata.additional_urls == item.metadata.additional_urls
                {
                    item.sites = old.sites.clone();
                }
            }
            if old != Some(item) {
                item.revision = old.map_or(Ok(1), |i| {
                    i.revision
                        .checked_add(1)
                        .filter(|value| *value <= MAX_ITEM_ID)
                        .ok_or_else(|| VaultError::Conflict("item revision exhausted".into()))
                })?;
            }
        }
        let write = self
            .store
            .commit_overlay(&self.data, &staged.data, &selected, key);
        if write
            .as_ref()
            .map_or_else(|error| error.committed(), |_| true)
        {
            let mut ids = std::collections::BTreeSet::new();
            for id in selected.iter().chain(staged.data.items.keys()) {
                ids.insert(*id);
                if ids.len() > 256 {
                    break;
                }
            }
            self.metadata.changes = (ids.len() <= 256).then(|| {
                (
                    self.data.revision,
                    staged.data.revision,
                    ids.into_iter()
                        .map(|id| id.public().expect("validated item ID"))
                        .collect(),
                )
            });
            for id in selected {
                self.data.items.remove(&id);
            }
            self.data.items.append(&mut staged.data.items);
            self.data.next_item_id = staged.data.next_item_id;
            self.data.revision = staged.data.revision;
        }
        write?;
        Ok(result)
    }
    /// Apply related edits atomically with one encryption and durable replacement.
    /// Every target is resolved against the initial snapshot; errors commit nothing.
    pub fn update_many(
        &mut self,
        changes: Vec<TypedUpdate>,
        key: &mut VaultCredentials,
        history_limit: usize,
    ) -> Result<bool, VaultError> {
        let mut selected = HashSet::new();
        let mut resolved = Vec::with_capacity(changes.len());
        for change in changes {
            let id = self
                .entry_id(&change.entry.target)
                .ok_or_else(|| VaultError::NotFound("batch target not found".into()))?;
            selected.insert(ItemId::from_public(id)?);
            resolved.push((id, change));
        }
        self.transaction(TransactionScope::Items(selected), key, |staged| {
            let mut changed = false;
            for (id, change) in resolved {
                changed |= staged.apply_typed_update(id, change, history_limit);
            }
            Ok((changed, changed))
        })
    }
    pub(super) fn next_entry_id(&self) -> Result<usize, VaultError> {
        ItemId::try_from(self.data.next_item_id)
            .map_err(|e| VaultError::Validation(e.into()))?
            .public()
    }
    pub(super) fn allocate_entry_id(&mut self) -> Result<usize, VaultError> {
        let id = self.next_entry_id()?;
        self.data.next_item_id = self
            .data
            .next_item_id
            .checked_add(1)
            .ok_or_else(|| VaultError::InvalidInput("item ID space exhausted".into()))?;
        Ok(id)
    }
}
