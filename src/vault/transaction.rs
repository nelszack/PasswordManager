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
