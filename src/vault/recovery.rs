use super::*;
impl Vault {
    pub(super) fn push_password_history_with_limit(
        &mut self,
        id: usize,
        password: SecretString,
        limit: usize,
    ) {
        let item = self.item_mut(id).expect("selected item");
        if limit > 0 {
            item.history.push(PasswordRevision {
                password,
                changed: Timestamp::now(),
            });
        }
        let excess = item.history.len().saturating_sub(limit);
        item.history.drain(..excess);
    }
    pub fn view_password_history(&self, target: Target) -> Result<Vec<&str>, VaultError> {
        let id = self
            .entry_id(&target)
            .ok_or_else(|| VaultError::NotFound("entry not found".into()))?;
        Ok(self
            .item(id)
            .unwrap()
            .history
            .iter()
            .rev()
            .map(|r| r.changed.as_str())
            .collect())
    }
    pub fn restore_password(
        &mut self,
        target: Target,
        revision: usize,
        key: &mut VaultCredentials,
    ) -> Result<bool, VaultError> {
        let Some(id) = self.entry_id(&target) else {
            return Ok(false);
        };
        let index = self
            .item(id)
            .unwrap()
            .history
            .len()
            .checked_sub(revision)
            .filter(|_| revision > 0)
            .ok_or_else(|| VaultError::InvalidInput("invalid password-history revision".into()))?;
        self.transaction(TransactionScope::Entry(id), key, |vault| {
            let item = vault.item_mut(id).unwrap();
            let mut selected = item.history.remove(index);
            std::mem::swap(&mut item.entry.password, &mut selected.password);
            selected.changed = Timestamp::now();
            item.history.push(selected);
            item.entry.modified = Timestamp::now();
            item.metadata.password_changed = Some(Timestamp::now());
            Ok((true, true))
        })
    }
    pub fn view_trash(&self) -> Vec<TrashView<'_>> {
        self.data
            .items
            .values()
            .filter_map(|item| match &item.lifecycle {
                Lifecycle::Trashed { deleted_at } => Some(TrashView {
                    entry: self.view(item),
                    deleted: deleted_at.as_str(),
                }),
                _ => None,
            })
            .collect()
    }
    // Trash selection uses the stable item identity, never a shifting list index.
    pub fn restore_trashed(
        &mut self,
        id: usize,
        key: &mut VaultCredentials,
    ) -> Result<bool, VaultError> {
        let Some(item) = self.item(id).filter(|i| !i.active()) else {
            return Ok(false);
        };
        if self
            .active_entries()
            .any(|e| e.name == item.entry.name && e.username == item.entry.username)
        {
            return Err(VaultError::Conflict(
                "active item has the same name and username".into(),
            ));
        }
        self.transaction(TransactionScope::Entry(id), key, |v| {
            let item = v.item_mut(id).unwrap();
            item.lifecycle = Lifecycle::Active;
            item.entry.modified = Timestamp::now();
            Ok((true, true))
        })
    }
    pub fn purge_trash(
        &mut self,
        id: Option<usize>,
        key: &mut VaultCredentials,
    ) -> Result<bool, VaultError> {
        let ids: Vec<_> = self
            .data
            .items
            .iter()
            .filter(|(_, item)| !item.active() && id.is_none_or(|id| item.entry.id == id))
            .map(|(id, _)| *id)
            .collect();
        if ids.is_empty() {
            return Ok(false);
        }
        self.transaction(
            TransactionScope::Items(ids.iter().copied().collect()),
            key,
            |v| {
                for id in ids {
                    v.data.items.remove(&id);
                }
                Ok((true, true))
            },
        )
    }
    pub fn purge_expired_trash(
        &mut self,
        days: u64,
        key: &mut VaultCredentials,
    ) -> Result<usize, VaultError> {
        if days == 0 {
            return Ok(0);
        };
        let Some(cutoff) = i64::try_from(days)
            .ok()
            .and_then(chrono::Duration::try_days)
            .and_then(|d| chrono::Utc::now().checked_sub_signed(d))
        else {
            return Ok(0);
        };
        let ids: Vec<_> = self
            .data
            .items
            .iter()
            .filter_map(|(id, item)| match &item.lifecycle {
                Lifecycle::Trashed { deleted_at }
                    if parse_entry_timestamp(deleted_at).is_some_and(|t| t <= cutoff) =>
                {
                    Some(*id)
                }
                _ => None,
            })
            .collect();
        if ids.is_empty() {
            return Ok(0);
        };
        self.transaction(
            TransactionScope::Items(ids.iter().copied().collect()),
            key,
            |v| {
                let count = ids.len();
                for id in ids {
                    v.data.items.remove(&id);
                }
                Ok((true, count))
            },
        )
    }
}
