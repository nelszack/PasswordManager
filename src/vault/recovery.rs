use super::*;

impl Vault {
    pub(super) fn push_password_history_with_limit(
        &mut self,
        entry_id: usize,
        mut password: String,
        limit: usize,
    ) {
        if limit == 0 {
            password.zeroize();
            return;
        }
        self.recovery.password_history.push(PasswordRevision {
            entry_id,
            password,
            changed: chrono::Local::now().to_string(),
        });
        let mut count = self
            .recovery
            .password_history
            .iter()
            .filter(|revision| revision.entry_id == entry_id)
            .count();
        while count > limit {
            let Some(index) = self
                .recovery
                .password_history
                .iter()
                .position(|revision| revision.entry_id == entry_id)
            else {
                break;
            };
            let mut removed = self.recovery.password_history.remove(index);
            removed.zeroize();
            count -= 1;
        }
    }

    pub fn view_password_history(&self, target: Target) -> Result<Vec<&str>, VaultError> {
        let index = self
            .entry_index(&target)
            .ok_or_else(|| VaultError::NotFound("Entry not found.".into()))?;
        Ok(self
            .recovery
            .password_history
            .iter()
            .filter(|r| r.entry_id == self.entries[index].id)
            .rev()
            .map(|r| r.changed.as_str())
            .collect())
    }

    pub fn restore_password(
        &mut self,
        target: Target,
        revision: usize,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, VaultError> {
        let Some(entry_index) = self.entry_index(&target) else {
            return Ok(false);
        };
        let entry_id = self.entries[entry_index].id;
        let history_indices: Vec<_> = self
            .recovery
            .password_history
            .iter()
            .enumerate()
            .filter_map(|(index, item)| (item.entry_id == entry_id).then_some(index))
            .collect();
        let Some(history_index) = revision
            .checked_sub(1)
            .and_then(|offset| history_indices.iter().rev().nth(offset))
            .copied()
        else {
            return Err(("invalid password-history revision".to_string()).into());
        };
        self.transaction(TransactionScope::Entry(entry_id), key_pass, |vault| {
            let mut selected = vault.recovery.password_history.remove(history_index);
            let current =
                std::mem::replace(&mut vault.entries[entry_index].password, selected.password);
            selected.password = current;
            selected.changed = chrono::Local::now().to_string();
            vault.recovery.password_history.push(selected);
            vault.entries[entry_index].modified = chrono::Local::now().to_string();
            vault.apply_metadata_update(
                entry_id,
                MetadataUpdate {
                    kind: None,
                    add_urls: &[],
                    remove_urls: &[],
                    clear_urls: false,
                    primary_url: None,
                    password_changed: true,
                    set_fields: &[],
                    remove_fields: &[],
                    clear_fields: false,
                },
            );
            Ok((true, true))
        })
    }

    pub fn view_trash(&self) -> Vec<TrashView<'_>> {
        self.recovery
            .trash
            .iter()
            .map(|item| TrashView {
                entry: EntryView {
                    entry: &item.entry,
                    metadata: self.metadata(item.entry.id),
                    has_totp: !self.totp_marker(item.entry.id).is_empty(),
                    urls: self.all_urls(&item.entry).collect(),
                },
                deleted: &item.deleted,
            })
            .collect()
    }

    pub fn restore_trashed(
        &mut self,
        trash_id: usize,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, VaultError> {
        let Some(index) = trash_id
            .checked_sub(1)
            .filter(|i| *i < self.recovery.trash.len())
        else {
            return Ok(false);
        };
        let entry = &self.recovery.trash[index].entry;
        if self
            .entries
            .iter()
            .any(|e| e.name == entry.name && e.username == entry.username)
        {
            return Err(VaultError::Conflict(
                "an active entry with the same name and username already exists".to_string(),
            ));
        }
        let id = entry.id;
        if self.entries.iter().any(|e| e.id == id) {
            return Err(VaultError::Conflict(
                "an active entry already uses this stable ID".to_string(),
            ));
        }
        self.transaction(TransactionScope::Entry(id), key_pass, |vault| {
            let mut trashed = Zeroizing::new(vault.recovery.trash.remove(index));
            for revision in &mut trashed.history {
                revision.entry_id = id;
            }
            vault.recovery.password_history.append(&mut trashed.history);
            vault.entries.push(std::mem::take(&mut trashed.entry));
            Ok((true, true))
        })
    }

    pub fn purge_trash(
        &mut self,
        trash_id: Option<usize>,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, VaultError> {
        let indexes = if let Some(id) = trash_id {
            let Some(index) = id
                .checked_sub(1)
                .filter(|index| *index < self.recovery.trash.len())
            else {
                return Ok(false);
            };
            vec![index]
        } else {
            if self.recovery.trash.is_empty() {
                return Ok(false);
            }
            (0..self.recovery.trash.len()).collect()
        };
        let ids = indexes
            .into_iter()
            .map(|i| self.recovery.trash[i].entry.id)
            .collect();
        self.purge_ids(ids, key_pass).map(|count| count > 0)
    }

    pub fn purge_expired_trash(
        &mut self,
        retention_days: u64,
        key_pass: &mut ServerInfo,
    ) -> Result<usize, VaultError> {
        if retention_days == 0 || self.recovery.trash.is_empty() {
            return Ok(0);
        }
        let max_days = i64::MAX / 86_400;
        let days = i64::try_from(retention_days)
            .unwrap_or(max_days)
            .min(max_days);
        let cutoff = chrono::Utc::now()
            .checked_sub_signed(chrono::Duration::days(days))
            .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC);
        let removed_ids = self
            .recovery
            .trash
            .iter()
            .filter_map(|item| {
                chrono::DateTime::parse_from_str(&item.deleted, "%Y-%m-%d %H:%M:%S%.f %:z")
                    .ok()
                    .filter(|deleted| deleted.with_timezone(&chrono::Utc) <= cutoff)
                    .map(|_| item.entry.id)
            })
            .collect::<Vec<_>>();
        if removed_ids.is_empty() {
            return Ok(0);
        }
        self.purge_ids(removed_ids.into_iter().collect(), key_pass)
    }
}
