use super::*;

pub(super) enum TransactionScope {
    Entry(usize),
    Recovery,
    All,
}

/// Single-entry operations copy only that entry's records. Bulk import snapshots
/// the full vault; purging copies recovery data without copying active secrets.
struct Snapshot {
    entry_id: Option<usize>,
    entries: Vec<(usize, VaultEntry)>,
    history: Vec<(usize, PasswordRevision)>,
    trash: Vec<(usize, TrashedEntry)>,
    totp: Vec<(usize, TotpRecord)>,
    metadata: Vec<(usize, EntryMetadata)>,
    next_entry_id: usize,
    all_entries: bool,
}

fn indexed<T: Clone>(items: &[T], select: impl Fn(&T) -> bool) -> Vec<(usize, T)> {
    items
        .iter()
        .enumerate()
        .filter(|(_, item)| select(item))
        .map(|(index, item)| (index, item.clone()))
        .collect()
}

fn restore<T: Zeroize>(
    items: &mut Vec<T>,
    saved: &mut Vec<(usize, T)>,
    select: impl Fn(&T) -> bool,
) {
    let mut retained = Vec::with_capacity(items.len());
    for mut item in std::mem::take(items) {
        if select(&item) {
            item.zeroize();
        } else {
            retained.push(item);
        }
    }
    for (index, item) in std::mem::take(saved) {
        retained.insert(index.min(retained.len()), item);
    }
    *items = retained;
}

impl Snapshot {
    fn capture(vault: &Vault, scope: TransactionScope) -> Self {
        let id = match scope {
            TransactionScope::Entry(id) => Some(id),
            _ => None,
        };
        let matches = |entry_id| id.is_none_or(|id| id == entry_id);
        let all_entries = matches!(scope, TransactionScope::All);
        Self {
            entry_id: id,
            entries: indexed(&vault.entries, |e| all_entries || id == Some(e.id)),
            history: indexed(&vault.recovery.password_history, |r| matches(r.entry_id)),
            trash: indexed(&vault.recovery.trash, |r| matches(r.entry.id)),
            totp: indexed(&vault.recovery.totp, |r| matches(r.entry_id)),
            metadata: indexed(&vault.recovery.entry_metadata, |r| matches(r.entry_id)),
            next_entry_id: vault.recovery.next_entry_id,
            all_entries,
        }
    }

    fn rollback(&mut self, vault: &mut Vault) {
        let id = self.entry_id;
        let matches = |entry_id| id.is_none_or(|id| id == entry_id);
        if self.all_entries || id.is_some() {
            restore(&mut vault.entries, &mut self.entries, |e| {
                self.all_entries || id == Some(e.id)
            });
        }
        restore(
            &mut vault.recovery.password_history,
            &mut self.history,
            |r| matches(r.entry_id),
        );
        restore(&mut vault.recovery.trash, &mut self.trash, |r| {
            matches(r.entry.id)
        });
        restore(&mut vault.recovery.totp, &mut self.totp, |r| {
            matches(r.entry_id)
        });
        restore(
            &mut vault.recovery.entry_metadata,
            &mut self.metadata,
            |r| matches(r.entry_id),
        );
        vault.recovery.next_entry_id = self.next_entry_id;
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        for (_, entry) in &mut self.entries {
            entry.zeroize();
        }
        for (_, record) in &mut self.history {
            record.zeroize();
        }
        for (_, record) in &mut self.trash {
            record.zeroize();
        }
        for (_, record) in &mut self.totp {
            record.zeroize();
        }
        for (_, record) in &mut self.metadata {
            record.zeroize();
        }
    }
}

struct Transaction<'a> {
    vault: &'a mut Vault,
    snapshot: Option<Snapshot>,
}
impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if let Some(snapshot) = &mut self.snapshot {
            snapshot.rollback(self.vault);
        }
    }
}

impl Vault {
    pub(super) fn transaction<T>(
        &mut self,
        scope: TransactionScope,
        key: &mut ServerInfo,
        mutate: impl FnOnce(&mut Vault) -> Result<(bool, T), VaultError>,
    ) -> Result<T, VaultError> {
        let snapshot = Snapshot::capture(self, scope);
        let mut transaction = Transaction {
            vault: self,
            snapshot: Some(snapshot),
        };
        let (changed, result) = mutate(transaction.vault)?;
        if changed && let Err(error) = write_vault(transaction.vault, key) {
            if error.committed() {
                transaction.snapshot.take();
            }
            return Err(error);
        }
        transaction.snapshot.take();
        Ok(result)
    }

    pub(super) fn next_entry_id(&self) -> Result<usize, VaultError> {
        let highest = self
            .entries
            .iter()
            .map(|e| e.id)
            .chain(self.recovery.trash.iter().map(|r| r.entry.id))
            .max()
            .unwrap_or(0);
        let minimum = highest
            .checked_add(1)
            .ok_or_else(|| VaultError::InvalidInput("entry ID space is exhausted".into()))?;
        let id = self.recovery.next_entry_id.max(minimum).max(1);
        id.checked_add(1)
            .ok_or_else(|| VaultError::InvalidInput("entry ID space is exhausted".into()))?;
        Ok(id)
    }

    pub(super) fn take_history_records(&mut self, id: usize) -> Vec<PasswordRevision> {
        let mut history = Vec::new();
        self.recovery.password_history = std::mem::take(&mut self.recovery.password_history)
            .into_iter()
            .filter_map(|r| {
                if r.entry_id == id {
                    history.push(r);
                    None
                } else {
                    Some(r)
                }
            })
            .collect();
        history
    }

    pub(super) fn purge_ids(
        &mut self,
        ids: HashSet<usize>,
        key: &mut ServerInfo,
    ) -> Result<usize, VaultError> {
        self.transaction(TransactionScope::Recovery, key, |vault| {
            vault.recovery.trash.retain_mut(|r| {
                if ids.contains(&r.entry.id) {
                    r.zeroize();
                    false
                } else {
                    true
                }
            });
            vault.recovery.totp.retain_mut(|r| {
                if ids.contains(&r.entry_id) {
                    r.zeroize();
                    false
                } else {
                    true
                }
            });
            vault.recovery.entry_metadata.retain_mut(|r| {
                if ids.contains(&r.entry_id) {
                    r.zeroize();
                    false
                } else {
                    true
                }
            });
            Ok((!ids.is_empty(), ids.len()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_restores_entry_and_recovery_state_without_touching_other_entries() {
        let mut vault = Vault::default();
        vault.entries = vec![
            VaultEntry {
                id: 1,
                password: "first-secret".into(),
                ..Default::default()
            },
            VaultEntry {
                id: 2,
                password: "other-secret".into(),
                ..Default::default()
            },
        ];
        vault.recovery.password_history.push(PasswordRevision {
            entry_id: 1,
            password: "old-secret".into(),
            changed: "before".into(),
        });
        vault.recovery.totp.push(TotpRecord {
            entry_id: 1,
            configuration: "authenticator".into(),
        });
        let before = vault.clone();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), VaultError> = vault.transaction(
                TransactionScope::Entry(1),
                &mut ServerInfo::default(),
                |vault| {
                    vault.entries.remove(0).zeroize();
                    vault.recovery.password_history.clear();
                    vault.recovery.totp.clear();
                    vault.recovery.next_entry_id = 500;
                    panic!("abort mutation");
                },
            );
        }));
        assert!(panic.is_err());
        assert_eq!(vault, before);
    }

    #[test]
    fn persistence_failure_restores_all_affected_records_and_has_a_stable_category() {
        crate::file::init_test_data_dir();
        let mut vault = Vault::default();
        vault.metadata.filename = "missing-directory/vault.enc".into();
        vault.entries.push(VaultEntry {
            id: 1,
            password: "old-secret".into(),
            ..Default::default()
        });
        let before = vault.clone();
        // A cached key keeps this test independent of password derivation cost.
        let mut key = ServerInfo {
            locked: false,
            keypass: Some(PasswordType::Session {
                encryption_key: [42; 32],
                salt: [7; 16],
                kdf: 1,
                memory_kib: 8192,
                iterations: 1,
                parallelism: 1,
            }),
        };
        let result = vault.transaction(TransactionScope::Entry(1), &mut key, |vault| {
            vault.entries[0].password = "replacement-secret".into();
            vault.recovery.entry_metadata.push(EntryMetadata {
                entry_id: 1,
                kind: ItemKind::SecureNote,
                ..Default::default()
            });
            Ok((true, ()))
        });
        assert!(matches!(result, Err(VaultError::Persistence(_))));
        assert_eq!(vault, before);
    }
}
