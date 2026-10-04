use super::*;

impl Vault {
    pub fn export(&self, path: String, force: bool) -> Result<(), VaultError> {
        if std::path::Path::new(&path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        {
            let metadata_by_id: HashMap<_, _> = self
                .recovery
                .entry_metadata
                .iter()
                .map(|record| (record.entry_id, record))
                .collect();
            let totp_by_id: HashMap<_, _> = self
                .recovery
                .totp
                .iter()
                .map(|record| (record.entry_id, record))
                .collect();
            let mut history_by_id: HashMap<usize, Vec<&PasswordRevision>> = HashMap::new();
            for revision in &self.recovery.password_history {
                history_by_id
                    .entry(revision.entry_id)
                    .or_default()
                    .push(revision);
            }
            let items = self
                .entries
                .iter()
                .map(|entry| {
                    let metadata = metadata_by_id.get(&entry.id).copied();
                    PortableItem {
                        id: entry.id,
                        name: entry.name.clone(),
                        username: entry.username.clone(),
                        password: entry.password.clone(),
                        url: entry.url.clone(),
                        notes: entry.notes.clone(),
                        created: entry.created.clone(),
                        modified: entry.modified.clone(),
                        kind: self.item_kind(entry.id),
                        additional_urls: metadata
                            .map(|record| record.additional_urls.clone())
                            .unwrap_or_default(),
                        custom_fields: metadata
                            .map(|record| record.custom_fields.clone())
                            .unwrap_or_default(),
                        password_changed: metadata
                            .and_then(|record| record.password_changed.clone()),
                        password_history: history_by_id
                            .get(&entry.id)
                            .into_iter()
                            .flatten()
                            .map(|revision| PortableRevision {
                                password: revision.password.clone(),
                                changed: revision.changed.clone(),
                            })
                            .collect(),
                        totp: totp_by_id
                            .get(&entry.id)
                            .map(|record| record.configuration.clone()),
                    }
                })
                .collect();
            let mut export = PortableExport {
                format: PORTABLE_FORMAT.to_string(),
                version: PORTABLE_VERSION,
                exported_at: chrono::Utc::now().to_rfc3339(),
                items,
            };
            let encoded = serde_json::to_vec_pretty(&export);
            export.zeroize();
            let mut encoded = encoded.map_err(|e| format!("could not encode JSON export: {e}"))?;
            let result = persist_private_file(Path::new(&path), &encoded, force)
                .map_err(|e| e.context(format!("could not create export file {path:?}")));
            encoded.zeroize();
            return result;
        }
        let mut wtr = csv::Writer::from_writer(Vec::new());
        for i in &self.entries {
            wtr.serialize(i)
                .map_err(|e| format!("could not write export file {path:?}: {e}"))?;
        }
        let mut encoded = wtr
            .into_inner()
            .map_err(|e| format!("could not finish export file {path:?}: {}", e.error()))?;
        let result = persist_private_file(Path::new(&path), &encoded, force)
            .map_err(|e| e.context(format!("could not create export file {path:?}")));
        encoded.zeroize();
        result
    }
}
