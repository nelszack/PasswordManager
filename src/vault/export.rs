use super::*;

// Export the portable schema without duplicating vault-owned plaintext.
#[derive(Serialize)]
struct PortableExportRef<'a> {
    format: &'static str,
    version: u8,
    exported_at: String,
    items: Vec<PortableItemRef<'a>>,
}

#[derive(Serialize)]
struct PortableItemRef<'a> {
    id: usize,
    name: &'a str,
    username: Option<&'a str>,
    password: &'a str,
    url: Option<&'a str>,
    notes: Option<&'a str>,
    created: &'a str,
    modified: &'a str,
    #[serde(rename = "type")]
    kind: ItemKind,
    additional_urls: &'a [String],
    custom_fields: &'a [CustomField],
    password_changed: Option<&'a str>,
    password_history: Vec<PortableRevisionRef<'a>>,
    totp: Option<&'a str>,
}

#[derive(Serialize)]
struct PortableRevisionRef<'a> {
    password: &'a str,
    changed: &'a str,
}

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
                    PortableItemRef {
                        id: entry.id,
                        name: &entry.name,
                        username: entry.username.as_deref(),
                        password: &entry.password,
                        url: entry.url.as_deref(),
                        notes: entry.notes.as_deref(),
                        created: &entry.created,
                        modified: &entry.modified,
                        kind: metadata.map_or(ItemKind::Login, |record| record.kind),
                        additional_urls: metadata
                            .map_or(&[][..], |record| record.additional_urls.as_slice()),
                        custom_fields: metadata
                            .map_or(&[][..], |record| record.custom_fields.as_slice()),
                        password_changed: metadata
                            .and_then(|record| record.password_changed.as_deref()),
                        password_history: history_by_id
                            .get(&entry.id)
                            .into_iter()
                            .flatten()
                            .map(|revision| PortableRevisionRef {
                                password: &revision.password,
                                changed: &revision.changed,
                            })
                            .collect(),
                        totp: totp_by_id
                            .get(&entry.id)
                            .map(|record| record.configuration.as_str()),
                    }
                })
                .collect();
            let export = PortableExportRef {
                format: PORTABLE_FORMAT,
                version: PORTABLE_VERSION,
                exported_at: chrono::Utc::now().to_rfc3339(),
                items,
            };
            let mut encoded = Zeroizing::new(Vec::new());
            serde_json::to_writer_pretty(&mut *encoded, &export)
                .map_err(|e| format!("could not encode JSON export: {e}"))?;
            let result = persist_private_file(Path::new(&path), &encoded, force)
                .map_err(|e| e.context(format!("could not create export file {path:?}")));
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
