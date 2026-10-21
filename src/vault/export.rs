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
    #[serde(skip_serializing_if = "Option::is_none")]
    duo: Option<&'a DuoCredentials>,
}

#[derive(Serialize)]
struct PortableRevisionRef<'a> {
    password: &'a str,
    changed: &'a str,
}

impl Vault {
    pub fn export(&self, path: String, force: bool) -> Result<(), VaultError> {
        if Path::new(&path)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"))
        {
            let items = self
                .active_items()
                .map(|item| {
                    let e = &item.entry;
                    let m = &item.metadata;
                    PortableItemRef {
                        id: e.id,
                        name: &e.name,
                        username: e.username.as_deref(),
                        password: e.password.as_str(),
                        url: e.url.as_deref(),
                        notes: e.notes.as_ref().map(|s| s.as_str()),
                        created: &e.created,
                        modified: &e.modified,
                        kind: m.kind,
                        additional_urls: &m.additional_urls,
                        custom_fields: &m.custom_fields,
                        password_changed: m.password_changed.as_ref().map(Timestamp::as_str),
                        password_history: item
                            .history
                            .iter()
                            .map(|r| PortableRevisionRef {
                                password: r.password.as_str(),
                                changed: &r.changed,
                            })
                            .collect(),
                        totp: item
                            .authenticator
                            .as_ref()
                            .map(|a| a.configuration.as_str()),
                        duo: item.duo.as_ref().map(|d| &d.credentials),
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
                .map_err(|e| VaultError::Persistence(format!("could not encode export: {e}")))?;
            return persist_private_file(Path::new(&path), &encoded, force);
        }
        // CSV quoting does not prevent spreadsheet formula evaluation. Refuse
        // unsafe cells without altering credential bytes; JSON remains lossless.
        for entry in self.active_entries() {
            for value in [
                Some(entry.name.as_str()),
                entry.username.as_deref(),
                Some(entry.password.as_str()),
                entry.url.as_deref(),
                entry.notes.as_ref().map(|s| s.as_str()),
                Some(entry.created.as_str()),
                Some(entry.modified.as_str()),
            ]
            .into_iter()
            .flatten()
            {
                let significant = value.trim_start_matches(|c: char| {
                    c.is_whitespace() || c.is_control() || c == '\u{feff}'
                });
                let prefix = &value[..value.len() - significant.len()];
                if prefix.chars().any(char::is_control)
                    || significant.chars().next().is_some_and(|c| {
                        matches!(c, '=' | '+' | '-' | '@' | '＝' | '＋' | '－' | '＠')
                    })
                {
                    return Err(VaultError::Validation("CSV export contains a cell that a spreadsheet could interpret as a formula; export to a .json file to preserve the exact data safely".into()));
                }
            }
        }
        let mut writer = csv::Writer::from_writer(Vec::new());
        for entry in self.active_entries() {
            writer
                .serialize(entry)
                .map_err(|e| VaultError::Persistence(e.to_string()))?;
        }
        let encoded = Zeroizing::new(
            writer
                .into_inner()
                .map_err(|e| VaultError::Persistence(e.to_string()))?,
        );
        persist_private_file(Path::new(&path), &encoded, force)
    }
}
