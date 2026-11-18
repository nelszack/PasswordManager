use super::*;

// Export the portable schema without duplicating vault-owned plaintext.
#[derive(Serialize)]
struct PortableExportRef<'a> {
    format: &'static str,
    version: u8,
    exported_at: String,
    items: ExportItems<'a>,
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
    password_history: ExportHistory<'a>,
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
        let json = Path::new(&path)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"));
        persistence::persist_private_stream(Path::new(&path), force, |file| {
            self.write_export(file, json)
        })
    }
    pub(crate) fn export_bytes(&self, json: bool) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let mut bytes = Zeroizing::new(Vec::new());
        struct Bounded<'a>(&'a mut Vec<u8>);
        impl Write for Bounded<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0.len().saturating_add(bytes.len()) > 16 * 1024 * 1024 {
                    return Err(std::io::Error::other(
                        "Export exceeds the 16 MiB mobile transfer limit",
                    ));
                }
                self.0.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        self.write_export(Bounded(&mut bytes), json)?;
        if bytes.len() as u64 > MAX_IMPORT_BYTES {
            return Err(VaultError::InvalidInput(
                "Export exceeds mobile transfer limit".into(),
            ));
        }
        Ok(bytes)
    }
    fn write_export(&self, destination: impl Write, json: bool) -> Result<(), VaultError> {
        if json {
            let export = PortableExportRef {
                format: PORTABLE_FORMAT,
                version: PORTABLE_VERSION,
                exported_at: chrono::Utc::now().to_rfc3339(),
                items: ExportItems(self),
            };
            return serde_json::to_writer_pretty(destination, &export)
                .map_err(|e| VaultError::Persistence(format!("could not encode export: {e}")));
        }
        if self.active_items().any(Item::is_passkey) {
            return Err(VaultError::Validation(
                "CSV cannot preserve passkeys; use portable JSON or an encrypted backup".into(),
            ));
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
        {
            let mut writer = csv::Writer::from_writer(destination);
            for entry in self.active_entries() {
                writer
                    .serialize(entry)
                    .map_err(|e| VaultError::Persistence(e.to_string()))?;
            }
            writer
                .flush()
                .map_err(|e| VaultError::Persistence(e.to_string()))
        }
    }
}

struct ExportItems<'a>(&'a Vault);
impl Serialize for ExportItems<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut sequence = serializer.serialize_seq(None)?;
        for item in self.0.active_items() {
            let e = &item.entry;
            let m = &item.metadata;
            sequence.serialize_element(&PortableItemRef {
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
                password_history: ExportHistory(&item.history),
                totp: item
                    .authenticator
                    .as_ref()
                    .map(|a| a.configuration.as_str()),
                duo: item.duo.as_ref().map(|d| &d.credentials),
            })?;
        }
        sequence.end()
    }
}
struct ExportHistory<'a>(&'a [PasswordRevision]);
impl Serialize for ExportHistory<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for revision in self.0 {
            sequence.serialize_element(&PortableRevisionRef {
                password: revision.password.as_str(),
                changed: &revision.changed,
            })?;
        }
        sequence.end()
    }
}
