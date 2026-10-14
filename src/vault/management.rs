use super::*;

#[derive(Serialize)]
struct ManagementItem<'a> {
    id: usize,
    name: &'a str,
    username: Option<&'a str>,
    kind: ItemKind,
    urls: Vec<&'a str>,
    notes: Option<&'a str>,
    password: Option<&'a str>,
    has_secret: bool,
    fields: Vec<ManagementField<'a>>,
    has_totp: bool,
    has_duo: bool,
    created: &'a str,
    modified: &'a str,
}

#[derive(Serialize)]
struct ManagementField<'a> {
    name: &'a str,
    secret: bool,
    value: Option<&'a str>,
}

impl Vault {
    /// Summaries contain no notes, passwords, authenticator seeds or field values.
    pub fn management_list_json(&self, filter: SearchFilter) -> Result<String, VaultError> {
        let views = match self.search(filter) {
            Ok(views) => views,
            Err(VaultError::NotFound(_)) => Vec::new(),
            Err(error) => return Err(error),
        };
        let total = views.len();
        let items: Vec<_> = views
            .into_iter()
            .take(100)
            .map(|view| {
                json!({
                    "id": view.entry.id, "name": view.entry.name, "username": view.entry.username,
                    "kind": view.metadata.map_or(ItemKind::Login, |m| m.kind),
                    "urls": view.urls, "has_totp": view.has_totp,
                    "has_duo": self.recovery.duo.iter().any(|r| r.entry_id == view.entry.id),
                })
            })
            .collect();
        serde_json::to_string(&json!({ "items": items, "total": total }))
            .map_err(|_| VaultError::InvalidInput("could not encode item summaries".into()))
    }

    /// Secrets are included only in an explicit reveal of one selected item.
    pub fn management_item_json(&self, id: usize, reveal: bool) -> Result<String, VaultError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or_else(|| VaultError::NotFound("Item not found.".into()))?;
        let metadata = self
            .recovery
            .entry_metadata
            .iter()
            .find(|m| m.entry_id == id);
        let mut urls = entry.url.as_deref().into_iter().collect::<Vec<_>>();
        if let Some(metadata) = metadata {
            urls.extend(metadata.additional_urls.iter().map(String::as_str));
        }
        let fields: Vec<_> = metadata
            .into_iter()
            .flat_map(|m| &m.custom_fields)
            .map(|field| ManagementField {
                name: &field.name,
                secret: field.secret,
                value: (!(field.secret && !reveal)).then_some(field.value.as_str()),
            })
            .collect();
        serde_json::to_string(&ManagementItem {
            id: entry.id,
            name: &entry.name,
            username: entry.username.as_deref(),
            kind: metadata.map_or(ItemKind::Login, |m| m.kind),
            urls,
            notes: entry.notes.as_deref(),
            password: reveal.then_some(entry.password.as_str()),
            has_secret: !entry.password.is_empty(),
            fields,
            has_totp: self.recovery.totp.iter().any(|t| t.entry_id == id),
            has_duo: self.recovery.duo.iter().any(|r| r.entry_id == id),
            created: &entry.created,
            modified: &entry.modified,
        })
        .map_err(|_| VaultError::InvalidInput("could not encode item details".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn summaries_and_default_details_redact_secrets_and_selection_is_explicit() {
        let vault = Vault {
            entries: vec![VaultEntry {
                id: 4,
                name: "Example".into(),
                password: "synthetic-password".into(),
                url: Some("https://example.com".into()),
                notes: Some("private-notes".into()),
                ..Default::default()
            }],
            recovery: RecoveryData {
                entry_metadata: vec![EntryMetadata {
                    entry_id: 4,
                    additional_urls: vec!["https://accounts.example.com".into()],
                    custom_fields: vec![
                        CustomField {
                            name: "token".into(),
                            value: "secret-token".into(),
                            secret: true,
                        },
                        CustomField {
                            name: "environment".into(),
                            value: "prod \"blue\" 🔐".into(),
                            secret: false,
                        },
                    ],
                    ..Default::default()
                }],
                totp: vec![TotpRecord {
                    entry_id: 4,
                    configuration: "authenticator-seed".into(),
                }],
                ..Default::default()
            },
            metadata: VaultMetadata::default(),
        };
        let summaries = vault.management_list_json(SearchFilter::default()).unwrap();
        for secret in [
            "synthetic-password",
            "secret-token",
            "authenticator-seed",
            "private-notes",
        ] {
            assert!(!summaries.contains(secret));
        }
        let details = vault.management_item_json(4, false).unwrap();
        let mut expected = json!({
            "id": 4, "name": "Example", "username": null, "kind": "login",
            "urls": ["https://example.com", "https://accounts.example.com"],
            "notes": "private-notes", "password": null, "has_secret": true,
            "fields": [
                { "name": "token", "secret": true, "value": null },
                { "name": "environment", "secret": false, "value": "prod \"blue\" 🔐" },
            ],
            "has_totp": true, "has_duo": false, "created": "", "modified": "",
        });
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&details).unwrap(),
            expected
        );
        let revealed = vault.management_item_json(4, true).unwrap();
        expected["password"] = json!("synthetic-password");
        expected["fields"][0]["value"] = json!("secret-token");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&revealed).unwrap(),
            expected
        );
        assert!(vault.management_item_json(5, true).is_err());
        let search = vault
            .management_list_json(SearchFilter {
                query: Some("secret-token".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&search).unwrap()["total"],
            0
        );
    }
}
