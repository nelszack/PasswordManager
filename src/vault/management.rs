use super::*;

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
        let mut urls = entry.url.iter().collect::<Vec<_>>();
        if let Some(metadata) = metadata {
            urls.extend(metadata.additional_urls.iter());
        }
        let fields: Vec<_> = metadata
            .into_iter()
            .flat_map(|m| &m.custom_fields)
            .map(|field| {
                json!({
                    "name": field.name, "secret": field.secret,
                    "value": if field.secret && !reveal { None } else { Some(&field.value) },
                })
            })
            .collect();
        serde_json::to_string(&json!({
            "id": entry.id, "name": entry.name, "username": entry.username,
            "kind": metadata.map_or(ItemKind::Login, |m| m.kind), "urls": urls,
            "notes": entry.notes, "password": reveal.then_some(&entry.password),
            "has_secret": !entry.password.is_empty(), "fields": fields,
            "has_totp": self.recovery.totp.iter().any(|t| t.entry_id == id),
            "created": entry.created, "modified": entry.modified,
        }))
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
                notes: Some("private-notes".into()),
                ..Default::default()
            }],
            recovery: RecoveryData {
                entry_metadata: vec![EntryMetadata {
                    entry_id: 4,
                    custom_fields: vec![CustomField {
                        name: "token".into(),
                        value: "secret-token".into(),
                        secret: true,
                    }],
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
        assert!(!details.contains("synthetic-password"));
        assert!(!details.contains("secret-token"));
        let revealed = vault.management_item_json(4, true).unwrap();
        assert!(revealed.contains("synthetic-password"));
        assert!(revealed.contains("secret-token"));
        assert!(!revealed.contains("authenticator-seed"));
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
