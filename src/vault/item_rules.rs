//! Item shape and passkey rules shared by every client (CLI, desktop, browser,
//! and mobile). Adapters may pre-validate for better messages, but the vault
//! is the authority.
use super::*;

pub const MAX_NAME_BYTES: usize = 4096;
pub const MAX_URLS: usize = 128;
pub const MAX_URL_BYTES: usize = 8192;
pub const MAX_CUSTOM_FIELDS: usize = 128;
pub const MAX_FIELD_NAME_BYTES: usize = 128;
pub const MAX_FIELD_VALUE_BYTES: usize = 1024 * 1024;

/// Passkey private keys live in this reserved custom field. Only the passkey
/// workflow may create it; ordinary edits, reveals, and copies never touch it.
pub(crate) fn is_reserved_field(name: &str) -> bool {
    name.trim().eq_ignore_ascii_case(crate::passkey::FIELD)
}

impl Item {
    /// The passkey record itself, stored under the exact reserved name.
    pub(crate) fn passkey_field(&self) -> Option<&CustomField> {
        self.metadata
            .custom_fields
            .iter()
            .find(|f| f.name == crate::passkey::FIELD)
    }
    /// Whether ordinary edits must leave this item alone. Any spelling of the
    /// reserved name counts, because every such field is hidden from views
    /// and would be silently dropped by an edit that replaces fields.
    pub(crate) fn is_passkey(&self) -> bool {
        self.metadata
            .custom_fields
            .iter()
            .any(|f| is_reserved_field(&f.name))
    }
}

fn invalid(message: impl Into<String>) -> VaultError {
    VaultError::InvalidInput(message.into())
}

pub(super) fn check_name(name: &str) -> Result<(), VaultError> {
    if name.trim().is_empty() || name.len() > MAX_NAME_BYTES {
        return Err(invalid(format!(
            "Name is required (maximum {MAX_NAME_BYTES} bytes)"
        )));
    }
    Ok(())
}

pub(super) fn check_url(url: &str) -> Result<(), VaultError> {
    if url.len() > MAX_URL_BYTES {
        return Err(invalid(format!(
            "Websites are limited to {MAX_URL_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Trims names and rejects empty, oversized, or reserved fields supplied by a
/// user. Uniqueness is checked against the resulting item.
pub(super) fn normalize_new_fields(fields: &mut [CustomField]) -> Result<(), VaultError> {
    for field in fields {
        let trimmed = field.name.trim();
        if trimmed.len() != field.name.len() {
            field.name = trimmed.to_owned();
        }
        if field.name.is_empty() || field.name.len() > MAX_FIELD_NAME_BYTES {
            return Err(invalid(format!(
                "Custom field names must be 1 to {MAX_FIELD_NAME_BYTES} bytes"
            )));
        }
        if field.value.len() > MAX_FIELD_VALUE_BYTES {
            return Err(invalid("Custom field values are limited to 1 MiB"));
        }
        if is_reserved_field(&field.name) {
            return Err(invalid(format!(
                "`{}` is reserved for passkeys",
                crate::passkey::FIELD
            )));
        }
    }
    Ok(())
}

/// The parts of an item that count and uniqueness limits look at.
#[derive(Clone, Copy)]
pub(super) struct Shape {
    urls: usize,
    fields: usize,
    duplicate_fields: bool,
}

impl Shape {
    pub(super) fn of(item: &Item) -> Self {
        let mut names = HashSet::new();
        Self {
            urls: item.urls().count(),
            fields: item.metadata.custom_fields.len(),
            duplicate_fields: !item
                .metadata
                .custom_fields
                .iter()
                .all(|f| names.insert(f.name.to_lowercase())),
        }
    }
}

/// Count and uniqueness limits for a complete item. `before` is the item's
/// shape prior to an edit, so records imported before these limits stay
/// editable as long as an edit does not make them larger.
pub(super) fn check_item_limits(item: &Item, before: Option<Shape>) -> Result<(), VaultError> {
    let after = Shape::of(item);
    if after.urls > MAX_URLS && before.is_none_or(|b| after.urls > b.urls) {
        return Err(invalid(format!("Items are limited to {MAX_URLS} websites")));
    }
    if after.fields > MAX_CUSTOM_FIELDS && before.is_none_or(|b| after.fields > b.fields) {
        return Err(invalid(format!(
            "Items are limited to {MAX_CUSTOM_FIELDS} custom fields"
        )));
    }
    if after.duplicate_fields && before.is_none_or(|b| !b.duplicate_fields) {
        return Err(invalid("Custom field names must be unique"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, value: &str) -> CustomField {
        CustomField {
            name: name.into(),
            value: value.into(),
            secret: true,
        }
    }

    fn entry(name: &str, fields: Vec<CustomField>) -> TypedEntry {
        TypedEntry {
            entry: PasswordEntry {
                name: name.into(),
                username: Some("synthetic-user".into()),
                password: "".into(),
                url: Some("https://example.com".into()),
                notes: None,
                copy: false,
            },
            kind: ItemKind::Login,
            additional_urls: vec![],
            custom_fields: fields,
        }
    }

    fn edit(id: usize) -> TypedUpdate {
        TypedUpdate::from(EntryUpdate {
            target: Target::Id(id),
            update: EntryChanges::default(),
            password: None,
        })
    }

    #[test]
    fn every_client_gets_the_same_item_shape_limits() {
        let mut vault = Vault::memory();
        let mut key = VaultCredentials::default();
        let oversized_name = "x".repeat(MAX_NAME_BYTES + 1);
        let long_field = "x".repeat(MAX_FIELD_NAME_BYTES + 1);
        for (label, request) in [
            ("blank name", entry("  ", vec![])),
            ("oversized name", entry(&oversized_name, vec![])),
            ("blank field", entry("Item", vec![field(" ", "v")])),
            (
                "long field name",
                entry("Item", vec![field(&long_field, "v")]),
            ),
            (
                "duplicate fields",
                entry("Item", vec![field("Token", "a"), field("token ", "b")]),
            ),
            (
                "too many fields",
                entry(
                    "Item",
                    (0..=MAX_CUSTOM_FIELDS)
                        .map(|i| field(&format!("f{i}"), "v"))
                        .collect(),
                ),
            ),
        ] {
            assert!(vault.add_typed_entry(request, &mut key).is_err(), "{label}");
        }
        let mut too_many_urls = entry("Item", vec![]);
        too_many_urls.additional_urls = (0..MAX_URLS)
            .map(|i| format!("https://{i}.example.com"))
            .collect();
        assert!(vault.add_typed_entry(too_many_urls, &mut key).is_err());
        assert_eq!(vault.active_items().count(), 0);

        assert!(
            vault
                .add_typed_entry(entry("Item", vec![field(" Token ", "v")]), &mut key)
                .unwrap()
        );
        let detail = vault.management_item(1, false).unwrap();
        assert_eq!(detail.fields[0].name, "Token");
        let mut rename = edit(1);
        rename.entry.update.name = Some(" ".into());
        assert!(
            vault
                .update_typed_entry_with_limit(rename, &mut key, 10)
                .is_err()
        );
        let mut duplicate = edit(1);
        duplicate.set_fields = vec![field("other", "a"), field("OTHER", "b")];
        // Fields with matching names replace each other rather than duplicating.
        assert!(
            vault
                .update_typed_entry_with_limit(duplicate, &mut key, 10)
                .unwrap()
        );
        assert_eq!(vault.management_item(1, false).unwrap().fields.len(), 2);
    }

    #[test]
    fn passkey_records_stay_hidden_and_read_only_outside_the_passkey_workflow() {
        let mut vault = Vault::memory();
        let mut key = VaultCredentials::default();
        let reserved = crate::passkey::FIELD;
        for name in [
            reserved.to_owned(),
            format!(" {} ", reserved.to_uppercase()),
        ] {
            assert!(
                vault
                    .add_typed_entry(entry("Forged", vec![field(&name, "key")]), &mut key)
                    .is_err(),
                "{name}"
            );
        }
        assert!(
            vault
                .add_passkey_entry(entry("Missing", vec![]), &mut key)
                .is_err()
        );
        assert!(
            vault
                .add_passkey_entry(
                    entry("Passkey", vec![field(reserved, "private-key-material")]),
                    &mut key,
                )
                .unwrap()
        );
        assert!(
            vault
                .add_typed_entry(entry("Ordinary", vec![]), &mut key)
                .unwrap()
        );

        let detail = vault.management_item(1, true).unwrap();
        assert!(detail.is_passkey);
        assert!(detail.fields.is_empty());
        assert!(
            !serde_json::to_string(&detail)
                .unwrap()
                .contains("private-key")
        );
        assert!(!vault.management_item(2, true).unwrap().is_passkey);
        assert!(vault.get_custom_field(&Target::Id(1), reserved).is_err());

        let before = vault.clone();
        let mut rename = edit(1);
        rename.entry.update.name = Some("Renamed".into());
        let mut strip = edit(1);
        strip.clear_fields = true;
        let mut forge = edit(2);
        forge.set_fields = vec![field(reserved, "key")];
        for (label, change) in [("rename", rename), ("strip", strip), ("forge", forge)] {
            assert!(
                vault
                    .update_typed_entry_with_limit(change, &mut key, 10)
                    .is_err(),
                "{label}"
            );
        }
        assert_eq!(vault, before);
        // The record itself can still be trashed like any other item.
        assert!(vault.delete_entry(Target::Id(1), &mut key).unwrap());
    }

    #[test]
    fn any_spelling_of_the_reserved_field_keeps_an_imported_item_read_only() {
        let mut vault = Vault::memory();
        let mut key = VaultCredentials::default();
        assert!(
            vault
                .add_typed_entry(entry("Imported", vec![]), &mut key)
                .unwrap()
        );
        // Imports bypass item rules, so simulate one carrying a variant name.
        let variant = format!(" {} ", crate::passkey::FIELD.to_uppercase());
        vault.item_mut(1).unwrap().metadata.custom_fields = vec![field(&variant, "key")];
        assert!(vault.management_item(1, true).unwrap().fields.is_empty());
        let mut strip = edit(1);
        strip.clear_fields = true;
        assert!(
            vault
                .update_typed_entry_with_limit(strip, &mut key, 10)
                .is_err(),
            "a hidden field must not be dropped by an edit"
        );
        assert_eq!(vault.item(1).unwrap().metadata.custom_fields.len(), 1);
    }

    #[test]
    fn records_above_current_limits_remain_editable_without_growing() {
        let mut vault = Vault::memory();
        let mut key = VaultCredentials::default();
        assert!(
            vault
                .add_typed_entry(entry("Legacy", vec![]), &mut key)
                .unwrap()
        );
        // Simulate an older import that predates the field limit.
        vault.item_mut(1).unwrap().metadata.custom_fields = (0..=MAX_CUSTOM_FIELDS)
            .map(|i| field(&format!("f{i}"), "v"))
            .collect();
        let mut rename = edit(1);
        rename.entry.update.name = Some("Renamed".into());
        assert!(
            vault
                .update_typed_entry_with_limit(rename, &mut key, 10)
                .unwrap()
        );
        let mut grow = edit(1);
        grow.set_fields = vec![field("extra", "v")];
        assert!(
            vault
                .update_typed_entry_with_limit(grow, &mut key, 10)
                .is_err()
        );
        let mut shrink = edit(1);
        shrink.remove_fields = vec!["f0".into()];
        assert!(
            vault
                .update_typed_entry_with_limit(shrink, &mut key, 10)
                .unwrap()
        );
    }
}
