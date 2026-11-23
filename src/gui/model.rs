use iced::widget::text_editor;
use password_manager::{
    secret::SecretString,
    types::{
        CustomField, EntryChanges, EntryUpdate, ItemKind, PasswordEntry, ServerCommand, Target,
        TypedEntry, TypedUpdate,
    },
    vault::ItemDetail,
};
use zeroize::Zeroize;

pub use password_manager::item_profile::{KINDS, Profile, profile};

/// The item type's secret name for buttons and messages ("Password", "Card number").
pub fn secret_label(kind: ItemKind) -> String {
    profile(kind).secret_name().to_owned()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KindChoice(pub ItemKind);
impl std::fmt::Display for KindChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(profile(self.0).title)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClipboardPolicy {
    #[default]
    Default,
    Copy,
    DoNotCopy,
}

impl ClipboardPolicy {
    pub const ALL: [Self; 3] = [Self::Default, Self::Copy, Self::DoNotCopy];

    pub fn should_copy(self, kind: ItemKind, configured: bool) -> bool {
        match self {
            Self::Default => configured && kind == ItemKind::Login,
            Self::Copy => true,
            Self::DoNotCopy => false,
        }
    }
}

impl std::fmt::Display for ClipboardPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Default => "Use persistent setting (logins only)",
            Self::Copy => "Copy",
            Self::DoNotCopy => "Do not copy",
        })
    }
}

/// A zxcvbn score (0–4) and its display rating.
pub type Strength = (u8, &'static str);

#[derive(Default)]
pub struct FieldDraft {
    pub original_name: Option<String>,
    pub name: String,
    pub value: SecretString,
    pub secret: bool,
    pub hidden: bool,
    pub value_edited: bool,
    pub changed: bool,
    pub removed: bool,
}

#[derive(Default)]
pub struct Draft {
    pub id: Option<usize>,
    pub revision: Option<u64>,
    pub name: String,
    pub username: String,
    pub kind: ItemKind,
    pub password: SecretString,
    /// Scored when `password` changes (see [`Draft::set_password`]), never per frame.
    pub password_strength: Option<Strength>,
    pub replace_password: bool,
    pub urls: Vec<String>,
    pub notes: text_editor::Content,
    pub original_notes: SecretString,
    pub notes_changed: bool,
    pub dirty: bool,
    pub fields: Vec<FieldDraft>,
    pub multiline: bool,
    pub secret_editor: text_editor::Content,
    pub copy_policy: ClipboardPolicy,
    /// Comma-separated tags as typed; parsed by [`parse_tags`] on save.
    pub tags: String,
    pub favorite: bool,
}

/// Split a comma-separated tag list, dropping blanks. The vault normalizes
/// spacing and duplicates and enforces the limits.
pub fn parse_tags(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_owned)
        .collect()
}

pub struct Validation {
    fields: Vec<Option<&'static str>>,
    pub error: Option<&'static str>,
}

impl Validation {
    pub fn field_error(&self, index: usize) -> Option<&'static str> {
        self.fields.get(index).copied().flatten()
    }
}

impl Draft {
    /// Replace the primary secret and score it once, so redraws only read the result.
    pub fn set_password(&mut self, value: SecretString) {
        self.password_strength = (!value.is_empty())
            .then(|| password_manager::password::strength_rating(value.expose()));
        self.password = value;
    }

    pub fn clear_password(&mut self) {
        self.password.zeroize();
        self.password_strength = None;
    }

    pub fn from_item(item: &ItemDetail) -> Self {
        let notes = item.notes.clone().unwrap_or_default();
        Self {
            id: Some(item.id),
            revision: Some(item.revision),
            name: item.name.clone(),
            username: item.username.clone().unwrap_or_default(),
            kind: item.kind,
            urls: item.urls.clone(),
            notes: text_editor::Content::with_text(&notes),
            original_notes: notes,
            tags: item.tags.join(", "),
            favorite: item.favorite,
            fields: item
                .fields
                .iter()
                .map(|field| FieldDraft {
                    original_name: Some(field.name.clone()),
                    name: field.name.clone(),
                    value: if field.secret {
                        SecretString::default()
                    } else {
                        field.value.clone().unwrap_or_default()
                    },
                    secret: field.secret,
                    hidden: field.secret,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    /// Public metadata and note previews only; primary and secret field values
    /// are deliberately excluded, even if a caller accidentally supplied them.
    pub fn conflict_summary(&self, original: &ItemDetail, latest: &ItemDetail) -> Vec<String> {
        fn preview(value: &str) -> String {
            let text: String = value.chars().take(240).collect();
            format!(
                "{}{}",
                text,
                if value.chars().count() > 240 {
                    "… (preview)"
                } else {
                    ""
                }
            )
        }
        fn comparison(label: &str, before: &str, latest: &str, local: &str) -> String {
            format!(
                "{label} · {}\nOriginal: {}\nLatest: {}\nYour edit: {}",
                if before != latest {
                    "also changed in another client"
                } else {
                    "only your edit"
                },
                preview(before),
                preview(latest),
                preview(local)
            )
        }
        let mut rows = Vec::new();
        if self.name != original.name {
            rows.push(comparison("Name", &original.name, &latest.name, &self.name));
        }
        if self.username != original.username.as_deref().unwrap_or_default() {
            rows.push(comparison(
                "Username / owner",
                original.username.as_deref().unwrap_or_default(),
                latest.username.as_deref().unwrap_or_default(),
                &self.username,
            ));
        }
        if self.kind != original.kind {
            rows.push(comparison(
                "Item type",
                &original.kind.to_string(),
                &latest.kind.to_string(),
                &self.kind.to_string(),
            ));
        }
        if parse_tags(&self.tags) != original.tags {
            rows.push(comparison(
                "Tags",
                &original.tags.join(", "),
                &latest.tags.join(", "),
                &parse_tags(&self.tags).join(", "),
            ));
        }
        if self.urls != original.urls {
            rows.push(comparison(
                "Websites",
                &original.urls.join("\n"),
                &latest.urls.join("\n"),
                &self.urls.join("\n"),
            ));
        }
        if self.notes_changed {
            rows.push(comparison(
                "Notes",
                original
                    .notes
                    .as_ref()
                    .map(SecretString::expose)
                    .unwrap_or_default(),
                latest
                    .notes
                    .as_ref()
                    .map(SecretString::expose)
                    .unwrap_or_default(),
                &self.notes.text(),
            ));
        }
        if self.replace_password {
            rows.push(
                "Password · your new value replaces the latest saved one. Saved values stay \
                 hidden, so password changes cannot be compared."
                    .into(),
            );
        }
        for field in &self.fields {
            if !(field.changed || field.removed || field.original_name.is_none()) {
                continue;
            }
            fn find<'a>(
                item: &'a ItemDetail,
                name: Option<&str>,
            ) -> Option<&'a password_manager::vault::ItemField> {
                item.fields.iter().find(|candidate| {
                    name.is_some_and(|name| candidate.name.eq_ignore_ascii_case(name))
                })
            }
            let before = find(original, field.original_name.as_deref());
            let remote = find(latest, field.original_name.as_deref());
            let secret = field.secret
                || before.as_ref().is_some_and(|f| f.secret)
                || remote.as_ref().is_some_and(|f| f.secret);
            if secret {
                rows.push(format!(
                    "Custom field {} · {}. Secret values stay hidden; your change replaces or \
                     removes the latest field.",
                    field.name,
                    if field.removed {
                        "remove field"
                    } else {
                        "set field"
                    }
                ));
            } else {
                rows.push(comparison(
                    &format!("Custom field {}", field.name),
                    before
                        .as_ref()
                        .and_then(|f| f.value.as_ref())
                        .map(SecretString::expose)
                        .unwrap_or("(absent)"),
                    remote
                        .as_ref()
                        .and_then(|f| f.value.as_ref())
                        .map(SecretString::expose)
                        .unwrap_or("(absent)"),
                    if field.removed {
                        "(removed)"
                    } else {
                        field.value.expose()
                    },
                ));
            }
        }
        rows
    }

    pub fn rebase(&self, original: &ItemDetail, latest: &ItemDetail) -> Self {
        let mut merged = Self::from_item(latest);
        if self.name != original.name {
            merged.name = self.name.clone();
        }
        if self.username != original.username.as_deref().unwrap_or_default() {
            merged.username = self.username.clone();
        }
        if self.kind != original.kind {
            merged.kind = self.kind;
        }
        if self.urls != original.urls {
            merged.urls = self.urls.clone();
        }
        if parse_tags(&self.tags) != original.tags {
            merged.tags = self.tags.clone();
        }
        if self.favorite != original.favorite {
            merged.favorite = self.favorite;
        }
        if self.notes_changed {
            merged.notes = text_editor::Content::with_text(&self.notes.text());
            merged.notes_changed = true;
        }
        if self.replace_password {
            merged.password = self.password.clone();
            merged.password_strength = self.password_strength;
            merged.replace_password = true;
        }
        for field in &self.fields {
            if !(field.changed || field.removed || field.original_name.is_none()) {
                continue;
            }
            if let Some(name) = &field.original_name {
                for existing in &mut merged.fields {
                    if existing
                        .original_name
                        .as_ref()
                        .is_some_and(|value| value.eq_ignore_ascii_case(name))
                    {
                        existing.removed = true;
                    }
                }
            }
            if !field.removed {
                merged.fields.push(FieldDraft {
                    original_name: None,
                    name: field.name.clone(),
                    value: field.value.clone(),
                    secret: field.secret,
                    hidden: field.hidden,
                    value_edited: field.value_edited,
                    changed: true,
                    removed: false,
                });
            }
        }
        merged.dirty = true;
        merged
    }

    pub fn validation(&self) -> Validation {
        let names: Vec<_> = self
            .fields
            .iter()
            .map(|field| (!field.removed).then(|| field.name.trim().to_lowercase()))
            .collect();
        let mut counts = std::collections::HashMap::new();
        for name in names.iter().flatten() {
            *counts.entry(name.as_str()).or_insert(0usize) += 1;
        }
        let fields: Vec<_> = self
            .fields
            .iter()
            .zip(&names)
            .map(|(field, name)| {
                let name = name.as_deref()?;
                if name.is_empty() {
                    Some("Give this field a name.")
                } else if counts[name] > 1 {
                    Some("Use a unique name for each custom field.")
                } else if (field.changed || field.original_name.is_none())
                    && field.hidden
                    && !field.value_edited
                {
                    Some("Enter a replacement value before changing this hidden field.")
                } else {
                    None
                }
            })
            .collect();
        let error = if self.name.trim().is_empty() {
            Some("Enter an item name.")
        } else {
            fields.iter().copied().flatten().next()
        };
        Validation { fields, error }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validation()
            .error
            .map_or(Ok(()), |error| Err(error.into()))
    }

    pub fn command(&self) -> Result<ServerCommand, String> {
        self.validate()?;
        let notes: SecretString = if self.notes_changed {
            self.notes.text().into()
        } else {
            self.original_notes.clone()
        };
        let urls: Vec<_> = self
            .urls
            .iter()
            .map(|url| url.trim())
            .filter(|url| !url.is_empty())
            .map(str::to_owned)
            .collect();
        let mut set_fields = Vec::new();
        let mut remove_fields = Vec::new();
        for field in &self.fields {
            if field.removed {
                if let Some(name) = &field.original_name {
                    remove_fields.push(name.clone());
                }
                continue;
            }
            let name = field.name.trim();
            if field.changed || field.original_name.is_none() {
                if let Some(original) = &field.original_name
                    && !original.eq_ignore_ascii_case(name)
                {
                    remove_fields.push(original.clone());
                }
                set_fields.push(CustomField {
                    name: name.to_owned(),
                    value: field.value.clone(),
                    secret: field.secret,
                });
            }
        }
        if let Some(id) = self.id {
            Ok(ServerCommand::Update(TypedUpdate {
                entry: EntryUpdate {
                    target: Target::Id(id),
                    update: EntryChanges {
                        name: Some(self.name.clone()),
                        username: Some(self.username.clone()),
                        url: urls.first().cloned(),
                        notes: Some(notes),
                    },
                    password: self.replace_password.then(|| self.password.clone()),
                },
                kind: Some(self.kind),
                add_url: urls.into_iter().skip(1).collect(),
                remove_url: vec![],
                clear_urls: true,
                set_fields,
                remove_fields,
                clear_fields: false,
                add_tags: parse_tags(&self.tags),
                remove_tags: vec![],
                clear_tags: true,
                favorite: Some(self.favorite),
            }))
        } else {
            Ok(ServerCommand::Add {
                entry: TypedEntry {
                    entry: PasswordEntry {
                        name: self.name.clone(),
                        username: Some(self.username.clone()),
                        password: self.password.clone(),
                        url: urls.first().cloned(),
                        notes: Some(notes),
                        copy: false,
                    },
                    kind: self.kind,
                    additional_urls: urls.into_iter().skip(1).collect(),
                    custom_fields: set_fields,
                    tags: parse_tags(&self.tags),
                    favorite: self.favorite,
                },
                copy_timeout: 0,
            })
        }
    }

    /// Apply the add-only override after building the command. A zero timeout
    /// disables all copying, including an explicit Copy choice.
    pub fn apply_copy_policy(
        &self,
        command: &mut ServerCommand,
        conf: &password_manager::config::Config,
    ) {
        if let ServerCommand::Add {
            entry,
            copy_timeout,
        } = command
        {
            entry.entry.copy = self
                .copy_policy
                .should_copy(entry.kind, conf.copy.passwords)
                && conf.clipboard.timeout > 0;
            *copy_timeout = conf.clipboard.timeout;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item() -> ItemDetail {
        ItemDetail {
            attachments: vec![],
            tags: vec![],
            favorite: false,
            id: 42,
            revision: 7,
            name: "Example".into(),
            username: Some("alice".into()),
            kind: ItemKind::Login,
            urls: vec!["https://a.test".into(), "https://b.test".into()],
            notes: Some("a\r\nb\r".into()),
            password: None,
            has_secret: true,
            fields: vec![password_manager::vault::ItemField {
                name: "token".into(),
                secret: true,
                value: None,
            }],
            has_totp: false,
            has_duo: false,
            otp_mode: None,
            is_passkey: false,
            created: String::new(),
            modified: String::new(),
        }
    }

    #[test]
    fn editing_metadata_preserves_password_hidden_fields_and_exact_notes() {
        let draft = Draft::from_item(&item());
        let ServerCommand::Update(update) = draft.command().unwrap() else {
            panic!()
        };
        assert_eq!(draft.revision, Some(7));
        assert!(update.entry.password.is_none());
        assert_eq!(update.entry.update.notes.unwrap().expose(), "a\r\nb\r");
        assert_eq!(update.entry.update.url, Some("https://a.test".into()));
        assert_eq!(update.add_url, vec!["https://b.test"]);
        assert!(update.clear_urls);
        assert!(update.set_fields.is_empty());
        assert!(!update.clear_fields);
    }

    #[test]
    fn password_replacement_is_explicit_and_can_clear_a_secret() {
        let mut draft = Draft::from_item(&item());
        draft.replace_password = true;
        let ServerCommand::Update(update) = draft.command().unwrap() else {
            panic!()
        };
        assert_eq!(update.entry.password.unwrap().expose(), "");
    }

    #[test]
    fn hidden_custom_fields_are_preserved_until_explicitly_replaced_or_removed() {
        let mut draft = Draft::from_item(&item());
        draft.fields[0].name = "renamed".into();
        draft.fields[0].changed = true;
        assert!(draft.command().is_err());
        draft.fields[0].value = "new secret".into();
        draft.fields[0].value_edited = true;
        let ServerCommand::Update(update) = draft.command().unwrap() else {
            panic!()
        };
        assert_eq!(update.remove_fields, vec!["token"]);
        assert_eq!(update.set_fields[0].name, "renamed");
        assert_eq!(update.set_fields[0].value.expose(), "new secret");
        assert!(update.set_fields[0].secret);
        draft.fields[0].removed = true;
        let ServerCommand::Update(update) = draft.command().unwrap() else {
            panic!()
        };
        assert_eq!(update.remove_fields, vec!["token"]);
        assert!(update.set_fields.is_empty());
    }

    #[test]
    fn new_items_accept_public_and_secret_fields_and_reject_duplicate_names() {
        let mut draft = Draft {
            name: "Router".into(),
            fields: vec![
                FieldDraft {
                    name: "ssid".into(),
                    value: "home".into(),
                    ..Default::default()
                },
                FieldDraft {
                    name: "passphrase".into(),
                    value: "wifi secret".into(),
                    secret: true,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let ServerCommand::Add { entry, .. } = draft.command().unwrap() else {
            panic!()
        };
        assert_eq!(entry.custom_fields.len(), 2);
        assert!(entry.custom_fields[1].secret);
        draft.fields[1].name = "SSID".into();
        assert!(draft.command().is_err());
    }

    #[test]
    fn gui_url_replacement_roundtrips_through_an_in_memory_vault() {
        use password_manager::vault::{Vault, VaultCredentials};

        let mut vault = Vault::memory();
        let mut credentials = VaultCredentials::default();
        let draft = Draft {
            name: "URL replacement".into(),
            password: "retained secret".into(),
            urls: vec!["https://old.test".into(), "https://old-extra.test".into()],
            ..Default::default()
        };
        let ServerCommand::Add { entry, .. } = draft.command().unwrap() else {
            panic!()
        };
        assert!(vault.add_typed_entry(entry, &mut credentials).unwrap());
        let target = Target::Name(draft.name.clone());
        let original = vault.target_detail(&target, false).unwrap();
        let mut draft = Draft::from_item(&original);
        draft.urls = vec![
            " ".into(),
            " https://new.test ".into(),
            "https://extra.test".into(),
            "https://new.test".into(),
        ];
        let ServerCommand::Update(update) = draft.command().unwrap() else {
            panic!()
        };
        assert!(
            vault
                .update_typed_entry_with_limit(update, &mut credentials, 10)
                .unwrap()
        );
        let saved = vault.target_detail(&target, true).unwrap();
        assert_eq!(saved.urls, vec!["https://new.test", "https://extra.test"]);
        assert_eq!(saved.password.unwrap().expose(), "retained secret");
        {
            let entries = vault.management_list(Default::default()).unwrap().items;
            assert_eq!(
                entries[0].urls.first().map(String::as_str),
                Some("https://new.test")
            );
            assert_eq!(entries[0].urls[1..], vec!["https://extra.test"]);
        }

        let mut draft = Draft::from_item(&vault.target_detail(&target, false).unwrap());
        draft.urls.clear();
        let ServerCommand::Update(update) = draft.command().unwrap() else {
            panic!()
        };
        assert!(update.entry.update.url.is_none());
        assert!(
            vault
                .update_typed_entry_with_limit(update, &mut credentials, 10)
                .unwrap()
        );
        assert!(vault.target_detail(&target, false).unwrap().urls.is_empty());
        let entries = vault.management_list(Default::default()).unwrap().items;
        assert!(entries[0].urls.is_empty());
    }

    #[test]
    fn add_copy_policy_preserves_login_defaults_and_explicit_choices_for_every_kind() {
        let mut conf = password_manager::config::Config::default();
        for configured in [false, true] {
            conf.copy.passwords = configured;
            for kind in KINDS {
                for policy in ClipboardPolicy::ALL {
                    let draft = Draft {
                        name: "New item".into(),
                        kind,
                        copy_policy: policy,
                        ..Default::default()
                    };
                    let mut command = draft.command().unwrap();
                    draft.apply_copy_policy(&mut command, &conf);
                    let ServerCommand::Add {
                        entry,
                        copy_timeout,
                    } = command
                    else {
                        panic!()
                    };
                    let expected = match policy {
                        ClipboardPolicy::Default => configured && kind == ItemKind::Login,
                        ClipboardPolicy::Copy => true,
                        ClipboardPolicy::DoNotCopy => false,
                    };
                    assert_eq!(entry.entry.copy, expected, "{kind:?}, {policy:?}");
                    assert_eq!(copy_timeout, conf.clipboard.timeout);
                }
            }
        }
        conf.clipboard.timeout = 0;
        let draft = Draft {
            name: "No clipboard".into(),
            copy_policy: ClipboardPolicy::Copy,
            ..Default::default()
        };
        let mut command = draft.command().unwrap();
        draft.apply_copy_policy(&mut command, &conf);
        let ServerCommand::Add {
            entry,
            copy_timeout,
        } = command
        else {
            panic!()
        };
        assert!(!entry.entry.copy);
        assert_eq!(copy_timeout, 0);
    }
}

#[cfg(test)]
mod merge_tests {
    use super::*;
    #[test]
    fn validation_preserves_unicode_duplicates_hidden_values_and_error_order() {
        let mut draft = Draft {
            name: "Item".into(),
            fields: vec![
                FieldDraft {
                    name: " ÉCOLE ".into(),
                    hidden: true,
                    ..Default::default()
                },
                FieldDraft {
                    name: "école".into(),
                    ..Default::default()
                },
                FieldDraft {
                    removed: true,
                    ..Default::default()
                },
                FieldDraft {
                    name: "Hidden".into(),
                    hidden: true,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let validation = draft.validation();
        assert_eq!(
            validation.error,
            Some("Use a unique name for each custom field.")
        );
        assert_eq!(validation.field_error(0), validation.field_error(1));
        assert_eq!(validation.field_error(2), None);
        assert_eq!(
            validation.field_error(3),
            Some("Enter a replacement value before changing this hidden field.")
        );
        draft.fields[1].removed = true;
        draft.fields[0].original_name = Some("ÉCOLE".into());
        assert_eq!(
            draft.validation().field_error(0),
            None,
            "unchanged hidden fields are preserved"
        );
        draft.fields[3].value_edited = true;
        assert!(draft.command().is_ok());
        draft.fields[0].name = " ".into();
        assert_eq!(draft.validation().error, Some("Give this field a name."));
        draft.name.clear();
        assert_eq!(draft.validate().unwrap_err(), "Enter an item name.");
    }
    #[test]
    fn reapply_preserves_concurrent_metadata_and_unedited_hidden_fields() {
        let original = ItemDetail {
            attachments: vec![],
            tags: vec![],
            favorite: false,
            id: 5,
            revision: 1,
            name: "Original".into(),
            username: Some("old-owner".into()),
            kind: ItemKind::Login,
            urls: vec!["https://old.test".into()],
            notes: None,
            password: None,
            has_secret: true,
            fields: vec![],
            has_totp: false,
            has_duo: false,
            otp_mode: None,
            is_passkey: false,
            created: String::new(),
            modified: String::new(),
        };
        let mut draft = Draft::from_item(&original);
        draft.name = "My edit".into();
        draft.replace_password = true;
        draft.password = "my-secret".into();
        let mut latest = original.clone();
        latest.revision = 2;
        latest.username = Some("new-owner".into());
        latest.urls = vec!["https://new.test".into()];
        latest.fields.push(password_manager::vault::ItemField {
            name: "server-added-token".into(),
            secret: true,
            value: None,
        });
        let merged = draft.rebase(&original, &latest);
        assert_eq!(merged.name, "My edit");
        assert_eq!(merged.username, "new-owner");
        assert_eq!(merged.urls, latest.urls);
        assert_eq!(merged.fields[0].name, "server-added-token");
        assert!(merged.fields[0].hidden);
        assert_eq!(merged.password.expose(), "my-secret");
        assert_eq!(merged.revision, Some(2));
        let ServerCommand::Update(update) = merged.command().unwrap() else {
            panic!()
        };
        assert!(update.set_fields.is_empty());
        assert!(update.remove_fields.is_empty());
    }
}
