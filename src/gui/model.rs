use iced::widget::text_editor;
use password_manager::{
    secret::SecretString,
    types::{
        CustomField, EntryChanges, EntryUpdate, ItemKind, PasswordEntry, ServerCommand, Target,
        TypedEntry, TypedUpdate,
    },
    vault::ItemDetail,
};

pub const KINDS: [ItemKind; 8] = [
    ItemKind::Login,
    ItemKind::SecureNote,
    ItemKind::PaymentCard,
    ItemKind::Identity,
    ItemKind::Wifi,
    ItemKind::SoftwareLicense,
    ItemKind::SshKey,
    ItemKind::ApiSecret,
];

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
}

impl Draft {
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

    pub fn command(&self) -> Result<ServerCommand, String> {
        if self.name.trim().is_empty() {
            return Err("Enter an item name.".into());
        }
        // Do not normalize existing multiline notes when another field changes.
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
        let mut names = std::collections::HashSet::new();
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
            if name.is_empty() {
                return Err("Custom fields need a name.".into());
            }
            if !names.insert(name.to_lowercase()) {
                return Err(format!("Custom field names must be unique: {name}."));
            }
            if field.changed || field.original_name.is_none() {
                if field.hidden && !field.value_edited {
                    return Err(format!(
                        "Enter a replacement value before renaming or changing hidden field {name}."
                    ));
                }
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
        use password_manager::{
            types::ListOptions,
            vault::{Vault, VaultCredentials},
        };

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
            let entries = vault.view_entries(ListOptions::default()).unwrap();
            assert_eq!(entries[0].entry.url.as_deref(), Some("https://new.test"));
            assert_eq!(
                entries[0].metadata.unwrap().additional_urls,
                vec!["https://extra.test"]
            );
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
        let entries = vault.view_entries(ListOptions::default()).unwrap();
        assert!(entries[0].entry.url.is_none());
        assert!(entries[0].metadata.unwrap().additional_urls.is_empty());
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
