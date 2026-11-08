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

pub struct Profile {
    pub title: &'static str,
    pub owner: &'static str,
    pub secret: &'static str,
    pub name_hint: &'static str,
    pub guidance: &'static str,
    pub suggested: &'static [(&'static str, bool)],
}
pub fn profile(kind: ItemKind) -> Profile {
    match kind {
        ItemKind::Login => Profile {
            title: "Login",
            owner: "Username or email",
            secret: "Password",
            name_hint: "e.g. Personal email",
            guidance: "Save sign-in details and the websites where they work.",
            suggested: &[],
        },
        ItemKind::SecureNote => Profile {
            title: "Secure note",
            owner: "Owner (optional)",
            secret: "Private content",
            name_hint: "e.g. Recovery instructions",
            guidance: "Store private content. Choose the multiline editor for longer text.",
            suggested: &[],
        },
        ItemKind::PaymentCard => Profile {
            title: "Payment card",
            owner: "Cardholder",
            secret: "Card number",
            name_hint: "e.g. Everyday card",
            guidance: "Keep your card number, cardholder, and optional expiry and security code together.",
            suggested: &[
                ("Expiry", false),
                ("Security code", true),
                ("Billing address", false),
            ],
        },
        ItemKind::Identity => Profile {
            title: "Identity",
            owner: "Full name",
            secret: "Identity number (optional)",
            name_hint: "e.g. Personal identity",
            guidance: "Store identity and contact details. Add the fields you need below.",
            suggested: &[
                ("Email", false),
                ("Phone", false),
                ("Address", false),
                ("Date of birth", true),
            ],
        },
        ItemKind::Wifi => Profile {
            title: "Wi-Fi",
            owner: "Network name (SSID)",
            secret: "Wi-Fi password",
            name_hint: "e.g. Home Wi-Fi",
            guidance: "Save the network name and the password used to join it.",
            suggested: &[("Security", false), ("Router address", false)],
        },
        ItemKind::SoftwareLicense => Profile {
            title: "Software license",
            owner: "Licensed to",
            secret: "License key",
            name_hint: "e.g. Photo editor license",
            guidance: "Keep the license key with the product, version, and renewal details.",
            suggested: &[("Software", false), ("Version", false), ("Expires", false)],
        },
        ItemKind::SshKey => Profile {
            title: "SSH key",
            owner: "User or host",
            secret: "Private key",
            name_hint: "e.g. Production SSH key",
            guidance: "Store the private key with its connection details. Use the multiline editor to paste a key.",
            suggested: &[
                ("Hostname", false),
                ("Port", false),
                ("Public key", false),
                ("Passphrase", true),
            ],
        },
        ItemKind::ApiSecret => Profile {
            title: "API secret",
            owner: "Account or service",
            secret: "API key or token",
            name_hint: "e.g. Development API token",
            guidance: "Store the token issued by your service, plus its environment and expiry.",
            suggested: &[
                ("Endpoint", false),
                ("Environment", false),
                ("Expires", false),
            ],
        },
    }
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
            rows.push("Primary secret · your replacement will replace the latest stored value. Stored values stay hidden; secret changes cannot be compared.".into());
        }
        for field in &self.fields {
            if !(field.changed || field.removed || field.original_name.is_none()) {
                continue;
            }
            let find = |item: &ItemDetail| {
                item.fields
                    .iter()
                    .find(|candidate| {
                        field
                            .original_name
                            .as_ref()
                            .is_some_and(|name| candidate.name.eq_ignore_ascii_case(name))
                    })
                    .cloned()
            };
            let before = find(original);
            let remote = find(latest);
            let secret = field.secret
                || before.as_ref().is_some_and(|f| f.secret)
                || remote.as_ref().is_some_and(|f| f.secret);
            if secret {
                rows.push(format!("Custom field {} · {}. Secret values stay hidden; your change replaces or removes the latest field.", field.name, if field.removed { "remove field" } else { "set field" }));
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
        if self.notes_changed {
            merged.notes = text_editor::Content::with_text(&self.notes.text());
            merged.notes_changed = true;
        }
        if self.replace_password {
            merged.password = self.password.clone();
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

    pub fn field_error(&self, index: usize) -> Option<String> {
        let field = self.fields.get(index).filter(|field| !field.removed)?;
        let name = field.name.trim();
        if name.is_empty() {
            return Some("Give this field a name.".into());
        }
        if self.fields.iter().enumerate().any(|(other, candidate)| {
            other != index
                && !candidate.removed
                && candidate.name.trim().to_lowercase() == name.to_lowercase()
        }) {
            return Some("Use a unique name for each custom field.".into());
        }
        if (field.changed || field.original_name.is_none()) && field.hidden && !field.value_edited {
            return Some("Enter a replacement value before changing this hidden field.".into());
        }
        None
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("Enter an item name.".into());
        }
        for index in 0..self.fields.len() {
            if let Some(error) = self.field_error(index) {
                return Err(error);
            }
        }
        Ok(())
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
    fn reapply_preserves_concurrent_metadata_and_unedited_hidden_fields() {
        let original = ItemDetail {
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
