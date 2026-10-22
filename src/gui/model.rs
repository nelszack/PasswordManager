use iced::widget::text_editor;
use password_manager::{
    secret::SecretString,
    types::{
        EntryChanges, EntryUpdate, ItemKind, PasswordEntry, ServerCommand, Target, TypedEntry,
        TypedUpdate,
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
            .filter(|url| !url.trim().is_empty())
            .cloned()
            .collect();
        if let Some(id) = self.id {
            Ok(ServerCommand::Update(TypedUpdate {
                entry: EntryUpdate {
                    target: Target::Id(id),
                    update: EntryChanges {
                        name: Some(self.name.clone()),
                        username: Some(self.username.clone()),
                        url: None,
                        notes: Some(notes),
                    },
                    password: self.replace_password.then(|| self.password.clone()),
                },
                kind: Some(self.kind),
                add_url: urls,
                remove_url: vec![],
                clear_urls: true,
                // This editor does not change custom fields or authenticators.
                set_fields: vec![],
                remove_fields: vec![],
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
                    custom_fields: vec![],
                },
                copy_timeout: 0,
            })
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
        assert_eq!(update.add_url, item().urls);
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
}
