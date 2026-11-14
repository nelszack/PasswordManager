//! Device-local display names. Encrypted vault filenames remain unchanged.
use password_manager::{
    file::{AtomicWriteMode, atomic_write_private},
    vault::validate_vault_filename,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct Names(pub BTreeMap<String, String>);

impl Names {
    pub fn read(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(value) => serde_json::from_str(&value).map_err(|_| {
                "Could not read local vault names. The vault files have not been changed.".into()
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(_) => Err("Could not read local vault names.".into()),
        }
    }
    pub fn save(path: &Path, id: &str, label: &str) -> Result<Self, String> {
        validate_vault_filename(id).map_err(|error| error.to_string())?;
        let label = label.trim();
        validate_name(label)?;
        let mut names = Self::read(path)?;
        names.0.insert(id.into(), label.into());
        let bytes =
            serde_json::to_vec_pretty(&names).map_err(|_| "Could not encode vault names.")?;
        atomic_write_private(path, &bytes, AtomicWriteMode::Replace)
            .map_err(|error| format!("Could not save vault name: {error}"))?;
        Ok(names)
    }
    pub fn label(&self, id: &str, vaults: &[String]) -> String {
        self.label_at(
            id,
            vaults.iter().position(|value| value == id).unwrap_or(0),
            vaults.len(),
        )
    }
    pub fn label_at(&self, id: &str, index: usize, total: usize) -> String {
        self.0.get(id).cloned().unwrap_or_else(|| {
            if total == 1 {
                "Personal vault".into()
            } else {
                format!("Vault {}", index + 1)
            }
        })
    }
}

pub(super) fn validate_name(label: &str) -> Result<(), &'static str> {
    let label = label.trim();
    if label.is_empty() || label.chars().count() > 80 || label.chars().any(char::is_control) {
        Err("Choose a vault name with 1–80 characters and no line breaks.")
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Choice {
    pub id: String,
    pub label: String,
}
impl std::fmt::Display for Choice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn indexed_and_lookup_labels_share_the_same_defaults_and_names() {
        let mut names = Names::default();
        for vaults in [
            vec!["one.enc".to_owned()],
            vec!["one.enc".to_owned(), "two.enc".to_owned()],
        ] {
            for (index, id) in vaults.iter().enumerate() {
                assert_eq!(
                    names.label_at(id, index, vaults.len()),
                    names.label(id, &vaults)
                );
            }
        }
        names.0.insert("one.enc".into(), "Named vault".into());
        assert_eq!(names.label_at("one.enc", 0, 2), "Named vault");
        assert_eq!(names.label_at("two.enc", 1, 2), "Vault 2");
        assert_eq!(Names::default().label_at("one.enc", 0, 1), "Personal vault");
    }
    #[test]
    fn labels_are_atomic_separate_from_vault_files_and_preserve_other_names() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("names.json");
        Names::save(&path, "first.enc", "Personal").unwrap();
        let names = Names::save(&path, "second.enc", "Work").unwrap();
        assert_eq!(names.0["first.enc"], "Personal");
        assert_eq!(names.0["second.enc"], "Work");
        let before = std::fs::read(&path).unwrap();
        for (id, label) in [
            ("../outside.enc", "Name"),
            ("first.enc", ""),
            ("first.enc", "a\nb"),
        ] {
            assert!(Names::save(&path, id, label).is_err());
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
