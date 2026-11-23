//! Device-local display names shared by the desktop app and the CLI.
//! Encrypted vault filenames remain unchanged.
use crate::{
    file::{AtomicWriteMode, atomic_write_private, config_dir},
    vault::validate_vault_filename,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Names(pub BTreeMap<String, String>);

/// The device-local names file in the configuration directory.
pub fn path() -> std::path::PathBuf {
    config_dir().join("vault-names.json")
}

impl Names {
    /// Names from the default location; a missing or unreadable file means no names.
    pub fn load() -> Self {
        Self::read(&path()).unwrap_or_default()
    }
    /// Resolve a vault given by display name (case-insensitive) or `.enc` filename.
    pub fn resolve(&self, wanted: &str, vaults: &[String]) -> Result<String, String> {
        // Filenames pass through; the server reports missing or invalid ones.
        if vaults.iter().any(|id| id == wanted) || wanted.ends_with(".enc") {
            return Ok(wanted.to_owned());
        }
        let matches: Vec<_> = vaults
            .iter()
            .enumerate()
            .filter(|(index, id)| {
                self.label_at(id, *index, vaults.len())
                    .eq_ignore_ascii_case(wanted.trim())
            })
            .map(|(_, id)| id.clone())
            .collect();
        match matches.as_slice() {
            [id] => Ok(id.clone()),
            [] => Err(format!(
                "No vault is named {wanted:?}. Run `pm vaults` to see vault names."
            )),
            _ => Err(format!(
                "Several vaults are named {wanted:?}; choose one by its .enc file from `pm vaults`."
            )),
        }
    }
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

pub fn validate_name(label: &str) -> Result<(), &'static str> {
    let label = label.trim();
    if label.is_empty() || label.chars().count() > 80 || label.chars().any(char::is_control) {
        Err("Choose a vault name with 1–80 characters and no line breaks.")
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choice {
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
    fn vaults_resolve_by_name_ignoring_case_or_by_filename() {
        let vaults = vec!["a.enc".to_owned(), "b.enc".to_owned()];
        let mut names = Names::default();
        names.0.insert("a.enc".into(), "Work".into());
        assert_eq!(names.resolve("work", &vaults).unwrap(), "a.enc");
        assert_eq!(names.resolve("b.enc", &vaults).unwrap(), "b.enc");
        assert_eq!(names.resolve("Vault 2", &vaults).unwrap(), "b.enc");
        assert!(
            names
                .resolve("Home", &vaults)
                .unwrap_err()
                .contains("pm vaults")
        );
        names.0.insert("b.enc".into(), "work".into());
        assert!(names.resolve("Work", &vaults).is_err());
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
