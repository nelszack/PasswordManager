//! Device-local display names. Encrypted vault filenames remain unchanged.
use password_manager::{
    file::{set_private_perms, sync_parent},
    vault::validate_vault_filename,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Write, path::Path};

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
        let parent = path
            .parent()
            .ok_or("Could not locate the vault-name directory.")?;
        let mut file = tempfile::NamedTempFile::new_in(parent)
            .map_err(|_| "Could not save the vault name.")?;
        set_private_perms(file.path()).map_err(|_| "Could not protect local vault names.")?;
        file.write_all(
            &serde_json::to_vec_pretty(&names).map_err(|_| "Could not encode vault names.")?,
        )
        .and_then(|_| file.as_file().sync_all())
        .map_err(|_| "Could not save the vault name.")?;
        file.persist(path)
            .map_err(|_| "Could not replace local vault names.")?;
        sync_parent(path).map_err(|_| "Could not sync local vault names.")?;
        Ok(names)
    }
    pub fn label(&self, id: &str, vaults: &[String]) -> String {
        self.0.get(id).cloned().unwrap_or_else(|| {
            if vaults.len() == 1 {
                "Personal vault".into()
            } else {
                format!(
                    "Vault {}",
                    vaults
                        .iter()
                        .position(|value| value == id)
                        .map_or(1, |index| index + 1)
                )
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
