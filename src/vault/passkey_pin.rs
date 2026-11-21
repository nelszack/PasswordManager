//! A per-device passkey PIN for confirming browser passkey requests in the
//! desktop app or CLI, mainly for key-file vaults, which have no master
//! password to type. Only a keyed check value is stored, in
//! `passkey-pins.json` in the local data directory. The key is derived from the
//! unlocked vault's encryption key, so the file alone cannot be used to guess
//! the PIN, and changing the vault's credentials retires it.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const FILE: &str = "passkey-pins.json";
pub(crate) const MIN_PIN_CHARS: usize = 6;
const MAX_PIN_BYTES: usize = 256;
const MAX_FILE_BYTES: u64 = 256 * 1024;

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    /// Identifies the vault key the PIN was set with.
    key_id: String,
    salt: String,
    check: String,
}

fn path(dir: &Path) -> PathBuf {
    dir.join(FILE)
}

fn pin_key(encryption_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(
        "password-manager passkey pin v1",
        encryption_key,
    ))
}

fn key_id(key: &[u8; 32]) -> String {
    blake3::keyed_hash(key, b"key id").to_hex().to_string()
}

fn check(key: &[u8; 32], salt: &[u8], pin: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(salt);
    hasher.update(pin.as_bytes());
    *hasher.finalize().as_bytes()
}

fn read(dir: &Path) -> BTreeMap<String, Entry> {
    crate::file::read_bounded_file(&path(dir), MAX_FILE_BYTES)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn entry(dir: &Path, vault_id: &[u8; 16], key: &[u8; 32]) -> Option<Entry> {
    read(dir)
        .remove(&hex::encode(vault_id))
        .filter(|entry| entry.key_id == key_id(key))
}

/// Whether a PIN is set for this vault key on this device.
pub(crate) fn is_set(dir: &Path, vault_id: &[u8; 16], encryption_key: &[u8; 32]) -> bool {
    entry(dir, vault_id, &pin_key(encryption_key)).is_some()
}

/// Whether `pin` is this vault's passkey PIN, compared in constant time.
pub(crate) fn matches(
    dir: &Path,
    vault_id: &[u8; 16],
    encryption_key: &[u8; 32],
    pin: &str,
) -> bool {
    let key = pin_key(encryption_key);
    let Some(entry) = entry(dir, vault_id, &key) else {
        return false;
    };
    let (Ok(salt), Ok(expected)) = (hex::decode(&entry.salt), hex::decode(&entry.check)) else {
        return false;
    };
    pin.len() <= MAX_PIN_BYTES && bool::from(check(&key, &salt, pin).ct_eq(expected.as_slice()))
}

/// Set, replace, or (with `None`) remove the PIN for this vault.
pub(crate) fn set(
    dir: &Path,
    vault_id: &[u8; 16],
    encryption_key: &[u8; 32],
    pin: Option<&str>,
) -> Result<(), String> {
    let mut entries = read(dir);
    let name = hex::encode(vault_id);
    match pin {
        None => {
            if entries.remove(&name).is_none() {
                return Ok(());
            }
        }
        Some(pin) => {
            if pin.chars().count() < MIN_PIN_CHARS {
                return Err(format!(
                    "Use a passkey PIN of at least {MIN_PIN_CHARS} characters."
                ));
            }
            if pin.len() > MAX_PIN_BYTES {
                return Err("The passkey PIN is too long.".into());
            }
            let key = pin_key(encryption_key);
            let salt: [u8; 16] = rand::random();
            entries.insert(
                name,
                Entry {
                    key_id: key_id(&key),
                    salt: hex::encode(salt),
                    check: hex::encode(check(&key, &salt, pin)),
                },
            );
        }
    }
    let bytes = serde_json::to_vec_pretty(&entries).map_err(|e| e.to_string())?;
    crate::cloud::write_private(&path(dir), &bytes, true)
        .map_err(|e| format!("Could not save the passkey PIN: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pin_matches_only_its_vault_key_and_can_be_removed() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, key, other_key) = ([1; 16], [2; 32], [3; 32]);
        assert!(!is_set(dir.path(), &vault, &key));
        assert!(
            set(dir.path(), &vault, &key, Some("12345")).is_err(),
            "too short"
        );
        set(dir.path(), &vault, &key, Some("246810")).unwrap();
        assert!(is_set(dir.path(), &vault, &key));
        assert!(matches(dir.path(), &vault, &key, "246810"));
        assert!(!matches(dir.path(), &vault, &key, "246811"));
        assert!(
            !matches(dir.path(), &[9; 16], &key, "246810"),
            "other vault"
        );
        assert!(
            !is_set(dir.path(), &vault, &other_key),
            "new credentials retire the PIN"
        );
        assert!(!matches(dir.path(), &vault, &other_key, "246810"));
        let stored = std::fs::read_to_string(dir.path().join(FILE)).unwrap();
        assert!(!stored.contains("246810"));
        set(dir.path(), &vault, &key, None).unwrap();
        assert!(!is_set(dir.path(), &vault, &key));
        set(dir.path(), &vault, &key, None).unwrap();
    }
}
