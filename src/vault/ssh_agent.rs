//! Keys served by the local SSH agent. An SSH-key item is offered only when its
//! "SSH agent" custom field is `on` (or `confirm`, which asks before each use)
//! and its primary secret is an OpenSSH Ed25519 private key; a "Passphrase"
//! field decrypts a protected key. Only public keys and signatures leave the
//! vault, and a decrypted key is cached only while its vault stays unlocked.
// The agent itself is Unix-only; elsewhere this code is still compiled (and
// tested) but has no caller.
#![cfg_attr(not(unix), allow(dead_code))]
use super::*;
use ssh_key::{Algorithm, PrivateKey, Signature};

/// A public key blob (SSH wire encoding) and the item name as its comment.
pub(crate) struct SshIdentity {
    pub blob: Vec<u8>,
    pub comment: String,
}

/// Whether and how an item's key may be used through the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SshUse {
    Allow,
    Confirm,
}

/// A key the agent may sign with, found by its public blob.
#[derive(Debug, Clone)]
pub(crate) struct SshKeyMatch {
    pub id: usize,
    pub name: String,
    pub policy: SshUse,
}

const PASSPHRASE_FIELD: &str = "passphrase";
const AGENT_FIELD: &str = "ssh agent";

/// The decrypted key, kept until the item changes or its vault locks. Like the
/// other derived caches it never affects equality or persistence.
#[derive(Default)]
pub(super) struct CachedSshKey(std::sync::Arc<std::sync::OnceLock<Option<PrivateKey>>>);
impl Clone for CachedSshKey {
    fn clone(&self) -> Self {
        Self::default()
    }
}
impl PartialEq for CachedSshKey {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl std::fmt::Debug for CachedSshKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CachedSshKey(<redacted>)")
    }
}

impl Item {
    /// The parsed (possibly still encrypted) key, if this item holds one.
    fn ssh_key(&self) -> Option<PrivateKey> {
        if self.metadata.kind != ItemKind::SshKey {
            return None;
        }
        let text = self.entry.password.expose();
        if !text.contains("BEGIN OPENSSH PRIVATE KEY") {
            return None;
        }
        let key = PrivateKey::from_openssh(text.trim()).ok()?;
        (key.algorithm() == Algorithm::Ed25519).then_some(key)
    }
    fn ssh_field(&self, name: &str) -> Option<&SecretString> {
        self.metadata
            .custom_fields
            .iter()
            .find(|f| f.name.trim().eq_ignore_ascii_case(name))
            .map(|f| &f.value)
    }
    /// The item's agent setting; keys are off unless enabled.
    pub(crate) fn ssh_use(&self) -> Option<SshUse> {
        match self
            .ssh_field(AGENT_FIELD)?
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "on" | "yes" | "true" | "allow" => Some(SshUse::Allow),
            "confirm" | "ask" => Some(SshUse::Confirm),
            _ => None,
        }
    }
    /// The decrypted signing key, decrypting a protected key once.
    fn ssh_signing_key(&self) -> Option<&PrivateKey> {
        self.ssh
            .0
            .get_or_init(|| {
                let key = self.ssh_key()?;
                if key.is_encrypted() {
                    key.decrypt(self.ssh_field(PASSPHRASE_FIELD)?.expose()).ok()
                } else {
                    Some(key)
                }
            })
            .as_ref()
    }
}

impl Vault {
    /// Keys the agent can offer. Encrypted keys need a passphrase field; their
    /// public half is readable without decrypting them.
    pub(crate) fn ssh_identities(&self) -> Vec<SshIdentity> {
        self.active_items()
            .filter(|item| item.ssh_use().is_some())
            .filter_map(|item| {
                let key = item.ssh_key()?;
                if key.is_encrypted() && item.ssh_field(PASSPHRASE_FIELD).is_none() {
                    return None;
                }
                Some(SshIdentity {
                    blob: key.public_key().to_bytes().ok()?,
                    comment: item.entry.name.clone(),
                })
            })
            .collect()
    }

    /// The enabled key with this public blob.
    pub(crate) fn ssh_key_for(&self, blob: &[u8]) -> Option<SshKeyMatch> {
        self.active_items().find_map(|item| {
            let policy = item.ssh_use()?;
            let key = item.ssh_key()?;
            (key.public_key().to_bytes().ok()? == blob).then(|| SshKeyMatch {
                id: item.entry.id,
                name: item.entry.name.clone(),
                policy,
            })
        })
    }

    /// Signs `data` with item `id`, if it is still the enabled key for `blob`,
    /// returning the SSH signature encoding (algorithm name, then signature).
    pub(crate) fn ssh_sign(&self, id: usize, blob: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        let item = self
            .item(id)
            .filter(|item| item.active() && item.ssh_use().is_some())?;
        let key = item.ssh_signing_key()?;
        if key.public_key().to_bytes().ok()? != blob {
            return None;
        }
        let signature: Signature = signature::Signer::try_sign(key, data).ok()?;
        let mut encoded = Vec::new();
        put_string(&mut encoded, signature.algorithm().as_str().as_bytes());
        put_string(&mut encoded, signature.as_bytes());
        Some(encoded)
    }
}

/// SSH `string`: a big-endian u32 length followed by the bytes.
pub(crate) fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A synthetic key generated only for these tests.
    pub(crate) fn test_key(passphrase: Option<&str>) -> (String, Vec<u8>) {
        let key = PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]));
        let key = match passphrase {
            Some(pass) => key.encrypt(&mut rand_core_compat::Rng, pass).unwrap(),
            None => key,
        };
        let blob = key.public_key().to_bytes().unwrap();
        (
            key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string(),
            blob,
        )
    }

    mod rand_core_compat {
        /// ssh-key 0.6 uses rand_core 0.6; adapt the OS generator for key encryption.
        pub struct Rng;
        impl ssh_key::rand_core::RngCore for Rng {
            fn next_u32(&mut self) -> u32 {
                rand::random()
            }
            fn next_u64(&mut self) -> u64 {
                rand::random()
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                for byte in dest {
                    *byte = rand::random();
                }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ssh_key::rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
        impl ssh_key::rand_core::CryptoRng for Rng {}
    }

    /// Adds an SSH-key item. `agent` is the item's "SSH agent" field value.
    pub(crate) fn add_key(
        vault: &mut Vault,
        name: &str,
        secret: &str,
        passphrase: Option<&str>,
        kind: ItemKind,
        agent: Option<&str>,
    ) -> usize {
        let mut key = VaultCredentials::default();
        let field = |name: &str, value: &str, secret: bool| CustomField {
            name: name.into(),
            value: value.into(),
            secret,
        };
        let mut custom_fields = Vec::new();
        if let Some(pass) = passphrase {
            custom_fields.push(field("Passphrase", pass, true));
        }
        if let Some(agent) = agent {
            custom_fields.push(field("SSH agent", agent, false));
        }
        vault
            .add_typed_entry(
                TypedEntry {
                    entry: PasswordEntry {
                        name: name.into(),
                        username: None,
                        password: secret.into(),
                        url: None,
                        notes: None,
                        copy: false,
                    },
                    kind,
                    additional_urls: vec![],
                    custom_fields,
                    tags: vec![],
                    favorite: false,
                },
                &mut key,
            )
            .unwrap();
        vault.entry_id(&Target::Name(name.into())).unwrap().unwrap()
    }

    fn parts(signed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut reader = signed;
        let mut take = || {
            let len = u32::from_be_bytes(reader[..4].try_into().unwrap()) as usize;
            let value = reader[4..4 + len].to_vec();
            reader = &reader[4 + len..];
            value
        };
        (take(), take())
    }

    #[test]
    fn only_enabled_ed25519_keys_are_listed_and_they_sign_verifiably() {
        use signature::Verifier;
        let mut vault = Vault::memory();
        let (plain, plain_blob) = test_key(None);
        let garbage = "-----BEGIN OPENSSH PRIVATE KEY-----\nnope";
        // Only the first is enabled, parseable, and an SSH-key item.
        let mut ids = Vec::new();
        for (name, secret, kind, agent) in [
            ("Deploy key", plain.as_str(), ItemKind::SshKey, Some("on")),
            ("Not enabled", &plain, ItemKind::SshKey, None),
            ("Off", &plain, ItemKind::SshKey, Some("no")),
            ("Not SSH", &plain, ItemKind::SecureNote, Some("on")),
            ("Garbage", garbage, ItemKind::SshKey, Some("on")),
        ] {
            ids.push(add_key(&mut vault, name, secret, None, kind, agent));
        }
        let deploy = ids[0];
        let identities = vault.ssh_identities();
        assert_eq!(
            identities.len(),
            1,
            "only enabled, parseable SSH-key items are offered"
        );
        assert_eq!(identities[0].comment, "Deploy key");
        assert_eq!(identities[0].blob, plain_blob);

        let found = vault.ssh_key_for(&plain_blob).unwrap();
        assert_eq!((found.id, found.policy), (deploy, SshUse::Allow));
        let (algorithm, raw) = parts(&vault.ssh_sign(deploy, &plain_blob, b"challenge").unwrap());
        assert_eq!(algorithm, b"ssh-ed25519");
        let signature = Signature::new(Algorithm::Ed25519, raw).unwrap();
        let public = ssh_key::PublicKey::from_bytes(&plain_blob).unwrap();
        public.key_data().verify(b"challenge", &signature).unwrap();
        assert!(vault.ssh_key_for(b"unknown blob").is_none());
        assert!(
            vault
                .ssh_sign(deploy, b"other blob", b"challenge")
                .is_none()
        );
        assert!(vault.ssh_sign(999, &plain_blob, b"challenge").is_none());
    }

    #[test]
    fn protected_keys_need_their_passphrase_and_confirmation_is_per_key() {
        let mut vault = Vault::memory();
        let (encrypted, blob) = test_key(Some("synthetic-pass"));
        add_key(
            &mut vault,
            "No passphrase",
            &encrypted,
            None,
            ItemKind::SshKey,
            Some("on"),
        );
        assert!(vault.ssh_identities().is_empty());
        let wrong = add_key(
            &mut vault,
            "Wrong passphrase",
            &encrypted,
            Some("other"),
            ItemKind::SshKey,
            Some("on"),
        );
        assert_eq!(vault.ssh_identities().len(), 1);
        assert!(
            vault.ssh_sign(wrong, &blob, b"data").is_none(),
            "a wrong passphrase cannot sign"
        );
        let mut vault = Vault::memory();
        let id = add_key(
            &mut vault,
            "Protected",
            &encrypted,
            Some("synthetic-pass"),
            ItemKind::SshKey,
            Some("Confirm"),
        );
        assert_eq!(vault.ssh_key_for(&blob).unwrap().policy, SshUse::Confirm);
        assert!(vault.ssh_sign(id, &blob, b"data").is_some());
        // The decrypted key is reused until the item changes.
        assert!(vault.item(id).unwrap().ssh.0.get().is_some());
        assert!(vault.ssh_sign(id, &blob, b"again").is_some());
        vault.item_mut(id).unwrap();
        assert!(
            vault.item(id).unwrap().ssh.0.get().is_none(),
            "editing an item drops its cached key"
        );
    }
}
