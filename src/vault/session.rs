use super::{Vault, VaultError};
use crate::types::PasswordType;
use zeroize::{Zeroize, Zeroizing};

/// Credentials used while staging a command. Never the live session state.
#[derive(Debug)]
pub struct VaultCredentials {
    pub locked: bool,
    pub keypass: Option<PasswordType>,
}
impl Default for VaultCredentials {
    fn default() -> Self {
        Self {
            locked: true,
            keypass: None,
        }
    }
}
impl Zeroize for VaultCredentials {
    fn zeroize(&mut self) {
        self.keypass.zeroize();
        self.locked = true;
    }
}
impl Drop for VaultCredentials {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// An unlocked capability always owns both the vault and its encryption key.
#[derive(Debug)]
pub struct UnlockedVault {
    pub(crate) vault: Vault,
    key: SessionKey,
    epoch: u64,
}

/// Cached encryption material cannot contain a master password or key path and
/// has no serialization implementation. External credentials exist only during
/// unlock/rekey; the live session keeps this dedicated key type.
struct SessionKey {
    encryption_key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    kdf: u8,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}
impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey(<redacted>)")
    }
}
impl SessionKey {
    fn from_cached(mut key: PasswordType) -> Option<Self> {
        let PasswordType::Session {
            encryption_key,
            salt,
            kdf,
            memory_kib,
            iterations,
            parallelism,
        } = &mut key
        else {
            return None;
        };
        Some(Self {
            encryption_key: Zeroizing::new(std::mem::take(encryption_key)),
            salt: *salt,
            kdf: *kdf,
            memory_kib: *memory_kib,
            iterations: *iterations,
            parallelism: *parallelism,
        })
    }
    fn into_staging(self) -> PasswordType {
        PasswordType::Session {
            encryption_key: *self.encryption_key,
            salt: self.salt,
            kdf: self.kdf,
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
        }
    }
}
#[derive(Debug, Default)]
pub enum VaultSession {
    #[default]
    Locked,
    Unlocked(Box<UnlockedVault>),
}
impl VaultSession {
    #[cfg(test)]
    pub fn unlock(vault: Vault, key: PasswordType) -> Self {
        Self::Unlocked(Box::new(UnlockedVault {
            vault,
            key: SessionKey::from_cached(key)
                .expect("test sessions require cached encryption material"),
            epoch: rand::random(),
        }))
    }
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Locked)
    }
    pub fn lock(&mut self) {
        *self = Self::Locked;
    }
    pub(crate) fn epoch(&self) -> Option<u64> {
        match self {
            Self::Locked => None,
            Self::Unlocked(live) => Some(live.epoch),
        }
    }
    pub(crate) fn vault(&self) -> Option<&Vault> {
        match self {
            Self::Locked => None,
            Self::Unlocked(live) => Some(&live.vault),
        }
    }
    /// Restore a complete unlocked capability or discard all staged secrets on
    /// every return. The transient staging state never becomes live state.
    pub(crate) fn edit(&mut self) -> SessionEdit<'_> {
        let (credentials, vault, epoch) = match std::mem::take(self) {
            Self::Locked => (VaultCredentials::default(), None, rand::random()),
            Self::Unlocked(live) => {
                let UnlockedVault { vault, key, epoch } = *live;
                (
                    VaultCredentials {
                        locked: false,
                        keypass: Some(key.into_staging()),
                    },
                    Some(vault),
                    epoch,
                )
            }
        };
        SessionEdit {
            session: self,
            credentials,
            vault,
            epoch,
        }
    }
}
pub(crate) struct SessionEdit<'a> {
    session: &'a mut VaultSession,
    credentials: VaultCredentials,
    vault: Option<Vault>,
    epoch: u64,
}
impl SessionEdit<'_> {
    pub(crate) fn parts_mut(&mut self) -> (&mut VaultCredentials, &mut Option<Vault>) {
        (&mut self.credentials, &mut self.vault)
    }
}
impl Drop for SessionEdit<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking()
            && !self.credentials.locked
            && let (Some(vault), Some(key)) = (self.vault.take(), self.credentials.keypass.take())
            && let Some(key) = SessionKey::from_cached(key)
        {
            *self.session = VaultSession::Unlocked(Box::new(UnlockedVault {
                vault,
                key,
                epoch: self.epoch,
            }));
        }
    }
}
pub(crate) fn available(vault: &mut Option<Vault>) -> Result<&mut Vault, VaultError> {
    vault.as_mut().ok_or(VaultError::Locked)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn staging_cannot_install_an_unkeyed_or_missing_vault() {
        let mut session = VaultSession::default();
        {
            let mut edit = session.edit();
            edit.credentials.locked = false;
            edit.vault = Some(Vault::default());
        }
        assert!(session.is_locked());
        {
            let mut edit = session.edit();
            edit.credentials.locked = false;
            edit.credentials.keypass = Some(PasswordType::Password("synthetic".into()));
        }
        assert!(session.is_locked());
    }
    #[test]
    fn unwinding_fails_closed() {
        let mut session = VaultSession::unlock(
            Vault::default(),
            PasswordType::Session {
                encryption_key: [42; 32],
                salt: [42; 16],
                kdf: 1,
                memory_kib: 8192,
                iterations: 1,
                parallelism: 1,
            },
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _edit = session.edit();
            panic!("synthetic command failure");
        }));
        assert!(result.is_err());
        assert!(session.is_locked());
    }
}
