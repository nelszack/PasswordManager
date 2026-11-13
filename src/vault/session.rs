use super::{Vault, VaultError};
use crate::types::PasswordType;
use zeroize::Zeroize;

/// Local encryption state. Supplied credentials never contain a cached key and
/// cannot represent a live session on the wire. Successful encryption/unlock
/// replaces and wipes the supplied credential.
#[derive(Clone, Default)]
pub enum VaultCredentials {
    #[default]
    Locked,
    Unlock(PasswordType),
    Session {
        encryption_key: [u8; 32],
        salt: [u8; 16],
        kdf: u8,
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    },
}
impl Drop for VaultCredentials {
    fn drop(&mut self) {
        match self {
            Self::Locked => {}
            Self::Unlock(credential) => credential.zeroize(),
            Self::Session {
                encryption_key,
                salt,
                kdf,
                memory_kib,
                iterations,
                parallelism,
            } => {
                encryption_key.zeroize();
                salt.zeroize();
                kdf.zeroize();
                memory_kib.zeroize();
                iterations.zeroize();
                parallelism.zeroize();
            }
        }
    }
}
impl Zeroize for VaultCredentials {
    fn zeroize(&mut self) {
        *self = Self::Locked;
    }
}
impl std::fmt::Debug for VaultCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Locked => "Locked",
            Self::Unlock(_) => "Unlock(<redacted>)",
            Self::Session { .. } => "Session(<redacted>)",
        })
    }
}
impl From<PasswordType> for VaultCredentials {
    fn from(credential: PasswordType) -> Self {
        Self::Unlock(credential)
    }
}
impl VaultCredentials {
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Locked)
    }
    pub(crate) fn supplied(&mut self) -> Result<&mut PasswordType, String> {
        match self {
            Self::Unlock(credential) => Ok(credential),
            _ => Err("an unlock credential is required".into()),
        }
    }
    pub(crate) fn cached(&self) -> bool {
        matches!(self, Self::Session { .. })
    }
}

/// An unlocked capability owns a complete vault and validated cached credentials.
#[derive(Debug)]
pub struct UnlockedVault {
    pub(crate) vault: Vault,
    credentials: VaultCredentials,
    epoch: [u8; 16],
}
#[derive(Debug, Default)]
pub enum VaultSession {
    #[default]
    Locked,
    Unlocked(Box<UnlockedVault>),
}
impl VaultSession {
    #[cfg(test)]
    pub fn unlock(vault: Vault, key: VaultCredentials) -> Self {
        let mut session = Self::Locked;
        session
            .install(vault, key)
            .expect("cached test credentials");
        session
    }
    pub(crate) fn install(
        &mut self,
        vault: Vault,
        credentials: VaultCredentials,
    ) -> Result<(), VaultError> {
        if !credentials.cached() {
            return Err(VaultError::Locked);
        }
        *self = Self::Unlocked(Box::new(UnlockedVault {
            vault,
            credentials,
            epoch: rand::random(),
        }));
        Ok(())
    }
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Locked)
    }
    pub fn lock(&mut self) {
        *self = Self::Locked;
    }
    pub(crate) fn epoch(&self) -> Option<[u8; 16]> {
        match self {
            Self::Locked => None,
            Self::Unlocked(live) => Some(live.epoch),
        }
    }
    pub(crate) fn session_id(&self) -> Option<String> {
        match self {
            Self::Locked => None,
            Self::Unlocked(live) => Some(format!(
                "{}{}",
                hex::encode(live.vault.vault_id()),
                hex::encode(live.epoch)
            )),
        }
    }
    pub(crate) fn vault(&self) -> Option<&Vault> {
        match self {
            Self::Locked => None,
            Self::Unlocked(live) => Some(&live.vault),
        }
    }
    /// Borrow complete unlocked state. A panic drops it and leaves this session
    /// locked; normal reads and mutations retain the same capability and epoch.
    pub(crate) fn with_unlocked<T>(
        &mut self,
        action: impl FnOnce(&mut Vault, &mut VaultCredentials) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        let mut current = std::mem::take(self);
        let Self::Unlocked(live) = &mut current else {
            return Err(VaultError::Locked);
        };
        let result = action(&mut live.vault, &mut live.credentials);
        if !live.credentials.cached() {
            return Err(VaultError::Locked);
        }
        *self = current;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key() -> VaultCredentials {
        VaultCredentials::Session {
            encryption_key: [42; 32],
            salt: [42; 16],
            kdf: 1,
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
        }
    }
    #[test]
    fn only_complete_cached_credentials_can_install_an_unlocked_session() {
        let mut session = VaultSession::Locked;
        for credentials in [
            VaultCredentials::default(),
            VaultCredentials::from(PasswordType::Password("synthetic".into())),
        ] {
            assert!(session.install(Vault::memory(), credentials).is_err());
            assert!(session.is_locked());
        }
    }
    #[test]
    fn invalidated_credentials_cannot_escape_an_unlocked_operation() {
        let mut session = VaultSession::unlock(Vault::memory(), key());
        let result = session.with_unlocked(|_, credentials| {
            *credentials = PasswordType::Password("external credential".into()).into();
            Ok(())
        });
        assert!(result.is_err());
        assert!(session.is_locked());
    }
    #[test]
    fn errors_preserve_the_session_and_panics_discard_it() {
        let mut session = VaultSession::unlock(Vault::memory(), key());
        let epoch = session.epoch();
        let result: Result<(), _> =
            session.with_unlocked(|_, _| Err(VaultError::NotFound("synthetic".into())));
        assert!(result.is_err());
        assert_eq!(session.epoch(), epoch);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), _> = session.with_unlocked(|_, _| panic!("synthetic failure"));
        }));
        assert!(result.is_err());
        assert!(session.is_locked());
    }
}
