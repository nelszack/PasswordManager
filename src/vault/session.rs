use super::{Vault, VaultError};
use crate::types::PasswordType;
use zeroize::Zeroize;

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
        self.locked.zeroize();
        self.keypass.zeroize();
        *self = Self::default()
    }
}
/// Owns the live vault and its credentials under a single server lock.
#[derive(Debug, Default)]
pub struct VaultSession {
    pub(crate) credentials: VaultCredentials,
    pub(crate) vault: Option<Vault>,
}
impl VaultSession {
    pub fn is_locked(&self) -> bool {
        self.credentials.locked || self.vault.is_none()
    }
    pub fn lock(&mut self) {
        self.vault.zeroize();
        self.credentials.zeroize();
    }
    pub(crate) fn parts_mut(&mut self) -> (&mut VaultCredentials, &mut Option<Vault>) {
        (&mut self.credentials, &mut self.vault)
    }
}
impl Drop for VaultSession {
    fn drop(&mut self) {
        self.lock();
    }
}

pub(crate) fn available(vault: &mut Option<Vault>) -> Result<&mut Vault, VaultError> {
    vault.as_mut().ok_or(VaultError::Locked)
}
