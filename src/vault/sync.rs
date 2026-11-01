//! Applying cloud snapshots stays on the vault owner's queue.
use super::*;

impl Vault {
    pub(crate) fn sync_path(&self) -> Result<std::path::PathBuf, String> {
        match &self.store {
            VaultStore::File {
                directory,
                filename,
            } => Ok(directory.join(filename)),
            _ => Err("Only saved vaults can synchronize".into()),
        }
    }
    pub(crate) fn apply_cloud(
        &mut self,
        credentials: &mut VaultCredentials,
        bytes: &[u8],
    ) -> Result<(), String> {
        let mut key = credentials.keypass.as_ref().ok_or("Vault locked")?.clone();
        let plaintext = Zeroizing::new(decrypt_file(&mut key, bytes).ok_or(
            "Cannot decrypt cloud update with this session key; the password/key may have changed on another device. Download a comparison copy with the new credentials; local vault preserved.",
        )?);
        let data = persistence::decode_document(&plaintext).map_err(|e| e.to_string())?;
        if data.vault_id != self.vault_id() {
            return Err("Cloud update has the wrong encrypted vault identity".into());
        }
        let VaultStore::File {
            directory,
            filename,
        } = &self.store
        else {
            return Err("Vault has no file".into());
        };
        let result = persistence::persist_ciphertext(directory, filename, bytes);
        if result.as_ref().map_or_else(|e| e.committed(), |_| true) {
            self.data = data;
            self.metadata.duo_session.zeroize();
            credentials.keypass = Some(key);
        }
        result.map_err(|e| e.to_string())
    }
}
