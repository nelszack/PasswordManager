//! Applying cloud snapshots stays on the vault owner's queue.
use super::*;

/// Constructed only from authenticated remote data or this vault's validated merge.
pub(crate) struct PreparedCloud {
    pub(super) data: VaultData,
    pub(super) bytes: Vec<u8>,
    pub(super) credentials: VaultCredentials,
}

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
        let mut key = credentials.clone();
        let plaintext = Zeroizing::new(decrypt_file(&mut key, bytes).ok_or(
            "Cannot decrypt cloud update with this session key; the password/key may have changed on another device. Download a comparison copy with the new credentials; local vault preserved.",
        )?);
        let data = persistence::decode_document(&plaintext).map_err(|e| e.to_string())?;
        if data.vault_id != self.vault_id() {
            return Err("Cloud update has the wrong encrypted vault identity".into());
        }
        self.persist_cloud_data(credentials, data, key, bytes)
            .map_err(|error| error.to_string())
    }
    pub(crate) fn apply_prepared_cloud(
        &mut self,
        credentials: &mut VaultCredentials,
        prepared: PreparedCloud,
    ) -> Result<(), VaultError> {
        self.persist_cloud_data(
            credentials,
            prepared.data,
            prepared.credentials,
            &prepared.bytes,
        )
    }
    fn persist_cloud_data(
        &mut self,
        credentials: &mut VaultCredentials,
        mut data: VaultData,
        key: VaultCredentials,
        bytes: &[u8],
    ) -> Result<(), VaultError> {
        let VaultStore::File {
            directory,
            filename,
        } = &self.store
        else {
            return Err(VaultError::Persistence("Vault has no file".into()));
        };
        let result = persistence::persist_ciphertext(directory, filename, bytes);
        if result.as_ref().map_or_else(|e| e.committed(), |_| true) {
            // A snapshot replacement invalidates every prior Duo review, even
            // when the prepared merge retained an otherwise unchanged item.
            for item in data.items.values_mut() {
                if let Some(duo) = &mut item.duo {
                    duo.review_key.zeroize();
                }
            }
            self.data = data;
            self.metadata.duo_session.zeroize();
            *credentials = key;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_merge_adopts_data_only_when_replacement_commits() {
        for fault in [0, 1, 2] {
            let mut vault = Vault::from_entries(
                vec![
                    VaultEntry {
                        id: 1,
                        name: "Local".into(),
                        password: "local-secret".into(),
                        ..Default::default()
                    },
                    VaultEntry {
                        id: 2,
                        name: "Unchanged".into(),
                        ..Default::default()
                    },
                ],
                None,
            );
            let duo_key = crate::duo::crypto::new_key().unwrap();
            vault.item_mut(2).unwrap().duo = Some(DuoRecord {
                credentials: DuoCredentials {
                    host: "api-test.duosecurity.com".into(),
                    akey: "syntheticAccount".into(),
                    pkey: "syntheticDevice".into(),
                    private_key: crate::duo::crypto::private_pem(&duo_key)
                        .unwrap()
                        .to_string()
                        .into(),
                },
                review_key: Some([37; 32]),
            });
            let (directory, mut vault, mut credentials) =
                crate::vault::test::persist_fixture(vault, "test.enc");
            let original = vault.data.clone();
            let original_file = fs::read(directory.path().join("test.enc")).unwrap();
            let mut remote = vault.clone();
            remote.item_mut(1).unwrap().entry.name = "Remote".into();
            let mut plaintext = persistence::encode_document(&remote.data, None).unwrap();
            let bytes = try_encrypt_file_in_place(
                &mut credentials.clone(),
                std::mem::take(&mut *plaintext),
            )
            .unwrap();
            let choices = vec![crate::cloud::Choice {
                id: 1,
                field: "name".into(),
                side: crate::cloud::Side::Remote,
            }];
            let prepared = vault.merge_cloud(&credentials, &bytes, &choices).unwrap();
            let mut expected = prepared.data.clone();
            assert!(
                expected.items[&ItemId(2)]
                    .duo
                    .as_ref()
                    .unwrap()
                    .review_key
                    .is_some()
            );
            expected
                .items
                .get_mut(&ItemId(2))
                .unwrap()
                .duo
                .as_mut()
                .unwrap()
                .review_key = None;
            let expected_file = prepared.bytes.clone();
            let result = persistence::with_write_fault(fault, || {
                vault.apply_prepared_cloud(&mut credentials, prepared)
            });
            if fault == 1 {
                assert!(!result.unwrap_err().committed());
                assert_eq!(vault.data, original);
                assert_eq!(
                    fs::read(directory.path().join("test.enc")).unwrap(),
                    original_file
                );
            } else {
                if fault == 2 {
                    assert!(result.unwrap_err().committed());
                } else {
                    result.unwrap();
                }
                assert_eq!(vault.data, expected);
                assert_eq!(
                    fs::read(directory.path().join("test.enc")).unwrap(),
                    expected_file
                );
                let decoded =
                    Zeroizing::new(decrypt_file(&mut credentials, &expected_file).unwrap());
                assert_eq!(persistence::decode_document(&decoded).unwrap(), expected);
            }
        }
    }
}
