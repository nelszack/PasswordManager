use super::*;
use crate::types::DuoCommand;

pub(crate) struct PreparedDuoEnrollment {
    command: Zeroizing<DuoCommand>,
    push: bool,
    entry_id: usize,
    session: [u8; 32],
    state: [u8; 32],
}
pub(crate) enum DuoEnrollmentMaterial {
    Push(crate::duo::PushEnrollment),
    Passcodes(Zeroizing<String>),
}
impl PreparedDuoEnrollment {
    pub(crate) fn enroll(&self) -> Result<DuoEnrollmentMaterial, VaultError> {
        let DuoCommand::Enroll {
            activation, mode, ..
        } = &*self.command
        else {
            unreachable!()
        };
        if self.push {
            crate::duo::enroll_push(activation, *mode).map(DuoEnrollmentMaterial::Push)
        } else {
            crate::duo::enroll(activation, mode.unwrap_or(crate::types::OtpMode::Hotp))
                .map(DuoEnrollmentMaterial::Passcodes)
        }
    }
}

impl Vault {
    fn duo_enrollment_state(&self, id: usize) -> Result<[u8; 32], VaultError> {
        let index = self
            .entry_index(&Target::Id(id))
            .ok_or_else(|| VaultError::NotFound("entry not found".into()))?;
        // The temporary serialization is erased, and only its keyed review token
        // crosses the vault lock. No existing vault or device keys are retained.
        let bytes = Zeroizing::new(
            serde_json::to_vec(&(
                &self.entries[index],
                self.recovery.totp.iter().find(|r| r.entry_id == id),
                self.recovery.duo.iter().find(|r| r.entry_id == id),
            ))
            .map_err(|_| VaultError::Validation("could not bind Duo enrollment to item".into()))?,
        );
        let review_key = self
            .metadata
            .duo_session
            .as_ref()
            .ok_or_else(|| VaultError::Conflict("Duo enrollment session changed".into()))?;
        let mut hash = Zeroizing::new(blake3::Hasher::new_keyed(review_key));
        hash.update(b"password-manager.duo-enrollment.v1\0");
        hash.update(&bytes);
        Ok(*hash.finalize().as_bytes())
    }
    pub(crate) fn prepare_duo_enrollment(
        &mut self,
        command: DuoCommand,
        push: bool,
        key: &mut VaultCredentials,
    ) -> Result<PreparedDuoEnrollment, VaultError> {
        let command = Zeroizing::new(command);
        if key.locked || key.keypass.is_none() {
            return Err(VaultError::Locked);
        }
        let DuoCommand::Enroll {
            target, replace, ..
        } = &*command
        else {
            return Err(VaultError::InvalidInput(
                "invalid Duo enrollment operation".into(),
            ));
        };
        let index = self
            .entry_index(target)
            .ok_or_else(|| VaultError::NotFound("entry not found".into()))?;
        let entry_id = self.entries[index].id;
        if !replace
            && (self.recovery.totp.iter().any(|r| r.entry_id == entry_id)
                || (push && self.recovery.duo.iter().any(|r| r.entry_id == entry_id)))
        {
            return Err(VaultError::Conflict("entry already has an authenticator; remove it or use --replace before enrolling Duo".into()));
        }
        // Check persistence before consuming the single-use activation link.
        write_vault(self, key)?;
        let review_key = self.metadata.duo_session.get_or_insert_with(rand::random);
        let session = *blake3::hash(review_key).as_bytes();
        let state = self.duo_enrollment_state(entry_id)?;
        Ok(PreparedDuoEnrollment {
            command,
            push,
            entry_id,
            session,
            state,
        })
    }
    pub(crate) fn finish_duo_enrollment(
        &mut self,
        prepared: &PreparedDuoEnrollment,
        material: DuoEnrollmentMaterial,
        key: &mut VaultCredentials,
    ) -> Result<String, VaultError> {
        if key.locked || key.keypass.is_none() {
            return Err(VaultError::Locked);
        }
        if self
            .metadata
            .duo_session
            .as_ref()
            .map(|k| *blake3::hash(k).as_bytes())
            != Some(prepared.session)
            || self.duo_enrollment_state(prepared.entry_id)? != prepared.state
        {
            return Err(VaultError::Conflict(
                "unlock session or item changed during Duo enrollment".into(),
            ));
        }
        match material {
            DuoEnrollmentMaterial::Push(enrollment) => {
                self.store_duo_enrollment(prepared.entry_id, enrollment, key)?;
                Ok(
                    "Duo push credentials and passcode authenticator saved in the encrypted vault."
                        .into(),
                )
            }
            DuoEnrollmentMaterial::Passcodes(configuration) => {
                self.set_totp(Target::Id(prepared.entry_id), &configuration, key)?;
                Ok("Duo passcode authenticator saved in the encrypted vault.".into())
            }
        }
    }
}

impl Vault {
    fn duo_record(&mut self, target: &Target) -> Result<&mut DuoRecord, VaultError> {
        let index = self
            .entry_index(target)
            .ok_or_else(|| VaultError::NotFound("entry not found".into()))?;
        self.recovery
            .duo
            .iter_mut()
            .find(|r| r.entry_id == self.entries[index].id)
            .ok_or_else(|| {
                VaultError::NotFound(
                    "entry has no push credentials; enroll a fresh link using pm duo enroll".into(),
                )
            })
    }
    #[cfg(test)]
    fn enroll_push_with(
        &mut self,
        target: &Target,
        replace: bool,
        key: &mut VaultCredentials,
        enroll: impl FnOnce() -> Result<crate::duo::PushEnrollment, VaultError>,
    ) -> Result<(), VaultError> {
        let prepared = self.prepare_duo_enrollment(
            DuoCommand::Enroll {
                target: target.clone(),
                activation: String::new(),
                mode: None,
                replace,
            },
            true,
            key,
        )?;
        self.finish_duo_enrollment(&prepared, DuoEnrollmentMaterial::Push(enroll()?), key)
            .map(|_| ())
    }
    fn store_duo_enrollment(
        &mut self,
        id: usize,
        mut enrollment: crate::duo::PushEnrollment,
        key: &mut VaultCredentials,
    ) -> Result<(), VaultError> {
        let index = self
            .entry_index(&Target::Id(id))
            .ok_or_else(|| VaultError::NotFound("entry not found".into()))?;
        let (configuration, _) = totp::normalize_totp_configuration(&enrollment.configuration)?;
        self.transaction(TransactionScope::Entry(id), key, |vault| {
            vault.recovery.duo.retain_mut(|r| {
                if r.entry_id == id {
                    r.zeroize();
                    false
                } else {
                    true
                }
            });
            vault.recovery.totp.retain_mut(|r| {
                if r.entry_id == id {
                    r.zeroize();
                    false
                } else {
                    true
                }
            });
            vault.recovery.duo.push(DuoRecord {
                entry_id: id,
                review_key: None,
                credentials: std::mem::take(&mut enrollment.credentials),
            });
            vault.recovery.totp.push(TotpRecord {
                entry_id: id,
                configuration,
            });
            vault.entries[index].modified = chrono::Local::now().to_string();
            Ok((true, ()))
        })
        .map_err(|e| {
            e.context("Duo enrolled but saving failed; check enrollment status before retrying")
        })
    }
    pub(crate) fn duo_command(
        &mut self,
        command: &DuoCommand,
        key: &mut VaultCredentials,
    ) -> Result<String, VaultError> {
        if key.locked || key.keypass.is_none() {
            return Err(VaultError::Locked);
        }
        match command {
            DuoCommand::Enroll { .. }
            | DuoCommand::Requests { .. }
            | DuoCommand::Respond { .. } => Err(VaultError::InvalidInput(
                "Duo I/O must run outside the live vault lock".into(),
            )),
            DuoCommand::Remove { target } => {
                let index = self
                    .entry_index(target)
                    .ok_or_else(|| VaultError::NotFound("entry not found".into()))?;
                let id = self.entries[index].id;
                self.transaction(TransactionScope::Entry(id),key,|vault| {
                    let before=vault.recovery.duo.len();
                    vault.recovery.duo.retain_mut(|r| { if r.entry_id == id {r.zeroize();false} else {true} });
                    let changed=before!=vault.recovery.duo.len();
                    if changed { vault.entries[index].modified=chrono::Local::now().to_string(); }
                    Ok((changed,"Local push credentials removed. Remove the device separately in Duo; passcodes are retained.".into()))
                })
            }
        }
    }
}

pub(crate) struct PreparedDuoPoll {
    pub request: crate::duo::PreparedRequest,
    pub review: DuoReview,
}
pub(crate) struct DuoReview {
    pub command: Zeroizing<DuoCommand>,
    pub session_tag: [u8; 32],
}
pub(crate) enum DuoPollResult {
    Requests(String),
    Decision(Box<crate::duo::PreparedRequest>),
}
impl Vault {
    pub(crate) fn prepare_duo_poll(
        &mut self,
        command: DuoCommand,
        key: &VaultCredentials,
    ) -> Result<PreparedDuoPoll, VaultError> {
        let mut command = Zeroizing::new(command);
        if key.locked || key.keypass.is_none() {
            return Err(VaultError::Locked);
        }
        let is_poll = matches!(&*command, DuoCommand::Requests { .. });
        let target = match &mut *command {
            DuoCommand::Requests { target } | DuoCommand::Respond { target, .. } => target,
            _ => {
                return Err(VaultError::InvalidInput(
                    "invalid Duo push operation".into(),
                ));
            }
        };
        let record = self.duo_record(target)?;
        target.zeroize();
        *target = Target::Id(record.entry_id);
        if is_poll && record.review_key.is_none() {
            record.review_key = Some(rand::random());
        }
        let review_key = record.review_key.as_ref().ok_or_else(|| {
            VaultError::InvalidInput("Review the Duo request again in this unlock session".into())
        })?;
        let session_tag = *blake3::hash(review_key).as_bytes();
        let request = crate::duo::prepare_poll(&record.credentials)?;
        Ok(PreparedDuoPoll {
            request,
            review: DuoReview {
                command,
                session_tag,
            },
        })
    }
    pub(crate) fn finish_duo_poll(
        &mut self,
        review: &DuoReview,
        body: &[u8],
        key: &VaultCredentials,
    ) -> Result<DuoPollResult, VaultError> {
        if key.locked || key.keypass.is_none() {
            return Err(VaultError::Locked);
        }
        let target = match &*review.command {
            DuoCommand::Requests { target } | DuoCommand::Respond { target, .. } => target,
            _ => {
                return Err(VaultError::InvalidInput(
                    "invalid Duo push operation".into(),
                ));
            }
        };
        let record = self.duo_record(target)?;
        let review_key = record.review_key.as_ref().ok_or_else(|| {
            VaultError::InvalidInput("Duo unlock session changed; review the request again".into())
        })?;
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            blake3::hash(review_key).as_bytes().as_slice(),
            review.session_tag.as_slice(),
        )) {
            return Err(VaultError::InvalidInput(
                "Duo unlock session changed; review the request again".into(),
            ));
        }
        let pending = crate::duo::parse_requests(body, review_key)?;
        match &*review.command {
            DuoCommand::Requests { .. } => serde_json::to_string(&pending)
                .map(DuoPollResult::Requests)
                .map_err(|_| VaultError::Validation("could not encode Duo requests".into())),
            DuoCommand::Respond {
                request_id,
                fingerprint,
                approve,
                code,
                ..
            } => crate::duo::prepare_decision(
                &record.credentials,
                &pending,
                request_id,
                fingerprint,
                *approve,
                code,
            )
            .map(|request| DuoPollResult::Decision(Box::new(request))),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn synthetic_record() -> DuoRecord {
        let key = crate::duo::crypto::new_key().unwrap();
        DuoRecord {
            entry_id: 1,
            credentials: DuoCredentials {
                host: "api-test.duosecurity.com".into(),
                akey: "syntheticAccount".into(),
                pkey: "syntheticDevice".into(),
                private_key: crate::duo::crypto::private_pem(&key).unwrap().to_string(),
            },
            review_key: None,
        }
    }
    #[test]
    fn review_keys_are_ephemeral_redacted_and_erased_on_lock() {
        let mut record = synthetic_record();
        record.review_key = Some([37; 32]);
        let encoded = Zeroizing::new(serde_json::to_string(&record).unwrap());
        assert!(!encoded.contains("review_key"));
        let restored: DuoRecord = serde_json::from_str(&encoded).unwrap();
        assert!(restored.review_key.is_none());
        let debug = format!("{record:?}");
        assert!(!debug.contains("PRIVATE KEY"));
        assert!(!debug.contains("37"));
        let mut metadata = VaultMetadata {
            filename: "synthetic".into(),
            duo_session: Some([37; 32]),
        };
        assert!(
            !serde_json::to_string(&metadata)
                .unwrap()
                .contains("duo_session")
        );
        assert!(!format!("{metadata:?}").contains("37"));
        let restored: VaultMetadata =
            rmp_serde::from_slice(&rmp_serde::to_vec(&metadata).unwrap()).unwrap();
        assert!(restored.duo_session.is_none());
        metadata.zeroize();
        assert!(metadata.duo_session.is_none());
        record.zeroize();
        assert!(record.review_key.is_none());
        assert!(record.credentials.private_key.is_empty());
    }
    #[test]
    fn locked_or_reopened_sessions_cannot_prepare_a_reviewed_decision() {
        let mut vault = Vault::default();
        vault.entries.push(VaultEntry {
            id: 1,
            ..Default::default()
        });
        vault.recovery.duo.push(synthetic_record());
        let mut key = VaultCredentials {
            locked: false,
            keypass: Some(PasswordType::Key("synthetic".into())),
        };
        let body = serde_json::to_vec(&json!({"stat":"OK","response":{"transactions":[{
            "urgid":"test-id", "type":"Login", "expiration":chrono::Utc::now().timestamp()+120,
            "step_up_code_info":{"num_digits":3}
        }]}}))
        .unwrap();
        let poll = vault
            .prepare_duo_poll(
                DuoCommand::Requests {
                    target: Target::Id(1),
                },
                &key,
            )
            .unwrap();
        let DuoPollResult::Requests(output) =
            vault.finish_duo_poll(&poll.review, &body, &key).unwrap()
        else {
            panic!("expected requests")
        };
        let requests: Vec<crate::types::DuoPushRequest> = serde_json::from_str(&output).unwrap();
        let reviewed = vault
            .prepare_duo_poll(
                DuoCommand::Respond {
                    target: Target::Id(1),
                    request_id: requests[0].id.clone(),
                    fingerprint: requests[0].fingerprint.clone(),
                    approve: true,
                    code: "012".into(),
                },
                &key,
            )
            .unwrap();
        assert!(matches!(
            vault.finish_duo_poll(&reviewed.review, &body, &key),
            Ok(DuoPollResult::Decision(_))
        ));
        key.locked = true;
        assert!(matches!(
            vault.finish_duo_poll(&reviewed.review, &body, &key),
            Err(VaultError::Locked)
        ));
        key.locked = false;
        vault.recovery.duo[0].review_key = None;
        assert!(
            vault
                .finish_duo_poll(&reviewed.review, &body, &key)
                .is_err()
        );
        // A new poll after unlock initializes another key, but old reviews fail.
        let new_poll = vault
            .prepare_duo_poll(
                DuoCommand::Requests {
                    target: Target::Id(1),
                },
                &key,
            )
            .unwrap();
        assert_ne!(poll.review.session_tag, new_poll.review.session_tag);
        assert!(
            vault
                .finish_duo_poll(&reviewed.review, &body, &key)
                .is_err()
        );
    }
    #[test]
    fn enrollment_cannot_commit_after_lock_reopen_or_item_changes() {
        crate::file::init_test_data_dir();
        let mut vault = Vault::default();
        vault.metadata.filename = random_vault_filename();
        vault.entries.push(VaultEntry {
            id: 1,
            ..Default::default()
        });
        let mut key = VaultCredentials {
            locked: false,
            keypass: Some(PasswordType::Session {
                encryption_key: [42; 32],
                salt: [7; 16],
                kdf: 1,
                memory_kib: 8192,
                iterations: 1,
                parallelism: 1,
            }),
        };
        let prepared = vault
            .prepare_duo_enrollment(
                DuoCommand::Enroll {
                    target: Target::Id(1),
                    activation: "synthetic-never-used".into(),
                    mode: Some(crate::types::OtpMode::Hotp),
                    replace: false,
                },
                false,
                &mut key,
            )
            .unwrap();
        let material = || {
            DuoEnrollmentMaterial::Passcodes(Zeroizing::new(
                "otpauth://hotp/Duo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0&digits=6"
                    .into(),
            ))
        };
        key.locked = true;
        assert!(matches!(
            vault.finish_duo_enrollment(&prepared, material(), &mut key),
            Err(VaultError::Locked)
        ));
        key.locked = false;
        let session = vault.metadata.duo_session;
        vault.metadata.duo_session = Some(rand::random());
        assert!(
            vault
                .finish_duo_enrollment(&prepared, material(), &mut key)
                .is_err()
        );
        vault.metadata.duo_session = session;
        vault.entries[0].name = "changed".into();
        assert!(
            vault
                .finish_duo_enrollment(&prepared, material(), &mut key)
                .is_err()
        );
        assert!(vault.recovery.totp.is_empty());
        vault.entries[0].name.clear();
        vault
            .finish_duo_enrollment(&prepared, material(), &mut key)
            .unwrap();
        // A competing enrollment cannot overwrite the authenticator just saved.
        assert!(
            vault
                .finish_duo_enrollment(&prepared, material(), &mut key)
                .is_err()
        );
        assert_eq!(vault.recovery.totp.len(), 1);
        fs::remove_file(data_dir().join(&vault.metadata.filename)).unwrap();
    }
    #[test]
    fn enrollment_never_consumes_link_if_locked_existing_or_unwritable() {
        crate::file::init_test_data_dir();
        let mut vault = Vault::default();
        vault.entries.push(VaultEntry {
            id: 1,
            ..Default::default()
        });
        let target = Target::Id(1);
        let mut key = VaultCredentials::default();
        assert!(matches!(
            vault.enroll_push_with(&target, false, &mut key, || panic!("must not enroll")),
            Err(VaultError::Locked)
        ));
        key.locked = false;
        key.keypass = Some(PasswordType::Key("not-a-real-key".into()));
        vault.recovery.totp.push(TotpRecord {
            entry_id: 1,
            configuration: "old".into(),
        });
        assert!(matches!(
            vault.enroll_push_with(&target, false, &mut key, || panic!("must not enroll")),
            Err(VaultError::Conflict(_))
        ));
        vault.metadata.filename = "missing-directory/push-vault.enc".into();
        let before = vault.clone();
        assert!(
            vault
                .enroll_push_with(&target, true, &mut key, || panic!("must not enroll"))
                .is_err()
        );
        assert_eq!(vault, before);
    }
    #[test]
    fn old_messagepack_recovery_loads_with_empty_push_records() {
        #[derive(Serialize)]
        struct Old {
            password_history: Vec<PasswordRevision>,
            trash: Vec<TrashedEntry>,
            next_entry_id: usize,
            totp: Vec<TotpRecord>,
            entry_metadata: Vec<EntryMetadata>,
        }
        let data = rmp_serde::to_vec(&Old {
            password_history: vec![],
            trash: vec![],
            next_entry_id: 2,
            totp: vec![],
            entry_metadata: vec![],
        })
        .unwrap();
        let recovery: RecoveryData = rmp_serde::from_slice(&data).unwrap();
        assert!(recovery.duo.is_empty());
        assert_eq!(recovery.next_entry_id, 2);
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    #[test]
    fn push_credentials_survive_encrypted_storage_and_portable_id_remapping() {
        crate::file::init_test_data_dir();
        let private = crate::duo::crypto::new_key().unwrap();
        let credentials = DuoCredentials {
            host: "api-test.duosecurity.com".into(),
            akey: "syntheticAccount".into(),
            pkey: "syntheticDevice".into(),
            private_key: crate::duo::crypto::private_pem(&private)
                .unwrap()
                .to_string(),
        };
        let mut vault = Vault::default();
        vault.metadata.filename = random_vault_filename();
        vault.entries.push(VaultEntry {
            id: 1,
            name: "work".into(),
            ..Default::default()
        });
        let mut key = VaultCredentials {
            locked: false,
            keypass: Some(PasswordType::Session {
                encryption_key: [42; 32],
                salt: [7; 16],
                kdf: 1,
                memory_kib: 8192,
                iterations: 1,
                parallelism: 1,
            }),
        };
        vault.enroll_push_with(&Target::Id(1),false,&mut key,|| Ok(crate::duo::PushEnrollment {credentials:credentials.clone(),configuration:"otpauth://hotp/Duo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0&digits=6".into()})).unwrap();
        assert_eq!(vault.recovery.duo[0].credentials, credentials);
        assert_eq!(vault.recovery.totp.len(), 1);
        let encrypted = fs::read(data_dir().join(&vault.metadata.filename)).unwrap();
        assert!(
            !encrypted
                .windows(credentials.akey.len())
                .any(|s| s == credentials.akey.as_bytes())
        );
        assert!(!encrypted.windows(11).any(|s| s == b"PRIVATE KEY"));
        let plaintext =
            Zeroizing::new(decrypt_file(key.keypass.as_mut().unwrap(), &encrypted).unwrap());
        let mut restored: Vault = rmp_serde::from_slice(&plaintext).unwrap();
        validate_backup_vault(&mut restored).unwrap();
        assert_eq!(restored.recovery.duo, vault.recovery.duo);
        let before = vault.clone();
        assert!(
            vault
                .enroll_push_with(&Target::Id(1), true, &mut key, || Err(
                    VaultError::InvalidInput("synthetic activation rejection".into())
                ))
                .is_err()
        );
        assert_eq!(vault, before);
        for reveal in [false, true] {
            let item = vault.management_item_json(1, reveal).unwrap();
            assert!(!item.contains(&credentials.akey));
            assert!(!item.contains("PRIVATE KEY"));
            assert!(item.contains("\"has_duo\":true"));
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("export.json");
        vault.export(path.display().to_string(), false).unwrap();
        let exported = Zeroizing::new(fs::read_to_string(path).unwrap());
        let mut imported = import::import_json(&exported, "synthetic portable export").unwrap();
        let mut receiver = Vault::default();
        receiver.replace_portable_records(9, &mut imported[0], None, 10);
        assert_eq!(receiver.recovery.duo[0].entry_id, 9);
        assert_eq!(receiver.recovery.duo[0].credentials, credentials);
        restored.recovery.duo.push(restored.recovery.duo[0].clone());
        assert!(validate_backup_vault(&mut restored).is_err());
        let mut secret_copy = credentials.clone();
        secret_copy.zeroize();
        assert!(secret_copy.private_key.is_empty());
        fs::remove_file(data_dir().join(&vault.metadata.filename)).unwrap();
    }
}
