use super::*;
use crate::types::DuoCommand;

pub(crate) struct PreparedDuoEnrollment {
    command: Zeroizing<DuoCommand>,
    push: bool,
    entry_id: usize,
    session: [u8; 32],
    revision: u64,
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
    pub(crate) fn prepare_duo_enrollment(
        &mut self,
        command: DuoCommand,
        push: bool,
        key: &mut VaultCredentials,
    ) -> Result<PreparedDuoEnrollment, VaultError> {
        if key.locked || key.keypass.is_none() {
            return Err(VaultError::Locked);
        }
        let command = Zeroizing::new(command);
        let DuoCommand::Enroll {
            target, replace, ..
        } = &*command
        else {
            return Err(VaultError::InvalidInput(
                "invalid Duo enrollment operation".into(),
            ));
        };
        let id = self
            .entry_id(target)
            .ok_or_else(|| VaultError::NotFound("entry not found".into()))?;
        let item = self.item(id).unwrap();
        if !replace && (item.authenticator.is_some() || (push && item.duo.is_some())) {
            return Err(VaultError::Conflict(
                "item already has an authenticator; use --replace".into(),
            ));
        }
        let revision = item.revision;
        write_vault(self, key)?;
        let review_key = self.metadata.duo_session.get_or_insert_with(rand::random);
        let session = *blake3::hash(review_key).as_bytes();
        Ok(PreparedDuoEnrollment {
            command,
            push,
            entry_id: id,
            session,
            revision,
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
            || self
                .item(prepared.entry_id)
                .filter(|i| i.active())
                .map(|i| i.revision)
                != Some(prepared.revision)
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
    fn duo_record(&mut self, target: &Target) -> Result<&mut DuoRecord, VaultError> {
        let id = self
            .entry_id(target)
            .ok_or_else(|| VaultError::NotFound("entry not found".into()))?;
        self.item_mut(id).unwrap().duo.as_mut().ok_or_else(|| {
            VaultError::NotFound(
                "item has no push credentials; enroll a fresh link using pm duo enroll".into(),
            )
        })
    }
    fn store_duo_enrollment(
        &mut self,
        id: usize,
        mut enrollment: crate::duo::PushEnrollment,
        key: &mut VaultCredentials,
    ) -> Result<(), VaultError> {
        let authenticator = Authenticator::parse(&enrollment.configuration)?;
        self.transaction(TransactionScope::Entry(id), key, |v| {
            let item = v.item_mut(id).unwrap();
            item.authenticator = Some(authenticator);
            item.duo = Some(DuoRecord {
                credentials: std::mem::take(&mut enrollment.credentials),
                review_key: None,
            });
            item.entry.modified = Timestamp::now();
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
            DuoCommand::Remove { target } => {
                let id = self
                    .entry_id(target)
                    .ok_or_else(|| VaultError::NotFound("entry not found".into()))?;
                self.transaction(TransactionScope::Entry(id),key,|v| {let item=v.item_mut(id).unwrap();let changed=item.duo.take().is_some();if changed {item.entry.modified=Timestamp::now();}Ok((changed,"Local push credentials removed. Remove the device separately in Duo; passcodes are retained.".into()))})
            }
            _ => Err(VaultError::InvalidInput(
                "Duo I/O must run outside the live vault owner".into(),
            )),
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
    revision: u64,
}
pub(crate) enum DuoPollResult {
    Requests(Vec<crate::types::DuoPushRequest>),
    Decision(Box<crate::duo::PreparedRequest>),
}
impl Vault {
    pub(crate) fn prepare_duo_poll(
        &mut self,
        command: DuoCommand,
        key: &VaultCredentials,
    ) -> Result<PreparedDuoPoll, VaultError> {
        if key.locked || key.keypass.is_none() {
            return Err(VaultError::Locked);
        }
        let mut command = Zeroizing::new(command);
        let poll = matches!(&*command, DuoCommand::Requests { .. });
        let target = match &mut *command {
            DuoCommand::Requests { target } | DuoCommand::Respond { target, .. } => target,
            _ => {
                return Err(VaultError::InvalidInput(
                    "invalid Duo push operation".into(),
                ));
            }
        };
        let id = self
            .entry_id(target)
            .ok_or_else(|| VaultError::NotFound("entry not found".into()))?;
        let revision = self.revision(id).unwrap();
        *target = Target::Id(id);
        let record = self.duo_record(target)?;
        if poll && record.review_key.is_none() {
            record.review_key = Some(rand::random());
        }
        let review_key = record.review_key.as_ref().ok_or_else(|| {
            VaultError::InvalidInput("review the Duo request again in this unlock session".into())
        })?;
        let session_tag = *blake3::hash(review_key).as_bytes();
        let request = crate::duo::prepare_poll(&record.credentials)?;
        Ok(PreparedDuoPoll {
            request,
            review: DuoReview {
                command,
                session_tag,
                revision,
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
        if self.target_revision(target) != Some(review.revision) {
            return Err(VaultError::Conflict(
                "item changed; review the Duo request again".into(),
            ));
        }
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
            DuoCommand::Requests { .. } => Ok(DuoPollResult::Requests(pending)),
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
            .map(|r| DuoPollResult::Decision(Box::new(r))),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn credentials() -> DuoCredentials {
        let key = crate::duo::crypto::new_key().unwrap();
        DuoCredentials {
            host: "api-test.duosecurity.com".into(),
            akey: "syntheticAccount".into(),
            pkey: "syntheticDevice".into(),
            private_key: crate::duo::crypto::private_pem(&key)
                .unwrap()
                .to_string()
                .into(),
        }
    }
    fn fixture() -> (Vault, VaultCredentials) {
        let mut vault = Vault::from_entries(
            vec![VaultEntry {
                id: 1,
                name: "Account".into(),
                password: "password".into(),
                ..Default::default()
            }],
            None,
        );
        vault.set_test_duo(1, credentials());
        let key = VaultCredentials {
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
        (vault, key)
    }
    fn body() -> Vec<u8> {
        serde_json::to_vec(&json!({"stat":"OK","response":{"transactions":[{"urgid":"test-id","type":"Login","expiration":chrono::Utc::now().timestamp()+120,"step_up_code_info":{"num_digits":3}}]}})).unwrap()
    }
    fn enroll() -> DuoCommand {
        DuoCommand::Enroll {
            target: Target::Id(1),
            activation: "synthetic-unused-activation".into(),
            mode: Some(crate::types::OtpMode::Hotp),
            replace: true,
        }
    }
    fn material() -> DuoEnrollmentMaterial {
        DuoEnrollmentMaterial::Passcodes(Zeroizing::new(
            "otpauth://hotp/Duo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0".into(),
        ))
    }
    #[test]
    fn poll_reviews_are_bound_to_session_key_and_item_revision() {
        let (mut vault, mut key) = fixture();
        let poll = vault
            .prepare_duo_poll(
                DuoCommand::Requests {
                    target: Target::Id(1),
                },
                &key,
            )
            .unwrap();
        let DuoPollResult::Requests(requests) =
            vault.finish_duo_poll(&poll.review, &body(), &key).unwrap()
        else {
            panic!("expected typed requests")
        };
        let review = vault
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
            vault.finish_duo_poll(&review.review, &body(), &key),
            Ok(DuoPollResult::Decision(_))
        ));
        key.locked = true;
        assert!(matches!(
            vault.finish_duo_poll(&review.review, &body(), &key),
            Err(VaultError::Locked)
        ));
        key.locked = false;
        vault.item_mut(1).unwrap().duo.as_mut().unwrap().review_key = None;
        assert!(
            vault
                .finish_duo_poll(&review.review, &body(), &key)
                .is_err()
        );
        let new_poll = vault
            .prepare_duo_poll(
                DuoCommand::Requests {
                    target: Target::Id(1),
                },
                &key,
            )
            .unwrap();
        assert_ne!(new_poll.review.session_tag, poll.review.session_tag);
        let mut change = EntryUpdate {
            target: Target::Id(1),
            update: EntryChanges::default(),
            password: Some("updated".into()),
        };
        change.update.notes = Some("changed while reviewing".into());
        vault.update_entry_with_limit(change, &mut key, 10).unwrap();
        assert!(
            vault
                .finish_duo_poll(&new_poll.review, &body(), &key)
                .is_err()
        );
    }
    #[test]
    fn enrollment_rejects_stale_session_and_changed_or_deleted_item() {
        let (mut vault, mut key) = fixture();
        let prepared = vault
            .prepare_duo_enrollment(enroll(), false, &mut key)
            .unwrap();
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
        vault
            .update_entry_with_limit(
                EntryUpdate {
                    target: Target::Id(1),
                    update: EntryChanges::default(),
                    password: Some("changed".into()),
                },
                &mut key,
                10,
            )
            .unwrap();
        assert!(
            vault
                .finish_duo_enrollment(&prepared, material(), &mut key)
                .is_err()
        );
        let prepared = vault
            .prepare_duo_enrollment(enroll(), false, &mut key)
            .unwrap();
        vault.delete_entry(Target::Id(1), &mut key).unwrap();
        assert!(
            vault
                .finish_duo_enrollment(&prepared, material(), &mut key)
                .is_err()
        );
    }
    #[test]
    fn enrollment_preflight_checks_lock_target_conflicts_and_store_before_network() {
        let (mut vault, mut key) = fixture();
        key.locked = true;
        assert!(
            vault
                .prepare_duo_enrollment(enroll(), false, &mut key)
                .is_err()
        );
        key.locked = false;
        let missing = DuoCommand::Enroll {
            target: Target::Id(99),
            activation: "never-consumed".into(),
            mode: None,
            replace: false,
        };
        assert!(
            vault
                .prepare_duo_enrollment(missing, false, &mut key)
                .is_err()
        );
        let conflict = DuoCommand::Enroll {
            target: Target::Id(1),
            activation: "never-consumed".into(),
            mode: None,
            replace: false,
        };
        assert!(
            vault
                .prepare_duo_enrollment(conflict, true, &mut key)
                .is_err()
        );
        let directory = tempfile::tempdir().unwrap();
        vault.store = VaultStore::File {
            directory: directory.path().join("missing"),
            filename: "vault.enc".into(),
        };
        assert!(
            vault
                .prepare_duo_enrollment(enroll(), true, &mut key)
                .is_err()
        );
        assert!(vault.metadata.duo_session.is_none());
    }
    #[test]
    fn enrollment_stores_complete_item_and_review_keys_never_enter_document_or_export() {
        let (mut vault, mut key) = fixture();
        let prepared = vault
            .prepare_duo_enrollment(enroll(), true, &mut key)
            .unwrap();
        let material = DuoEnrollmentMaterial::Push(crate::duo::PushEnrollment {
            credentials: credentials(),
            configuration: "otpauth://hotp/Duo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=4"
                .into(),
        });
        vault
            .finish_duo_enrollment(&prepared, material, &mut key)
            .unwrap();
        let _poll = vault
            .prepare_duo_poll(
                DuoCommand::Requests {
                    target: Target::Id(1),
                },
                &key,
            )
            .unwrap();
        assert!(
            vault
                .item(1)
                .unwrap()
                .duo
                .as_ref()
                .unwrap()
                .review_key
                .is_some()
        );
        let document = persistence::encode_document(&vault.data, None).unwrap();
        let decoded = persistence::decode_document(&document).unwrap();
        assert!(
            decoded
                .items
                .values()
                .next()
                .unwrap()
                .duo
                .as_ref()
                .unwrap()
                .review_key
                .is_none()
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("portable.json");
        vault.export(path.display().to_string(), false).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("review_key"));
        assert!(!String::from_utf8_lossy(&bytes).contains("duo_session"));
        let mut imported = Vault::memory();
        imported
            .import_with_options(
                path.display().to_string(),
                ConflictPolicy::Skip,
                false,
                10,
                &mut VaultCredentials::default(),
            )
            .unwrap();
        assert_eq!(
            imported.item(1).unwrap().duo.as_ref().unwrap().credentials,
            vault.item(1).unwrap().duo.as_ref().unwrap().credentials
        );
        assert_eq!(
            imported.item(1).unwrap().authenticator,
            vault.item(1).unwrap().authenticator
        );
    }
    #[test]
    fn browser_duo_summaries_match_exact_https_issuer_without_device_keys() {
        let (vault, _) = fixture();
        let summaries = vault.browser_duo_items("https://api-test.duosecurity.com/frame/prompt");
        assert_eq!(summaries.len(), 1);
        let encoded = serde_json::to_string(&summaries).unwrap();
        for secret in [
            "syntheticAccount",
            "syntheticDevice",
            "PRIVATE KEY",
            "password",
        ] {
            assert!(!encoded.contains(secret));
        }
        for origin in [
            "http://api-test.duosecurity.com",
            "https://api-test.duosecurity.com:8443",
            "https://api-test.duosecurity.com.evil.example",
            "https://api-test.duosecurity.com./",
            "https://user@api-test.duosecurity.com",
            "https://api-missing.duosecurity.com",
            "https://duosecurity.com",
            "invalid",
        ] {
            assert!(vault.browser_duo_items(origin).is_empty(), "{origin}");
        }
    }
}
