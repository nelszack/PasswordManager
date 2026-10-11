use super::*;

/// Code material is cleared on drop. HOTP has a counter, TOTP has a lifetime.
pub struct AuthenticatorCode {
    pub code: Zeroizing<String>,
    pub expires_in: Option<u64>,
    pub counter: Option<u64>,
}

impl Vault {
    #[cfg(test)]
    fn enroll_duo_with(
        &mut self,
        target: Target,
        key_pass: &mut VaultCredentials,
        enroll: impl FnOnce() -> Result<Zeroizing<String>, VaultError>,
    ) -> Result<(), VaultError> {
        let prepared = self.prepare_duo_enrollment(
            crate::types::DuoCommand::Enroll {
                target,
                activation: String::new(),
                mode: None,
                replace: false,
            },
            false,
            key_pass,
        )?;
        self.finish_duo_enrollment(
            &prepared,
            super::duo::DuoEnrollmentMaterial::Passcodes(enroll()?),
            key_pass,
        )
        .map(|_| ())
    }

    pub fn set_totp(
        &mut self,
        target: Target,
        configuration: &str,
        key_pass: &mut VaultCredentials,
    ) -> Result<Option<usize>, VaultError> {
        let Some(index) = self.entry_index(&target) else {
            return Ok(None);
        };
        let (configuration, bits) = normalize_totp_configuration(configuration)?;
        let id = self.entries[index].id;
        self.transaction(TransactionScope::Entry(id), key_pass, |vault| {
            if let Some(record) = vault.recovery.totp.iter_mut().find(|r| r.entry_id == id) {
                record.configuration.zeroize();
                record.configuration = configuration;
            } else {
                vault.recovery.totp.push(TotpRecord {
                    entry_id: id,
                    configuration,
                });
            }
            vault.entries[index].modified = chrono::Local::now().to_string();
            Ok((true, Some(bits)))
        })
    }

    pub fn remove_totp(
        &mut self,
        target: Target,
        key_pass: &mut VaultCredentials,
    ) -> Result<bool, VaultError> {
        let Some(index) = self.entry_index(&target) else {
            return Ok(false);
        };
        let id = self.entries[index].id;
        let Some(record) = self.recovery.totp.iter().position(|r| r.entry_id == id) else {
            return Ok(false);
        };
        self.transaction(TransactionScope::Entry(id), key_pass, |vault| {
            vault.recovery.totp.remove(record).zeroize();
            vault.entries[index].modified = chrono::Local::now().to_string();
            Ok((true, true))
        })
    }

    pub(super) fn totp_at(
        &self,
        target: &Target,
        timestamp: u64,
    ) -> Result<(String, u64), VaultError> {
        let Some(entry_index) = self.entry_index(target) else {
            return Err(VaultError::NotFound("entry not found".into()));
        };
        let entry_id = self.entries[entry_index].id;
        let record = self
            .recovery
            .totp
            .iter()
            .find(|record| record.entry_id == entry_id)
            .ok_or_else(|| "entry has no TOTP authenticator".to_string())?;
        let totp = parse_totp_configuration(&record.configuration)?;
        let ttl = totp.step() - (timestamp % totp.step());
        Ok((totp.generate(timestamp).to_string(), ttl))
    }

    pub fn current_totp(&self, target: Target) -> Result<(String, u64), VaultError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_string())?
            .as_secs();
        self.totp_at(&target, timestamp)
    }

    pub fn current_otp(
        &mut self,
        target: Target,
        key_pass: &mut VaultCredentials,
    ) -> Result<AuthenticatorCode, VaultError> {
        let index = self
            .entry_index(&target)
            .ok_or_else(|| VaultError::NotFound("entry not found".into()))?;
        let id = self.entries[index].id;
        let record_index = self
            .recovery
            .totp
            .iter()
            .position(|r| r.entry_id == id)
            .ok_or_else(|| VaultError::NotFound("entry has no authenticator".into()))?;
        let configuration = &self.recovery.totp[record_index].configuration;
        if !is_hotp_uri(configuration) {
            let (code, ttl) = self.current_totp(target)?;
            return Ok(AuthenticatorCode {
                code: Zeroizing::new(code),
                expires_in: Some(ttl),
                counter: None,
            });
        }
        let (hotp, counter) = parse_hotp_configuration(configuration)?;
        let next_counter = counter
            .checked_add(1)
            .ok_or_else(|| VaultError::InvalidInput("HOTP counter is exhausted".into()))?;
        // A one-second step makes totp-rs's moving factor exactly the HOTP counter,
        // reusing its HMAC/truncation implementation without counter multiplication.
        let code = Zeroizing::new(hotp.generate(counter).to_string());
        let mut url = url::Url::parse(configuration)
            .map_err(|_| VaultError::InvalidInput("invalid HOTP URI".into()))?;
        let pairs = Zeroizing::new(
            url.query_pairs()
                .filter(|(key, _)| key != "counter")
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<Vec<_>>(),
        );
        url.query_pairs_mut()
            .clear()
            .extend_pairs(pairs.iter())
            .append_pair("counter", &next_counter.to_string());
        let mut next_configuration = Zeroizing::new(url.to_string());
        // Never return a code until its next counter is persisted. The transaction
        // restores the previous counter on any failure before the atomic replace.
        self.transaction(TransactionScope::Entry(id), key_pass, |vault| {
            let record = &mut vault.recovery.totp[record_index];
            record.configuration.zeroize();
            record.configuration = std::mem::take(&mut *next_configuration);
            Ok((
                true,
                AuthenticatorCode {
                    code,
                    expires_in: None,
                    counter: Some(counter),
                },
            ))
        })
    }

    pub(super) fn remove_totp_records(&mut self, entry_ids: &[usize]) {
        let mut retained = Vec::with_capacity(self.recovery.totp.len());
        for mut record in std::mem::take(&mut self.recovery.totp) {
            if entry_ids.contains(&record.entry_id) {
                record.zeroize();
            } else {
                retained.push(record);
            }
        }
        self.recovery.totp = retained;
    }

    pub(super) fn totp_marker(&self, entry_id: usize) -> &'static str {
        if let Some(record) = self
            .recovery
            .totp
            .iter()
            .find(|record| record.entry_id == entry_id)
        {
            if is_hotp_uri(&record.configuration) {
                " [HOTP]"
            } else {
                " [TOTP]"
            }
        } else {
            ""
        }
    }
}

pub(super) fn is_otpauth_uri(value: &str) -> bool {
    value
        .get(.."otpauth://".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("otpauth://"))
}

pub(super) fn is_hotp_uri(value: &str) -> bool {
    value
        .get(.."otpauth://hotp/".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("otpauth://hotp/"))
}

fn parse_hotp_configuration(value: &str) -> Result<(Totp, u64), VaultError> {
    let invalid = || {
        VaultError::InvalidInput("invalid HOTP URI: requires a secret, SHA1/SHA256/SHA512, 6–8 digits, and one unsigned counter".into())
    };
    let mut url = url::Url::parse(value).map_err(|_| invalid())?;
    if url.scheme() != "otpauth"
        || url.host_str() != Some("hotp")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.path().trim_matches('/').is_empty()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    let pairs = Zeroizing::new(
        url.query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<Vec<_>>(),
    );
    for name in ["secret", "counter", "algorithm", "digits", "issuer"] {
        let count = pairs.iter().filter(|(key, _)| key == name).count();
        if count > 1 || ((name == "secret" || name == "counter") && count != 1) {
            return Err(invalid());
        }
    }
    if pairs.iter().any(|(key, _)| key == "period") {
        return Err(invalid());
    }
    let counter_text = &pairs
        .iter()
        .find(|(key, _)| key == "counter")
        .ok_or_else(invalid)?
        .1;
    if counter_text.is_empty() || !counter_text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let counter = counter_text.parse::<u64>().map_err(|_| invalid())?;
    url.set_host(Some("totp")).map_err(|_| invalid())?;
    url.query_pairs_mut()
        .clear()
        .extend_pairs(pairs.iter().filter(|(key, _)| key != "counter"))
        .append_pair("period", "1");
    let converted = Zeroizing::new(url.to_string());
    let hotp = compatible_totp_from_url(&converted).map_err(|_| invalid())?;
    Ok((hotp, counter))
}

const MIN_COMPATIBLE_TOTP_SECRET_BYTES: usize = 10;

pub(super) fn compatible_totp_from_url(value: &str) -> Result<Totp, VaultError> {
    match Totp::from_url(value) {
        Ok(totp) => Ok(totp),
        Err(TotpError::SecretTooShort { bits }) if bits >= MIN_COMPATIBLE_TOTP_SECRET_BYTES * 8 => {
            let totp = Totp::from_url_unchecked(value)
                .map_err(|error| format!("invalid otpauth URI: {error}"))?;
            if !(6..=8).contains(&totp.digits()) {
                return Err((format!(
                    "invalid otpauth URI: unsupported digit count {}",
                    totp.digits()
                ))
                .into());
            }
            if totp.step() == 0 {
                return Err(("invalid otpauth URI: period cannot be zero".to_string()).into());
            }
            Ok(totp)
        }
        Err(error) => Err((format!("invalid otpauth URI: {error}")).into()),
    }
}

pub(super) fn compatible_totp_from_secret(secret: TotpSecret) -> Result<Totp, VaultError> {
    let secret_bytes = secret.as_ref().len();
    if secret_bytes < MIN_COMPATIBLE_TOTP_SECRET_BYTES {
        return Err((format!(
            "TOTP secret must be at least {} bits, got {} bits",
            MIN_COMPATIBLE_TOTP_SECRET_BYTES * 8,
            secret_bytes * 8
        ))
        .into());
    }
    let builder = TotpBuilder::new().with_secret(secret);
    if secret_bytes < 16 {
        Ok(builder.build_noncompliant())
    } else {
        builder.build().map_err(|error| {
            VaultError::InvalidInput(format!("invalid TOTP configuration: {error}"))
        })
    }
}

pub(super) fn normalize_totp_configuration(value: &str) -> Result<(String, usize), VaultError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(("TOTP configuration cannot be empty".to_string()).into());
    }
    if trimmed.len() > 4096 {
        return Err(("TOTP configuration is too long".to_string()).into());
    }
    if is_otpauth_uri(trimmed) {
        let totp = if is_hotp_uri(trimmed) {
            parse_hotp_configuration(trimmed)?.0
        } else {
            compatible_totp_from_url(trimmed)?
        };
        return Ok((trimmed.to_string(), totp.secret().as_ref().len() * 8));
    }

    let mut normalized: String = trimmed
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '-')
        .flat_map(char::to_uppercase)
        .collect();
    let secret = match TotpSecret::try_from_base32(&normalized) {
        Ok(secret) => secret,
        Err(error) => {
            normalized.zeroize();
            return Err((format!("invalid Base32 TOTP secret: {error}")).into());
        }
    };
    let secret_bits = secret.as_ref().len() * 8;
    if let Err(error) = compatible_totp_from_secret(secret) {
        normalized.zeroize();
        return Err(error);
    }
    Ok((normalized, secret_bits))
}

pub(super) fn parse_totp_configuration(value: &str) -> Result<Totp, VaultError> {
    if is_otpauth_uri(value) {
        compatible_totp_from_url(value)
    } else {
        let secret = TotpSecret::try_from_base32(value)
            .map_err(|error| format!("invalid Base32 TOTP secret: {error}"))?;
        compatible_totp_from_secret(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn uri(counter: u64) -> String {
        format!(
            "otpauth://hotp/Work:alice?secret={SECRET}&issuer=Work&algorithm=SHA1&digits=6&counter={counter}"
        )
    }

    fn fixture() -> (Vault, VaultCredentials) {
        crate::file::init_test_data_dir();
        let vault = Vault {
            entries: vec![VaultEntry {
                id: 7,
                name: "work".into(),
                password: "password".into(),
                ..Default::default()
            }],
            metadata: VaultMetadata {
                filename: format!("hotp-{:016x}.enc", rand::random::<u64>()),
                duo_session: None,
            },
            recovery: RecoveryData::default(),
        };
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

    #[test]
    fn hotp_matches_all_rfc_4226_vectors_and_consumes_one_counter_per_request() {
        let (mut vault, _) = fixture();
        let mut key = VaultCredentials::default();
        assert_eq!(
            vault.set_totp(Target::Id(7), &uri(0), &mut key).unwrap(),
            Some(160)
        );
        for (counter, expected) in [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ]
        .into_iter()
        .enumerate()
        {
            let code = vault.current_otp(Target::Id(7), &mut key).unwrap();
            assert_eq!(*code.code, expected);
            assert_eq!(code.counter, Some(counter as u64));
            assert_eq!(code.expires_in, None);
            assert!(
                vault.recovery.totp[0]
                    .configuration
                    .ends_with(&format!("counter={}", counter + 1))
            );
        }
        assert_eq!(vault.totp_marker(7), " [HOTP]");
        // The legacy read-only TOTP API cannot accidentally reuse HOTP counters.
        assert!(vault.current_totp(Target::Id(7)).is_err());
    }

    #[test]
    fn hotp_counter_survives_encrypted_reload_and_secret_is_not_plaintext_on_disk() {
        let (mut vault, mut key) = fixture();
        vault.set_totp(Target::Id(7), &uri(0), &mut key).unwrap();
        assert_eq!(
            *vault.current_otp(Target::Id(7), &mut key).unwrap().code,
            "755224"
        );
        let ciphertext = fs::read(data_dir().join(&vault.metadata.filename)).unwrap();
        assert!(
            !ciphertext
                .windows(SECRET.len())
                .any(|bytes| bytes == SECRET.as_bytes())
        );
        let (_, mut restored) = lookup_vault(
            key.keypass.as_mut().unwrap(),
            Some(&vault.metadata.filename),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            *restored.current_otp(Target::Id(7), &mut key).unwrap().code,
            "287082"
        );
        assert_eq!(restored.recovery.totp[0].configuration, uri(2));
    }

    #[test]
    fn hotp_write_failure_returns_no_code_and_restores_counter() {
        let (mut vault, mut key) = fixture();
        vault.set_totp(Target::Id(7), &uri(0), &mut key).unwrap();
        let filename = vault.metadata.filename.clone();
        vault.metadata.filename = "nonexistent-directory/vault.enc".into();
        let before = vault.clone();
        assert!(matches!(
            vault.current_otp(Target::Id(7), &mut key),
            Err(VaultError::Persistence(_))
        ));
        assert_eq!(vault, before);
        vault.metadata.filename = filename;
        assert_eq!(
            *vault.current_otp(Target::Id(7), &mut key).unwrap().code,
            "755224"
        );
    }

    #[test]
    fn hotp_uses_full_width_counters_and_refuses_overflow() {
        let (mut vault, _) = fixture();
        let mut key = VaultCredentials::default();
        vault
            .set_totp(Target::Id(7), &uri(u64::MAX - 1), &mut key)
            .unwrap();
        let code = vault.current_otp(Target::Id(7), &mut key).unwrap();
        assert_eq!(code.counter, Some(u64::MAX - 1));
        assert_eq!(code.code.len(), 6);
        let before = vault.clone();
        assert!(matches!(
            vault.current_otp(Target::Id(7), &mut key),
            Err(VaultError::InvalidInput(_))
        ));
        assert_eq!(vault, before);
    }

    #[test]
    fn hotp_rejects_ambiguous_counters_and_invalid_parameters_without_changing_vault() {
        let (mut vault, _) = fixture();
        let mut key = VaultCredentials::default();
        let base = format!("otpauth://hotp/Work?secret={SECRET}");
        for suffix in [
            "",
            "&counter=-1",
            "&counter=18446744073709551616",
            "&counter=1&counter=2",
            "&counter=1&digits=10",
            "&counter=1&algorithm=MD5",
            "&counter=1&period=30",
            "&counter=1&secret=INVALID",
            "&counter=abc",
        ] {
            let before = vault.clone();
            assert!(
                vault
                    .set_totp(Target::Id(7), &format!("{base}{suffix}"), &mut key)
                    .is_err(),
                "accepted {suffix}"
            );
            assert_eq!(vault, before);
        }
    }

    #[test]
    fn totp_generation_keeps_existing_state_and_has_a_lifetime() {
        let (mut vault, _) = fixture();
        let mut key = VaultCredentials::default();
        vault.set_totp(Target::Id(7), SECRET, &mut key).unwrap();
        let before = vault.clone();
        let code = vault.current_otp(Target::Id(7), &mut key).unwrap();
        assert_eq!(code.counter, None);
        assert!((1..=30).contains(&code.expires_in.unwrap()));
        assert_eq!(vault, before);
    }

    #[test]
    fn hotp_trash_restore_and_portable_export_import_preserve_counter() {
        let (mut vault, mut key) = fixture();
        vault.set_totp(Target::Id(7), &uri(5), &mut key).unwrap();
        vault.delete_entry(Target::Id(7), &mut key).unwrap();
        assert!(vault.current_otp(Target::Id(7), &mut key).is_err());
        vault.restore_trashed(1, &mut key).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("export.json");
        vault.export(path.display().to_string(), false).unwrap();
        let items =
            super::super::import::import_json(&fs::read_to_string(path).unwrap(), "export.json")
                .unwrap();
        assert_eq!(items[0].totp.as_deref(), Some(uri(5).as_str()));
        assert_eq!(
            *vault.current_otp(Target::Id(7), &mut key).unwrap().code,
            "254676"
        );
        vault.delete_entry(Target::Id(7), &mut key).unwrap();
        vault.purge_trash(None, &mut key).unwrap();
        assert!(vault.recovery.totp.is_empty());
    }

    #[test]
    fn duo_enrollment_preflight_checks_lock_target_conflicts_and_persistence_before_network() {
        let (mut vault, mut key) = fixture();
        key.locked = true;
        assert!(matches!(
            vault.enroll_duo_with(Target::Id(7), &mut key, || panic!("must not enroll")),
            Err(VaultError::Locked)
        ));
        key.locked = false;
        assert!(matches!(
            vault.enroll_duo_with(Target::Id(99), &mut key, || panic!("must not enroll")),
            Err(VaultError::NotFound(_))
        ));
        vault.set_totp(Target::Id(7), SECRET, &mut key).unwrap();
        assert!(matches!(
            vault.enroll_duo_with(Target::Id(7), &mut key, || panic!("must not enroll")),
            Err(VaultError::Conflict(_))
        ));
        vault.remove_totp(Target::Id(7), &mut key).unwrap();
        vault.metadata.filename = "nonexistent-directory/vault.enc".into();
        assert!(matches!(
            vault.enroll_duo_with(Target::Id(7), &mut key, || panic!("must not enroll")),
            Err(VaultError::Persistence(_))
        ));
    }

    #[test]
    fn duo_enrollment_saves_configuration_and_leaves_vault_unchanged_on_rejection() {
        let (mut vault, mut key) = fixture();
        let before = vault.clone();
        assert!(
            vault
                .enroll_duo_with(Target::Id(7), &mut key, || Err(VaultError::InvalidInput(
                    "rejected".into()
                )))
                .is_err()
        );
        assert_eq!(vault.entries, before.entries);
        assert_eq!(vault.recovery, before.recovery);
        vault
            .enroll_duo_with(Target::Id(7), &mut key, || Ok(Zeroizing::new(uri(0))))
            .unwrap();
        let (_, mut restored) = lookup_vault(
            key.keypass.as_mut().unwrap(),
            Some(&vault.metadata.filename),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            *restored.current_otp(Target::Id(7), &mut key).unwrap().code,
            "755224"
        );
    }
}
