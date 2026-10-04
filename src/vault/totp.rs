use super::*;

impl Vault {
    pub fn set_totp(
        &mut self,
        target: Target,
        configuration: &str,
        key_pass: &mut ServerInfo,
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
        key_pass: &mut ServerInfo,
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
        if self
            .recovery
            .totp
            .iter()
            .any(|record| record.entry_id == entry_id)
        {
            " [TOTP]"
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
        let totp = compatible_totp_from_url(trimmed)?;
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
