use super::*;
pub struct AuthenticatorCode {
    pub code: Zeroizing<String>,
    pub expires_in: Option<u64>,
    pub counter: Option<u64>,
}
impl Vault {
    pub fn set_totp(
        &mut self,
        target: Target,
        configuration: &str,
        key: &mut VaultCredentials,
    ) -> Result<Option<usize>, VaultError> {
        let Some(id) = self.entry_id(&target) else {
            return Ok(None);
        };
        let (normalized, bits) = normalize_totp_configuration(configuration)?;
        let normalized = Zeroizing::new(normalized);
        let authenticator = Authenticator::parse(&normalized)?;
        if self.item(id).unwrap().authenticator.as_ref() == Some(&authenticator) {
            return Ok(Some(bits));
        }
        self.transaction(TransactionScope::Entry(id), key, |v| {
            let item = v.item_mut(id).unwrap();
            item.authenticator = Some(authenticator);
            item.entry.modified = Timestamp::now();
            Ok((true, Some(bits)))
        })
    }
    pub fn remove_totp(
        &mut self,
        target: Target,
        key: &mut VaultCredentials,
    ) -> Result<bool, VaultError> {
        let Some(id) = self.entry_id(&target) else {
            return Ok(false);
        };
        if self.item(id).unwrap().authenticator.is_none() {
            return Ok(false);
        };
        self.transaction(TransactionScope::Entry(id), key, |v| {
            let item = v.item_mut(id).unwrap();
            item.authenticator = None;
            item.entry.modified = Timestamp::now();
            Ok((true, true))
        })
    }
    pub(super) fn totp_at(
        &self,
        target: &Target,
        timestamp: u64,
    ) -> Result<(String, u64), VaultError> {
        let id = self
            .entry_id(target)
            .ok_or_else(|| VaultError::NotFound("entry not found".into()))?;
        let authenticator = self
            .item(id)
            .unwrap()
            .authenticator
            .as_ref()
            .ok_or_else(|| VaultError::NotFound("item has no authenticator".into()))?;
        let AuthenticatorState::Totp(totp) = &authenticator.state else {
            return Err(VaultError::InvalidInput(
                "HOTP requires consuming its persistent counter".into(),
            ));
        };
        Ok((
            totp.generate(timestamp).to_string(),
            totp.step() - (timestamp % totp.step()),
        ))
    }
    pub fn current_totp(&self, target: Target) -> Result<(String, u64), VaultError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| VaultError::Validation(e.to_string()))?
            .as_secs();
        self.totp_at(&target, timestamp)
    }
    pub fn current_otp(
        &mut self,
        target: Target,
        key: &mut VaultCredentials,
    ) -> Result<AuthenticatorCode, VaultError> {
        let id = self
            .entry_id(&target)
            .ok_or_else(|| VaultError::NotFound("entry not found".into()))?;
        let a = self
            .item(id)
            .unwrap()
            .authenticator
            .as_ref()
            .ok_or_else(|| VaultError::NotFound("item has no authenticator".into()))?;
        if matches!(&a.state, AuthenticatorState::Totp(_)) {
            let (code, ttl) = self.current_totp(target)?;
            return Ok(AuthenticatorCode {
                code: Zeroizing::new(code),
                expires_in: Some(ttl),
                counter: None,
            });
        }
        let AuthenticatorState::Hotp {
            generator: hotp,
            counter,
        } = &a.state
        else {
            unreachable!()
        };
        let counter = *counter;
        let next = counter
            .checked_add(1)
            .ok_or_else(|| VaultError::InvalidInput("HOTP counter exhausted".into()))?;
        let code = Zeroizing::new(hotp.generate(counter).to_string());
        let mut url =
            url::Url::parse(&a.configuration).map_err(|e| VaultError::Validation(e.to_string()))?;
        let pairs = Zeroizing::new(
            url.query_pairs()
                .filter(|(k, _)| k != "counter")
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect::<Vec<_>>(),
        );
        url.query_pairs_mut()
            .clear()
            .extend_pairs(pairs.iter())
            .append_pair("counter", &next.to_string());
        let mut configuration = a.clone();
        configuration.configuration = url.to_string().into();
        if let AuthenticatorState::Hotp { counter, .. } = &mut configuration.state {
            *counter = next;
        }
        self.transaction(TransactionScope::Entry(id), key, |v| {
            v.item_mut(id).unwrap().authenticator = Some(configuration);
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

pub(super) fn parse_hotp_configuration(value: &str) -> Result<(Totp, u64), VaultError> {
    let invalid = || {
        VaultError::InvalidInput("invalid HOTP URI: requires a secret, SHA1/SHA256/SHA512, 6–8 digits, and one unsigned counter".into())
    };
    let mut url = url::Url::parse(value).map_err(|_| invalid())?;
    if value.chars().any(char::is_control)
        || url.scheme() != "otpauth"
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
    // The dependency accepts repeated parameters (the last value wins), URL
    // credentials, ports and fragments. Reject ambiguous configurations before
    // parsing either compliant or legacy-length secrets.
    let invalid = || {
        VaultError::InvalidInput("invalid TOTP URI: requires one secret, unique parameters, and an otpauth://totp/ label without credentials, port, fragment, or HOTP counter".into())
    };
    let url = url::Url::parse(value).map_err(|_| invalid())?;
    if value.chars().any(char::is_control)
        || url.scheme() != "otpauth"
        || url.host_str() != Some("totp")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.path().trim_matches('/').is_empty()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    for name in [
        "secret",
        "algorithm",
        "digits",
        "period",
        "issuer",
        "counter",
    ] {
        let count = url.query_pairs().filter(|(key, _)| key == name).count();
        if count > 1 || (name == "secret" && count != 1) || (name == "counter" && count != 0) {
            return Err(invalid());
        }
    }
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
