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
        let Some(item) = self.resolve_target(&target)? else {
            return Ok(None);
        };
        let id = item.entry.id;
        let (configuration, state, bits) = parse_authenticator_configuration(configuration)?;
        let authenticator = Authenticator {
            configuration: configuration.into(),
            state,
        };
        if item.authenticator.as_ref() == Some(&authenticator) {
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
        let Some(id) = self
            .resolve_target(&target)?
            .filter(|item| item.authenticator.is_some())
            .map(|item| item.entry.id)
        else {
            return Ok(false);
        };
        self.transaction(TransactionScope::Entry(id), key, |v| {
            let item = v.item_mut(id).unwrap();
            item.authenticator = None;
            item.entry.modified = Timestamp::now();
            Ok((true, true))
        })
    }
    fn authenticator(&self, target: &Target) -> Result<(usize, &Authenticator), VaultError> {
        let item = self.require_target(target)?;
        let authenticator = item
            .authenticator
            .as_ref()
            .ok_or_else(|| VaultError::NotFound("item has no authenticator".into()))?;
        Ok((item.entry.id, authenticator))
    }
    pub(super) fn totp_at(
        &self,
        target: &Target,
        timestamp: u64,
    ) -> Result<(String, u64), VaultError> {
        let (_, authenticator) = self.authenticator(target)?;
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
        let (id, a) = self.authenticator(&target)?;
        let (hotp, counter) = match &a.state {
            AuthenticatorState::Totp(_) => {
                let (code, ttl) = self.current_totp(target)?;
                return Ok(AuthenticatorCode {
                    code: Zeroizing::new(code),
                    expires_in: Some(ttl),
                    counter: None,
                });
            }
            AuthenticatorState::Hotp { generator, counter } => (generator, *counter),
        };
        let next = counter
            .checked_add(1)
            .ok_or_else(|| VaultError::InvalidInput("HOTP counter exhausted".into()))?;
        let code = Zeroizing::new(hotp.generate(counter).to_string());
        let mut updated = hotp_configuration_with_counter(&a.configuration, next)?;
        let mut configuration = a.clone();
        configuration.configuration = std::mem::take(&mut *updated).into();
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
/// The HOTP URI with its counter replaced by `counter` and every other
/// parameter kept, serialized as `url::Url` would. Only the label prefix is
/// parsed as a URL: the query holding the secret is decoded and re-encoded
/// into wiped buffers sized so they never reallocate.
fn hotp_configuration_with_counter(
    configuration: &str,
    counter: u64,
) -> Result<Zeroizing<String>, VaultError> {
    // Validated configurations have no credentials or fragment, so the
    // first `?` starts the query.
    let (prefix, query) = configuration.split_once('?').unwrap_or((configuration, ""));
    // An empty query keeps trailing label characters internal, so they are
    // encoded exactly as in the full URI rather than trimmed.
    let prefix = url::Url::parse(&format!("{prefix}?"))
        .map_err(|e| VaultError::Validation(e.to_string()))?;
    let pairs = Zeroizing::new(
        url::form_urlencoded::parse(query.as_bytes())
            .filter(|(k, _)| k != "counter")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<Vec<_>>(),
    );
    // Percent-encoding at most triples each byte.
    let mut serialized = Zeroizing::new(String::with_capacity(
        prefix.as_str().len() + query.len().saturating_mul(3) + 32,
    ));
    serialized.push_str(prefix.as_str());
    let start = serialized.len();
    let mut query =
        url::form_urlencoded::Serializer::for_suffix(std::mem::take(&mut *serialized), start);
    query
        .extend_pairs(pairs.iter())
        .append_pair("counter", &counter.to_string());
    Ok(Zeroizing::new(query.finish()))
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
    let (configuration, _, bits) = parse_authenticator_configuration(value)?;
    Ok((configuration, bits))
}

/// Normalize and validate once, retaining the parsed state for ingestion.
pub(super) fn parse_authenticator_configuration(
    value: &str,
) -> Result<(String, AuthenticatorState, usize), VaultError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(VaultError::Validation(
            "TOTP configuration cannot be empty".into(),
        ));
    }
    if trimmed.len() > 4096 {
        return Err(VaultError::Validation(
            "TOTP configuration is too long".into(),
        ));
    }
    if is_otpauth_uri(trimmed) {
        let (state, bits) = if is_hotp_uri(trimmed) {
            let (generator, counter) = parse_hotp_configuration(trimmed)?;
            let bits = generator.secret().as_ref().len() * 8;
            (AuthenticatorState::Hotp { generator, counter }, bits)
        } else {
            let generator = compatible_totp_from_url(trimmed)?;
            let bits = generator.secret().as_ref().len() * 8;
            (AuthenticatorState::Totp(generator), bits)
        };
        return Ok((trimmed.to_owned(), state, bits));
    }
    let mut normalized = Zeroizing::new(
        trimmed
            .chars()
            .filter(|character| !character.is_ascii_whitespace() && *character != '-')
            .flat_map(char::to_uppercase)
            .collect::<String>(),
    );
    let secret = TotpSecret::try_from_base32(&normalized)
        .map_err(|error| VaultError::Validation(format!("invalid Base32 TOTP secret: {error}")))?;
    let bits = secret.as_ref().len() * 8;
    let state = AuthenticatorState::Totp(compatible_totp_from_secret(secret)?);
    Ok((std::mem::take(&mut *normalized), state, bits))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The previous implementation, which round-tripped the secret through
    /// `url::Url`: the replacement must serialize identically.
    fn through_url(configuration: &str, counter: u64) -> String {
        let mut url = url::Url::parse(configuration).unwrap();
        let pairs = url
            .query_pairs()
            .filter(|(k, _)| k != "counter")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<Vec<_>>();
        url.query_pairs_mut()
            .clear()
            .extend_pairs(pairs.iter())
            .append_pair("counter", &counter.to_string());
        url.to_string()
    }

    #[test]
    fn hotp_counter_rewrite_matches_url_serialization() {
        for configuration in [
            "otpauth://hotp/Duo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0",
            "otpauth://hotp/Duo?counter=7&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8",
            "OTPAUTH://HOTP/Example%20Co:alice%40example.com?secret=GEZDGNBVGY3TQOJQ\
             &issuer=Example+Co&counter=12&algorithm=SHA256",
            "otpauth://hotp/caf\u{e9} label?issuer=Caf\u{e9} \"Q\"&secret=GEZDGNBVGY3TQOJQ\
             &counter=3&note=a%2Bb%26c&flag&&empty=",
            "otpauth://hotp/odd%zz?secret=GEZDGNBVGY3TQOJQ&counter=1&pct=100%&tilde=~*'()",
            "otpauth://hotp/trailing space ?secret=GEZDGNBVGY3TQOJQ&counter=5",
        ] {
            for counter in [0, 1, 42, u64::MAX] {
                assert_eq!(
                    hotp_configuration_with_counter(configuration, counter)
                        .unwrap()
                        .as_str(),
                    through_url(configuration, counter),
                    "{configuration}"
                );
            }
        }
    }

    proptest::proptest! {
        #[test]
        fn hotp_counter_rewrite_matches_url_serialization_for_any_query(
            label in "[a-zA-Z0-9 %:@.\u{e9}-]{1,16}",
            query in "[ -\"$-~\u{e9}\u{1f510}]{0,48}",
            counter: u64,
        ) {
            // Stored configurations are trimmed and contain no fragment.
            let configuration = format!("otpauth://hotp/{label}?{query}");
            proptest::prop_assume!(configuration.trim() == configuration);
            let rewritten = hotp_configuration_with_counter(&configuration, counter).unwrap();
            proptest::prop_assert_eq!(rewritten.as_str(), through_url(&configuration, counter));
        }
    }
}
