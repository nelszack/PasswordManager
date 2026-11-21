//! Stored passkeys, shared by the Android provider and the desktop browser
//! extension. Each passkey is a login item whose reserved secret field holds the
//! credential record; only the passkey workflow may write it.
use super::*;
use crate::passkey::{self, Passkey, PasskeyIdentity};
use serde_json::Value;

pub use pm_contracts::vault::PasskeyChoice;

impl Vault {
    /// Valid stored passkey identities, with a count of unreadable records.
    pub(crate) fn passkey_identities(&self) -> (Vec<(usize, PasskeyIdentity)>, usize) {
        let mut result = Vec::new();
        let mut skipped = 0usize;
        for item in self.active_items() {
            if let Some(field) = item.passkey_field() {
                match serde_json::from_str::<PasskeyIdentity>(&field.value) {
                    Ok(p) if p.validate().is_ok() => result.push((item.entry.id, p)),
                    _ => skipped += 1,
                }
            }
        }
        (result, skipped)
    }

    /// One stored passkey with its signing key, fully validated before use.
    pub(crate) fn stored_passkey(&self, id: usize) -> Result<Passkey, String> {
        let field = self
            .item(id)
            .filter(|item| item.active())
            .and_then(|item| item.passkey_field())
            .ok_or("Passkey not found")?;
        let p: Passkey =
            serde_json::from_str(&field.value).map_err(|_| "Invalid stored passkey")?;
        p.validate()?;
        Ok(p)
    }

    pub(crate) fn save_passkey(
        &mut self,
        p: &Passkey,
        credentials: &mut VaultCredentials,
    ) -> Result<(), String> {
        p.validate()?;
        let entry = TypedEntry {
            entry: crate::types::PasswordEntry {
                name: format!(
                    "Passkey: {} ({}) {}",
                    p.rp_id,
                    p.user_name,
                    &p.credential_id[..8]
                ),
                username: Some(p.user_name.clone()),
                password: "".into(),
                url: Some(format!("https://{}", p.rp_id)),
                notes: None,
                copy: false,
            },
            kind: ItemKind::Login,
            additional_urls: vec![],
            custom_fields: vec![CustomField {
                name: passkey::FIELD.into(),
                value: serde_json::to_string(p)
                    .map_err(|_| "Could not encode passkey")?
                    .into(),
                secret: true,
            }],
            tags: vec![],
            favorite: false,
        };
        if !self
            .add_passkey_entry(entry, credentials)
            .map_err(|e| e.to_string())?
        {
            return Err("Passkey entry already exists; retry registration".into());
        }
        Ok(())
    }

    /// Passkeys for this website that a WebAuthn request can use. The origin is
    /// the browser-verified page origin, never a value the page supplied.
    pub(crate) fn browser_passkeys(
        &self,
        origin: &str,
        request: &Value,
    ) -> Result<Vec<PasskeyChoice>, String> {
        browser_origin(origin)?;
        let (identities, _) = self.passkey_identities();
        Ok(identities
            .into_iter()
            .filter(|(_, p)| {
                passkey::validate_origin(&p.rp_id, origin).is_ok() && p.matches(request)
            })
            .filter_map(|(id, p)| {
                Some(PasskeyChoice {
                    id,
                    revision: self.revision(id)?,
                    rp_id: p.rp_id,
                    user_name: p.user_name,
                    display_name: p.display_name,
                })
            })
            .collect())
    }

    /// Registers a new passkey for the verified origin and stores it. The
    /// `verified` flag reports whether the person was re-verified for this
    /// operation; a site that requires verification is refused without it.
    pub(crate) fn browser_passkey_create(
        &mut self,
        origin: &str,
        request: &Value,
        credentials: &mut VaultCredentials,
        verified: bool,
    ) -> Result<Value, String> {
        browser_origin(origin)?;
        require_verification(request, verified)?;
        let existing: Vec<_> = self
            .passkey_identities()
            .0
            .into_iter()
            .map(|(_, p)| p)
            .collect();
        let (p, response) = passkey::create(request, origin, None, &existing, verified)?;
        self.save_passkey(&p, credentials)?;
        Ok(response)
    }

    /// Signs a sign-in challenge with the chosen passkey for the verified origin.
    pub(crate) fn browser_passkey_get(
        &self,
        origin: &str,
        id: usize,
        request: &Value,
        verified: bool,
    ) -> Result<Value, String> {
        browser_origin(origin)?;
        require_verification(request, verified)?;
        self.stored_passkey(id)?
            .authenticate(request, origin, None, verified)
    }
}

/// Browser requests always come from an HTTPS page; Android app origins are
/// only for the Android provider, which verifies them itself.
fn browser_origin(origin: &str) -> Result<(), String> {
    if origin.starts_with("https://") {
        Ok(())
    } else {
        Err("Browser passkeys need an HTTPS page".into())
    }
}

fn require_verification(request: &Value, verified: bool) -> Result<(), String> {
    if passkey::user_verification(request) == Some(true) && !verified {
        return Err("This site requires verification; confirm it is you in the desktop app".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn registration(rp: &str) -> Value {
        json!({"rp":{"id":rp,"name":"Example"},"user":{"id":passkey::encode(b"user-1"),"name":"alice","displayName":"Alice"},
            "challenge":passkey::encode([5;32]),"pubKeyCredParams":[{"type":"public-key","alg":-7}]})
    }

    /// The flags byte of base64url authenticator data.
    fn flags(value: &Value) -> u8 {
        passkey::decode(value.as_str().unwrap()).unwrap()[32]
    }

    #[test]
    fn browser_requests_cannot_use_android_app_origins() {
        let mut vault = Vault::memory();
        let mut key = VaultCredentials::default();
        let app = format!("android:apk-key-hash:{}", passkey::encode([1; 32]));
        assert!(
            vault
                .browser_passkey_create(&app, &registration("example.com"), &mut key, false)
                .is_err()
        );
        assert!(
            vault
                .browser_passkeys(&app, &json!({"rpId":"example.com"}))
                .is_err()
        );
    }

    #[test]
    fn user_verification_is_claimed_only_after_reverification() {
        let mut vault = Vault::memory();
        let mut key = VaultCredentials::default();
        let unverified = vault
            .browser_passkey_create(
                "https://example.com",
                &registration("example.com"),
                &mut key,
                false,
            )
            .unwrap();
        assert_eq!(
            flags(&unverified["response"]["authenticatorData"]) & 0x04,
            0
        );
        assert_eq!(
            flags(&unverified["response"]["authenticatorData"]) & 0x01,
            0x01,
            "user present"
        );
        let mut required = registration("example.com");
        required["authenticatorSelection"] = json!({ "userVerification": "required" });
        required["user"]["id"] = json!(passkey::encode(b"user-2"));
        assert!(
            vault
                .browser_passkey_create("https://example.com", &required, &mut key, false)
                .is_err()
        );
        let verified = vault
            .browser_passkey_create("https://example.com", &required, &mut key, true)
            .unwrap();
        assert_eq!(
            flags(&verified["response"]["authenticatorData"]) & 0x04,
            0x04
        );
        let choices = vault
            .browser_passkeys(
                "https://example.com",
                &json!({"rpId":"example.com","challenge":"AAAA"}),
            )
            .unwrap();
        let get = json!({"rpId":"example.com","challenge":"AAAA","userVerification":"required"});
        assert!(
            vault
                .browser_passkey_get("https://example.com", choices[0].id, &get, false)
                .is_err()
        );
        let signed = vault
            .browser_passkey_get("https://example.com", choices[0].id, &get, true)
            .unwrap();
        assert_eq!(flags(&signed["response"]["authenticatorData"]) & 0x04, 0x04);
        assert_eq!(
            passkey::user_verification(&json!({"userVerification":"discouraged"})),
            Some(false)
        );
        assert_eq!(passkey::user_verification(&json!({})), None);
    }

    #[test]
    fn browser_passkeys_register_list_and_sign_only_for_their_site() {
        let mut vault = Vault::memory();
        let mut key = VaultCredentials::default();
        let created = vault
            .browser_passkey_create(
                "https://login.example.com",
                &registration("example.com"),
                &mut key,
                false,
            )
            .unwrap();
        assert_eq!(created["type"], "public-key");
        assert!(created["response"]["attestationObject"].is_string());
        assert_eq!(created["response"]["publicKeyAlgorithm"], -7);
        assert!(created["response"]["publicKey"].is_string());
        assert!(created["response"]["authenticatorData"].is_string());
        // A page cannot register for a domain it does not belong to.
        assert!(
            vault
                .browser_passkey_create(
                    "https://evil.test",
                    &registration("example.com"),
                    &mut key,
                    false
                )
                .is_err()
        );
        let get = json!({"rpId":"example.com","challenge":passkey::encode([6;32])});
        let choices = vault.browser_passkeys("https://example.com", &get).unwrap();
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].user_name, "alice");
        assert!(
            vault
                .browser_passkeys("https://evil.test", &get)
                .unwrap()
                .is_empty()
        );
        let assertion = vault
            .browser_passkey_get("https://example.com", choices[0].id, &get, false)
            .unwrap();
        assert_eq!(assertion["id"], created["id"]);
        assert!(assertion["response"]["signature"].is_string());
        assert!(
            vault
                .browser_passkey_get("https://evil.test", choices[0].id, &get, false)
                .is_err()
        );
        // Registering the same credential ID again is excluded.
        let mut excluded = registration("example.com");
        excluded["excludeCredentials"] = json!([{"type":"public-key","id":created["id"]}]);
        assert_eq!(
            vault
                .browser_passkey_create("https://example.com", &excluded, &mut key, false)
                .unwrap_err(),
            "CredentialExcluded"
        );
    }
}
