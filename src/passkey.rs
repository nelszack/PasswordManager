//! WebAuthn ES256 software authenticator. The platform adapter must authenticate
//! the user and validate native app / delegated browser identity before calling.
//! Keys are vault secrets, never Android Keystore keys: they must sync to devices.
use aws_lc_rs::{
    digest::{SHA256, digest},
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const FIELD: &str = "pm.passkey.v1";

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Passkey {
    pub credential_id: String,
    pub rp_id: String,
    pub user_handle: String,
    pub user_name: String,
    pub display_name: String,
    private_key: String,
}
/// A stored passkey's public identity, read without copying or parsing its
/// private key. Listing and exclusion checks need nothing more.
#[derive(Clone, Deserialize)]
pub struct PasskeyIdentity {
    pub credential_id: String,
    pub rp_id: String,
    pub user_name: String,
    pub display_name: String,
}
impl PasskeyIdentity {
    /// Cheap structural checks; the signing key is validated only when used.
    pub fn validate(&self) -> Result<()> {
        validate_rp(&self.rp_id)?;
        if self.credential_id.len() > 2048
            || self.user_name.len() > 1024
            || self.display_name.len() > 1024
            || decode(&self.credential_id)?.is_empty()
        {
            return Err("Invalid passkey identity".into());
        }
        Ok(())
    }
    pub fn matches(&self, request: &Value) -> bool {
        request_matches(&self.rp_id, &self.credential_id, request)
    }
}
/// Whether a WebAuthn get request may use this RP's credential.
fn request_matches(rp_id: &str, credential_id: &str, request: &Value) -> bool {
    request["rpId"].as_str() == Some(rp_id)
        && match request.get("allowCredentials") {
            None => true,
            Some(Value::Array(ids)) => {
                ids.is_empty()
                    || ids.iter().any(|id| {
                        id["type"] == "public-key" && id["id"].as_str() == Some(credential_id)
                    })
            }
            _ => false,
        }
}
impl std::fmt::Debug for Passkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passkey").finish_non_exhaustive()
    }
}
type Result<T> = std::result::Result<T, String>;
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn decode(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "Invalid base64url data".into())
}
fn bytes(value: &Value, key: &str, max: usize) -> Result<Vec<u8>> {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or("Missing WebAuthn field")?;
    if text.len() > max * 2 {
        return Err("WebAuthn field exceeds limit".into());
    }
    let bytes = decode(text)?;
    if bytes.is_empty() || bytes.len() > max {
        return Err("Invalid WebAuthn field length".into());
    }
    Ok(bytes)
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 1024)
        .ok_or_else(|| "Missing or oversized WebAuthn text field".into())
}
pub fn parse(request: &str) -> Result<Value> {
    if request.len() > 256 * 1024 {
        return Err("WebAuthn request exceeds limit".into());
    }
    serde_json::from_str(request).map_err(|_| "Invalid WebAuthn request".into())
}
pub fn validate_rp(rp: &str) -> Result<()> {
    let url = url::Url::parse(&format!("https://{rp}")).map_err(|_| "Invalid RP ID")?;
    if rp.len() > 253
        || url.host_str() != Some(rp)
        || url.port().is_some()
        || url.path() != "/"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || rp.parse::<std::net::IpAddr>().is_ok()
        || psl::domain(rp.as_bytes()).is_none()
    {
        return Err("RP ID must be a registrable DNS domain".into());
    }
    Ok(())
}
pub fn validate_origin(rp: &str, origin: &str) -> Result<()> {
    validate_rp(rp)?;
    // Android origins are accepted only after the native adapter verifies DAL.
    if let Some(hash) = origin.strip_prefix("android:apk-key-hash:") {
        if decode(hash)?.len() == 32 {
            return Ok(());
        }
        return Err("Invalid Android origin".into());
    }
    let url = url::Url::parse(origin).map_err(|_| "Invalid origin")?;
    let host = url.host_str().ok_or("Missing origin host")?;
    if url.scheme() != "https"
        || url.origin().ascii_serialization() != origin
        || !(host == rp || host.ends_with(&format!(".{rp}")))
    {
        return Err("Origin does not belong to the relying party".into());
    }
    Ok(())
}
fn client_data(kind: &str, request: &Value, origin: &str) -> Result<Vec<u8>> {
    let challenge = bytes(request, "challenge", 8192)?;
    serde_json::to_vec(&json!({
        "type": kind,
        "challenge": encode(challenge),
        "origin": origin,
        "crossOrigin": false,
    }))
    .map_err(|_| "Could not encode client data".into())
}
// Minimal canonical CBOR for WebAuthn's fixed COSE/attestation structures.
fn cbor_len(out: &mut Vec<u8>, major: u8, n: usize) {
    if n < 24 {
        out.push(major | n as u8);
    } else if n < 256 {
        out.extend_from_slice(&[major | 24, n as u8]);
    } else {
        out.push(major | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    }
}
fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    cbor_len(out, 0x40, bytes.len());
    out.extend_from_slice(bytes);
}
fn cbor_text(out: &mut Vec<u8>, text: &str) {
    cbor_len(out, 0x60, text.len());
    out.extend_from_slice(text.as_bytes());
}
/// Whether a request requires (`Some(true)`) or discourages (`Some(false)`)
/// user verification; `None` is WebAuthn's default, "preferred".
pub fn user_verification(request: &Value) -> Option<bool> {
    let value = request["userVerification"]
        .as_str()
        .or_else(|| request["authenticatorSelection"]["userVerification"].as_str());
    match value {
        Some("required") => Some(true),
        Some("discouraged") => Some(false),
        _ => None,
    }
}
fn authenticator_data(rp: &str, attested: bool, verified: bool) -> Vec<u8> {
    let mut result = digest(&SHA256, rp.as_bytes()).as_ref().to_vec();
    // UP and BE always; UV only after the person was actually verified for this
    // operation. Eligible for backup, without claiming a completed backup.
    // Synchronized credentials use a zero signature counter.
    let mut flags = 0x09;
    if verified {
        flags |= 0x04;
    }
    if attested {
        flags |= 0x40;
    }
    result.push(flags);
    result.extend_from_slice(&0u32.to_be_bytes());
    result
}
pub fn create(
    request: &Value,
    origin: &str,
    client_hash: Option<&[u8]>,
    existing: &[PasskeyIdentity],
    verified: bool,
) -> Result<(Passkey, Value)> {
    let rp = text(request.get("rp").ok_or("Missing RP")?, "id")?;
    validate_origin(rp, origin)?;
    let user = request.get("user").ok_or("Missing user")?;
    let handle = bytes(user, "id", 64)?;
    let name = text(user, "name")?;
    let display = text(user, "displayName")?;
    if !request
        .get("pubKeyCredParams")
        .and_then(Value::as_array)
        .is_some_and(|v| {
            v.iter()
                .any(|p| p["type"] == "public-key" && p["alg"] == -7)
        })
    {
        return Err("Only ES256 passkeys are supported".into());
    }
    if request["authenticatorSelection"]["authenticatorAttachment"] == "cross-platform" {
        return Err("Cross-platform authenticators are unsupported".into());
    }
    if request
        .get("extensions")
        .and_then(Value::as_object)
        .is_some_and(|e| e.keys().any(|k| !matches!(k.as_str(), "credProps")))
    {
        return Err("Unsupported WebAuthn extension".into());
    }
    if let Some(excluded) = request.get("excludeCredentials").and_then(Value::as_array) {
        for id in excluded {
            let id = encode(bytes(id, "id", 1024)?);
            if existing
                .iter()
                .any(|p| p.rp_id == rp && p.credential_id == id)
            {
                return Err("CredentialExcluded".into());
            }
        }
    }
    let client = client_data("webauthn.create", request, origin)?;
    if client_hash.is_some_and(|h| h.len() != 32) {
        return Err("Invalid client data hash".into());
    }
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| "Key generation failed")?;
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
        .map_err(|_| "Invalid signing key")?;
    let id: [u8; 32] = rand::random();
    let public = key.public_key().as_ref();
    let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
    cbor_bytes(&mut cose, &public[1..33]);
    cose.push(0x22);
    cbor_bytes(&mut cose, &public[33..65]);
    let mut auth = authenticator_data(rp, true, verified);
    auth.extend_from_slice(&[0; 16]); // no identifying attestation / AAGUID
    auth.extend_from_slice(&(id.len() as u16).to_be_bytes());
    auth.extend_from_slice(&id);
    auth.extend(cose);
    let mut attestation = vec![0xa3];
    cbor_text(&mut attestation, "fmt");
    cbor_text(&mut attestation, "none");
    cbor_text(&mut attestation, "attStmt");
    attestation.push(0xa0);
    cbor_text(&mut attestation, "authData");
    cbor_bytes(&mut attestation, &auth);
    let passkey = Passkey {
        credential_id: encode(id),
        rp_id: rp.into(),
        user_handle: encode(handle),
        user_name: name.into(),
        display_name: display.into(),
        private_key: encode(pkcs8.as_ref()),
    };
    // SubjectPublicKeyInfo for an uncompressed P-256 key, as WebAuthn's
    // getPublicKey() and toJSON() report it.
    let mut spki = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    spki.extend_from_slice(public);
    let response = json!({
        "attestationObject": encode(attestation),
        "transports": ["internal"],
        "clientDataJSON": client_data_field(&client, client_hash),
        "authenticatorData": encode(&auth),
        "publicKey": encode(spki),
        "publicKeyAlgorithm": -7,
    });
    let extensions = if request["extensions"]["credProps"] == true {
        json!({ "credProps": { "rk": true } })
    } else {
        json!({})
    };
    let value = credential(&passkey.credential_id, extensions, response);
    Ok((passkey, value))
}
/// Android browsers supply their own client-data hash and replace this
/// placeholder. The response field must still exist for JSON parsers.
fn client_data_field(client: &[u8], client_hash: Option<&[u8]>) -> String {
    match client_hash {
        None => encode(client),
        Some(_) => encode(b"{}"),
    }
}
/// A `PublicKeyCredential` as serialized by WebAuthn's `toJSON()`.
fn credential(id: &str, extensions: Value, response: Value) -> Value {
    json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "clientExtensionResults": extensions,
        "response": response,
    })
}
impl Passkey {
    pub fn validate(&self) -> Result<()> {
        validate_rp(&self.rp_id)?;
        if self.credential_id.len() > 2048
            || self.user_handle.len() > 128
            || self.private_key.len() > 16384
            || self.user_name.len() > 1024
            || self.display_name.len() > 1024
        {
            return Err("Passkey exceeds size limit".into());
        }

        if decode(&self.credential_id)?.is_empty()
            || decode(&self.user_handle)?.len() > 64
            || decode(&self.user_handle)?.is_empty()
        {
            return Err("Invalid passkey identity".into());
        }
        self.key().map(|_| ())
    }
    fn key(&self) -> Result<EcdsaKeyPair> {
        let der = Zeroizing::new(decode(&self.private_key)?);
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &der)
            .map_err(|_| "Invalid passkey signing key".into())
    }
    pub fn matches(&self, request: &Value) -> bool {
        request_matches(&self.rp_id, &self.credential_id, request)
    }
    pub fn identity(&self) -> PasskeyIdentity {
        PasskeyIdentity {
            credential_id: self.credential_id.clone(),
            rp_id: self.rp_id.clone(),
            user_name: self.user_name.clone(),
            display_name: self.display_name.clone(),
        }
    }
    pub fn authenticate(
        &self,
        request: &Value,
        origin: &str,
        client_hash: Option<&[u8]>,
        verified: bool,
    ) -> Result<Value> {
        validate_origin(&self.rp_id, origin)?;
        if !self.matches(request) {
            return Err("No matching passkey".into());
        }
        if request
            .get("extensions")
            .and_then(Value::as_object)
            .is_some_and(|e| !e.is_empty())
        {
            return Err("Unsupported WebAuthn extension".into());
        }
        let client = client_data("webauthn.get", request, origin)?;
        let hash = client_hash.map_or_else(
            || digest(&SHA256, &client).as_ref().to_vec(),
            |h| h.to_vec(),
        );
        if hash.len() != 32 {
            return Err("Invalid client data hash".into());
        }
        let auth = authenticator_data(&self.rp_id, false, verified);
        let mut message = auth.clone();
        message.extend(hash);
        let signature = self
            .key()?
            .sign(&SystemRandom::new(), &message)
            .map_err(|_| "Passkey signing failed")?;
        let response = json!({
            "authenticatorData": encode(auth),
            "signature": encode(signature.as_ref()),
            "userHandle": self.user_handle,
            "clientDataJSON": client_data_field(&client, client_hash),
        });
        Ok(credential(&self.credential_id, json!({}), response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
    fn registration() -> Value {
        json!({"rp":{"id":"example.com","name":"Example"},"user":{"id":encode(b"user"),"name":"alice","displayName":"Alice"},"challenge":encode([9;32]),"pubKeyCredParams":[{"type":"public-key","alg":-7}]})
    }
    #[test]
    fn browser_hash_is_signed_and_client_data_placeholder_is_present() {
        let browser_hash = [8; 32];
        let (key, registration) = create(
            &registration(),
            "https://example.com",
            Some(&browser_hash),
            &[],
            true,
        )
        .unwrap();
        assert_eq!(registration["response"]["clientDataJSON"], encode(b"{}"));
        let request = json!({"rpId":"example.com","challenge":encode([7;32])});
        let response = key
            .authenticate(&request, "https://example.com", Some(&browser_hash), true)
            .unwrap();
        assert_eq!(response["response"]["clientDataJSON"], encode(b"{}"));
        let mut signed =
            decode(response["response"]["authenticatorData"].as_str().unwrap()).unwrap();
        signed.extend_from_slice(&browser_hash);
        UnparsedPublicKey::new(
            &ECDSA_P256_SHA256_ASN1,
            key.key().unwrap().public_key().as_ref(),
        )
        .verify(
            &signed,
            &decode(response["response"]["signature"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert!(
            key.authenticate(&request, "https://example.com", Some(&[0; 31]), true)
                .is_err()
        );
    }
    #[test]
    fn registration_assertion_and_verifier_agree() {
        let (key, registration) = create(
            &registration(),
            "https://login.example.com",
            None,
            &[],
            true,
        )
        .unwrap();
        let att = decode(
            registration["response"]["attestationObject"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert!(att.windows(4).any(|w| w == b"none"));
        let request = json!({"rpId":"example.com","challenge":encode([7;32])});
        let response = key
            .authenticate(&request, "https://example.com", None, true)
            .unwrap();
        let body = &response["response"];
        let auth = decode(body["authenticatorData"].as_str().unwrap()).unwrap();
        assert_eq!(auth.len(), 37);
        assert_eq!(auth[32], 0x0d);
        assert_eq!(&auth[..32], digest(&SHA256, b"example.com").as_ref());
        let mut message = auth;
        message.extend(
            digest(
                &SHA256,
                &decode(body["clientDataJSON"].as_str().unwrap()).unwrap(),
            )
            .as_ref(),
        );
        UnparsedPublicKey::new(
            &ECDSA_P256_SHA256_ASN1,
            key.key().unwrap().public_key().as_ref(),
        )
        .verify(
            &message,
            &decode(body["signature"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        message[0] ^= 1;
        assert!(
            UnparsedPublicKey::new(
                &ECDSA_P256_SHA256_ASN1,
                key.key().unwrap().public_key().as_ref()
            )
            .verify(
                &message,
                &decode(body["signature"].as_str().unwrap()).unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn reject_wrong_origin_algorithm_exclusion_and_allow_list() {
        let (key, _) = create(&registration(), "https://example.com", None, &[], true).unwrap();
        for origin in [
            "https://evil.com",
            "http://example.com",
            "https://example.com.evil.com",
            "https://example.com/path",
        ] {
            assert!(create(&registration(), origin, None, &[], true).is_err());
        }
        assert!(validate_rp("com").is_err());
        let mut options = registration();
        options["pubKeyCredParams"][0]["alg"] = (-257).into();
        assert!(create(&options, "https://example.com", None, &[], true).is_err());
        options = registration();
        options["excludeCredentials"] = json!([{"type":"public-key","id":key.credential_id}]);
        assert!(
            create(
                &options,
                "https://example.com",
                None,
                &[key.identity()],
                true
            )
            .is_err()
        );
        let request = json!({"rpId":"example.com","challenge":encode([1;32]),"allowCredentials":[{"type":"public-key","id":encode([0;32])}]});
        assert!(
            key.authenticate(&request, "https://example.com", None, true)
                .is_err()
        );
    }
}
