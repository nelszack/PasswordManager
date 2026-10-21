pub mod native_contract;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const SECURE_PREFACE: &[u8; 4] = b"PMS2";
pub const SECURE_HELLO_LEN: usize = 4 + 32 + 32;
pub const SECURE_RECORD_HEADER_LEN: usize = 24 + 4;

pub struct TransportKeys {
    pub request: [u8; 32],
    pub response: [u8; 32],
}

impl Drop for TransportKeys {
    fn drop(&mut self) {
        self.request.zeroize();
        self.response.zeroize();
    }
}

fn token_key(token: &str) -> Option<[u8; 32]> {
    let mut decoded = hex::decode(token).ok()?;
    let result = decoded.as_slice().try_into().ok();
    decoded.zeroize();
    result
}

fn keyed_value(key: &[u8; 32], label: &[u8], challenge: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(label);
    hasher.update(challenge);
    *hasher.finalize().as_bytes()
}

fn transport_keys(key: &[u8; 32], challenge: &[u8; 32]) -> TransportKeys {
    TransportKeys {
        request: keyed_value(key, b"password-manager-request-v2", challenge),
        response: keyed_value(key, b"password-manager-response-v2", challenge),
    }
}

pub fn server_hello(token: &str) -> Option<([u8; SECURE_HELLO_LEN], TransportKeys)> {
    let mut key = token_key(token)?;
    let challenge = rand::random::<[u8; 32]>();
    let authenticator = keyed_value(&key, b"password-manager-server-v2", &challenge);
    let keys = transport_keys(&key, &challenge);
    key.zeroize();

    let mut hello = [0u8; SECURE_HELLO_LEN];
    hello[..4].copy_from_slice(SECURE_PREFACE);
    hello[4..36].copy_from_slice(&challenge);
    hello[36..].copy_from_slice(&authenticator);
    Some((hello, keys))
}

pub fn verify_server_hello(token: &str, hello: &[u8]) -> Option<TransportKeys> {
    if hello.len() != SECURE_HELLO_LEN || &hello[..4] != SECURE_PREFACE {
        return None;
    }
    let challenge: [u8; 32] = hello[4..36].try_into().ok()?;
    let mut key = token_key(token)?;
    let mut expected = keyed_value(&key, b"password-manager-server-v2", &challenge);
    let authenticated: bool = expected.ct_eq(&hello[36..]).into();
    expected.zeroize();
    if !authenticated {
        key.zeroize();
        return None;
    }
    let keys = transport_keys(&key, &challenge);
    key.zeroize();
    Some(keys)
}

pub fn encrypt_record(key: &[u8; 32], plaintext: &[u8]) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::generate();
    let ciphertext = cipher.encrypt(&nonce, plaintext).ok()?;
    let length = u32::try_from(ciphertext.len()).ok()?;
    let mut record = Vec::with_capacity(SECURE_RECORD_HEADER_LEN + ciphertext.len());
    record.extend_from_slice(&nonce);
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(&ciphertext);
    Some(record)
}

pub fn decrypt_record(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::try_from(nonce).ok()?;
    cipher.decrypt(&nonce, ciphertext).ok()
}

pub fn decrypt_record_stream(
    key: &[u8; 32],
    mut records: &[u8],
    maximum_plaintext: usize,
) -> Result<Vec<u8>, String> {
    let mut plaintext = Vec::new();
    while !records.is_empty() {
        if records.len() < SECURE_RECORD_HEADER_LEN {
            plaintext.zeroize();
            return Err("server returned a truncated encrypted response".to_string());
        }
        let length = u32::from_be_bytes(
            records[24..28]
                .try_into()
                .map_err(|_| "server returned an invalid encrypted response length")?,
        ) as usize;
        let nonce: [u8; 24] = records[..24]
            .try_into()
            .map_err(|_| "server returned an invalid encrypted response nonce")?;
        records = &records[SECURE_RECORD_HEADER_LEN..];
        if length < 16 || length > maximum_plaintext.saturating_add(16) || records.len() < length {
            plaintext.zeroize();
            return Err("server returned an invalid encrypted response length".to_string());
        }
        let Some(mut part) = decrypt_record(key, &nonce, &records[..length]) else {
            plaintext.zeroize();
            return Err("server returned an unauthenticated encrypted response".to_string());
        };
        if plaintext.len().saturating_add(part.len()) > maximum_plaintext {
            part.zeroize();
            plaintext.zeroize();
            return Err("server response exceeds the configured limit".to_string());
        }
        plaintext.extend_from_slice(&part);
        part.zeroize();
        records = &records[length..];
    }
    Ok(plaintext)
}

pub const PROTOCOL_VERSION: u16 = 2;
pub const DEFAULT_PORT: u16 = 7878;
pub fn server_addr(port: u16) -> std::net::SocketAddr {
    ([127, 0, 0, 1], port).into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum ResponseCode {
    Success = 0,
    Failure = 1,
    InvalidInput = 2,
    NotFound = 3,
    Conflict = 4,
    Durability = 5,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub protocol_version: u16,
    pub request_id: String,
    pub operation_id: Option<String>,
    pub expected_revision: Option<u64>,
    #[serde(default)]
    pub expected_session: Option<String>,
    pub command: crate::types::ServerCommand,
}
impl RequestEnvelope {
    pub fn new(command: crate::types::ServerCommand) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: hex::encode(rand::random::<[u8; 16]>()),
            operation_id: command
                .is_mutation()
                .then(|| hex::encode(rand::random::<[u8; 16]>())),
            expected_revision: None,
            expected_session: None,
            command,
        }
    }
    pub fn with_operation(
        mut self,
        operation_id: Option<String>,
        expected_revision: Option<u64>,
    ) -> Self {
        self.operation_id = operation_id;
        self.expected_revision = expected_revision;
        self
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "unsupported protocol version {}; expected {}",
                self.protocol_version, PROTOCOL_VERSION
            ));
        }
        if matches!(
            self.command,
            crate::types::ServerCommand::BrowserLogin { .. }
                | crate::types::ServerCommand::BrowserAutofillItem(_)
                | crate::types::ServerCommand::BrowserAuthenticatorData { .. }
        ) && (self.expected_session.is_none() || self.expected_revision.is_none())
        {
            return Err(
                "browser selections require the reviewed unlock session and item revision".into(),
            );
        }
        if self
            .expected_session
            .as_ref()
            .is_some_and(|id| id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err("invalid unlock session identifier".into());
        }
        for id in std::iter::once(&self.request_id).chain(self.operation_id.iter()) {
            if id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err("invalid request or operation identifier".into());
            }
        }
        if self.command.is_mutation() && self.operation_id.is_none() {
            return Err("mutations require an operation identifier".into());
        }
        Ok(())
    }
}
impl Zeroize for RequestEnvelope {
    fn zeroize(&mut self) {
        self.command.zeroize();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Pending,
    Committed,
    CommittedDurabilityUnknown,
    Failed,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationReceipt {
    pub operation_id: String,
    pub state: OperationState,
    pub revision: Option<u64>,
}

/// Dynamically structured reports still own the cleanup of every string.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct SecretJson(serde_json::Value);
impl SecretJson {
    pub fn expose_owned(mut self) -> serde_json::Value {
        std::mem::take(&mut self.0)
    }
}
impl From<serde_json::Value> for SecretJson {
    fn from(value: serde_json::Value) -> Self {
        Self(value)
    }
}
impl std::ops::Deref for SecretJson {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::fmt::Debug for SecretJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}
impl Zeroize for SecretJson {
    fn zeroize(&mut self) {
        fn wipe(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::String(s) => s.zeroize(),
                serde_json::Value::Array(v) => v.iter_mut().for_each(wipe),
                serde_json::Value::Object(v) => v.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
        self.0 = serde_json::Value::Null;
    }
}
impl Drop for SecretJson {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultReference {
    pub vault_file: String,
}

/// Responses carry records; terminal and browser formatting live in adapters.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ResponsePayload {
    Message(String),
    Secret(crate::secret::SecretString),
    Status(ServerStatus),
    Authenticator(AuthenticatorResponse),
    Vault(VaultReference),
    ItemPage(crate::vault::ItemPage),
    Item(crate::vault::ItemDetail),
    Summaries(Vec<crate::vault::ItemSummary>),
    Login(crate::vault::BrowserLogin),
    Autofill(crate::vault::AutofillItem),
    Operation(OperationReceipt),
    Audit(crate::vault::AuditReport),
    ImportReport(crate::vault::ImportReport),
    DuoRequests(Vec<crate::types::DuoPushRequest>),
    History(crate::vault::HistoryPage),
    Trash(crate::vault::TrashPage),
}
impl ResponsePayload {
    pub fn into_json(self) -> serde_json::Value {
        match self {
            Self::Message(value) => serde_json::Value::String(value),
            Self::Secret(value) => serde_json::to_value(value).expect("secret is serializable"),
            Self::Status(value) => serde_json::to_value(value).expect("status is serializable"),
            Self::Authenticator(value) => {
                serde_json::to_value(value).expect("code is serializable")
            }
            Self::Vault(value) => serde_json::to_value(value).expect("vault reference serializes"),
            Self::ItemPage(value) => serde_json::to_value(value).expect("page is serializable"),
            Self::Item(value) => serde_json::to_value(value).expect("item is serializable"),
            Self::Summaries(value) => {
                serde_json::to_value(value).expect("summaries are serializable")
            }
            Self::Login(value) => serde_json::to_value(value).expect("login is serializable"),
            Self::Autofill(value) => serde_json::to_value(value).expect("autofill is serializable"),
            Self::Operation(value) => serde_json::to_value(value).expect("receipt is serializable"),
            Self::DuoRequests(value) => serde_json::to_value(value).expect("requests serialize"),
            Self::ImportReport(value) => {
                serde_json::to_value(value).expect("import report serializes")
            }
            Self::Audit(value) => serde_json::to_value(value).expect("audit is serializable"),
            Self::History(value) => serde_json::to_value(value).expect("history serializes"),
            Self::Trash(value) => serde_json::to_value(value).expect("trash serializes"),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcResponse {
    pub protocol_version: u16,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    pub code: i32,
    pub payload: ResponsePayload,
    pub operation: Option<OperationReceipt>,
}
impl RpcResponse {
    pub fn new(code: ResponseCode, payload: ResponsePayload) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: None,
            session_id: None,
            code: code as i32,
            payload,
            operation: None,
        }
    }
    pub fn success(payload: ResponsePayload) -> Self {
        Self::new(ResponseCode::Success, payload)
    }
    pub fn message(code: ResponseCode, message: impl Into<String>) -> Self {
        Self::new(code, ResponsePayload::Message(message.into()))
    }
    pub fn error_message(&self) -> String {
        match &self.payload {
            ResponsePayload::Message(s) => s.clone(),
            ResponsePayload::Audit(report) => report
                .breach_error
                .clone()
                .unwrap_or_else(|| "Audit checks are incomplete".into()),
            _ => "operation failed".into(),
        }
    }
}
impl Zeroize for RpcResponse {
    fn zeroize(&mut self) {
        match &mut self.payload {
            ResponsePayload::Message(s) => s.zeroize(),
            ResponsePayload::Secret(s) => s.zeroize(),
            ResponsePayload::Authenticator(a) => a.zeroize(),
            // Typed DTO secret fields own their cleanup. Replacing drops them.
            _ => {}
        }
        self.payload = ResponsePayload::Message(String::new());
    }
}
// Responses are often moved into adapters; secret fields have their own Drop.
pub type ProtocolResponse = RpcResponse;

pub fn encode_rpc_response(response: &RpcResponse) -> Result<Vec<u8>, String> {
    rmp_serde::to_vec_named(response).map_err(|_| "could not encode server response".into())
}
pub fn decode_responses(bytes: &[u8]) -> Result<RpcResponse, String> {
    use serde::Deserialize;
    let mut cursor = std::io::Cursor::new(bytes);
    let mut deserializer = rmp_serde::Deserializer::new(&mut cursor);
    let response = RpcResponse::deserialize(&mut deserializer)
        .map_err(|_| "server returned an invalid response".to_string())?;
    if cursor.position() != bytes.len() as u64 {
        return Err("server returned trailing response data".into());
    }
    if response.protocol_version != PROTOCOL_VERSION {
        return Err("server uses an incompatible protocol version".into());
    }
    if let ResponsePayload::Authenticator(code) = &response.payload
        && !code.valid()
    {
        return Err("server returned invalid authenticator data".into());
    }
    if !(0..=ResponseCode::Durability as i32).contains(&response.code) {
        return Err("server returned an unknown response code".into());
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn authenticator_responses_preserve_codes_lifetimes_and_full_u64_counters() {
        for counter in [0, (1 << 53) - 1, 1 << 53, u64::MAX] {
            let authenticator = AuthenticatorResponse {
                code: "123456".into(),
                expires_in: None,
                counter: Some(counter),
                mode: "hotp".into(),
            };
            assert!(authenticator.valid());
            let json = serde_json::to_value(&authenticator).unwrap();
            assert_eq!(json["counter"], counter.to_string());
            assert_eq!(json["code"], "123456");
            assert_eq!(json["mode"], "hotp");
            assert!(json["expires_in"].is_null());
            assert_eq!(
                serde_json::from_value::<AuthenticatorResponse>(json.clone())
                    .unwrap()
                    .counter,
                Some(counter)
            );
            let encoded = rmp_serde::to_vec_named(&authenticator).unwrap();
            let wire: serde_json::Value = rmp_serde::from_slice(&encoded).unwrap();
            assert_eq!(wire["counter"].as_u64(), Some(counter));
            let response = RpcResponse::success(ResponsePayload::Authenticator(authenticator));
            let decoded = decode_responses(&encode_rpc_response(&response).unwrap()).unwrap();
            assert_eq!(decoded.payload.into_json(), json);
        }
        let totp = AuthenticatorResponse {
            code: "123456".into(),
            expires_in: Some(30),
            counter: None,
            mode: "totp".into(),
        };
        assert!(totp.valid());
        let json = serde_json::json!({
            "code": "123456", "expires_in": 30, "counter": null, "mode": "totp"
        });
        let response = RpcResponse::success(ResponsePayload::Authenticator(totp));
        let decoded = decode_responses(&encode_rpc_response(&response).unwrap()).unwrap();
        assert_eq!(decoded.payload.into_json(), json);
        assert!(
            serde_json::from_value::<AuthenticatorResponse>(json)
                .unwrap()
                .valid()
        );
    }

    #[test]
    fn json_hotp_counters_reject_lossy_or_noncanonical_values() {
        for counter in [
            serde_json::json!(0),
            serde_json::json!(9007199254740992u64),
            serde_json::json!(""),
            serde_json::json!("00"),
            serde_json::json!("+1"),
            serde_json::json!("-1"),
            serde_json::json!(" 1"),
            serde_json::json!("1.0"),
            serde_json::json!("1e3"),
            serde_json::json!("18446744073709551616"),
        ] {
            assert!(
                serde_json::from_value::<AuthenticatorResponse>(serde_json::json!({
                    "code": "123456", "mode": "hotp", "expires_in": null, "counter": counter
                }))
                .is_err()
            );
        }
    }
    proptest! {
        #[test]
        fn secret_payloads_preserve_every_byte(secret in ".{0,2048}") {
            let original = RpcResponse::success(ResponsePayload::Secret(secret.as_str().into()));
            let encoded = encode_rpc_response(&original).unwrap();
            let response = decode_responses(&encoded).unwrap();
            match response.payload {
                ResponsePayload::Secret(value) => prop_assert_eq!(value.expose(), secret),
                _ => prop_assert!(false, "expected a typed secret payload"),
            }
        }
        #[test]
        fn arbitrary_responses_never_panic(bytes in proptest::collection::vec(any::<u8>(),0..4096)) {
            let _=decode_responses(&bytes);
        }
    }
    #[test]
    fn explicit_versions_and_single_response_reject_ambiguity() {
        let mut response = RpcResponse::message(ResponseCode::Success, "one");
        response.protocol_version += 1;
        assert!(decode_responses(&encode_rpc_response(&response).unwrap()).is_err());
        let mut encoded =
            encode_rpc_response(&RpcResponse::message(ResponseCode::Success, "one")).unwrap();
        encoded.extend(
            encode_rpc_response(&RpcResponse::message(ResponseCode::Success, "two")).unwrap(),
        );
        assert!(decode_responses(&encoded).is_err());
    }
    #[test]
    fn secure_transport_authenticates_the_server_and_encrypts_both_directions() {
        let token = "ab".repeat(32);
        let (hello, server_keys) = server_hello(&token).unwrap();
        let client_keys = verify_server_hello(&token, &hello).unwrap();
        assert_eq!(client_keys.request, server_keys.request);
        assert_eq!(client_keys.response, server_keys.response);

        let secret = b"master-password-must-not-appear-on-the-wire";
        let mut request = encrypt_record(&client_keys.request, secret).unwrap();
        assert!(!request.windows(secret.len()).any(|window| window == secret));
        let decrypted = decrypt_record(
            &server_keys.request,
            &request[..24],
            &request[SECURE_RECORD_HEADER_LEN..],
        )
        .unwrap();
        assert_eq!(decrypted, secret);

        *request.last_mut().unwrap() ^= 1;
        assert!(
            decrypt_record(
                &server_keys.request,
                &request[..24],
                &request[SECURE_RECORD_HEADER_LEN..],
            )
            .is_none()
        );
    }

    #[test]
    fn impostor_server_cannot_authenticate_before_receiving_a_command() {
        let real_token = "ab".repeat(32);
        let attacker_token = "cd".repeat(32);
        let (impostor_hello, _) = server_hello(&attacker_token).unwrap();
        assert!(verify_server_hello(&real_token, &impostor_hello).is_none());

        let mut tampered = server_hello(&real_token).unwrap().0;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(verify_server_hello(&real_token, &tampered).is_none());
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerStatus {
    pub locked: bool,
    pub version: String,
    pub warning: Option<String>,
}
impl ServerStatus {
    pub fn new(locked: bool, warning: Option<String>) -> Self {
        Self {
            locked,
            version: env!("CARGO_PKG_VERSION").into(),
            warning,
        }
    }
}
#[derive(
    Clone, Debug, serde::Serialize, serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop,
)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorResponse {
    pub code: crate::secret::SecretString,
    pub expires_in: Option<u64>,
    #[serde(with = "optional_json_u64")]
    pub counter: Option<u64>,
    pub mode: String,
}
impl AuthenticatorResponse {
    pub fn valid(&self) -> bool {
        (6..=8).contains(&self.code.len())
            && self.code.bytes().all(|b| b.is_ascii_digit())
            && match self.mode.as_str() {
                "hotp" => self.counter.is_some() && self.expires_in.is_none(),
                "totp" => self.counter.is_none() && self.expires_in.is_some(),
                _ => false,
            }
    }
}

// JSON numbers cannot preserve every HOTP counter in JavaScript. Keep the full
// domain range as decimal text there, while MessagePack retains its typed u64.
mod optional_json_u64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            value
                .map(|counter| counter.to_string())
                .serialize(serializer)
        } else {
            value.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        if !deserializer.is_human_readable() {
            return Option::<u64>::deserialize(deserializer);
        }
        Option::<String>::deserialize(deserializer)?
            .map(|counter| {
                if counter.is_empty()
                    || counter.len() > 20
                    || !counter.bytes().all(|byte| byte.is_ascii_digit())
                    || counter.len() > 1 && counter.starts_with('0')
                {
                    return Err(serde::de::Error::custom("invalid decimal u64 counter"));
                }
                counter.parse().map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}
