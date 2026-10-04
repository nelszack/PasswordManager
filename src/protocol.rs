use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const RESPONSE_MAGIC: &[u8; 4] = b"PMR1";
const RESPONSE_HEADER_LEN: usize = 9;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseCode {
    Success = 0,
    Failure = 1,
    InvalidInput = 2,
    NotFound = 3,
    Conflict = 4,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProtocolResponse {
    pub code: i32,
    pub message: String,
}

pub fn encode_response(code: ResponseCode, message: &str) -> Vec<u8> {
    let mut frame = Vec::with_capacity(RESPONSE_HEADER_LEN + message.len());
    frame.extend_from_slice(RESPONSE_MAGIC);
    frame.push(code as u8);
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(message.as_bytes());
    frame
}

pub fn decode_responses(mut bytes: &[u8]) -> Result<ProtocolResponse, String> {
    let mut message = String::new();
    let mut code = ResponseCode::Success as i32;
    while !bytes.is_empty() {
        if bytes.len() < RESPONSE_HEADER_LEN || &bytes[..4] != RESPONSE_MAGIC {
            return Err("server returned an invalid response frame".to_string());
        }
        let frame_code = bytes[4] as i32;
        if frame_code > ResponseCode::Conflict as i32 {
            return Err("server returned an unknown response code".to_string());
        }
        let length = u32::from_be_bytes(
            bytes[5..9]
                .try_into()
                .map_err(|_| "server returned an invalid response length".to_string())?,
        ) as usize;
        bytes = &bytes[RESPONSE_HEADER_LEN..];
        if bytes.len() < length {
            return Err("server returned a truncated response".to_string());
        }
        let text = std::str::from_utf8(&bytes[..length])
            .map_err(|_| "server returned invalid UTF-8".to_string())?;
        message.push_str(text);
        if !text.ends_with('\n') {
            message.push('\n');
        }
        code = code.max(frame_code);
        bytes = &bytes[length..];
    }
    if message.is_empty() {
        return Err("server returned an empty response".to_string());
    }
    Ok(ProtocolResponse { code, message })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn arbitrary_input_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = decode_responses(&bytes);
        }

        #[test]
        fn arbitrary_utf8_messages_round_trip(message in ".{1,2048}") {
            let response = decode_responses(&encode_response(ResponseCode::Success, &message)).unwrap();
            prop_assert_eq!(response.code, ResponseCode::Success as i32);
            let expected = if message.ends_with('\n') { message } else { format!("{message}\n") };
            prop_assert_eq!(response.message, expected);
        }
    }

    #[test]
    fn structured_frames_round_trip_and_preserve_the_highest_error_code() {
        let mut frames = encode_response(ResponseCode::Success, "first");
        frames.extend(encode_response(ResponseCode::NotFound, "missing"));
        let response = decode_responses(&frames).unwrap();
        assert_eq!(response.code, ResponseCode::NotFound as i32);
        assert_eq!(response.message, "first\nmissing\n");
    }

    #[test]
    fn malformed_and_unknown_frames_are_rejected() {
        assert!(decode_responses(b"not-a-frame").is_err());
        let mut frame = encode_response(ResponseCode::Success, "ok");
        frame[4] = 99;
        assert!(decode_responses(&frame).is_err());
        frame[4] = 0;
        frame.pop();
        assert!(decode_responses(&frame).is_err());
    }

    #[test]
    fn response_codes_are_not_derived_from_human_readable_messages() {
        let frame = encode_response(ResponseCode::Conflict, "wording may change freely");
        let response = decode_responses(&frame).unwrap();
        assert_eq!(response.code, ResponseCode::Conflict as i32);
        assert_eq!(response.message, "wording may change freely\n");
    }

    #[test]
    fn framing_preserves_utf8_and_does_not_duplicate_existing_newlines() {
        let mut frames = encode_response(ResponseCode::Success, "héllo 🔐\n");
        frames.extend(encode_response(ResponseCode::Success, "done"));
        let response = decode_responses(&frames).unwrap();
        assert_eq!(response.message, "héllo 🔐\ndone\n");
    }

    #[test]
    fn empty_and_invalid_utf8_responses_are_rejected() {
        assert!(decode_responses(&[]).is_err());

        let mut frame = encode_response(ResponseCode::Success, "x");
        *frame.last_mut().unwrap() = 0xff;
        assert!(decode_responses(&frame).is_err());
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

/// Machine-readable server state. CLI presentation is kept outside this contract.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
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
