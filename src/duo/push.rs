//! The mobile push API uses RSA-SHA512 signatures over the date and exact form.
//! Protocol checked against the current official Duo Mobile Android APK.
use super::*;
use crate::types::{DuoCredentials, DuoPushRequest};
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use subtle::ConstantTimeEq;

pub(crate) fn validate_credentials(c: &DuoCredentials) -> Result<(), VaultError> {
    if !valid_host(&c.host, "api-")
        || c.host != c.host.to_ascii_lowercase()
        || [&c.akey, &c.pkey]
            .iter()
            .any(|s| s.is_empty() || s.len() > 256 || !s.bytes().all(|b| b.is_ascii_alphanumeric()))
        || c.private_key.len() > 16384
    {
        return Err(invalid("invalid Duo push credentials"));
    }
    crypto::load_key(&c.private_key).map(|_| ())
}

fn common(c: &DuoCredentials) -> BTreeMap<String, String> {
    [
        ("akey", c.akey.as_str()),
        ("pkpush", "rsa-sha512"),
        ("hsm_status", "false"),
        ("fips_status", "2"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect()
}
fn encoded(params: &BTreeMap<String, String>) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish()
}
fn canonical(date: &str, method: &str, host: &str, path: &str, form: &str) -> String {
    format!("{date}\n{method}\n{host}\n{path}\n{form}")
}
fn authorization(c: &DuoCredentials, message: &str) -> Result<Zeroizing<String>, VaultError> {
    let signature = crypto::sign(&c.private_key, message.as_bytes())?;
    let raw = Zeroizing::new(format!("{}:{}", c.pkey, STANDARD.encode(&signature)));
    Ok(Zeroizing::new(format!(
        "Basic {}",
        STANDARD.encode(raw.as_bytes())
    )))
}

#[cfg(test)]
trait PushTransport {
    fn send(
        &self,
        method: &str,
        path: &str,
        params: BTreeMap<String, String>,
        txid: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError>;
}
struct SignedHttp<'a> {
    c: &'a DuoCredentials,
    client: reqwest::Client,
    deadline: Instant,
}
impl<'a> SignedHttp<'a> {
    fn new(c: &'a DuoCredentials) -> Result<Self, VaultError> {
        validate_credentials(c)?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| invalid("could not initialize Duo push client"))?;
        Ok(Self {
            c,
            client,
            deadline: Instant::now() + Duration::from_secs(15),
        })
    }
    fn prepare(
        &self,
        method: &str,
        path: &str,
        mut params: BTreeMap<String, String>,
        txid: Option<&str>,
    ) -> Result<PreparedRequest, VaultError> {
        let date = chrono::Utc::now().to_rfc2822();
        let form = Zeroizing::new(encoded(&params));
        for value in params.values_mut() {
            value.zeroize();
        }
        let message = Zeroizing::new(canonical(&date, method, &self.c.host, path, &form));
        let auth = authorization(self.c, &message)?;
        let mut url = Url::parse(&format!("https://{}{path}", self.c.host))
            .map_err(|_| invalid("invalid Duo push endpoint"))?;
        validate_https(&url)?;
        let mut request = if method == "GET" {
            url.set_query(Some(&form));
            self.client.get(url)
        } else {
            self.client
                .post(url)
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(form.to_string())
        };
        let mut auth_header = reqwest::header::HeaderValue::from_str(&auth)
            .map_err(|_| invalid("invalid Duo request authorization"))?;
        auth_header.set_sensitive(true);
        request = request
            .header(reqwest::header::AUTHORIZATION, auth_header)
            .header("x-duo-date", &date)
            .header(reqwest::header::USER_AGENT, enrollment_user_agent());
        if let Some(id) = txid {
            request = request.header("txId", id);
        }
        let request = request
            .build()
            .map_err(|_| invalid("could not prepare Duo push request"))?;
        Ok(PreparedRequest {
            client: self.client.clone(),
            request,
            deadline: self.deadline,
            decision: method == "POST",
        })
    }
}
/// Contains an already signed request, never the RSA key or vault credentials.
/// Network I/O runs after the live vault guard has been released.
pub(crate) struct PreparedRequest {
    client: reqwest::Client,
    request: reqwest::Request,
    deadline: Instant,
    decision: bool,
}
impl PreparedRequest {
    #[cfg(test)]
    pub(crate) fn mock_get(url: &str) -> Self {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let request = client.get(url).build().unwrap();
        Self {
            client,
            request,
            deadline: Instant::now() + Duration::from_secs(15),
            decision: false,
        }
    }
    pub(crate) async fn execute(mut self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        *self.request.timeout_mut() = Some(
            self.deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| invalid("Duo request expired before it could be sent"))?,
        );
        let mut response = self.client.execute(self.request).await.map_err(|_| invalid(if self.decision {
            "Duo decision request failed; its outcome is unknown. Check the login before retrying"
        } else { "could not fetch Duo push requests" }))?;
        let status = response.status();
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| invalid(if self.decision {
            "could not read Duo decision response; its outcome is unknown. Check the login before retrying"
        } else { "could not read Duo push response" }))? {
            if body.len().saturating_add(chunk.len()) as u64 > MAX_RESPONSE_BYTES { return Err(invalid("Duo push response exceeded the size limit")); }
            body.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            return Err(rejection_error(RequestPhase::Push, Some(status), &body));
        }
        Ok(body)
    }
}
pub(crate) fn prepare_poll(c: &DuoCredentials) -> Result<PreparedRequest, VaultError> {
    SignedHttp::new(c)?.prepare("GET", "/push/v2/device/transactions", common(c), None)
}

struct SensitiveJson(Value);
impl std::ops::Deref for SensitiveJson {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}
impl Zeroize for SensitiveJson {
    fn zeroize(&mut self) {
        fn clear(value: &mut Value) {
            match value {
                Value::String(s) => s.zeroize(),
                Value::Array(a) => a.iter_mut().for_each(clear),
                Value::Object(o) => o.values_mut().for_each(clear),
                _ => {}
            }
            *value = Value::Null;
        }
        clear(&mut self.0);
    }
}
fn envelope(body: &[u8]) -> Result<Zeroizing<SensitiveJson>, VaultError> {
    let mut value = Zeroizing::new(SensitiveJson(
        serde_json::from_slice(body).map_err(|_| invalid("invalid Duo push response"))?,
    ));
    if value.get("stat").and_then(Value::as_str) != Some("OK") {
        return Err(rejection_error(RequestPhase::Push, None, body));
    }
    let response = value
        .0
        .get_mut("response")
        .ok_or_else(|| invalid("missing Duo push response"))?
        .take();
    Ok(Zeroizing::new(SensitiveJson(response)))
}
fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}
fn text(value: Option<&Value>) -> String {
    crate::terminal::metadata(
        &value
            .and_then(Value::as_str)
            .unwrap_or_default()
            .chars()
            .take(256)
            .collect::<String>(),
    )
    .to_string()
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn attributes(value: &Value, result: &mut BTreeMap<String, String>, depth: usize) {
    if depth > 6 || result.len() >= 32 {
        return;
    }
    let allow = |key: &str| {
        matches!(
            key.to_ascii_lowercase().as_str(),
            "application"
                | "username"
                | "account"
                | "user"
                | "location"
                | "ip address"
                | "ip"
                | "host"
        )
    };
    match value {
        Value::Object(map) => {
            if let (Some(name), Some(v)) =
                (map.get("name").and_then(Value::as_str), map.get("value"))
                && allow(name)
            {
                result.insert(name.to_ascii_lowercase(), text(Some(v)));
            }
            for (k, v) in map.iter().take(64) {
                if allow(k) && v.is_string() {
                    result.insert(k.to_ascii_lowercase(), text(Some(v)));
                } else if v.is_array() || v.is_object() {
                    attributes(v, result, depth + 1);
                }
            }
        }
        Value::Array(items) => {
            if items.len() == 2
                && let Some(name) = items[0].as_str()
                && allow(name)
                && items[1].is_string()
            {
                result.insert(name.to_ascii_lowercase(), text(Some(&items[1])));
            } else {
                for item in items.iter().take(64) {
                    attributes(item, result, depth + 1);
                }
            }
        }
        _ => {}
    }
}
fn request(
    value: &Value,
    timestamp: u64,
    review_key: &[u8; 32],
) -> Result<Option<DuoPushRequest>, VaultError> {
    let id = value
        .get("urgid")
        .or_else(|| value.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Duo push request has no identifier"))?;
    if !valid_id(id) {
        return Err(invalid("invalid Duo push request identifier"));
    }
    if value
        .get("status")
        .is_some_and(|s| s.as_str() != Some("pending"))
    {
        return Ok(None);
    }
    let expires = value
        .get("expiration")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("Duo push request has no valid expiry"))?;
    if expires <= timestamp {
        return Ok(None);
    }
    let mut context = BTreeMap::new();
    if let Some(v) = value.get("attributes") {
        attributes(v, &mut context, 0);
    }
    let field = |keys: &[&str], fallback: &str| {
        keys.iter()
            .find_map(|k| context.get(*k))
            .cloned()
            .unwrap_or_else(|| text(value.get(fallback)))
    };
    let mut unsupported = None;
    for (flag, reason) in [
        (
            "require_touch_id",
            "This request requires device biometric authentication.",
        ),
        (
            "new_keys_required",
            "This request requires device key rotation.",
        ),
        (
            "is_pwl_os_logon",
            "Passwordless device authentication is unsupported.",
        ),
        (
            "require_second_auth",
            "This request requires device biometric authentication.",
        ),
        (
            "require_gps",
            "This request requires device location verification.",
        ),
        (
            "is_proximity_push",
            "This request requires proximity verification.",
        ),
        (
            "is_strict_proximity_push",
            "This request requires proximity verification.",
        ),
        (
            "must_rotate_on_approve",
            "This request requires device key rotation.",
        ),
    ] {
        if value.get(flag).is_some_and(|v| {
            !v.is_null() && v != &Value::Bool(false) && v.as_str() != Some("false")
        }) {
            unsupported = Some(reason.into());
        }
    }
    for flag in [
        "passwordless_os_login_id",
        "passwordless_os_offline_enrollment",
    ] {
        if value.get(flag).is_some_and(|v| !v.is_null()) {
            unsupported = Some("Passwordless device authentication is unsupported.".into());
        }
    }
    let code_digits = if let Some(info) = value.get("step_up_code_info").filter(|v| !v.is_null()) {
        match info.get("num_digits").and_then(Value::as_u64) {
            Some(n @ 3..=6) => Some(n as usize),
            _ => {
                unsupported = Some("Unrecognized verification-code requirements.".into());
                None
            }
        }
    } else {
        None
    };
    if value.get("type").and_then(Value::as_str) != Some("Login") {
        unsupported = Some("Unrecognized push request type.".into());
    }
    let mut verified = false;
    let mut ordinary = false;
    for flag in [
        "verified_push",
        "requires_code",
        "verification_required",
        "contains_step_up_code",
    ] {
        if let Some(v) = value.get(flag) {
            match v {
                Value::Bool(true) => verified = true,
                Value::Bool(false) => ordinary = true,
                Value::String(s) if s == "true" => verified = true,
                Value::String(s) if s == "false" => ordinary = true,
                _ => unsupported = Some("Unrecognized verification requirements.".into()),
            }
        }
    }
    if value
        .get("verified_push_info")
        .is_some_and(|v| !v.is_null())
    {
        verified = true;
    }
    for flag in ["push_type", "transaction_type"] {
        if let Some(value) = value.get(flag) {
            match value.as_str() {
                Some("push" | "ordinary" | "plain" | "duo_push") => ordinary = true,
                Some("verified" | "verified_push" | "step_up" | "code_required") => verified = true,
                _ => {
                    unsupported =
                        Some("Unrecognized push verification mode; use Duo Mobile.".into())
                }
            }
        }
    }
    if verified && code_digits.is_none() {
        unsupported = Some("Missing verification-code requirements; use Duo Mobile.".into());
    }
    if ordinary && code_digits.is_some() {
        unsupported = Some("Conflicting verification requirements; use Duo Mobile.".into());
    }
    if code_digits.is_none()
        && !ordinary
        && !(value.get("phone_notification_type").and_then(Value::as_str)
            == Some("visible_notification")
            && value.get("is_proximity_push") == Some(&Value::Bool(false))
            && value.get("is_strict_proximity_push") == Some(&Value::Bool(false)))
    {
        unsupported = Some("Unrecognized verification requirements; use Duo Mobile.".into());
    }
    let mut result = DuoPushRequest {
        id: id.into(),
        application: field(&["application"], "application"),
        username: field(&["username", "account", "user"], "username"),
        location: field(&["location", "ip address", "ip", "host"], "location"),
        summary: text(value.get("summary")),
        expires_at: expires,
        code_digits,
        unsupported,
        fingerprint: String::new(),
    };
    // Bind the review to the complete server transaction, including requirements
    // we do not display. Never return the raw transaction (which may contain codes).
    let encoded = Zeroizing::new(
        serde_json::to_vec(value).map_err(|_| invalid("invalid Duo request context"))?,
    );
    // A keyed token prevents the payload hash from becoming an offline oracle
    // for low-entropy verification codes, and binds reviews to this unlock.
    let mut hash = Zeroizing::new(blake3::Hasher::new_keyed(review_key));
    hash.update(b"password-manager.duo-review.v1\0");
    hash.update(encoded.as_slice());
    let mut token = [0; 64];
    Zeroizing::new(hash.finalize_xof()).fill(&mut token);
    result.fingerprint = hex::encode(token);
    Ok(Some(result))
}
pub(crate) fn parse_requests(
    body: &[u8],
    review_key: &[u8; 32],
) -> Result<Vec<DuoPushRequest>, VaultError> {
    let response = envelope(body)?;
    let timestamp = now().max(
        response
            .get("current_time")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    );
    let list = response
        .get("transactions")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("missing Duo push transactions"))?;
    if list.len() > 128 {
        return Err(invalid("too many Duo push requests"));
    }
    let mut ids = HashSet::new();
    let mut result = Vec::new();
    for value in list {
        if let Some(r) = request(value, timestamp, review_key)? {
            if !ids.insert(r.id.clone()) {
                return Err(invalid("duplicate Duo push request identifier"));
            }
            result.push(r);
        }
    }
    Ok(result)
}
#[cfg(test)]
fn requests_with(
    transport: &impl PushTransport,
    c: &DuoCredentials,
    review_key: &[u8; 32],
) -> Result<Vec<DuoPushRequest>, VaultError> {
    let body = transport.send("GET", "/push/v2/device/transactions", common(c), None)?;
    parse_requests(&body, review_key)
}
fn decision_params(
    pending: &[DuoPushRequest],
    c: &DuoCredentials,
    id: &str,
    fingerprint: &str,
    approve: bool,
    code: &str,
) -> Result<BTreeMap<String, String>, VaultError> {
    if !valid_id(id)
        || fingerprint.len() != 128
        || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid("invalid Duo review identifier"));
    }
    let selected = pending
        .iter()
        .find(|r| r.id == id)
        .ok_or_else(|| invalid("Duo request has expired or was already answered"))?;
    if !bool::from(
        selected
            .fingerprint
            .as_bytes()
            .ct_eq(fingerprint.as_bytes()),
    ) {
        return Err(invalid(
            "Duo request changed; review it again before responding",
        ));
    }
    if selected.expires_at <= now() {
        return Err(invalid("Duo request has expired"));
    }
    let mut params = common(c);
    params.insert(
        "answer".into(),
        if approve { "approve" } else { "deny" }.into(),
    );
    if approve {
        if let Some(reason) = &selected.unsupported {
            return Err(invalid(reason));
        }
        match selected.code_digits {
            Some(n) if code.len() == n && code.bytes().all(|b| b.is_ascii_digit()) => {
                params.insert("step_up_code".into(), code.into());
                params.insert("step_up_code_autofilled".into(), "false".into());
            }
            Some(_) => {
                return Err(invalid(
                    "enter the verification code shown on the login page",
                ));
            }
            None if !code.is_empty() => {
                return Err(invalid("this request does not require a verification code"));
            }
            None => {}
        }
        params.insert("touchid".into(), "false".into());
    } else if !code.is_empty() {
        return Err(invalid("a denial does not use a verification code"));
    }
    Ok(params)
}
pub(crate) fn prepare_decision(
    c: &DuoCredentials,
    pending: &[DuoPushRequest],
    id: &str,
    fingerprint: &str,
    approve: bool,
    code: &str,
) -> Result<PreparedRequest, VaultError> {
    let http = SignedHttp::new(c)?;
    let params = decision_params(pending, c, id, fingerprint, approve, code)?;
    http.prepare(
        "POST",
        &format!("/push/v2/device/transactions/{id}"),
        params,
        Some(id),
    )
}
pub(crate) fn acknowledge(body: &[u8]) -> Result<(), VaultError> {
    envelope(body).map(|_| ())
}
#[cfg(test)]
fn respond_with(
    transport: &impl PushTransport,
    c: &DuoCredentials,
    review_key: &[u8; 32],
    id: &str,
    fingerprint: &str,
    approve: bool,
    code: &str,
) -> Result<(), VaultError> {
    let pending = requests_with(transport, c, review_key)?;
    let params = decision_params(&pending, c, id, fingerprint, approve, code)?;
    acknowledge(&transport.send(
        "POST",
        &format!("/push/v2/device/transactions/{id}"),
        params,
        Some(id),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::RefCell;
    struct Mock {
        value: Value,
        calls: RefCell<Vec<(String, BTreeMap<String, String>)>>,
    }
    impl PushTransport for Mock {
        fn send(
            &self,
            method: &str,
            path: &str,
            params: BTreeMap<String, String>,
            txid: Option<&str>,
        ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
            self.calls.borrow_mut().push((path.into(), params));
            if method == "POST" {
                assert_eq!(txid, Some("test-id"));
                Ok(Zeroizing::new(br#"{"stat":"OK","response":{}}"#.to_vec()))
            } else {
                Ok(Zeroizing::new(
                    serde_json::to_vec(
                        &json!({"stat":"OK","response":{"transactions":[self.value.clone()]}}),
                    )
                    .unwrap(),
                ))
            }
        }
    }
    const REVIEW_KEY: &[u8; 32] = &[7; 32];
    fn transaction() -> Value {
        json!({"urgid":"test-id","type":"Login","expiration":now()+120,"attributes":[[["Application","Test app"]],[["Username","user"]]],"step_up_code_info":{"num_digits":3}})
    }
    fn mock(value: Value) -> Mock {
        Mock {
            value,
            calls: RefCell::new(vec![]),
        }
    }
    #[test]
    fn canonical_form_is_sorted_and_signature_verifies() {
        use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_2048_8192_SHA512, UnparsedPublicKey};
        let key = crypto::new_key().unwrap();
        let c = DuoCredentials {
            host: "api-test.duosecurity.com".into(),
            akey: "account".into(),
            pkey: "device".into(),
            private_key: crypto::private_pem(&key).unwrap().to_string(),
        };
        validate_credentials(&c).unwrap();
        let form = encoded(&BTreeMap::from([
            ("z".into(), "a+b c".into()),
            ("a".into(), "/".into()),
        ]));
        assert_eq!(form, "a=%2F&z=a%2Bb+c");
        let message = canonical(
            "date",
            "POST",
            &c.host,
            "/push/v2/device/transactions/test-id",
            &form,
        );
        let auth = authorization(&c, &message).unwrap();
        let decoded = STANDARD
            .decode(auth.strip_prefix("Basic ").unwrap())
            .unwrap();
        let raw = String::from_utf8(decoded).unwrap();
        let signature = STANDARD
            .decode(raw.strip_prefix("device:").unwrap())
            .unwrap();
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, key.public_key().as_ref())
            .verify(message.as_bytes(), &signature)
            .unwrap();
    }
    #[test]
    fn review_tokens_are_keyed_and_bound_to_every_transaction_field() {
        let mut value = transaction();
        value["step_up_code_info"]["correct_answer"] = json!("123");
        let first = request(&value, now(), REVIEW_KEY).unwrap().unwrap();
        assert_eq!(
            first.fingerprint,
            request(&value, now(), REVIEW_KEY)
                .unwrap()
                .unwrap()
                .fingerprint
        );
        assert_ne!(
            first.fingerprint,
            request(&value, now(), &[8; 32])
                .unwrap()
                .unwrap()
                .fingerprint
        );
        value["step_up_code_info"]["correct_answer"] = json!("124");
        assert_ne!(
            first.fingerprint,
            request(&value, now(), REVIEW_KEY)
                .unwrap()
                .unwrap()
                .fingerprint
        );
        let public = serde_json::to_string(&first).unwrap();
        assert!(!public.contains("correct_answer"));
        assert!(!public.contains("step_up_code_info"));
    }
    #[test]
    fn unfamiliar_push_types_cannot_be_approved_even_with_ordinary_fields() {
        let mut value = transaction();
        value.as_object_mut().unwrap().remove("step_up_code_info");
        value["phone_notification_type"] = json!("visible_notification");
        value["is_proximity_push"] = json!(false);
        value["is_strict_proximity_push"] = json!(false);
        assert!(
            request(&value, now(), REVIEW_KEY)
                .unwrap()
                .unwrap()
                .unsupported
                .is_none()
        );
        for field in ["push_type", "transaction_type"] {
            let mut unknown = value.clone();
            unknown[field] = json!("future_hardware_challenge");
            let m = mock(unknown);
            let c = DuoCredentials::default();
            let r = requests_with(&m, &c, REVIEW_KEY).unwrap().remove(0);
            assert!(r.unsupported.is_some());
            assert!(respond_with(&m, &c, REVIEW_KEY, &r.id, &r.fingerprint, true, "").is_err());
            assert!(
                !m.calls
                    .borrow()
                    .iter()
                    .any(|(path, _)| path.ends_with("test-id"))
            );
        }
    }
    #[test]
    fn verified_push_requires_typed_code_and_uses_exact_fields() {
        let m = mock(transaction());
        let c = DuoCredentials::default();
        let r = requests_with(&m, &c, REVIEW_KEY).unwrap().remove(0);
        assert_eq!(r.application, "Test app");
        assert_eq!(r.username, "user");
        assert!(respond_with(&m, &c, REVIEW_KEY, &r.id, &r.fingerprint, true, "").is_err());
        assert!(respond_with(&m, &c, REVIEW_KEY, &r.id, &r.fingerprint, true, "12x").is_err());
        respond_with(&m, &c, REVIEW_KEY, &r.id, &r.fingerprint, true, "012").unwrap();
        let calls = m.calls.borrow();
        let (_, form) = calls.last().unwrap();
        assert_eq!(form["step_up_code"], "012");
        assert_eq!(form["step_up_code_autofilled"], "false");
        assert_eq!(form["hsm_status"], "false");
        assert_eq!(form["answer"], "approve");
    }
    #[test]
    fn stale_changed_and_unsupported_requests_cannot_be_approved() {
        let c = DuoCredentials::default();
        let original = transaction();
        let r = request(&original, now(), REVIEW_KEY).unwrap().unwrap();
        let mut changed = original.clone();
        changed["summary"] = json!("changed");
        let m = mock(changed);
        assert!(respond_with(&m, &c, REVIEW_KEY, &r.id, &r.fingerprint, true, "012").is_err());
        assert!(
            !m.calls
                .borrow()
                .iter()
                .any(|(path, _)| path.ends_with("test-id"))
        );
        let mut proximity = original.clone();
        proximity["is_proximity_push"] = json!(true);
        let m = mock(proximity);
        let r = requests_with(&m, &c, REVIEW_KEY).unwrap().remove(0);
        assert!(respond_with(&m, &c, REVIEW_KEY, &r.id, &r.fingerprint, true, "012").is_err());
        respond_with(&m, &c, REVIEW_KEY, &r.id, &r.fingerprint, false, "").unwrap();
        let mut expired = original;
        expired["expiration"] = json!(now());
        assert!(
            requests_with(&mock(expired), &c, REVIEW_KEY)
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn hostile_ids_and_metadata_are_not_executed_or_exposed() {
        let mut value = transaction();
        value["urgid"] = json!("../unsafe");
        assert!(request(&value, now(), REVIEW_KEY).is_err());
        value["urgid"] = json!("test-id");
        value["summary"] = json!("a\u{1b}[31m\nsecret");
        value["step_up_code_info"]["code"] = json!("999");
        let r = request(&value, now(), REVIEW_KEY).unwrap().unwrap();
        assert!(!r.summary.contains('\x1b'));
        assert!(!r.summary.contains('\n'));
        // Check the public schema and displayed metadata rather than searching
        // fingerprints or timestamps, which can contain any digit sequence.
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({
                "id": "test-id",
                "application": "Test app",
                "username": "user",
                "location": "",
                "summary": "a\\u{1b}[31m\\nsecret",
                "expires_at": value["expiration"],
                "code_digits": 3,
                "unsupported": null,
                "fingerprint": r.fingerprint,
            })
        );
        value["step_up_code_info"]["num_digits"] = json!(10);
        assert!(
            request(&value, now(), REVIEW_KEY)
                .unwrap()
                .unwrap()
                .unsupported
                .is_some()
        );
    }
    #[test]
    fn plain_verified_and_unknown_challenges_are_distinguished() {
        let mut value = transaction();
        value.as_object_mut().unwrap().remove("step_up_code_info");
        assert!(
            request(&value, now(), REVIEW_KEY)
                .unwrap()
                .unwrap()
                .unsupported
                .is_some()
        );
        value["phone_notification_type"] = json!("visible_notification");
        value["is_proximity_push"] = json!(false);
        value["is_strict_proximity_push"] = json!(false);
        assert!(
            request(&value, now(), REVIEW_KEY)
                .unwrap()
                .unwrap()
                .unsupported
                .is_none()
        );
        for flag in [
            "require_touch_id",
            "require_gps",
            "new_keys_required",
            "require_second_auth",
            "is_pwl_os_logon",
        ] {
            let mut restricted = value.clone();
            restricted[flag] = json!("true");
            assert!(
                request(&restricted, now(), REVIEW_KEY)
                    .unwrap()
                    .unwrap()
                    .unsupported
                    .is_some(),
                "{flag}"
            );
        }
        value["verified_push"] = json!(true);
        assert!(
            request(&value, now(), REVIEW_KEY)
                .unwrap()
                .unwrap()
                .unsupported
                .is_some()
        );
        value["step_up_code_info"] = json!({"num_digits":3,"correct_answer":"999"});
        assert!(
            request(&value, now(), REVIEW_KEY)
                .unwrap()
                .unwrap()
                .unsupported
                .is_none()
        );
        value["requires_code"] = json!(false);
        assert!(
            request(&value, now(), REVIEW_KEY)
                .unwrap()
                .unwrap()
                .unsupported
                .is_some()
        );
    }
}
