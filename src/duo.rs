//! Duo enrollment. The mobile activation endpoint is undocumented.
//! Protocol reference: https://github.com/WillForan/duo-hotp/blob/main/duo.py
//! Parameter names: https://www.nilsstreedain.com/blog/2023/05/28/reverse-engineering-duo-mobile/
//! Form transport: https://github.com/char/duo-hotp-export/blob/main/src/main.rs
//! Current Android request metadata: https://dl.duosecurity.com/DuoMobile-latest.apk
//! Passcode-only enrollment discards push credentials. Push enrollment retains
//! only the credentials needed for explicit user approvals in the encrypted vault.
use crate::{types::OtpMode, vault::VaultError};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use serde::Deserialize;
use std::{
    io::Read,
    time::{Duration, Instant},
};
use totp_rs::Secret;
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_LINK_BYTES: usize = 4096;
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;
const ENROLLMENT_TIMEOUT: Duration = Duration::from_secs(45);
// Compatibility metadata, inspected in the official Android 4.123.0 APK.
// Keep the form and header versions together. This is not an Android app and
// cannot provide hardware key attestation or attest to mobile device security.
const MOBILE_VERSION: &str = "4.123.0";
const MOBILE_BUILD: &str = "4123000";
const ANDROID_VERSION: &str = "12";
const DEVICE_MODEL: &str = "PasswordManager";
pub(crate) mod crypto;
mod push;
pub(crate) use push::{
    PreparedRequest, acknowledge, parse_requests, prepare_decision, prepare_poll,
    validate_credentials,
};

fn enrollment_user_agent() -> String {
    // Preserve the mobile protocol's version and CA capability markers while
    // identifying our implementation. Rustls verifies certificates using its
    // root store; we do not claim to implement Duo's certificate pinning.
    format!(
        "DuoMobileApp/{MOBILE_VERSION} (Android {ANDROID_VERSION}; {DEVICE_MODEL}) password-manager/{} ca_bundle/1.0 (ca_pinning=disabled)",
        env!("CARGO_PKG_VERSION")
    )
}

fn invalid(message: &str) -> VaultError {
    VaultError::InvalidInput(message.into())
}

pub(crate) fn valid_host(host: &str, prefix: &str) -> bool {
    host.strip_suffix(".duosecurity.com")
        .and_then(|label| label.strip_prefix(prefix))
        .is_some_and(|id| {
            !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn validate_https(url: &Url) -> Result<(), VaultError> {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || !url
            .host_str()
            .is_some_and(|host| valid_host(host, "m-") || valid_host(host, "api-"))
        || url.fragment().is_some()
    {
        return Err(invalid(
            "Duo enrollment requires an HTTPS m- or api- host under duosecurity.com",
        ));
    }
    Ok(())
}

fn activation_url(link: &str) -> Result<Url, VaultError> {
    let value = link
        .strip_prefix("duo://")
        .ok_or_else(|| invalid("expected a duo:// activation link"))?;
    let (code, encoded_host) = value
        .split_once('-')
        .ok_or_else(|| invalid("invalid Duo activation link"))?;
    if code.is_empty() || code.len() > 256 || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(invalid("invalid Duo activation code"));
    }
    let encoded_host = encoded_host.trim_end_matches('=');
    let host_bytes = STANDARD_NO_PAD
        .decode(encoded_host)
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded_host))
        .map_err(|_| invalid("invalid encoded Duo activation host"))?;
    let host =
        std::str::from_utf8(&host_bytes).map_err(|_| invalid("invalid Duo activation host"))?;
    if !valid_host(host, "api-") {
        return Err(invalid("Duo activation host must be api-*.duosecurity.com"));
    }
    Url::parse(&format!(
        "https://{host}/push/v2/activation/{code}?customer_protocol=1"
    ))
    .map_err(|_| invalid("invalid Duo activation endpoint"))
}

fn page_url(link: &str) -> Result<Url, VaultError> {
    let url = Url::parse(link).map_err(|_| invalid("invalid Duo setup URL"))?;
    validate_https(&url)?;
    let token = url
        .path()
        .strip_prefix("/activate/")
        .ok_or_else(|| invalid("expected a Duo /activate/ setup link or duo:// link"))?;
    if token.is_empty() || token.len() > 256 || !token.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(invalid("invalid Duo setup token"));
    }
    Ok(url)
}

fn link_from_page(body: &[u8]) -> Result<Zeroizing<String>, VaultError> {
    let html = std::str::from_utf8(body).map_err(|_| invalid("invalid Duo setup page encoding"))?;
    let decoded = Zeroizing::new(html_escape::decode_html_entities(html).into_owned());
    for (offset, _) in decoded.match_indices("duo://") {
        let candidate = decoded[offset..]
            .split(|c: char| c.is_whitespace() || "\"'<>\\".contains(c))
            .next()
            .unwrap_or_default();
        if activation_url(candidate).is_ok() {
            return Ok(Zeroizing::new(candidate.to_string()));
        }
    }
    Err(invalid(
        "Duo setup page has no usable activation link; paste its duo:// link instead",
    ))
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct ActivationResponse {
    stat: String,
    response: Option<ActivationSecrets>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct ActivationSecrets {
    hotp_secret: String,
    akey: Option<String>,
    pkey: Option<String>,
    use_totp: Option<bool>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct FailureDetails {
    stat: Option<String>,
    code: Option<u32>,
    message: Option<String>,
    message_detail: Option<String>,
}

#[derive(Clone, Copy)]
enum RequestPhase {
    SetupPage,
    Activation,
    Push,
}

impl RequestPhase {
    fn label(self) -> &'static str {
        match self {
            Self::SetupPage => "Duo setup page",
            Self::Activation => "Duo activation",
            Self::Push => "Duo Push",
        }
    }
}

fn response_hints(details: &FailureDetails) -> Vec<&'static str> {
    // Return only fixed topic names, never excerpts from server-provided text.
    // A mention is a clue for troubleshooting, not proof of the rejection cause.
    let topics: &[(&str, &[&str])] = &[
        (
            "client version",
            &[
                "app_version",
                "app_build_number",
                "app version",
                "client version",
                "mobile version",
                "outdated client",
                "unsupported client",
            ],
        ),
        (
            "certificate/CA bundle",
            &["certificate", "ca_bundle", "ca bundle", "ca_pinning"],
        ),
        (
            "key attestation",
            &[
                "attestation",
                "attestation_challenge_set",
                "key_attestation_cert_chain_information",
                "hsm_status",
            ],
        ),
        (
            "public key/signature",
            &["pubkey", "pkpush", "public key", "signature"],
        ),
        ("enrollment policy", &["policy", "enrollment restriction"]),
        (
            "platform/OS",
            &["platform", "operating system", "os version"],
        ),
    ];
    let mut hints = Vec::new();
    for message in details.message.iter().chain(details.message_detail.iter()) {
        let message = Zeroizing::new(message.to_ascii_lowercase());
        for (topic, phrases) in topics {
            if !hints.contains(topic)
                && phrases.iter().any(|phrase| {
                    message.match_indices(phrase).any(|(offset, _)| {
                        let is_word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
                        (offset == 0 || !is_word(message.as_bytes()[offset - 1]))
                            && (offset + phrase.len() == message.len()
                                || !is_word(message.as_bytes()[offset + phrase.len()]))
                    })
                })
            {
                hints.push(*topic);
            }
        }
    }
    hints
}

fn rejection_error(
    phase: RequestPhase,
    status: Option<reqwest::StatusCode>,
    body: &[u8],
) -> VaultError {
    let details = serde_json::from_slice::<FailureDetails>(body).ok();
    let code = details.as_ref().and_then(|details| details.code);
    let mut identifiers = Vec::new();
    if let Some(status) = status {
        identifiers.push(format!("HTTP {}", status.as_u16()));
    }
    if let Some(code) = code {
        identifiers.push(format!("Duo code {code}"));
    }
    // Use only fixed, recognized descriptions. Arbitrary server messages and
    // HTML error pages can contain the activation token or returned credentials.
    let message = details
        .as_ref()
        .and_then(|details| details.message.as_deref());
    let reason = if message
        .is_some_and(|message| message.eq_ignore_ascii_case("unsupported platform"))
    {
        "unsupported platform; Duo rejected the enrollment client's platform"
    } else if message.is_some_and(|message| message.eq_ignore_ascii_case("unknown activation code"))
        || code == Some(40403)
    {
        "unknown activation code; request a fresh enrollment link"
    } else {
        match code {
            Some(40032) => "incorrect verification code; enter the code shown on the login page",
            Some(40001) => "missing required request parameters",
            Some(40002) => "invalid request parameters",
            _ => match status.map(|status| status.as_u16()) {
                Some(403) => {
                    "request forbidden; the response does not establish whether the cause is client compatibility or organization policy"
                }
                Some(429) => "too many requests; wait before retrying",
                Some(500..=599) => "Duo service error; try again later",
                _ => "request rejected; the cause is not available in the safe response details",
            },
        }
    };
    let parameter = details
        .as_ref()
        .and_then(|details| details.message_detail.as_deref())
        .filter(|parameter| {
            matches!(
                *parameter,
                "platform"
                    | "version"
                    | "app_id"
                    | "app_version"
                    | "app_build_number"
                    | "pubkey"
                    | "pkpush"
                    | "customer_protocol"
                    | "hsm_status"
                    | "attestation_challenge_set"
                    | "key_attestation_cert_chain_information"
            )
        });
    let identifiers = if identifiers.is_empty() {
        String::new()
    } else {
        format!(" ({})", identifiers.join("; "))
    };
    let parameter = parameter
        .map(|parameter| format!(" (parameter: {parameter})"))
        .unwrap_or_default();
    let hints = details.as_ref().map(response_hints).unwrap_or_default();
    let hints = if hints.is_empty() {
        String::new()
    } else {
        format!("; response mentions: {}", hints.join(", "))
    };
    invalid(&format!(
        "{} rejected{identifiers}: {reason}{parameter}{hints}",
        phase.label()
    ))
}

fn configuration_from_response(
    body: &[u8],
    mode: OtpMode,
) -> Result<Zeroizing<String>, VaultError> {
    // Never include the response or serde error in diagnostics: both may contain secrets.
    let details: FailureDetails = serde_json::from_slice(body)
        .map_err(|_| invalid("Duo returned an invalid activation response"))?;
    if details.stat.as_deref() == Some("FAIL") {
        return Err(rejection_error(RequestPhase::Activation, None, body));
    }
    let response: ActivationResponse = serde_json::from_slice(body)
        .map_err(|_| invalid("Duo returned an invalid activation response"))?;
    if response.stat != "OK" {
        return Err(invalid(
            "Duo activation was rejected; the link may be expired or already used",
        ));
    }
    let secret = response
        .response
        .as_ref()
        .ok_or_else(|| invalid("Duo activation did not return an OTP secret"))?;
    if !(10..=1024).contains(&secret.hotp_secret.len()) {
        return Err(invalid("Duo returned an invalid OTP secret"));
    }
    // Duo's hotp_secret is used as UTF-8 bytes, even when it looks hexadecimal.
    // Decoding it as hex produces a different key and incorrect passcodes.
    let base32 = Zeroizing::new(Secret::from(secret.hotp_secret.as_bytes()).to_base32());
    let (kind, settings) = match mode {
        OtpMode::Hotp => ("hotp", "counter=0"),
        OtpMode::Totp => ("totp", "period=30"),
    };
    Ok(Zeroizing::new(format!(
        "otpauth://{kind}/Duo?secret={}&issuer=Duo&algorithm=SHA1&digits=6&{settings}",
        *base32
    )))
}

trait Transport {
    fn get(&self, url: Url) -> Result<Zeroizing<Vec<u8>>, VaultError>;
    fn post(&self, url: Url, public_key: &str) -> Result<Zeroizing<Vec<u8>>, VaultError>;
}

struct HttpTransport {
    client: reqwest::blocking::Client,
    deadline: Instant,
}

impl HttpTransport {
    fn activation_request(
        &self,
        url: Url,
        public_key: &str,
    ) -> Result<reqwest::blocking::RequestBuilder, VaultError> {
        validate_https(&url)?;
        // Send mobile fields in an application/x-www-form-urlencoded body.
        // Only customer_protocol belongs in the URL; an empty POST with all
        // device fields in its query does not match the mobile form transport.
        // Passcode-only enrollment discards the signing key; Push enrollment
        // retains it in the encrypted vault for explicit user decisions.
        Ok(self
            .client
            .post(url)
            .timeout(self.remaining()?)
            .header(reqwest::header::USER_AGENT, enrollment_user_agent())
            .form(&[
                ("pkpush", "rsa-sha512"),
                ("pubkey", public_key),
                ("platform", "Android"),
                ("app_id", "com.duosecurity.duomobile"),
                ("app_version", MOBILE_VERSION),
                ("app_build_number", MOBILE_BUILD),
                ("version", ANDROID_VERSION),
                ("architecture", "arm64"),
                ("manufacturer", "unknown"),
                ("model", DEVICE_MODEL),
                ("language", "en"),
                ("region", "US"),
                // Our software-generated key has no Android hardware attestation.
                // Do not invent a certificate chain or device security measurements.
                ("attestation_challenge_set", "false"),
                ("hsm_status", "false"),
            ]))
    }

    fn remaining(&self) -> Result<Duration, VaultError> {
        self.deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                invalid("Duo enrollment timed out; check enrollment status before retrying")
            })
    }

    fn body(
        &self,
        response: reqwest::blocking::Response,
        phase: RequestPhase,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let status = response.status();
        let mut body = Zeroizing::new(Vec::new());
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| {
                invalid(&format!(
                    "could not read {} response (HTTP {})",
                    phase.label(),
                    status.as_u16()
                ))
            })?;
        if body.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(invalid(&format!(
                "{} response exceeded the size limit (HTTP {})",
                phase.label(),
                status.as_u16()
            )));
        }
        if !status.is_success() {
            return Err(rejection_error(phase, Some(status), &body));
        }
        Ok(body)
    }
}

impl Transport for HttpTransport {
    fn get(&self, mut url: Url) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        for _ in 0..=3 {
            validate_https(&url)?;
            let response = self
                .client
                .get(url.clone())
                .timeout(self.remaining()?)
                .send()
                .map_err(|_| {
                    invalid("could not fetch Duo setup page; paste its duo:// link instead")
                })?;
            if response.status().is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| invalid("Duo setup page returned an invalid redirect"))?;
                url = url
                    .join(location)
                    .map_err(|_| invalid("invalid Duo setup redirect"))?;
                continue;
            }
            return self.body(response, RequestPhase::SetupPage);
        }
        Err(invalid(
            "too many Duo setup redirects; paste its duo:// link instead",
        ))
    }

    fn post(&self, url: Url, public_key: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let response = self
            .activation_request(url, public_key)?
            .send()
            .map_err(|_| {
                invalid("Duo activation request failed; check enrollment status before retrying")
            })?;
        self.body(response, RequestPhase::Activation)
    }
}

fn enroll_with(
    transport: &impl Transport,
    link: &str,
    mode: OtpMode,
    public_key: &str,
) -> Result<Zeroizing<String>, VaultError> {
    let endpoint = enrollment_endpoint(transport, link)?;
    configuration_from_response(&transport.post(endpoint, public_key)?, mode)
}

fn enrollment_endpoint(transport: &impl Transport, link: &str) -> Result<Url, VaultError> {
    let link = link.trim();
    if link.len() > MAX_LINK_BYTES {
        return Err(invalid("Duo activation link is too long"));
    }
    if link.starts_with("duo://") {
        activation_url(link)
    } else {
        let page = transport.get(page_url(link)?)?;
        activation_url(&link_from_page(&page)?)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct PushEnrollment {
    pub credentials: crate::types::DuoCredentials,
    pub configuration: String,
}

pub(crate) fn enroll_push(link: &str, mode: Option<OtpMode>) -> Result<PushEnrollment, VaultError> {
    validate_link(link)?;
    let transport = enrollment_transport()?;
    let endpoint = enrollment_endpoint(&transport, link)?;
    let host = endpoint.host_str().unwrap().to_owned();
    let private_key = crypto::new_key()?;
    let public_key = crypto::public_pem(&private_key)?;
    let body = transport.post(endpoint, &public_key)?;
    let configuration = configuration_from_response(&body, mode.unwrap_or(OtpMode::Hotp))?;
    let response: ActivationResponse = serde_json::from_slice(&body)
        .map_err(|_| invalid("invalid Duo push enrollment response"))?;
    let secrets = response
        .response
        .as_ref()
        .ok_or_else(|| invalid("missing Duo push credentials"))?;
    let configuration = if mode.is_none() && secrets.use_totp == Some(true) {
        configuration_from_response(&body, OtpMode::Totp)?
    } else {
        configuration
    };
    let credentials = crate::types::DuoCredentials {
        host,
        akey: secrets
            .akey
            .as_ref()
            .ok_or_else(|| invalid("Duo did not return push account credentials"))?
            .clone(),
        pkey: secrets
            .pkey
            .as_ref()
            .ok_or_else(|| invalid("Duo did not return a push device identifier"))?
            .clone(),
        private_key: crypto::private_pem(&private_key)?.to_string().into(),
    };
    validate_credentials(&credentials)?;
    Ok(PushEnrollment {
        credentials,
        configuration: configuration.to_string(),
    })
}

fn validate_link(link: &str) -> Result<(), VaultError> {
    let link = link.trim();
    if link.len() > MAX_LINK_BYTES {
        return Err(invalid("Duo activation link is too long"));
    }
    if link.starts_with("duo://") {
        activation_url(link)?;
    } else {
        page_url(link)?;
    }
    Ok(())
}

fn enrollment_transport() -> Result<HttpTransport, VaultError> {
    Ok(HttpTransport {
        client: reqwest::blocking::Client::builder()
            .user_agent(concat!(
                "password-manager/",
                env!("CARGO_PKG_VERSION"),
                " duo-enrollment"
            ))
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(ENROLLMENT_TIMEOUT)
            .build()
            .map_err(|_| invalid("could not initialize Duo enrollment client"))?,
        deadline: Instant::now() + ENROLLMENT_TIMEOUT,
    })
}

pub(crate) fn enroll(link: &str, mode: OtpMode) -> Result<Zeroizing<String>, VaultError> {
    // Called only by the server's blocking command worker, with the vault unlocked.
    validate_link(link)?;
    let transport = enrollment_transport()?;
    let private_key = crypto::new_key()?;
    let public_key = crypto::public_pem(&private_key)?;
    drop(private_key);
    enroll_with(&transport, link, mode, &public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const HOST: &str = "api-test.duosecurity.com";
    const CODE: &str = "SyntheticActivation123";
    const SECRET: &str = "12345678901234567890";

    fn link() -> String {
        format!("duo://{CODE}-{}", STANDARD_NO_PAD.encode(HOST))
    }

    struct MockTransport {
        calls: RefCell<Vec<String>>,
        page: Vec<u8>,
        response: Vec<u8>,
    }

    impl Transport for MockTransport {
        fn get(&self, url: Url) -> Result<Zeroizing<Vec<u8>>, VaultError> {
            self.calls.borrow_mut().push(format!("GET {url}"));
            Ok(Zeroizing::new(self.page.clone()))
        }

        fn post(&self, url: Url, public_key: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
            assert_eq!(public_key, "synthetic-public-key");
            self.calls.borrow_mut().push(format!("POST {url}"));
            Ok(Zeroizing::new(self.response.clone()))
        }
    }

    fn mock() -> MockTransport {
        MockTransport {
            calls: RefCell::new(vec![]),
            page: format!("<a href=\"{}\">Activate</a>", link().replace("duo://", "duo&#x3a;&#x2f;&#x2f;")).into_bytes(),
            response: format!(r#"{{"stat":"OK","response":{{"hotp_secret":"{SECRET}","private":"ignored-push-credential"}}}}"#).into_bytes(),
        }
    }

    #[test]
    fn activation_request_uses_mobile_field_names_and_preserves_key_encoding() {
        let transport = HttpTransport {
            client: reqwest::blocking::Client::new(),
            deadline: Instant::now() + ENROLLMENT_TIMEOUT,
        };
        let public_key =
            "-----BEGIN PUBLIC KEY-----\nSynthetic+Key/With=Padding\n-----END PUBLIC KEY-----\n";
        let request = transport
            .activation_request(activation_url(&link()).unwrap(), public_key)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.url().path(), format!("/push/v2/activation/{CODE}"));
        assert_eq!(request.url().query(), Some("customer_protocol=1"));
        assert_eq!(
            request.headers()[reqwest::header::CONTENT_TYPE],
            "application/x-www-form-urlencoded"
        );
        let body = request.body().unwrap().as_bytes().unwrap();
        let params: std::collections::HashMap<_, _> = url::form_urlencoded::parse(body).collect();
        for (key, value) in [
            ("app_id", "com.duosecurity.duomobile"),
            ("app_version", MOBILE_VERSION),
            ("app_build_number", MOBILE_BUILD),
            ("version", ANDROID_VERSION),
            ("model", DEVICE_MODEL),
            ("architecture", "arm64"),
            ("region", "US"),
            ("attestation_challenge_set", "false"),
            ("hsm_status", "false"),
            ("pkpush", "rsa-sha512"),
            ("pubkey", public_key),
        ] {
            assert_eq!(params.get(key).map(|value| value.as_ref()), Some(value));
        }
        for incorrect in ["App_id", "Architecture", "Legion", "jail broken"] {
            assert!(!params.contains_key(incorrect));
        }
        assert_eq!(
            request.headers()[reqwest::header::USER_AGENT],
            enrollment_user_agent()
        );
        for unmeasured in [
            "jailbroken",
            "full_disk_encryption",
            "passcode_status",
            "security_patch_level",
            "key_attestation_cert_chain_information",
        ] {
            assert!(!params.contains_key(unmeasured));
        }
    }

    #[test]
    fn activation_form_is_transmitted_with_its_content_type_and_encoded_public_key() {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                headers.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            assert!(length > 0 && length < MAX_LINK_BYTES);
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .unwrap();
            (headers, body)
        });
        let transport = HttpTransport {
            client: reqwest::blocking::Client::builder()
                .no_proxy()
                .build()
                .unwrap(),
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let public_key =
            "-----BEGIN PUBLIC KEY-----\nSynthetic+Key/With=Padding\n-----END PUBLIC KEY-----\n";
        let mut request = transport
            .activation_request(activation_url(&link()).unwrap(), public_key)
            .unwrap()
            .build()
            .unwrap();
        // Redirect only the synthetic test request to our loopback receiver.
        // Production requests retain HTTPS and the Duo host validation.
        *request.url_mut() = Url::parse(&format!(
            "http://{address}/push/v2/activation/{CODE}?customer_protocol=1"
        ))
        .unwrap();
        let response = transport.client.execute(request).unwrap();
        assert!(response.status().is_success());
        let (headers, body) = server.join().unwrap();
        assert!(headers.starts_with(&format!(
            "POST /push/v2/activation/{CODE}?customer_protocol=1 HTTP/1.1\r\n"
        )));
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("content-type: application/x-www-form-urlencoded\r\n")
        );
        assert!(headers.contains(&format!("user-agent: {}\r\n", enrollment_user_agent())));
        let params: std::collections::HashMap<_, _> = url::form_urlencoded::parse(&body).collect();
        assert_eq!(
            params.get("pubkey").map(|value| value.as_ref()),
            Some(public_key)
        );
        assert_eq!(
            params.get("pkpush").map(|value| value.as_ref()),
            Some("rsa-sha512")
        );
    }

    #[test]
    fn both_link_formats_enroll_for_hotp_or_totp_without_retaining_push_secrets() {
        for input in [
            link(),
            "https://m-test.duosecurity.com/activate/SyntheticToken123".into(),
        ] {
            for mode in [OtpMode::Hotp, OtpMode::Totp] {
                let transport = mock();
                let configuration =
                    enroll_with(&transport, &input, mode, "synthetic-public-key").unwrap();
                let url = Url::parse(&configuration).unwrap();
                assert_eq!(
                    url.host_str(),
                    Some(if mode == OtpMode::Hotp {
                        "hotp"
                    } else {
                        "totp"
                    })
                );
                let encoded = url
                    .query_pairs()
                    .find(|(key, _)| key == "secret")
                    .unwrap()
                    .1
                    .into_owned();
                assert_eq!(
                    Secret::try_from_base32(encoded).unwrap().as_ref(),
                    SECRET.as_bytes()
                );
                assert!(!configuration.contains("ignored-push-credential"));
                assert!(!configuration.contains(CODE));
                let calls = transport.calls.borrow();
                assert_eq!(calls.len(), if input.starts_with("https") { 2 } else { 1 });
                assert_eq!(
                    calls.last().unwrap(),
                    &format!("POST https://{HOST}/push/v2/activation/{CODE}?customer_protocol=1")
                );
            }
        }
    }

    #[test]
    fn encoded_host_cannot_redirect_activation_outside_duo() {
        for host in [
            "localhost",
            "127.0.0.1",
            "api-test.duosecurity.com.evil.example",
            "evil.duosecurity.com",
            "api-test.duosecurity.com@evil.example",
            "api-test.duosecurity.com:443",
            "api-nested.foo.duosecurity.com",
            "api-test.duosecurity.com/path",
        ] {
            let input = format!("duo://{CODE}-{}", STANDARD_NO_PAD.encode(host));
            let transport = mock();
            assert!(
                enroll_with(&transport, &input, OtpMode::Hotp, "synthetic-public-key").is_err()
            );
            assert!(transport.calls.borrow().is_empty());
        }
        for input in [
            "duo://",
            "duo://code-invalid!",
            "duo://../code-aG9zdA",
            "duo://code-aG9zdA?query=1",
        ] {
            assert!(activation_url(input).is_err());
        }
    }

    #[test]
    fn setup_urls_are_validated_before_any_request() {
        for input in [
            "http://m-test.duosecurity.com/activate/token",
            "https://evil.example/activate/token",
            "https://m-test.duosecurity.com.evil.example/activate/token",
            "https://user:pass@m-test.duosecurity.com/activate/token",
            "https://m-test.duosecurity.com:8443/activate/token",
            "https://m-test.duosecurity.com/activate/",
            "https://m-test.duosecurity.com/activate/token/extra",
            "https://m-test.duosecurity.com/activate/token#fragment",
            "https://m-test.duosecurity.com/other",
        ] {
            let transport = mock();
            assert!(enroll_with(&transport, input, OtpMode::Hotp, "synthetic-public-key").is_err());
            assert!(transport.calls.borrow().is_empty());
        }
        let transport = mock();
        assert!(
            enroll_with(
                &transport,
                &"x".repeat(MAX_LINK_BYTES + 1),
                OtpMode::Hotp,
                "synthetic-public-key"
            )
            .is_err()
        );
        assert!(transport.calls.borrow().is_empty());
    }

    #[test]
    fn setup_page_handles_html_entities_and_rejects_missing_links() {
        for prefix in ["duo://", "duo&#x3a;&#x2f;&#x2f;", "duo&#58;&#47;&#47;"] {
            let html = format!(
                "<a href='{}'>Activate</a>",
                link().replace("duo://", prefix)
            );
            assert_eq!(*link_from_page(html.as_bytes()).unwrap(), link());
        }
        assert!(link_from_page(b"<html>expired</html>").is_err());
        assert!(link_from_page(&[0xff]).is_err());
    }

    #[test]
    fn rejected_and_malformed_activation_responses_do_not_leak_secrets() {
        for body in [
            r#"{"stat":"FAIL","message":"sensitive-server-message"}"#,
            r#"{"stat":"OK"}"#,
            r#"{"stat":"OK","response":{"hotp_secret":"short"}}"#,
            r#"{"stat":"OK","response":{"hotp_secret":123,"private":"sensitive-server-message"}}"#,
            "sensitive-server-message",
        ] {
            let error = configuration_from_response(body.as_bytes(), OtpMode::Hotp)
                .err()
                .unwrap();
            assert!(!error.to_string().contains("sensitive-server-message"));
        }
    }

    #[test]
    fn duo_secret_that_looks_hexadecimal_is_used_as_text_bytes() {
        let body =
            br#"{"stat":"OK","response":{"hotp_secret":"0123456789abcdef0123456789abcdef"}}"#;
        let configuration = configuration_from_response(body, OtpMode::Totp).unwrap();
        let totp = totp_rs::Totp::from_url(&configuration).unwrap();
        assert_eq!(totp.secret().as_ref(), b"0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn activation_rejections_report_status_code_and_safe_parameter_without_echoing_response() {
        let body = br#"{"stat":"FAIL","code":40002,"message":"sensitive-token-and-server-message","message_detail":"platform","response":{"hotp_secret":"sensitive-secret"}}"#;
        let message = rejection_error(
            RequestPhase::Activation,
            Some(reqwest::StatusCode::BAD_REQUEST),
            body,
        )
        .to_string();
        assert!(message.contains("Duo activation rejected (HTTP 400; Duo code 40002)"));
        assert!(message.contains("invalid request parameters"));
        assert!(message.contains("parameter: platform"));
        assert!(!message.contains("sensitive"));
        // A FAIL response containing a non-secret response object must still
        // surface the rejection code instead of a secret-deserialization error.
        let error = configuration_from_response(body, OtpMode::Hotp)
            .err()
            .unwrap();
        assert!(error.to_string().contains("Duo code 40002"));
        assert!(!error.to_string().contains("sensitive"));
    }

    #[test]
    fn known_rejections_have_specific_reasons_and_unknown_messages_remain_private() {
        for (phase, status, body, expected) in [
            (
                RequestPhase::Activation,
                reqwest::StatusCode::BAD_REQUEST,
                br#"{"stat":"FAIL","code":40002,"message":"Unsupported platform"}"#.as_slice(),
                "unsupported platform",
            ),
            (
                RequestPhase::Activation,
                reqwest::StatusCode::NOT_FOUND,
                br#"{"stat":"FAIL","code":40403,"message_detail":"sensitive-token"}"#,
                "unknown activation code",
            ),
            (
                RequestPhase::SetupPage,
                reqwest::StatusCode::FORBIDDEN,
                b"<html>sensitive-token and credentials</html>",
                "Duo setup page rejected (HTTP 403)",
            ),
        ] {
            let message = rejection_error(phase, Some(status), body).to_string();
            assert!(message.contains(expected), "{expected}: {message}");
            assert!(!message.contains("sensitive-token"), "{expected}");
        }
    }

    #[test]
    fn rejection_hints_preserve_server_topics_without_exposing_response_text() {
        let message = rejection_error(
            RequestPhase::Activation,
            Some(reqwest::StatusCode::FORBIDDEN),
            br#"{"stat":"FAIL","code":40301,"message":"Client version rejected: sensitive-token","message_detail":"CA bundle and key attestation required by policy for duo://sensitive-code-host; pubkey=sensitive-key","response":{"hotp_secret":"sensitive-secret"}}"#,
        ).to_string();
        assert!(message.contains("HTTP 403; Duo code 40301"));
        for topic in [
            "client version",
            "certificate/CA bundle",
            "key attestation",
            "enrollment policy",
            "public key/signature",
        ] {
            assert!(message.contains(topic), "missing {topic}");
        }
        assert!(!message.contains("sensitive"));
        assert!(!message.contains("duo://"));
        // Do not recognize topic words embedded in arbitrary credentials.
        let opaque = rejection_error(
            RequestPhase::Activation,
            Some(reqwest::StatusCode::FORBIDDEN),
            br#"{"stat":"FAIL","code":40301,"message_detail":"OpaquePolicyTokenWithSignatureAndCertificate"}"#,
        ).to_string();
        assert!(!opaque.contains("response mentions:"));
        assert!(!opaque.contains("Opaque"));
    }

    fn mock_http_response(
        status: u16,
        body: &[u8],
    ) -> (reqwest::blocking::Response, std::thread::JoinHandle<()>) {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let body = body.to_vec();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
            }
            write!(
                stream,
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            // The client may deliberately stop reading an oversized body.
            let _ = stream.write_all(&body);
        });
        let response = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
            .get(format!("http://{address}/synthetic-response"))
            .send()
            .unwrap();
        (response, server)
    }

    #[test]
    fn http_error_responses_are_read_bounded_and_report_the_rejection_details() {
        let transport = HttpTransport {
            client: reqwest::blocking::Client::new(),
            deadline: Instant::now() + ENROLLMENT_TIMEOUT,
        };
        let (response, server) = mock_http_response(
            400,
            br#"{"stat":"FAIL","code":40002,"message":"Unsupported platform"}"#,
        );
        let error = transport
            .body(response, RequestPhase::Activation)
            .err()
            .unwrap()
            .to_string();
        server.join().unwrap();
        assert!(error.contains("HTTP 400; Duo code 40002"));
        assert!(error.contains("unsupported platform"));
        let (response, server) =
            mock_http_response(403, &vec![b'x'; MAX_RESPONSE_BYTES as usize + 1]);
        let error = transport
            .body(response, RequestPhase::Activation)
            .err()
            .unwrap()
            .to_string();
        server.join().unwrap();
        assert!(error.contains("size limit (HTTP 403)"));
        let (response, server) = mock_http_response(200, b"synthetic-success");
        assert_eq!(
            *transport.body(response, RequestPhase::Activation).unwrap(),
            b"synthetic-success"
        );
        server.join().unwrap();
    }
}
