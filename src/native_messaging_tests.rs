use super::*;
use proptest::prelude::*;
use std::io::Cursor;

#[test]
fn management_edits_validate_fields_and_preserve_unmodified_secrets() {
    let mut request: NativeRequest = serde_json::from_value(json!({ "id": 1, "action": "managerUpdate", "entryId": 4,
        "item": { "name": "Example", "password": null, "urls": ["https://new.example"], "removeUrls": ["https://old.example"],
            "fields": [{ "name": "environment", "value": "prod", "secret": false }] } })).unwrap();
    let command = command_for_request(&mut request).unwrap();
    let ServerCommand::UpdateTyped(update) = command else {
        panic!("expected update")
    };
    assert!(update.entry.password.is_none());
    assert!(!update.clear_urls);
    assert_eq!(
        update.entry.update.url.as_deref(),
        Some("https://new.example")
    );
    assert_eq!(update.remove_url, ["https://old.example"]);
    let mut invalid: NativeRequest = serde_json::from_value(
        json!({ "id": 1, "action": "managerAdd", "item": { "name": "", "password": "synthetic" } }),
    )
    .unwrap();
    assert!(command_for_request(&mut invalid).is_err());
    let mut invalid: NativeRequest = serde_json::from_value(json!({ "id": 1, "action": "managerAdd", "item": { "name": "Example", "fields": [
        { "name": "same", "value": "synthetic", "secret": true }, { "name": "SAME", "value": "synthetic", "secret": false } ] } })).unwrap();
    assert!(command_for_request(&mut invalid).is_err());
}

proptest! {
    #[test]
    fn arbitrary_native_frames_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let _ = read_message(&mut Cursor::new(bytes));
    }
}

#[test]
fn validates_chrome_extension_ids() {
    assert!(validate_extension_id("abcdefghijklmnopabcdefghijklmnop").is_ok());
    assert!(validate_extension_id("too-short").is_err());
    assert!(validate_extension_id("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
}

#[test]
fn native_host_uses_the_platform_executable_name() {
    #[cfg(target_os = "windows")]
    assert_eq!(HOST_BINARY_NAME, "pm-native-host.exe");
    #[cfg(not(target_os = "windows"))]
    assert_eq!(HOST_BINARY_NAME, "pm-native-host");
}

#[test]
fn native_manifest_directory_matches_the_current_platform() {
    let base_dirs = BaseDirs::new().unwrap();
    let host_dir = data_dir().join("native-messaging");
    let chrome = native_manifest_dir(&base_dirs, NativeBrowser::Chrome, &host_dir);
    let chromium = native_manifest_dir(&base_dirs, NativeBrowser::Chromium, &host_dir);
    let helium = native_manifest_dir(&base_dirs, NativeBrowser::Helium, &host_dir);

    #[cfg(target_os = "linux")]
    {
        assert!(chrome.ends_with("google-chrome/NativeMessagingHosts"));
        assert!(chromium.ends_with("chromium/NativeMessagingHosts"));
        assert!(helium.ends_with("net.imput.helium/NativeMessagingHosts"));
    }
    #[cfg(target_os = "macos")]
    {
        assert!(chrome.ends_with("Google/Chrome/NativeMessagingHosts"));
        assert!(chromium.ends_with("Chromium/NativeMessagingHosts"));
        assert!(helium.ends_with("net.imput.helium/NativeMessagingHosts"));
    }
    #[cfg(target_os = "windows")]
    {
        assert_eq!(chrome, host_dir);
        assert_eq!(chromium, host_dir);
        assert_eq!(helium, host_dir);
    }
}

#[test]
fn native_manifest_directories_cover_every_supported_platform() {
    let config_dir = Path::new("config");
    let host_dir = Path::new("host");

    let cases = [
        (
            NativePlatform::Linux,
            NativeBrowser::Chrome,
            "config/google-chrome/NativeMessagingHosts",
        ),
        (
            NativePlatform::Linux,
            NativeBrowser::Chromium,
            "config/chromium/NativeMessagingHosts",
        ),
        (
            NativePlatform::Linux,
            NativeBrowser::Helium,
            "config/net.imput.helium/NativeMessagingHosts",
        ),
        (
            NativePlatform::Macos,
            NativeBrowser::Chrome,
            "config/Google/Chrome/NativeMessagingHosts",
        ),
        (
            NativePlatform::Macos,
            NativeBrowser::Chromium,
            "config/Chromium/NativeMessagingHosts",
        ),
        (
            NativePlatform::Macos,
            NativeBrowser::Helium,
            "config/net.imput.helium/NativeMessagingHosts",
        ),
    ];
    for (platform, browser, expected) in cases {
        assert_eq!(
            native_manifest_dir_for(config_dir, browser, host_dir, platform),
            PathBuf::from(expected)
        );
    }
    for browser in [
        NativeBrowser::Chrome,
        NativeBrowser::Chromium,
        NativeBrowser::Helium,
    ] {
        assert_eq!(
            native_manifest_dir_for(config_dir, browser, host_dir, NativePlatform::Windows),
            host_dir
        );
    }
}

#[test]
fn windows_registry_locations_cover_supported_browsers() {
    assert_eq!(
        windows_registry_vendor(NativeBrowser::Chrome),
        "Google\\Chrome"
    );
    assert_eq!(windows_registry_vendor(NativeBrowser::Chromium), "Chromium");
    assert_eq!(windows_registry_vendor(NativeBrowser::Helium), "Chromium");
}

#[test]
fn native_message_round_trip_uses_native_endian_framing() {
    let response = NativeResponse::success(7, json!({ "ok": true }));
    let mut encoded = Vec::new();
    write_message(&mut encoded, &response).unwrap();
    let length = u32::from_ne_bytes(encoded[..4].try_into().unwrap()) as usize;
    assert_eq!(length, encoded.len() - 4);
    let decoded: Value = serde_json::from_slice(&encoded[4..]).unwrap();
    assert_eq!(decoded["id"], 7);
    assert_eq!(decoded["nativeVersion"], env!("CARGO_PKG_VERSION"));
    assert_eq!(decoded["data"]["ok"], true);

    let payload = read_message(&mut Cursor::new(&encoded)).unwrap().unwrap();
    assert_eq!(payload.as_slice(), &encoded[4..]);
}

#[test]
fn authenticator_responses_preserve_codes_and_mode_specific_lifetimes() {
    for expected in [
        json!({ "code": "287082", "expires_in": 19, "counter": null, "mode": "totp" }),
        json!({ "code": "755224", "expires_in": null, "counter": 0, "mode": "hotp" }),
    ] {
        let parsed = response_data("getTotp", expected.to_string()).unwrap();
        assert_eq!(parsed, expected, "mode {}", expected["mode"]);
    }
}

#[test]
fn malformed_authenticator_data_fails_without_exposing_code_material() {
    for payload in [
        r#"{"code":"secret","expires_in":19,"counter":null,"mode":"totp"}"#,
        r#"{"code":"287082","expires_in":null,"counter":null,"mode":"totp"}"#,
        r#"{"code":"755224","expires_in":null,"counter":0,"mode":"unknown"}"#,
        r#"{"code":"755224","expires_in":null,"counter":"0","mode":"hotp"}"#,
        r#"{"code":"755224","expires_in":19,"counter":0,"mode":"hotp"}"#,
        "TOTP: 287082 (19s remaining)",
    ] {
        let error = response_data("getTotp", payload.into()).unwrap_err();
        assert_eq!(error, "invalid authenticator response from server");
    }
}

#[test]
fn native_requests_are_whitelisted_and_use_stable_ids() {
    let mut duo = NativeRequest {
        action: "getDuoItems".into(),
        domain: Some("https://api-test.duosecurity.com".into()),
        ..NativeRequest::default()
    };
    assert!(
        matches!(command_for_request(&mut duo).unwrap(), ServerCommand::BrowserDuoItems(domain) if domain == "https://api-test.duosecurity.com")
    );
    let mut logins = NativeRequest {
        action: "getLoginItems".into(),
        domain: Some("https://example.com".into()),
        ..NativeRequest::default()
    };
    assert!(
        matches!(command_for_request(&mut logins).unwrap(), ServerCommand::BrowserLogins(domain) if domain == "https://example.com")
    );
    let mut login = NativeRequest {
        action: "getLoginItem".into(),
        domain: Some("https://example.com".into()),
        entry_id: Some(7),
        ..NativeRequest::default()
    };
    assert!(
        matches!(command_for_request(&mut login).unwrap(), ServerCommand::BrowserLogin { domain, id: 7 } if domain == "https://example.com")
    );
    for id in [None, Some(0)] {
        let mut invalid = NativeRequest {
            action: "getLoginItem".into(),
            domain: Some("https://example.com".into()),
            entry_id: id,
            ..NativeRequest::default()
        };
        assert!(command_for_request(&mut invalid).is_err());
    }
    let mut autofill = NativeRequest {
        action: "getAutofillItems".into(),
        ..NativeRequest::default()
    };
    assert!(matches!(
        command_for_request(&mut autofill).unwrap(),
        ServerCommand::BrowserAutofill
    ));

    let mut selected_autofill = NativeRequest {
        action: "getAutofillItem".into(),
        entry_id: Some(9),
        ..NativeRequest::default()
    };
    assert!(matches!(
        command_for_request(&mut selected_autofill).unwrap(),
        ServerCommand::BrowserAutofillItem(9)
    ));

    let mut request = NativeRequest {
        action: "getTotp".into(),
        entry_id: Some(17),
        ..NativeRequest::default()
    };
    assert!(matches!(
        command_for_request(&mut request).unwrap(),
        ServerCommand::AuthenticatorData(Target::Id(17))
    ));

    let mut unsupported = NativeRequest {
        action: "export".into(),
        ..NativeRequest::default()
    };
    assert!(command_for_request(&mut unsupported).is_err());
}

#[test]
fn native_bridge_rejects_oversized_and_truncated_frames() {
    let mut input = Cursor::new(((MAX_NATIVE_MESSAGE + 1) as u32).to_ne_bytes());
    assert!(read_message(&mut input).is_err());
    let mut framed = 12u32.to_ne_bytes().to_vec();
    framed.extend_from_slice(b"short");
    assert!(read_message(&mut Cursor::new(framed)).is_err());

    let secret = "synthetic-response-secret";
    let response = Zeroizing::new(NativeResponse::success(
        1,
        Value::String(secret.repeat(MAX_NATIVE_MESSAGE / secret.len() + 1)),
    ));
    let mut output = Vec::new();
    let error = write_message(&mut output, &response).unwrap_err();
    assert!(error.contains("1 MiB limit"));
    assert!(!error.contains(secret));
    assert!(output.is_empty());

    let response = Zeroizing::new(NativeResponse::success(1, json!({ "password": secret })));
    let mut header_only = [0u8; 4];
    let error = write_message(&mut header_only.as_mut_slice(), &response).unwrap_err();
    assert!(error.contains("could not write native response"));
    assert!(!error.contains(secret));
}

#[test]
fn native_bridge_rejects_control_characters_and_oversized_fields() {
    let mut newline = NativeRequest {
        action: "saveCredentials".into(),
        domain: Some("https://example.com\nforged".into()),
        username: Some("alice".into()),
        password: Some("secret".into()),
        name: Some("example".into()),
        ..NativeRequest::default()
    };
    assert!(command_for_request(&mut newline).is_err());

    let mut oversized = NativeRequest {
        action: "getCredentials".into(),
        domain: Some("x".repeat(2049)),
        ..NativeRequest::default()
    };
    assert!(command_for_request(&mut oversized).is_err());
}

#[test]
fn native_bridge_does_not_echo_validation_or_deserialization_inputs() {
    let secret = "never-echo-this-password";
    for (label, request, expected_id) in [
        (
            "command validation",
            json!({
                "id": 91, "action": "saveCredentials", "domain": "https://example.com\ninvalid",
                "username": "alice", "password": secret, "name": "example"
            }),
            91,
        ),
        (
            "invalid ID type",
            json!({ "id": secret, "action": "status" }),
            0,
        ),
        (
            "invalid decision type",
            json!({ "id": 1, "action": "managerDuoRespond", "approve": secret }),
            0,
        ),
        (
            "invalid item kind",
            json!({ "id": 1, "action": "managerAdd", "item": { "name": "test", "kind": secret } }),
            0,
        ),
    ] {
        let payload = serde_json::to_vec(&request).unwrap();
        let mut framed = (payload.len() as u32).to_ne_bytes().to_vec();
        framed.extend_from_slice(&payload);
        let mut output = Vec::new();
        run_with_io(
            &AuthenticatedClient::new(crate::server::DEFAULT_PORT),
            &mut Cursor::new(framed),
            &mut output,
        )
        .unwrap();
        let length = u32::from_ne_bytes(output[..4].try_into().unwrap()) as usize;
        let response: Value = serde_json::from_slice(&output[4..4 + length]).unwrap();
        assert_eq!(response["id"], expected_id, "{label}");
        assert_eq!(response["success"], false, "{label}");
        if expected_id == 0 {
            assert!(
                response["error"]
                    .as_str()
                    .unwrap()
                    .starts_with("invalid request at line "),
                "{label}"
            );
        }
        assert!(
            !String::from_utf8_lossy(&output).contains(secret),
            "{label}"
        );
    }
}

#[test]
fn native_mutations_report_committed_durability_as_uncertain() {
    use crate::protocol::{
        ResponseCode, SECURE_PREFACE, SECURE_RECORD_HEADER_LEN, decrypt_record, encode_response,
        encrypt_record, server_hello,
    };
    use std::{net::TcpListener, thread, time::Duration};

    let directory = tempfile::tempdir().unwrap();
    let token_path = directory.path().join("token");
    let token = "ab".repeat(32);
    fs::write(&token_path, &token).unwrap();
    for code in [ResponseCode::Failure, ResponseCode::Durability] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = AuthenticatedClient::new(listener.local_addr().unwrap().port());
        client.token_path = token_path.clone();
        let token = token.clone();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut preface = [0; SECURE_PREFACE.len()];
            stream.read_exact(&mut preface).unwrap();
            assert_eq!(&preface, SECURE_PREFACE);
            let (hello, keys) = server_hello(&token).unwrap();
            stream.write_all(&hello).unwrap();
            let mut header = [0; SECURE_RECORD_HEADER_LEN];
            stream.read_exact(&mut header).unwrap();
            let length = u32::from_be_bytes(header[24..].try_into().unwrap()) as usize;
            let mut ciphertext = vec![0; length];
            stream.read_exact(&mut ciphertext).unwrap();
            let request = decrypt_record(&keys.request, &header[..24], &ciphertext).unwrap();
            assert!(matches!(
                rmp_serde::from_slice::<ServerCommand>(&request).unwrap(),
                ServerCommand::Delete(Target::Id(7))
            ));
            // Identical wording proves uncertainty follows the authenticated
            // error code, rather than parsing a human-readable error.
            let response = encrypt_record(
                &keys.response,
                &encode_response(code, "synthetic persistence failure"),
            )
            .unwrap();
            stream.write_all(&response).unwrap();
        });
        let response = Zeroizing::new(handle_request(
            &client,
            NativeRequest {
                id: 77,
                action: "managerDelete".into(),
                entry_id: Some(7),
                ..Default::default()
            },
        ));
        assert!(!response.success);
        assert_eq!(response.id, 77);
        assert_eq!(response.uncertain, code == ResponseCode::Durability);
        let mut output = Vec::new();
        write_message(&mut output, &response).unwrap();
        let payload: Value = serde_json::from_slice(&output[4..]).unwrap();
        if code == ResponseCode::Durability {
            assert_eq!(payload["uncertain"], true);
            assert!(
                response
                    .error
                    .as_ref()
                    .unwrap()
                    .contains("operation committed")
            );
            assert!(
                !response
                    .error
                    .as_ref()
                    .unwrap()
                    .contains("may still complete")
            );
        } else {
            assert!(payload.get("uncertain").is_none());
        }
        worker.join().unwrap();
    }
}

#[test]
fn native_status_requires_and_preserves_structured_server_state() {
    let status = crate::protocol::ServerStatus::new(false, Some("Lock failed".into()));
    let output = serde_json::to_string(&status).unwrap();
    let parsed = response_data("status", output).unwrap();
    assert_eq!(parsed["locked"], false);
    assert_eq!(parsed["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(parsed["warning"], "Lock failed");
    assert!(response_data("status", "Status: Unlocked".into()).is_err());
    assert!(response_data("status", r#"{"locked":"false","version":"0.1.0"}"#.into()).is_err());
}

#[test]
fn duo_decisions_require_exact_identifiers_boolean_and_bounded_code() {
    let base = json!({"id":1,"action":"managerDuoRespond","entryId":4,"requestId":"test-request","fingerprint":"a".repeat(128),"approve":true,"verificationCode":"012"});
    let mut request: NativeRequest = serde_json::from_value(base.clone()).unwrap();
    let command = command_for_request(&mut request).unwrap();
    assert!(
        matches!(command,ServerCommand::Duo(DuoCommand::Respond {approve:true,ref code,..}) if code=="012")
    );
    assert!(request.verification_code.is_none());
    for (key, value) in [
        ("entryId", json!(0)),
        ("requestId", json!("../escape")),
        ("fingerprint", json!("short")),
        ("verificationCode", json!("1234567")),
        ("verificationCode", json!("12x")),
        ("approve", Value::Null),
    ] {
        let mut invalid = base.clone();
        invalid[key] = value;
        let mut request: NativeRequest = serde_json::from_value(invalid).unwrap();
        assert!(command_for_request(&mut request).is_err(), "{key}");
    }
    let mut denied = base;
    denied["approve"] = json!(false);
    let mut request: NativeRequest = serde_json::from_value(denied).unwrap();
    assert!(command_for_request(&mut request).is_err());
}
