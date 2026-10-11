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

    let mut input = Cursor::new(encoded[4..].to_vec());
    let mut framed = (length as u32).to_ne_bytes().to_vec();
    framed.extend(input.get_mut().iter());
    assert_eq!(
        read_message(&mut Cursor::new(framed))
            .unwrap()
            .unwrap()
            .len(),
        length
    );
}

#[test]
fn parses_totp_server_response() {
    let data = response_data("getTotp", "TOTP: 287082 (19s remaining)\n".into()).unwrap();
    assert_eq!(data["code"], "287082");
    assert_eq!(data["expires_in"], 19);
}

#[test]
fn parses_hotp_response_without_a_time_based_expiration() {
    let data = response_data(
        "getTotp",
        "HOTP: 755224 (counter 0; next counter saved)\n".into(),
    )
    .unwrap();
    assert_eq!(data["code"], "755224");
    assert_eq!(data["counter"], 0);
    assert_eq!(data["mode"], "hotp");
    assert!(data["expires_in"].is_null());
    assert!(
        response_data(
            "getTotp",
            "HOTP: 755224 (counter invalid; next counter saved)".into()
        )
        .is_err()
    );
}

#[test]
fn native_requests_are_whitelisted_and_use_stable_ids() {
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
        ServerCommand::Totp(TotpCommand::Show {
            target: Target::Id(17),
            copy_timeout: None
        })
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
fn native_bridge_does_not_echo_rejected_credentials() {
    let secret = "never-echo-this-password";
    let request = json!({
        "id": 91,
        "action": "saveCredentials",
        "domain": "https://example.com\ninvalid",
        "username": "alice",
        "password": secret,
        "name": "example"
    });
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
    assert_eq!(response["id"], 91);
    assert_eq!(response["success"], false);
    assert!(!String::from_utf8_lossy(&output).contains(secret));
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
