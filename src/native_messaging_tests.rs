use super::*;
use proptest::prelude::*;
use std::io::Cursor;

fn read_json_frame(reader: &mut impl std::io::Read) -> Value {
    serde_json::from_slice(&read_message(reader).unwrap().unwrap()).unwrap()
}

proptest! {
    #[test]
    fn arbitrary_native_frames_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let _ = read_message(&mut Cursor::new(bytes));
    }
}

#[test]
fn validates_chrome_extension_ids() {
    let chrome = NativeBrowser::Chrome;
    assert!(validate_extension_id("abcdefghijklmnopabcdefghijklmnop", chrome).is_ok());
    assert!(validate_extension_id("too-short", chrome).is_err());
    assert!(validate_extension_id("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", chrome).is_err());
    assert!(validate_extension_id(FIREFOX_EXTENSION_ID, chrome).is_err());
}

#[test]
fn validates_firefox_add_on_ids_and_uses_firefox_allow_lists() {
    let firefox = NativeBrowser::Firefox;
    for valid in [
        FIREFOX_EXTENSION_ID,
        "my-addon@example.org",
        "{12345678-90ab-cdef-1234-567890abcdef}",
    ] {
        assert!(validate_extension_id(valid, firefox).is_ok(), "{valid}");
    }
    for invalid in [
        "abcdefghijklmnopabcdefghijklmnop",
        "@example.org",
        "name@",
        "bad name@example.org",
        "{12345678-90ab-cdef-1234-567890abcdeg}",
        "{12345678090ab-cdef-1234-567890abcdef}",
    ] {
        assert!(
            validate_extension_id(invalid, firefox).is_err(),
            "{invalid}"
        );
    }
    assert_eq!(
        manifest_allow_list(FIREFOX_EXTENSION_ID, firefox),
        ("allowed_extensions", json!([FIREFOX_EXTENSION_ID]))
    );
    assert_eq!(
        manifest_allow_list("abcdefghijklmnopabcdefghijklmnop", NativeBrowser::Helium),
        (
            "allowed_origins",
            json!(["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"])
        )
    );
    assert_eq!(
        manifest_file_name(firefox),
        format!("{HOST_NAME}.firefox.json")
    );
    assert_eq!(
        manifest_file_name(NativeBrowser::Chrome),
        format!("{HOST_NAME}.json")
    );
    // Chrome-family installs default to the ID pinned by the manifest key.
    validate_extension_id(CHROME_EXTENSION_ID, NativeBrowser::Chrome).unwrap();
}

#[test]
fn native_manifest_directories_cover_all_platforms_and_current_platform_dispatch() {
    let base_dirs = BaseDirs::new().unwrap();
    let host_dir = Path::new("host");
    for (browser, linux, macos) in [
        (NativeBrowser::Chrome, "google-chrome", "Google/Chrome"),
        (NativeBrowser::Chromium, "chromium", "Chromium"),
        (
            NativeBrowser::Helium,
            "net.imput.helium",
            "net.imput.helium",
        ),
    ] {
        for (platform, vendor, current) in [
            (
                NativePlatform::Linux,
                Some(linux),
                cfg!(target_os = "linux"),
            ),
            (
                NativePlatform::Macos,
                Some(macos),
                cfg!(target_os = "macos"),
            ),
            (NativePlatform::Windows, None, cfg!(target_os = "windows")),
        ] {
            let expected = vendor.map_or_else(
                || host_dir.to_path_buf(),
                |vendor| {
                    base_dirs
                        .config_dir()
                        .join(vendor)
                        .join("NativeMessagingHosts")
                },
            );
            assert_eq!(
                native_manifest_dir_for(
                    base_dirs.config_dir(),
                    base_dirs.home_dir(),
                    browser,
                    host_dir,
                    platform
                ),
                expected
            );
            if current {
                assert_eq!(native_manifest_dir(&base_dirs, browser, host_dir), expected);
            }
        }
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
    assert_eq!(windows_registry_vendor(NativeBrowser::Firefox), "Mozilla");
}

#[test]
fn firefox_manifests_use_mozilla_locations() {
    let (config, home, host) = (Path::new("config"), Path::new("home"), Path::new("host"));
    let dir =
        |platform| native_manifest_dir_for(config, home, NativeBrowser::Firefox, host, platform);
    assert_eq!(
        dir(NativePlatform::Linux),
        home.join(".mozilla").join("native-messaging-hosts")
    );
    assert_eq!(
        dir(NativePlatform::Macos),
        config.join("Mozilla").join("NativeMessagingHosts")
    );
    assert_eq!(dir(NativePlatform::Windows), host);
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
fn malformed_authenticator_data_fails_without_exposing_code_material() {
    for payload in [
        r#"{"code":"secret","expires_in":19,"counter":null,"mode":"totp"}"#,
        r#"{"code":"287082","expires_in":null,"counter":null,"mode":"totp"}"#,
        r#"{"code":"755224","expires_in":null,"counter":0,"mode":"unknown"}"#,
        r#"{"code":"755224","expires_in":null,"counter":0,"mode":"hotp"}"#,
        r#"{"code":"755224","expires_in":19,"counter":"0","mode":"hotp"}"#,
        "TOTP: 287082 (19s remaining)",
    ] {
        let parsed = serde_json::from_str::<crate::protocol::AuthenticatorResponse>(payload);
        assert!(parsed.is_err() || !parsed.unwrap().valid());
    }
}

#[test]
fn native_requests_are_whitelisted_and_use_stable_ids() {
    let mut duo = NativeRequest {
        action: NativeAction::GetDuoItems,
        domain: Some("https://api-test.duosecurity.com".into()),
        ..NativeRequest::default()
    };
    assert!(
        matches!(command_for_request(&mut duo).unwrap(), ServerCommand::BrowserDuoItems(domain) if domain == "https://api-test.duosecurity.com")
    );
    let mut logins = NativeRequest {
        action: NativeAction::GetLoginItems,
        domain: Some("https://example.com".into()),
        ..NativeRequest::default()
    };
    assert!(
        matches!(command_for_request(&mut logins).unwrap(), ServerCommand::BrowserLogins(domain) if domain == "https://example.com")
    );
    let mut login = NativeRequest {
        action: NativeAction::GetLoginItem,
        domain: Some("https://example.com".into()),
        entry_id: Some(7),
        ..NativeRequest::default()
    };
    assert!(
        matches!(command_for_request(&mut login).unwrap(), ServerCommand::BrowserLogin { domain, id: 7 } if domain == "https://example.com")
    );
    for id in [None, Some(0)] {
        let mut invalid = NativeRequest {
            action: NativeAction::GetLoginItem,
            domain: Some("https://example.com".into()),
            entry_id: id,
            ..NativeRequest::default()
        };
        assert!(command_for_request(&mut invalid).is_err());
    }
    let mut autofill = NativeRequest {
        action: NativeAction::GetAutofillItems,
        ..NativeRequest::default()
    };
    assert!(matches!(
        command_for_request(&mut autofill).unwrap(),
        ServerCommand::BrowserAutofill
    ));

    let mut selected_autofill = NativeRequest {
        action: NativeAction::GetAutofillItem,
        entry_id: Some(9),
        ..NativeRequest::default()
    };
    assert!(matches!(
        command_for_request(&mut selected_autofill).unwrap(),
        ServerCommand::BrowserAutofillItem(9)
    ));

    let mut request = NativeRequest {
        action: NativeAction::GetTotp,
        domain: Some("https://example.com".into()),
        entry_id: Some(17),
        ..NativeRequest::default()
    };
    assert!(matches!(
        command_for_request(&mut request).unwrap(),
        ServerCommand::BrowserAuthenticatorData { id: 17, .. }
    ));

    assert!(serde_json::from_value::<NativeRequest>(json!({"id":1,"action":"export"})).is_err());
    assert!(
        serde_json::from_value::<NativeRequest>(json!({"id":1,"action":"getCredentials"})).is_err()
    );
}

#[test]
fn native_bridge_rejects_oversized_and_truncated_frames() {
    assert!(read_message(&mut Cursor::new([])).unwrap().is_none());
    let header = 12u32.to_ne_bytes();
    for length in 1..=header.len() {
        let error = read_message(&mut Cursor::new(&header[..length])).unwrap_err();
        assert!(error.contains(if length < header.len() {
            "message length"
        } else {
            "native message"
        }));
    }
    for frame in [
        ((MAX_NATIVE_MESSAGE + 1) as u32).to_ne_bytes().to_vec(),
        [header.as_slice(), b"short"].concat(),
    ] {
        assert!(read_message(&mut Cursor::new(frame)).is_err());
    }

    let secret = "synthetic-response-secret";
    let response = Zeroizing::new(NativeResponse::success(
        1,
        Value::String(secret.repeat(MAX_NATIVE_MESSAGE / secret.len() + 1)),
    ));
    let mut output = Vec::new();
    write_message(&mut output, &response).unwrap();
    // Another frame remains usable after an oversized read result.
    write_message(&mut output, &NativeResponse::success(2, json!({"ok":true}))).unwrap();
    let mut frames = Cursor::new(output);
    let fallback = read_json_frame(&mut frames);
    assert_eq!(fallback["id"], 1);
    assert_eq!(fallback["success"], false);
    assert!(fallback["error"].as_str().unwrap().contains("1 MiB limit"));
    assert!(!fallback.to_string().contains(secret));
    let next = read_json_frame(&mut frames);
    assert_eq!(next["id"], 2);

    let mut mutation = response;
    mutation.operation_id = Some("oversized-result-operation".into());
    mutation.operation = Some(OperationReceipt {
        operation_id: "oversized-result-operation".into(),
        state: OperationState::Committed,
        revision: Some(8),
    });
    let mut output = Vec::new();
    write_message(&mut output, &mutation).unwrap();
    let fallback = read_json_frame(&mut Cursor::new(output));
    assert_eq!(fallback["uncertain"], true);
    assert_eq!(fallback["operationId"], "oversized-result-operation");
    assert_eq!(fallback["operation"]["revision"], 8);

    let response = Zeroizing::new(NativeResponse::success(1, json!({ "password": secret })));
    let mut header_only = [0u8; 4];
    let error = write_message(&mut header_only.as_mut_slice(), &response).unwrap_err();
    assert!(error.contains("could not write native response"));
    assert!(!error.contains(secret));
}

#[test]
fn native_bridge_rejects_control_characters_and_oversized_fields() {
    let mut newline = NativeRequest {
        action: NativeAction::SaveCredentials,
        domain: Some("https://example.com\nforged".into()),
        username: Some("alice".into()),
        password: Some("secret".into()),
        name: Some("example".into()),
        ..NativeRequest::default()
    };
    assert!(command_for_request(&mut newline).is_err());

    let mut oversized = NativeRequest {
        action: NativeAction::GetLoginItems,
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
            json!({ "id": 1, "action": "duoRespond", "approve": secret }),
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
        let response = read_json_frame(&mut Cursor::new(&output));
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
        ResponseCode, RpcResponse, SECURE_PREFACE, SECURE_RECORD_HEADER_LEN, decrypt_record,
        encode_rpc_response, encrypt_record, server_hello,
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
                rmp_serde::from_slice::<RequestEnvelope>(&request)
                    .unwrap()
                    .command,
                ServerCommand::Lock(true)
            ));
            // Identical wording proves uncertainty follows the authenticated
            // error code, rather than parsing a human-readable error.
            let response = encrypt_record(
                &keys.response,
                &encode_rpc_response(&RpcResponse::message(code, "synthetic persistence failure"))
                    .unwrap(),
            )
            .unwrap();
            stream.write_all(&response).unwrap();
        });
        let response = Zeroizing::new(handle_request(
            &client,
            NativeRequest {
                id: 77,
                action: NativeAction::Lock,
                operation_id: Some("test-delete-77".into()),
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
    let parsed = ResponsePayload::Status(status).into_json();
    assert_eq!(parsed["locked"], false);
    assert_eq!(parsed["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(parsed["warning"], "Lock failed");
    assert!(serde_json::from_str::<crate::protocol::ServerStatus>("Status: Unlocked").is_err());
    assert!(
        serde_json::from_str::<crate::protocol::ServerStatus>(
            r#"{"locked":"false","version":"0.1.0"}"#
        )
        .is_err()
    );
}

#[test]
fn duo_decisions_require_exact_identifiers_boolean_and_bounded_code() {
    let base = json!({"id":1,"action":"duoRespond","entryId":4,"requestId":"test-request","fingerprint":"a".repeat(128),"approve":true,"verificationCode":"012"});
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

#[test]
fn native_policy_rejects_cross_operation_fields_and_requires_reviewed_revisions() {
    for request in [
        json!({"id":1,"action":"status","password":"must-not-appear"}),
        json!({"id":1,"action":"getTotp","entryId":0,"operationId":"otp-one"}),
    ] {
        let request: NativeRequest = serde_json::from_value(request).unwrap();
        let error = request.validate().unwrap_err();
        assert!(!error.contains("must-not-appear"));
    }
    let mut request: NativeRequest = serde_json::from_value(
        json!({"id":2,"action":"operationStatus","operationId":"delete-one"}),
    )
    .unwrap();
    request.validate().unwrap();
    assert!(
        matches!(command_for_request(&mut request).unwrap(),ServerCommand::OperationStatus(id) if id=="delete-one")
    );
}

#[test]
fn browser_native_reads_require_session_revision_and_site_for_otp() {
    for action in ["getLoginItem", "getAutofillItem", "getTotp"] {
        let mut valid = json!({"id":1,"action":action,"entryId":1,"expectedRevision":2,"expectedSession":"a".repeat(64)});
        if action != "getAutofillItem" {
            valid["domain"] = json!("https://example.com");
        }
        if action == "getTotp" {
            valid["operationId"] = json!("otp-review");
        }
        let mut parsed: NativeRequest = serde_json::from_value(valid.clone()).unwrap();
        parsed.validate().unwrap();
        let command = command_for_request(&mut parsed).unwrap();
        if action == "getTotp" {
            assert!(
                matches!(command, ServerCommand::BrowserAuthenticatorData {ref domain, id:1} if domain == "https://example.com")
            );
        }
        for field in ["expectedSession", "expectedRevision"] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(field);
            let request: NativeRequest = serde_json::from_value(missing).unwrap();
            assert!(request.validate().is_err());
        }
        for session in ["", "short", &"z".repeat(64)] {
            let mut invalid = valid.clone();
            invalid["expectedSession"] = json!(session);
            let request: NativeRequest = serde_json::from_value(invalid).unwrap();
            assert!(request.validate().is_err());
        }
        if action == "getTotp" {
            valid.as_object_mut().unwrap().remove("domain");
            assert!(
                serde_json::from_value::<NativeRequest>(valid)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }
}

#[test]
fn browser_password_updates_preserve_saved_site_information() {
    let mut request = NativeRequest {
        action: NativeAction::UpdateCredentials,
        domain: Some("https://alternate.example.com".into()),
        entry_id: Some(7),
        username: Some("alice".into()),
        password: Some("new-password".into()),
        ..NativeRequest::default()
    };
    let ServerCommand::Update(update) = command_for_request(&mut request).unwrap() else {
        panic!("expected credential update");
    };
    assert_eq!(update.entry.update.username.as_deref(), Some("alice"));
    assert_eq!(update.entry.update.url, None);
    assert_eq!(update.entry.password.unwrap().expose(), "new-password");
}

#[test]
fn desktop_launch_does_not_need_a_vault_server_and_preserves_errors() {
    let client = AuthenticatedClient::new(0);
    for outcome in [Ok(()), Err("synthetic launch failure".to_string())] {
        let expected = outcome.clone();
        let request: NativeRequest =
            serde_json::from_value(json!({"id": 91, "action": "openDesktop"})).unwrap();
        let response = handle_request_with_launcher(&client, request, |item| {
            assert_eq!(item, None);
            outcome
        });
        assert_eq!(response.id, 91);
        assert_eq!(response.success, expected.is_ok());
        assert_eq!(response.error, expected.err());
        assert!(!response.uncertain);
    }
    let request: NativeRequest = serde_json::from_value(
        json!({"id": 92, "action": "openDesktop", "domain": "https://example.com"}),
    )
    .unwrap();
    let response = handle_request_with_launcher(&client, request, |_| {
        panic!("invalid requests must not launch")
    });
    assert!(!response.success);
    // "Open in desktop app" passes the item ID to the launcher.
    let request: NativeRequest =
        serde_json::from_value(json!({"id": 93, "action": "openDesktop", "entryId": 7})).unwrap();
    let response = handle_request_with_launcher(&client, request, |item| {
        assert_eq!(item, Some(7));
        Ok(())
    });
    assert!(response.success);
}

#[cfg(feature = "desktop")]
#[test]
fn desktop_process_uses_explicit_gui_dispatch() {
    let command = desktop_command(Path::new("/synthetic/pm"));
    assert_eq!(command.get_program(), "/synthetic/pm");
    assert_eq!(command.get_args().collect::<Vec<_>>(), ["gui"]);
}

#[cfg(unix)]
#[test]
fn desktop_launch_resolves_native_host_symlink_to_normal_pm() {
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("pm");
    fs::write(&executable, "synthetic executable").unwrap();
    let host = root.path().join(HOST_BINARY_NAME);
    std::os::unix::fs::symlink(&executable, &host).unwrap();
    assert_eq!(
        desktop_executable(&host).unwrap(),
        fs::canonicalize(&executable).unwrap()
    );
}

#[test]
fn copied_native_host_launches_registered_pm_and_rejects_unusable_paths() {
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("pm.exe");
    fs::write(&executable, "synthetic application").unwrap();
    let host = root.path().join(HOST_BINARY_NAME);
    fs::write(&host, "synthetic bridge copy").unwrap();
    let error = desktop_executable(&host).unwrap_err();
    assert!(error.contains("pm native-host update"));
    record_desktop_executable(&host, &executable).unwrap();
    assert_eq!(
        desktop_executable(&host).unwrap(),
        fs::canonicalize(&executable).unwrap()
    );
    for invalid in [
        host.as_path(),
        Path::new("relative-pm"),
        &root.path().join("missing-pm"),
    ] {
        record_desktop_executable(&host, invalid).unwrap();
        assert!(desktop_executable(&host).is_err());
    }
    fs::write(host.with_file_name(DESKTOP_EXECUTABLE_FILE), "invalid json").unwrap();
    assert!(desktop_executable(&host).is_err());
}

#[test]
fn the_browser_cannot_unlock_or_choose_vaults() {
    // Unlocking happens only in the desktop app or CLI.
    for action in ["unlock", "vaults", "switchVault"] {
        assert!(
            serde_json::from_value::<NativeRequest>(
                json!({"id": 1, "action": action, "password": "synthetic-master"})
            )
            .is_err(),
            "{action}"
        );
    }
}

#[test]
fn passkey_requests_need_the_site_and_session_and_map_to_browser_commands() {
    let options = r#"{"rpId":"example.com","challenge":"AAAA"}"#;
    let mut list: NativeRequest = serde_json::from_value(json!({
        "id": 1, "action": "getPasskeys", "domain": "https://example.com", "passkeyRequest": options
    }))
    .unwrap();
    list.validate().unwrap();
    assert!(matches!(
        command_for_request(&mut list).unwrap(),
        ServerCommand::BrowserPasskeys { origin, request } if origin == "https://example.com" && request == options
    ));
    let mut get: NativeRequest = serde_json::from_value(json!({
        "id": 2, "action": "getPasskeyAssertion", "domain": "https://example.com", "entryId": 4,
        "passkeyRequest": options, "expectedRevision": 1, "expectedSession": "a".repeat(64)
    }))
    .unwrap();
    get.validate().unwrap();
    assert!(matches!(
        command_for_request(&mut get).unwrap(),
        ServerCommand::BrowserPasskeyGet { id: 4, .. }
    ));
    // A desktop-issued verification token passes through; `verified` is
    // never set by the native host, and passwords are not accepted.
    for (action, extra) in [
        (
            "createPasskey",
            json!({"expectedSession": "a".repeat(64), "operationId": "op-1"}),
        ),
        (
            "getPasskeyAssertion",
            json!({"entryId": 4, "expectedRevision": 1, "expectedSession": "a".repeat(64)}),
        ),
    ] {
        let mut value = json!({"id": 8, "action": action, "domain": "https://example.com",
            "passkeyRequest": options, "verificationToken": "c".repeat(64)});
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let mut request: NativeRequest = serde_json::from_value(value).unwrap();
        request.validate().unwrap();
        let (verification, verified) = match command_for_request(&mut request).unwrap() {
            ServerCommand::BrowserPasskeyCreate {
                verification,
                verified,
                ..
            }
            | ServerCommand::BrowserPasskeyGet {
                verification,
                verified,
                ..
            } => (verification, verified),
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(verification, Some("c".repeat(64)), "{action}");
        assert!(!verified);
    }
    let session = "a".repeat(64);
    for (case, invalid) in [
        (
            "missing WebAuthn request",
            json!({"id": 3, "action": "getPasskeys", "domain": "https://example.com"}),
        ),
        (
            "registration without a session or operation",
            json!({"id": 4, "action": "createPasskey", "domain": "https://example.com", "passkeyRequest": options}),
        ),
        (
            "registration without an operation",
            json!({"id": 5, "action": "createPasskey", "domain": "https://example.com",
                "passkeyRequest": options, "expectedSession": session}),
        ),
        (
            "sign-in without the reviewed revision",
            json!({"id": 6, "action": "getPasskeyAssertion", "domain": "https://example.com", "entryId": 4,
                "passkeyRequest": options, "expectedSession": session}),
        ),
        (
            "oversized WebAuthn request",
            json!({"id": 7, "action": "getPasskeys", "domain": "https://example.com",
                "passkeyRequest": "x".repeat(64 * 1024 + 1)}),
        ),
        (
            "a password instead of a desktop confirmation",
            json!({"id": 9, "action": "createPasskey", "domain": "https://example.com", "passkeyRequest": options,
                "expectedSession": session, "operationId": "op-2", "password": "synthetic-master"}),
        ),
        (
            "malformed verification token",
            json!({"id": 10, "action": "createPasskey", "domain": "https://example.com", "passkeyRequest": options,
                "expectedSession": session, "operationId": "op-3", "verificationToken": "not-hex"}),
        ),
    ] {
        let request: NativeRequest = serde_json::from_value(invalid).unwrap();
        assert!(request.validate().is_err(), "{case}");
    }
    let mut verify: NativeRequest = serde_json::from_value(json!({
        "id": 11, "action": "verifyPasskeyUser", "domain": "https://example.com",
        "expectedSession": "a".repeat(64)
    }))
    .unwrap();
    verify.validate().unwrap();
    assert!(matches!(
        command_for_request(&mut verify).unwrap(),
        ServerCommand::PasskeyVerification { origin } if origin == "https://example.com"
    ));
    assert_eq!(NativeAction::VerifyPasskeyUser.policy().lane, "approval");
    assert!(
        NativeAction::CreatePasskey.policy().mutates,
        "registration needs an operation ID"
    );
    assert_eq!(
        NativeAction::GetPasskeys.policy().allowed_senders,
        ["background"]
    );
}

#[test]
fn popup_copies_are_site_bound_and_read_the_configured_timeout() {
    let valid = json!({
        "id": 1,
        "action": "copyLoginValue",
        "domain": "https://example.com",
        "entryId": 4,
        "field": "totp",
        "expectedRevision": 2,
        "expectedSession": "a".repeat(64),
    });
    let mut parsed: NativeRequest = serde_json::from_value(valid.clone()).unwrap();
    parsed.validate().unwrap();
    assert!(matches!(
        command_for_request(&mut parsed).unwrap(),
        ServerCommand::BrowserCopy {
            ref domain,
            id: 4,
            field: crate::types::BrowserCopyField::Totp,
            ..
        } if domain == "https://example.com"
    ));
    for field in ["domain", "field", "expectedSession", "expectedRevision"] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        let request: NativeRequest = serde_json::from_value(missing).unwrap();
        assert!(request.validate().is_err(), "{field}");
    }
    let mut notes = valid.clone();
    notes["field"] = json!("notes");
    assert!(serde_json::from_value::<NativeRequest>(notes).is_err());
    // Copies never need an operation ID: repeating one changes nothing.
    let mut with_operation = valid;
    with_operation["operationId"] = json!("copy-1");
    let request: NativeRequest = serde_json::from_value(with_operation).unwrap();
    assert!(request.validate().is_err());

    let mut generated: NativeRequest = serde_json::from_value(
        json!({"id": 2, "action": "copyGenerated", "password": "generated"}),
    )
    .unwrap();
    generated.validate().unwrap();
    assert!(matches!(
        command_for_request(&mut generated).unwrap(),
        ServerCommand::CopyGenerated { ref value, .. } if value.expose() == "generated"
    ));
}
