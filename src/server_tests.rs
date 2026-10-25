use super::*;
use crate::file::init_test_data_dir;
use crate::protocol::{
    OperationState, SECURE_HELLO_LEN, decode_responses, decrypt_record_stream, verify_server_hello,
};
use crate::vault::{Vault, VaultCredentials, VaultEntry};

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}
fn test_connection_state() -> ConnectionState {
    let (kill_tx, _) = mpsc::channel(1);
    ConnectionState {
        instance_lock: None,
        kill_tx,
        token: Zeroizing::new("ab".repeat(32)),
        inactivity_timeout: Arc::new(AtomicU64::new(0)),
        stopping: Arc::new(AtomicBool::new(false)),
        background_error: Arc::new(Mutex::new(None)),
        system_lock: None,
        password_history_limit: 10,
        trash_retention_days: 0,
    }
}
fn test_worker(session: VaultSession, state: &ConnectionState) -> VaultWorker {
    VaultWorker::start(
        session,
        Arc::clone(&state.inactivity_timeout),
        Arc::clone(&state.background_error),
    )
}
fn session(vault: Vault) -> VaultSession {
    VaultSession::unlock(
        vault,
        PasswordType::Session {
            encryption_key: [42; 32],
            salt: [42; 16],
            kdf: 1,
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
        },
    )
}
async fn send(stream: &mut TcpStream, token: &str, request: RequestEnvelope) -> RpcResponse {
    stream.write_all(SECURE_PREFACE).await.unwrap();
    let mut hello = [0; SECURE_HELLO_LEN];
    stream.read_exact(&mut hello).await.unwrap();
    let keys = verify_server_hello(token, &hello).unwrap();
    let bytes = Zeroizing::new(rmp_serde::to_vec_named(&request).unwrap());
    stream
        .write_all(&encrypt_record(&keys.request, &bytes).unwrap())
        .await
        .unwrap();
    let mut encrypted = Vec::new();
    stream.read_to_end(&mut encrypted).await.unwrap();
    let plaintext =
        Zeroizing::new(decrypt_record_stream(&keys.response, &encrypted, 1024 * 1024).unwrap());
    decode_responses(&plaintext).unwrap()
}
async fn dispatch(vault: Vault, command: ServerCommand, locked: bool) -> RpcResponse {
    let state = test_connection_state();
    let worker = test_worker(
        if locked {
            VaultSession::Locked
        } else {
            session(vault)
        },
        &state,
    );
    let (mut client, server) = tcp_pair().await;
    let mut request = RequestEnvelope::new(command);
    if matches!(
        request.command,
        ServerCommand::BrowserLogin { .. }
            | ServerCommand::BrowserAutofillItem(_)
            | ServerCommand::BrowserAuthenticatorData { .. }
    ) {
        request.expected_session = worker.session_id();
        request.expected_revision = worker
            .with_session(|live| live.vault().and_then(|v| v.revision(1)))
            .await
            .unwrap();
        if request.expected_session.is_none() {
            request.expected_session = Some("0".repeat(64));
            request.expected_revision = Some(1);
        }
    }
    let task = tokio::spawn(handle_connection(server, state.clone(), worker));
    let response = send(&mut client, &state.token, request).await;
    task.await.unwrap();
    response
}
fn response_text(response: &RpcResponse) -> String {
    serde_json::to_string(&response.payload).unwrap()
}
fn sample_vault() -> Vault {
    Vault::from_entries(
        vec![VaultEntry {
            id: 1,
            name: "Account".into(),
            password: "synthetic-secret".into(),
            url: Some("https://example.com".into()),
            ..Default::default()
        }],
        None,
    )
}

#[tokio::test]
async fn history_and_trash_use_typed_records_without_exposing_secrets() {
    let mut vault = sample_vault();
    vault
        .update_entry_with_limit(
            EntryUpdate {
                target: Target::Id(1),
                update: EntryChanges::default(),
                password: Some("replacement-secret".into()),
            },
            &mut VaultCredentials::default(),
            10,
        )
        .unwrap();
    let response = dispatch(vault.clone(), ServerCommand::History(Target::Id(1)), false).await;
    let ResponsePayload::History(history) = &response.payload else {
        panic!("history must use its typed response");
    };
    assert_eq!(history.history.len(), 1);
    assert!(chrono::DateTime::parse_from_rfc3339(&history.history[0]).is_ok());
    let json = response.payload.into_json();
    assert!(json["history"].is_array());
    assert!(!json.to_string().contains("secret"));

    vault
        .delete_entry(Target::Id(1), &mut VaultCredentials::default())
        .unwrap();
    let response = dispatch(vault, ServerCommand::Trash, false).await;
    let ResponsePayload::Trash(trash) = &response.payload else {
        panic!("trash must use its typed response");
    };
    assert_eq!(trash.trash.len(), 1);
    assert_eq!(trash.trash[0].id, 1);
    let json = response.payload.into_json();
    assert_eq!(json["trash"][0]["name"], "Account");
    assert_eq!(json["trash"][0]["kind"], "login");
    assert!(!json.to_string().contains("secret"));
}

#[tokio::test]
async fn displayed_trash_ids_select_the_same_items_for_restore_and_purge() {
    let state = test_connection_state();
    let vault = Vault::from_entries(
        [3, 17, 42]
            .into_iter()
            .map(|id| VaultEntry {
                id,
                name: format!("Item {id}"),
                password: "synthetic-secret".into(),
                ..Default::default()
            })
            .collect(),
        None,
    );
    let worker = test_worker(session(vault), &state);
    for id in [17, 42] {
        let result = worker
            .execute(
                state.clone(),
                RequestEnvelope::new(ServerCommand::Delete(Target::Id(id))),
            )
            .await;
        assert_eq!(result.responses[0].code, 0);
    }
    let result = worker
        .execute(state.clone(), RequestEnvelope::new(ServerCommand::Trash))
        .await;
    let listing = crate::client::render_response(&result.responses[0].payload);
    let ids: Vec<usize> = listing
        .lines()
        .map(|line| line.split_once('.').unwrap().0.parse().unwrap())
        .collect();
    assert_eq!(ids, [17, 42]);

    for command in [
        ServerCommand::RestoreTrash(ids[0]),
        ServerCommand::PurgeTrash(Some(ids[1])),
    ] {
        let result = worker
            .execute(state.clone(), RequestEnvelope::new(command))
            .await;
        assert_eq!(result.responses[0].code, 0);
    }
    worker
        .with_session(|session| {
            let vault = session.vault().unwrap();
            assert!(vault.management_item(3, false).is_ok());
            assert!(vault.management_item(17, false).is_ok());
            assert!(vault.management_item(42, false).is_err());
            assert!(vault.view_trash().is_empty());
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn shutdown_rejects_already_authenticated_connections() {
    let mut state = test_connection_state();
    let (kill_tx, mut kill_rx) = mpsc::channel(1);
    state.kill_tx = kill_tx;
    let worker = test_worker(VaultSession::Locked, &state);
    let (mut delayed, server) = tcp_pair().await;
    let task = tokio::spawn(handle_connection(server, state.clone(), worker.clone()));
    delayed.write_all(SECURE_PREFACE).await.unwrap();
    let mut hello = [0; SECURE_HELLO_LEN];
    delayed.read_exact(&mut hello).await.unwrap();
    let keys = verify_server_hello(&state.token, &hello).unwrap();
    let result = worker
        .execute(state.clone(), RequestEnvelope::new(ServerCommand::Kill))
        .await;
    assert!(matches!(result.effect, CommandEffect::StopServer));
    let directory = tempfile::tempdir().unwrap();
    let key_path = directory.path().join("must-not-create.key");
    let request = RequestEnvelope::new(ServerCommand::New(PasswordType::Key(
        key_path.display().to_string(),
    )));
    let bytes = rmp_serde::to_vec_named(&request).unwrap();
    delayed
        .write_all(&encrypt_record(&keys.request, &bytes).unwrap())
        .await
        .unwrap();
    let mut encrypted = vec![];
    delayed.read_to_end(&mut encrypted).await.unwrap();
    let plaintext = decrypt_record_stream(&keys.response, &encrypted, 4096).unwrap();
    assert_eq!(
        decode_responses(&plaintext).unwrap().code,
        ResponseCode::Failure as i32
    );
    assert!(!key_path.exists());
    assert!(kill_rx.try_recv().is_err());
    task.await.unwrap();
}

#[test]
fn mutation_responses_preserve_precommit_and_committed_durability_states() {
    init_test_data_dir();
    let filename = format!("{}.enc", hex::encode(rand::random::<[u8; 16]>()));
    let path = data_dir().join(&filename);
    let vault = Vault::from_entries(
        vec![VaultEntry {
            id: 1,
            name: "Account".into(),
            password: "before".into(),
            ..Default::default()
        }],
        Some(filename),
    );
    let mut session = session(vault);
    let state = test_connection_state();
    for (fault, code, expected) in [
        (1, ResponseCode::Failure, "before"),
        (2, ResponseCode::Durability, "after"),
    ] {
        let command = ServerCommand::Update(TypedUpdate {
            entry: EntryUpdate {
                target: Target::Id(1),
                update: EntryChanges::default(),
                password: Some("after".into()),
            },
            kind: None,
            add_url: vec![],
            remove_url: vec![],
            clear_urls: false,
            set_fields: vec![],
            remove_fields: vec![],
            clear_fields: false,
        });
        let outcome = crate::vault::with_write_fault(fault, || {
            execute_command(state.clone(), command, &mut session)
        });
        assert_eq!(outcome.responses[0].code, code as i32);
        assert_eq!(
            session
                .vault()
                .unwrap()
                .get_secret(&Target::Id(1))
                .unwrap()
                .as_str(),
            expected
        );
        assert_eq!(path.exists(), fault == 2);
    }
    // The final committed key remains usable for a subsequent durable mutation.
    let result = execute_command(
        state,
        ServerCommand::Update(TypedUpdate {
            entry: EntryUpdate {
                target: Target::Id(1),
                update: EntryChanges {
                    name: Some("Updated".into()),
                    ..Default::default()
                },
                password: None,
            },
            kind: None,
            add_url: vec![],
            remove_url: vec![],
            clear_urls: false,
            set_fields: vec![],
            remove_fields: vec![],
            clear_fields: false,
        }),
        &mut session,
    );
    assert_eq!(result.responses[0].code, 0);
    fs::remove_file(path).unwrap();
}

#[test]
fn typed_authenticators_preserve_hotp_consumption_and_totp_read_semantics() {
    let mut vault = sample_vault();
    vault.set_test_totp(
        1,
        "otpauth://hotp/Example?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0",
    );
    let mut live = session(vault);
    let state = test_connection_state();
    let before = live.vault().unwrap().vault_revision();
    let rejected = execute_command(
        state.clone(),
        ServerCommand::Totp(TotpCommand::Watch {
            target: Target::Id(1),
            copy_timeout: None,
        }),
        &mut live,
    );
    assert_ne!(rejected.responses[0].code, 0);
    assert_eq!(live.vault().unwrap().vault_revision(), before);
    for (counter, code) in [(0, "755224"), (1, "287082")] {
        let result = execute_command(
            state.clone(),
            ServerCommand::AuthenticatorData(Target::Id(1)),
            &mut live,
        );
        let ResponsePayload::Authenticator(data) = &result.responses[0].payload else {
            panic!("expected structured code")
        };
        assert!(data.valid());
        assert_eq!(data.code, code);
        assert_eq!(data.counter, Some(counter));
        assert_eq!(data.expires_in, None);
    }
    let configured = execute_command(
        state.clone(),
        ServerCommand::Totp(TotpCommand::Set {
            target: Target::Id(1),
            configuration: "otpauth://totp/Example?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
        }),
        &mut live,
    );
    assert_eq!(configured.responses[0].code, 0);
    let before = live.vault().unwrap().vault_revision();
    let result = execute_command(
        state,
        ServerCommand::Totp(TotpCommand::Watch {
            target: Target::Id(1),
            copy_timeout: None,
        }),
        &mut live,
    );
    let ResponsePayload::Authenticator(data) = &result.responses[0].payload else {
        panic!("expected structured code")
    };
    assert!(data.valid());
    assert_eq!(data.mode, "totp");
    assert!(data.expires_in.unwrap() <= 30);
    assert_eq!(live.vault().unwrap().vault_revision(), before);
}

#[tokio::test]
async fn browser_reads_require_unlock_and_site_selection() {
    for (command, locked, code, secret) in [
        (
            ServerCommand::BrowserLogins("https://example.com".into()),
            false,
            ResponseCode::Success,
            false,
        ),
        (
            ServerCommand::BrowserLogin {
                domain: "https://example.com".into(),
                id: 1,
            },
            false,
            ResponseCode::Success,
            true,
        ),
        (
            ServerCommand::BrowserLogin {
                domain: "https://attacker.example".into(),
                id: 1,
            },
            false,
            ResponseCode::NotFound,
            false,
        ),
        (
            ServerCommand::BrowserLogin {
                domain: "https://example.com".into(),
                id: 1,
            },
            true,
            ResponseCode::Conflict,
            false,
        ),
        (
            ServerCommand::BrowserLogins("https://example.com".into()),
            true,
            ResponseCode::Failure,
            false,
        ),
        (
            ServerCommand::BrowserDuoItems("https://api-test.duosecurity.com".into()),
            true,
            ResponseCode::Failure,
            false,
        ),
    ] {
        let response = dispatch(sample_vault(), command, locked).await;
        assert_eq!(response.code, code as i32);
        assert_eq!(
            response_text(&response).contains("synthetic-secret"),
            secret
        );
    }
}

#[tokio::test]
async fn custom_fields_are_redacted_or_explicitly_revealed() {
    for (command, locked, code, visible) in [
        (
            ServerCommand::Get {
                target: Target::Id(1),
                copy_timeout: 0,
                reveal_secrets: false,
            },
            false,
            ResponseCode::Success,
            false,
        ),
        (
            ServerCommand::Get {
                target: Target::Id(1),
                copy_timeout: 0,
                reveal_secrets: true,
            },
            false,
            ResponseCode::Success,
            true,
        ),
        (
            ServerCommand::GetField {
                target: Target::Id(1),
                name: "RECOVERY-CODE".into(),
                copy_timeout: None,
            },
            false,
            ResponseCode::Success,
            true,
        ),
        (
            ServerCommand::GetField {
                target: Target::Id(1),
                name: "missing".into(),
                copy_timeout: None,
            },
            false,
            ResponseCode::NotFound,
            false,
        ),
        (
            ServerCommand::GetField {
                target: Target::Id(1),
                name: "recovery-code".into(),
                copy_timeout: Some(0),
            },
            false,
            ResponseCode::InvalidInput,
            false,
        ),
        (
            ServerCommand::Get {
                target: Target::Id(1),
                copy_timeout: 0,
                reveal_secrets: true,
            },
            true,
            ResponseCode::Failure,
            false,
        ),
    ] {
        let mut vault = sample_vault();
        vault.set_test_metadata(
            1,
            ItemKind::Login,
            vec![],
            vec![CustomField {
                name: "recovery-code".into(),
                value: "synthetic-field-secret".into(),
                secret: true,
            }],
        );
        let response = dispatch(vault, command, locked).await;
        assert_eq!(response.code, code as i32);
        assert_eq!(
            response_text(&response).contains("synthetic-field-secret"),
            visible
        );
    }
}

#[tokio::test]
async fn status_and_error_classification_are_typed_and_correlated() {
    let state = test_connection_state();
    *state.background_error.lock().await = Some("cleanup warning".into());
    let worker = test_worker(VaultSession::Locked, &state);
    let (mut client, server) = tcp_pair().await;
    let task = tokio::spawn(handle_connection(server, state.clone(), worker));
    let request = RequestEnvelope::new(ServerCommand::Status);
    let id = request.request_id.clone();
    let response = send(&mut client, &state.token, request).await;
    assert_eq!(response.request_id, Some(id));
    let ResponsePayload::Status(status) = response.payload else {
        panic!("expected status")
    };
    assert!(status.locked);
    assert_eq!(status.warning.as_deref(), Some("cleanup warning"));
    task.await.unwrap();
    let (mut client, mut server) = tcp_pair().await;
    let response_key = [42; 32];
    deliver_responses(
        vec![RpcResponse::message(
            ResponseCode::NotFound,
            "wording without classification keywords",
        )],
        &mut server,
        &response_key,
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();
    let mut bytes = vec![];
    client.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(
        decode_responses(&decrypt_record_stream(&response_key, &bytes, 4096).unwrap())
            .unwrap()
            .code,
        ResponseCode::NotFound as i32
    );
}

#[tokio::test]
async fn mutation_ids_deduplicate_and_conflicting_arguments_fail() {
    let state = test_connection_state();
    let mut vault = sample_vault();
    vault.set_test_totp(
        1,
        "otpauth://hotp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0",
    );
    let worker = test_worker(session(vault), &state);
    let request = || {
        RequestEnvelope::new(ServerCommand::AuthenticatorData(Target::Id(1)))
            .with_operation(Some("same-operation".into()), None)
    };
    let first = worker.execute(state.clone(), request()).await;
    assert_eq!(
        first.responses[0].operation.as_ref().unwrap().state,
        OperationState::Committed
    );
    let repeated = worker.execute(state.clone(), request()).await;
    assert_eq!(repeated.responses[0].code, 0);
    for response in [&first.responses[0], &repeated.responses[0]] {
        let ResponsePayload::Authenticator(code) = &response.payload else {
            panic!("expected exact authenticator response")
        };
        assert_eq!(code.counter, Some(0));
        assert_eq!(code.code, "755224");
    }
    let next = worker
        .execute(
            state.clone(),
            RequestEnvelope::new(ServerCommand::AuthenticatorData(Target::Id(1))),
        )
        .await;
    let ResponsePayload::Authenticator(code) = &next.responses[0].payload else {
        panic!("expected next code")
    };
    assert_eq!(
        code.counter,
        Some(1),
        "replaying an operation must not consume another counter"
    );
    let conflicting = RequestEnvelope::new(ServerCommand::AuthenticatorData(Target::Id(2)))
        .with_operation(Some("same-operation".into()), None);
    assert_eq!(
        worker.execute(state.clone(), conflicting).await.responses[0].code,
        ResponseCode::Conflict as i32
    );
    let result = worker
        .execute(
            state,
            RequestEnvelope::new(ServerCommand::OperationStatus("same-operation".into())),
        )
        .await;
    let ResponsePayload::Operation(receipt) = &result.responses[0].payload else {
        panic!("expected receipt")
    };
    assert_eq!(receipt.state, OperationState::Committed);
}

#[tokio::test]
async fn expected_revisions_prevent_overlapping_editor_writes() {
    let state = test_connection_state();
    let vault = sample_vault();
    let revision = vault.revision(1).unwrap();
    let worker = test_worker(session(vault), &state);
    let update = |name: &str| {
        ServerCommand::Update(TypedUpdate {
            entry: EntryUpdate {
                target: Target::Id(1),
                update: EntryChanges {
                    name: Some(name.into()),
                    ..Default::default()
                },
                password: None,
            },
            kind: None,
            add_url: vec![],
            remove_url: vec![],
            clear_urls: false,
            set_fields: vec![],
            remove_fields: vec![],
            clear_fields: false,
        })
    };
    let first = RequestEnvelope::new(update("First"))
        .with_operation(Some("editor-one".into()), Some(revision));
    assert_eq!(
        worker.execute(state.clone(), first).await.responses[0].code,
        0
    );
    let second = RequestEnvelope::new(update("Second"))
        .with_operation(Some("editor-two".into()), Some(revision));
    assert_eq!(
        worker.execute(state.clone(), second).await.responses[0].code,
        ResponseCode::Conflict as i32
    );
    let rejected = worker
        .execute(
            state,
            RequestEnvelope::new(ServerCommand::OperationStatus("editor-two".into())),
        )
        .await;
    let ResponsePayload::Operation(receipt) = &rejected.responses[0].payload else {
        panic!("expected rejected operation receipt")
    };
    assert_eq!(receipt.state, OperationState::Failed);
    assert_eq!(
        worker
            .with_session(|s| s.vault().unwrap().management_item(1, false).unwrap().name)
            .await
            .unwrap(),
        "First"
    );
}

#[tokio::test]
async fn operation_outcomes_are_explicitly_unknown_after_worker_restart() {
    let state = test_connection_state();
    let worker = test_worker(VaultSession::Locked, &state);
    let result = worker
        .execute(
            state,
            RequestEnvelope::new(ServerCommand::OperationStatus(
                "previous-daemon-operation".into(),
            )),
        )
        .await;
    let ResponsePayload::Operation(receipt) = &result.responses[0].payload else {
        panic!("expected receipt")
    };
    assert_eq!(receipt.state, OperationState::Unknown);
}

#[tokio::test]
async fn os_lock_discards_session_and_inactivity_does_not_need_a_writable_store() {
    let state = test_connection_state();
    let worker = test_worker(session(sample_vault()), &state);
    let callback = worker.system_lock_handler(Arc::clone(&state.background_error));
    tokio::task::spawn_blocking(move || callback())
        .await
        .unwrap();
    // An item-lane barrier proves the earlier control message finished.
    assert!(worker.with_session(|s| s.is_locked()).await.unwrap());
    assert!(worker.is_locked());
    let vault = Vault::from_entries(
        vec![VaultEntry {
            id: 1,
            password: "synthetic".into(),
            ..Default::default()
        }],
        Some("missing-dir/vault.enc".into()),
    );
    let mut live = session(vault);
    lock_session(&mut live).unwrap();
    assert!(live.is_locked());
}
#[test]
fn test_server_info_zeroize_restores_locked_defaults() {
    let defaults = ServerInfo::default();
    assert!(defaults.locked);
    assert!(defaults.keypass.is_none());
    for credential in [
        PasswordType::Password("secret".into()),
        PasswordType::Key("key.pem".into()),
    ] {
        let mut info = ServerInfo {
            locked: false,
            keypass: Some(credential),
        };
        info.zeroize();
        assert!(info.locked);
        assert!(info.keypass.is_none());
    }
}

#[test]
fn test_password_type_zeroize_password_and_key() {
    for mut credential in [
        PasswordType::Password("secret_password".into()),
        PasswordType::Key("secret_key.pem".into()),
    ] {
        let original_variant = std::mem::discriminant(&credential);
        credential.zeroize();
        assert_eq!(std::mem::discriminant(&credential), original_variant);
        match &credential {
            PasswordType::Password(value) | PasswordType::Key(value) => assert!(value.is_empty()),
            _ => panic!("credential variant changed during zeroization"),
        }
    }
}

#[test]
fn default_address_uses_the_loopback_interface() {
    assert_eq!(server_addr(DEFAULT_PORT).to_string(), "127.0.0.1:7878");
}

#[test]
fn session_token_rotation_replaces_old_tokens_and_cleanup_is_generation_safe() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(TOKEN_FILE);
    let mut first = rotate_token_file(&path).unwrap();
    let mut second = rotate_token_file(&path).unwrap();
    for token in [&first, &second] {
        assert_eq!(token.len(), TOKEN_HEX_LEN);
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    assert_ne!(first, second);
    assert_eq!(fs::read_to_string(&path).unwrap(), *second);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    remove_token_file_if_current(&path, &first);
    assert!(path.exists());
    remove_token_file_if_current(&path, &second);
    assert!(!path.exists());
    first.zeroize();
    second.zeroize();
}

#[tokio::test]
async fn authenticated_tcp_protocol_decodes_complete_and_fragmented_commands() {
    for fragmented in [false, true] {
        let token = "a".repeat(TOKEN_HEX_LEN);
        let (mut client, mut server) = tcp_pair().await;
        let server_token = token.clone();
        let task = tokio::spawn(async move { handler(&mut server, &server_token).await });
        if fragmented {
            // A valid but incomplete preface must remain pending, not be rejected.
            client.write_all(&SECURE_PREFACE[..1]).await.unwrap();
            let mut byte = [0u8; 1];
            assert!(
                tokio::time::timeout(Duration::from_millis(20), client.read_exact(&mut byte))
                    .await
                    .is_err(),
                "incomplete preface was rejected"
            );
            for byte in &SECURE_PREFACE[1..] {
                client.write_all(&[*byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        } else {
            client.write_all(SECURE_PREFACE).await.unwrap();
        }
        let mut hello = [0u8; SECURE_HELLO_LEN];
        client.read_exact(&mut hello).await.unwrap();
        let keys = verify_server_hello(&token, &hello).unwrap();
        let command = ServerCommand::Status;
        let encoded = rmp_serde::to_vec_named(&RequestEnvelope::new(command)).unwrap();
        let request = encrypt_record(&keys.request, &encoded).unwrap();
        let chunk_size = if fragmented { 3 } else { request.len() };
        for chunk in request.chunks(chunk_size) {
            client.write_all(chunk).await.unwrap();
            tokio::task::yield_now().await;
        }
        let parsed = task.await.unwrap();
        assert!(
            matches!(
                parsed,
                Some(AuthenticatedRequest {
                    request: RequestEnvelope {
                        command: ServerCommand::Status,
                        ..
                    },
                    ..
                })
            ),
            "command was not decoded; fragmented={fragmented}"
        );
    }
}

#[tokio::test]
async fn tcp_protocol_authenticates_before_commands_and_rejects_invalid_messages() {
    let token = "a".repeat(TOKEN_HEX_LEN);
    for (label, preface) in [
        ("invalid version", b"PMS1".as_slice()),
        ("truncated", b"PMS".as_slice()),
        ("empty", b"".as_slice()),
    ] {
        let (mut client, mut server) = tcp_pair().await;
        client.write_all(preface).await.unwrap();
        client.shutdown().await.unwrap();
        assert!(
            handler(&mut server, &token).await.is_none(),
            "{label} preface was accepted"
        );
    }
    let (mut client, mut server) = tcp_pair().await;
    let server_token = token.clone();
    let task = tokio::spawn(async move { handler(&mut server, &server_token).await });
    client.write_all(SECURE_PREFACE).await.unwrap();
    let mut hello = [0u8; SECURE_HELLO_LEN];
    client.read_exact(&mut hello).await.unwrap();
    assert!(verify_server_hello(&"b".repeat(TOKEN_HEX_LEN), &hello).is_none());
    client.shutdown().await.unwrap();
    assert!(task.await.unwrap().is_none());

    for (label, length, memory_kib) in [
        ("oversized record", MAX_TCP_MSG + 17, REQUEST_MEMORY_KIB),
        ("exhausted memory budget", MAX_TCP_MSG + 16, 1),
    ] {
        let (mut client, mut server) = tcp_pair().await;
        let server_token = token.clone();
        let task = tokio::spawn(async move {
            let budget = Semaphore::new(memory_kib);
            let command = handle_tcp_with_budget(&mut server, &server_token, &budget).await;
            assert_eq!(budget.available_permits(), memory_kib);
            command
        });
        client.write_all(SECURE_PREFACE).await.unwrap();
        client.read_exact(&mut hello).await.unwrap();
        let mut header = [0; SECURE_RECORD_HEADER_LEN];
        header[24..].copy_from_slice(&(length as u32).to_be_bytes());
        client.write_all(&header).await.unwrap();
        // Send no body: both limits must reject the header immediately.
        assert!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .is_none(),
            "{label} was accepted"
        );
    }

    let (mut client, mut server) = tcp_pair().await;
    let server_token = token.clone();
    let task = tokio::spawn(async move { handler(&mut server, &server_token).await });
    client.write_all(SECURE_PREFACE).await.unwrap();
    client.read_exact(&mut hello).await.unwrap();
    let keys = verify_server_hello(&token, &hello).unwrap();
    let mut command =
        rmp_serde::to_vec_named(&RequestEnvelope::new(ServerCommand::Status)).unwrap();
    command.push(0);
    let request = encrypt_record(&keys.request, &command).unwrap();
    client.write_all(&request).await.unwrap();
    assert!(task.await.unwrap().is_none());
}

#[test]
fn request_memory_budget_accounts_for_buffers_and_releases_reservations() {
    let budget = Semaphore::new(4);
    let permit = reserve_request_memory(&budget, 1024).unwrap();
    assert_eq!(budget.available_permits(), 2);
    assert!(reserve_request_memory(&budget, 1025).is_none());
    assert!(reserve_request_memory(&budget, usize::MAX).is_none());
    drop(permit);
    assert_eq!(budget.available_permits(), 4);
    let permit = reserve_request_memory(&budget, 2048).unwrap();
    assert_eq!(budget.available_permits(), 0);
    drop(permit);
    assert_eq!(budget.available_permits(), 4);
}

#[tokio::test]
async fn asynchronous_audit_reply_keeps_the_unlocked_session_over_encrypted_tcp() {
    let state = test_connection_state();
    let worker = test_worker(session(sample_vault()), &state);
    let expected_session = worker.session_id();
    assert!(expected_session.is_some());
    let (mut client, server) = tcp_pair().await;
    let mut request = RequestEnvelope::new(ServerCommand::Audit(Default::default()));
    request.expected_session = expected_session.clone();
    let task = tokio::spawn(handle_connection(server, state.clone(), worker));
    let response = send(&mut client, &state.token, request).await;
    task.await.unwrap();
    assert_eq!(response.code, ResponseCode::Success as i32);
    assert!(matches!(response.payload, ResponsePayload::Audit(_)));
    assert_eq!(response.session_id, expected_session);
}

#[tokio::test]
async fn duo_poll_preserves_session_through_async_completion_and_encrypted_delivery() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let http = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        let body = serde_json::to_vec(&serde_json::json!({
            "stat": "OK", "response": { "transactions": [{
                "urgid": "synthetic-request", "type": "Login",
                "expiration": chrono::Utc::now().timestamp() + 120,
                "step_up_code_info": { "num_digits": 3 }
            }] }
        }))
        .unwrap();
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(&body).await.unwrap();
    });
    let private = crate::duo::crypto::new_key().unwrap();
    let mut vault = sample_vault();
    vault.set_test_duo(
        1,
        DuoCredentials {
            host: "api-test.duosecurity.com".into(),
            akey: "synthetic".into(),
            pkey: "synthetic".into(),
            private_key: crate::duo::crypto::private_pem(&private)
                .unwrap()
                .to_string()
                .into(),
        },
    );
    let state = test_connection_state();
    let worker = test_worker(session(vault), &state);
    let expected_session = worker.session_id();
    assert!(expected_session.is_some());
    let mut request = RequestEnvelope::new(ServerCommand::Duo(DuoCommand::Requests {
        target: Target::Id(1),
    }));
    request.expected_session = expected_session.clone();
    let mut result = worker.execute(state, request).await;
    let CommandEffect::Duo(prepared) = &mut result.effect else {
        panic!("Duo polling must defer its network response");
    };
    assert!(result.responses.is_empty());
    // Replace only the remote transport. Session capture, parsing, completion,
    // response encryption, and decoding use the production path.
    prepared.request = crate::duo::PreparedRequest::mock_get(&format!("http://{address}/requests"));
    let result = finish_external_effect(result, worker, None).await;
    http.await.unwrap();
    let (mut client, mut server) = tcp_pair().await;
    let response_key = [17; 32];
    let delivery = tokio::spawn(async move {
        deliver_responses(result.responses, &mut server, &response_key)
            .await
            .unwrap();
    });
    let mut encrypted = vec![];
    client.read_to_end(&mut encrypted).await.unwrap();
    delivery.await.unwrap();
    let plaintext =
        Zeroizing::new(decrypt_record_stream(&response_key, &encrypted, 1024 * 1024).unwrap());
    let response = decode_responses(&plaintext).unwrap();
    assert_eq!(response.code, ResponseCode::Success as i32);
    assert_eq!(response.session_id, expected_session);
    let ResponsePayload::DuoRequests(requests) = response.payload else {
        panic!("expected pending Duo request");
    };
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].id, "synthetic-request");
    assert!(!requests[0].fingerprint.is_empty());
}

#[tokio::test]
async fn asynchronous_results_cannot_survive_a_lock_or_be_relabelled_with_a_new_session() {
    for unlock_again in [false, true] {
        let state = test_connection_state();
        let worker = test_worker(session(sample_vault()), &state);
        let original_session = worker.session_id();
        let result = worker
            .execute(
                state,
                RequestEnvelope::new(ServerCommand::Audit(Default::default())),
            )
            .await;
        assert!(matches!(result.effect, CommandEffect::Audit(..)));
        worker
            .with_session(move |live| {
                live.lock();
                if unlock_again {
                    *live = session(sample_vault());
                }
            })
            .await
            .unwrap();
        assert_ne!(worker.session_id(), original_session);
        let result = finish_external_effect(result, worker, None).await;
        assert_eq!(result.responses.len(), 1);
        assert_eq!(result.responses[0].code, ResponseCode::Conflict as i32);
        assert!(matches!(
            result.responses[0].payload,
            ResponsePayload::Message(_)
        ));
        assert_eq!(result.responses[0].session_id, original_session);
    }
}

#[tokio::test]
async fn slow_duo_network_job_allows_lock_and_cannot_return_stale_review() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = tokio::sync::oneshot::channel();
    let http = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        started.send(()).unwrap();
        wait.await.unwrap();
        let body = br#"{"stat":"OK","response":{"transactions":[]}}"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(body).await.unwrap();
    });
    let private = crate::duo::crypto::new_key().unwrap();
    let mut vault = sample_vault();
    vault.set_test_duo(
        1,
        DuoCredentials {
            host: "api-test.duosecurity.com".into(),
            akey: "synthetic".into(),
            pkey: "synthetic".into(),
            private_key: crate::duo::crypto::private_pem(&private)
                .unwrap()
                .to_string()
                .into(),
        },
    );
    let state = test_connection_state();
    let worker = test_worker(session(vault), &state);
    let mut prepared = worker
        .with_session(|session| {
            let mut edit = session.edit();
            let (key, vault) = edit.parts_mut();
            crate::vault::available(vault).unwrap().prepare_duo_poll(
                DuoCommand::Requests {
                    target: Target::Id(1),
                },
                key,
            )
        })
        .await
        .unwrap()
        .unwrap();
    prepared.request = crate::duo::PreparedRequest::mock_get(&format!("http://{address}/requests"));
    let handle = worker.clone();
    let pending = tokio::spawn(async move {
        let mut responses = vec![];
        finish_duo(prepared, handle, &mut responses).await;
        responses
    });
    tokio::time::timeout(Duration::from_secs(2), ready)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_millis(250), worker.lock())
        .await
        .expect("network I/O must not prevent vault locking");
    assert!(worker.is_locked());
    release.send(()).unwrap();
    let responses = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(responses[0].code, ResponseCode::Failure as i32);
    assert!(responses[0].error_message().contains("locked"));
    http.await.unwrap();
}

#[tokio::test]
async fn published_status_remains_responsive_while_owner_is_busy() {
    let state = test_connection_state();
    let worker = test_worker(session(sample_vault()), &state);
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let handle = worker.clone();
    let busy = tokio::spawn(async move {
        handle
            .with_session(move |_| {
                started.send(()).unwrap();
                wait.recv().unwrap();
            })
            .await
    });
    ready.await.unwrap();
    let (mut client, server) = tcp_pair().await;
    let connection = tokio::spawn(handle_connection(server, state.clone(), worker));
    let response = tokio::time::timeout(
        Duration::from_millis(250),
        send(
            &mut client,
            &state.token,
            RequestEnvelope::new(ServerCommand::Status),
        ),
    )
    .await
    .expect("status must use nonsecret published state");
    let ResponsePayload::Status(status) = response.payload else {
        panic!("expected status")
    };
    assert!(!status.locked);
    release.send(()).unwrap();
    busy.await.unwrap().unwrap();
    connection.await.unwrap();
}

#[tokio::test]
async fn browser_selections_reject_stale_sessions_revisions_and_unmatched_otp_origins() {
    let state = test_connection_state();
    let mut vault = sample_vault();
    vault.set_test_totp(
        1,
        "otpauth://hotp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0",
    );
    let original = vault.clone();
    let worker = test_worker(session(vault), &state);
    let lookup = worker
        .execute(
            state.clone(),
            RequestEnvelope::new(ServerCommand::BrowserLogins("https://example.com".into())),
        )
        .await;
    let session_id = lookup.responses[0].session_id.clone().unwrap();
    let ResponsePayload::Summaries(items) = &lookup.responses[0].payload else {
        panic!("expected summaries")
    };
    let revision = items[0].revision;
    let scoped = |command| {
        let mut request = RequestEnvelope::new(command);
        request.expected_revision = Some(revision);
        request.expected_session = Some(session_id.clone());
        request
    };
    let login = || ServerCommand::BrowserLogin {
        domain: "https://example.com".into(),
        id: 1,
    };
    let otp = |domain: &str| ServerCommand::BrowserAuthenticatorData {
        domain: domain.into(),
        id: 1,
    };
    for command in [
        login(),
        otp("https://example.com"),
        ServerCommand::BrowserAutofillItem(1),
    ] {
        let invalid = worker
            .execute(state.clone(), RequestEnvelope::new(command))
            .await;
        assert_eq!(invalid.responses[0].code, ResponseCode::InvalidInput as i32);
    }
    assert_eq!(
        worker
            .execute(state.clone(), scoped(login()))
            .await
            .responses[0]
            .code,
        0
    );
    let denied = worker
        .execute(state.clone(), scoped(otp("https://attacker.example")))
        .await;
    assert_eq!(denied.responses[0].code, ResponseCode::NotFound as i32);
    let allowed = worker
        .execute(state.clone(), scoped(otp("https://example.com")))
        .await;
    let ResponsePayload::Authenticator(code) = &allowed.responses[0].payload else {
        panic!("expected OTP")
    };
    assert_eq!(
        code.counter,
        Some(0),
        "rejected origins must not consume HOTP"
    );
    // HOTP changes the item revision; old non-mutating reads must also fail.
    assert_eq!(
        worker
            .execute(state.clone(), scoped(login()))
            .await
            .responses[0]
            .code,
        ResponseCode::Conflict as i32
    );
    worker.lock().await;
    for replacement in [original, sample_vault()] {
        worker
            .with_session(move |live| *live = session(replacement))
            .await
            .unwrap();
        assert_ne!(worker.session_id().as_deref(), Some(session_id.as_str()));
        for command in [
            login(),
            otp("https://example.com"),
            ServerCommand::BrowserAutofillItem(1),
        ] {
            assert_eq!(
                worker
                    .execute(state.clone(), scoped(command))
                    .await
                    .responses[0]
                    .code,
                ResponseCode::Conflict as i32
            );
        }
        let mut write = RequestEnvelope::new(ServerCommand::Delete(Target::Id(1)));
        write.expected_session = Some(session_id.clone());
        assert_eq!(
            worker.execute(state.clone(), write).await.responses[0].code,
            ResponseCode::Conflict as i32
        );
        assert!(
            worker
                .with_session(|live| live.vault().unwrap().revision(1).is_some())
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn automatic_browser_lookups_do_not_extend_inactivity() {
    let state = test_connection_state();
    state.inactivity_timeout.store(1, Ordering::Release);
    let worker = test_worker(session(sample_vault()), &state);
    worker
        .execute(
            state.clone(),
            RequestEnvelope::new(ServerCommand::GetSecret(Target::Id(1))),
        )
        .await;
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(350)).await;
        for command in [
            ServerCommand::BrowserLogins("https://attacker.example".into()),
            ServerCommand::BrowserAutofill,
            ServerCommand::BrowserDuoItems("https://api-test.duosecurity.com".into()),
        ] {
            assert!(!command.extends_unlock());
            worker
                .execute(state.clone(), RequestEnvelope::new(command))
                .await;
        }
    }
    assert!(
        worker.is_locked(),
        "background detections must not keep an idle vault unlocked"
    );
}
