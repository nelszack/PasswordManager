use super::*;
use crate::file::init_test_data_dir;
use crate::vault::RecoveryData;
use crate::vault::{Vault, VaultEntry, VaultMetadata};

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

async fn dispatch_test_command(
    vault: Vault,
    command: ServerCommand,
    locked: bool,
) -> crate::protocol::ProtocolResponse {
    let token = "ab".repeat(32);
    let (mut client, server) = tcp_pair().await;
    let (kill_tx, _kill_rx) = mpsc::channel(1);
    let state = ConnectionState {
        server_info: Arc::new(Mutex::new(ServerInfo {
            locked,
            keypass: None,
        })),
        vlt: Arc::new(Mutex::new(Some(vault))),
        kill_tx,
        token: token.clone(),
        lock_generation: Arc::new(AtomicU64::new(0)),
        inactivity_timeout: Arc::new(AtomicU64::new(0)),
        background_error: Arc::new(Mutex::new(None)),
        password_history_limit: 10,
        trash_retention_days: 0,
    };
    let task = tokio::spawn(handle_connection(server, state));
    client.write_all(SECURE_PREFACE).await.unwrap();
    let mut hello = [0; SECURE_HELLO_LEN];
    client.read_exact(&mut hello).await.unwrap();
    let keys = verify_server_hello(&token, &hello).unwrap();
    let encoded = rmp_serde::to_vec(&command).unwrap();
    client
        .write_all(&encrypt_record(&keys.request, &encoded).unwrap())
        .await
        .unwrap();
    let mut ciphertext = Vec::new();
    client.read_to_end(&mut ciphertext).await.unwrap();
    let plaintext = decrypt_record_stream(&keys.response, &ciphertext, 1024 * 1024).unwrap();
    let response = decode_responses(&plaintext).unwrap();
    task.await.unwrap();
    response
}

#[tokio::test]
async fn vault_commands_leave_the_single_thread_runtime_responsive() {
    let token = "ab".repeat(32);
    let info = Arc::new(Mutex::new(ServerInfo {
        locked: false,
        keypass: None,
    }));
    let vault = Vault {
        entries: (1..=256)
            .map(|id| VaultEntry {
                id,
                name: format!("Synthetic account {id}"),
                password: "Synthetic-Password-9274!".into(),
                ..VaultEntry::default()
            })
            .collect(),
        metadata: VaultMetadata::default(),
        recovery: RecoveryData::default(),
    };
    let (kill_tx, _kill_rx) = mpsc::channel(1);
    let state = ConnectionState {
        server_info: Arc::clone(&info),
        vlt: Arc::new(Mutex::new(Some(vault))),
        kill_tx,
        token: token.clone(),
        lock_generation: Arc::new(AtomicU64::new(0)),
        inactivity_timeout: Arc::new(AtomicU64::new(0)),
        background_error: Arc::new(Mutex::new(None)),
        password_history_limit: 10,
        trash_retention_days: 0,
    };
    let (mut client, server) = tcp_pair().await;
    let task = tokio::spawn(handle_connection(server, state));
    client.write_all(SECURE_PREFACE).await.unwrap();
    let mut hello = [0u8; SECURE_HELLO_LEN];
    client.read_exact(&mut hello).await.unwrap();
    let keys = verify_server_hello(&token, &hello).unwrap();
    let command = rmp_serde::to_vec(&ServerCommand::Audit(AuditOptions::default())).unwrap();
    client
        .write_all(&encrypt_record(&keys.request, &command).unwrap())
        .await
        .unwrap();
    // Observe an actual CPU-intensive audit owning the vault while this test's
    // future still runs. Synchronous dispatch on the sole Tokio thread cannot
    // reach this point until the audit has finished and released its locks.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if info.try_lock().is_err() {
                break;
            }
            assert!(
                !task.is_finished(),
                "audit blocked the runtime until it finished"
            );
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    let mut ciphertext = Vec::new();
    client.read_to_end(&mut ciphertext).await.unwrap();
    let plaintext = decrypt_record_stream(&keys.response, &ciphertext, 1024 * 1024).unwrap();
    assert_eq!(
        decode_responses(&plaintext).unwrap().code,
        ResponseCode::Success as i32
    );
    task.await.unwrap();
}

#[tokio::test]
async fn auto_lock_clears_secrets_even_when_the_vault_cannot_be_written() {
    init_test_data_dir();
    let directory = tempfile::tempdir_in(data_dir()).unwrap();
    let filename = directory
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    // The destination is a directory, so the old save-before-lock path would fail.
    let vault = Arc::new(Mutex::new(Some(Vault {
        entries: vec![VaultEntry {
            id: 1,
            password: "synthetic-secret".into(),
            ..VaultEntry::default()
        }],
        metadata: VaultMetadata { filename },
        recovery: RecoveryData::default(),
    })));
    let info = Arc::new(Mutex::new(ServerInfo {
        locked: false,
        keypass: Some(PasswordType::Password("synthetic-master-password".into())),
    }));
    let error = Arc::new(Mutex::new(None));
    schedule_auto_lock(
        1,
        1,
        Arc::new(AtomicU64::new(1)),
        Arc::clone(&info),
        Arc::clone(&vault),
        Arc::clone(&error),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert!(info.lock().await.locked);
    assert!(info.lock().await.keypass.is_none());
    assert!(vault.lock().await.is_none());
    assert!(error.lock().await.is_none());
    assert!(directory.path().is_dir());
}

#[test]
fn manual_lock_does_not_depend_on_a_writable_vault_destination() {
    let mut vault = Some(Vault {
        entries: vec![VaultEntry {
            password: "synthetic-secret".into(),
            ..VaultEntry::default()
        }],
        metadata: VaultMetadata {
            filename: "missing-directory/vault.enc".into(),
        },
        recovery: RecoveryData::default(),
    });
    let mut info = ServerInfo {
        locked: false,
        keypass: Some(PasswordType::Password("synthetic-master-password".into())),
    };
    lock_vlt(&mut vault, &mut info).unwrap();
    assert!(vault.is_none());
    assert!(info.locked);
    assert!(info.keypass.is_none());
}

#[test]
fn status_includes_persistent_background_warnings() {
    assert_eq!(
        status_message(true, None),
        format!("Status: Locked\nVersion: {}", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(
        status_message(false, Some("Automatic lock failed: disk full")),
        format!(
            "Status: Unlocked\nVersion: {}\nWarning: Automatic lock failed: disk full",
            env!("CARGO_PKG_VERSION")
        )
    );
}

#[tokio::test]
async fn auto_lock_completes_while_a_detached_breach_audit_is_slow() {
    init_test_data_dir();
    let vault = Vault {
        entries: vec![VaultEntry {
            id: 1,
            name: "slow audit".into(),
            password: "password".into(),
            ..VaultEntry::default()
        }],
        metadata: VaultMetadata {
            filename: "auto-lock-during-audit.vault".into(),
        },
        recovery: RecoveryData::default(),
    };
    let snapshot = vault.audit_snapshot(&AuditOptions {
        check_breaches: true,
        ..AuditOptions::default()
    });
    let server_info = Arc::new(Mutex::new(ServerInfo {
        locked: false,
        keypass: Some(PasswordType::Session {
            encryption_key: [7; 32],
            salt: [9; 16],
            kdf: 1,
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        }),
    }));
    let vault = Arc::new(Mutex::new(Some(vault)));
    let generation = Arc::new(AtomicU64::new(1));
    let background_error = Arc::new(Mutex::new(None));

    let slow_audit = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        drop(snapshot);
    });
    schedule_auto_lock(
        1,
        1,
        Arc::clone(&generation),
        Arc::clone(&server_info),
        Arc::clone(&vault),
        Arc::clone(&background_error),
    );

    tokio::time::sleep(Duration::from_millis(1_300)).await;
    assert!(server_info.lock().await.locked);
    assert!(vault.lock().await.is_none());
    assert!(background_error.lock().await.is_none());
    assert!(!slow_audit.is_finished());
    slow_audit.abort();
}

#[tokio::test]
async fn response_codes_are_explicit_and_independent_of_message_wording() {
    let (mut client, mut server) = tcp_pair().await;
    respond("Entry not found.", &mut server).await;
    server.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    client.read_to_end(&mut bytes).await.unwrap();
    let response = decode_responses(&bytes).unwrap();
    assert_eq!(response.code, ResponseCode::Success as i32);

    let (mut client, mut server) = tcp_pair().await;
    respond_with_code(
        ResponseCode::NotFound,
        "wording without classification keywords",
        &mut server,
    )
    .await;
    server.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    client.read_to_end(&mut bytes).await.unwrap();
    let response = decode_responses(&bytes).unwrap();
    assert_eq!(response.code, ResponseCode::NotFound as i32);
    assert_eq!(
        response.message,
        "wording without classification keywords\n"
    );
}

#[tokio::test]
async fn scoped_responses_are_buffered_until_state_work_finishes() {
    let (mut client, mut server) = tcp_pair().await;
    RESPONSE_BUFFER
        .scope(RefCell::new(Vec::new()), async {
            respond("buffered", &mut server).await;
            let mut byte = [0u8; 1];
            assert!(
                tokio::time::timeout(Duration::from_millis(20), client.read_exact(&mut byte))
                    .await
                    .is_err(),
                "a response was written before the critical section completed"
            );
            flush_buffered_responses(&mut server).await;
        })
        .await;
    server.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    client.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(decode_responses(&bytes).unwrap().message, "buffered\n");
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
fn test_vault_entries_zeroize() {
    let mut entry = VaultEntry {
        id: 42,
        name: "test".to_string(),
        username: Some("user".to_string()),
        password: "secret".to_string(),
        url: Some("https://example.com".to_string()),
        notes: Some("important".to_string()),
        created: "2024-01-01".to_string(),
        modified: "2024-01-01".to_string(),
    };
    entry.zeroize();
    assert_eq!(entry.id, 0);
    assert_eq!(entry.name, "");
    assert_eq!(entry.username, None);
    assert_eq!(entry.password, "");
    assert_eq!(entry.url, None);
    assert_eq!(entry.notes, None);
}

#[test]
fn test_vault_zeroize() {
    let mut vault = Vault {
        entries: vec![VaultEntry {
            id: 1,
            name: "test".to_string(),
            username: Some("user".to_string()),
            password: "secret".to_string(),
            url: None,
            notes: None,
            created: "2024-01-01".to_string(),
            modified: "2024-01-01".to_string(),
        }],
        metadata: VaultMetadata {
            filename: "test.enc".to_string(),
        },
        recovery: crate::vault::RecoveryData::default(),
    };
    vault.zeroize();
    assert!(vault.entries.is_empty());
    assert_eq!(vault.metadata.filename, "");
}

#[test]
fn default_address_uses_the_loopback_interface() {
    assert_eq!(server_addr(DEFAULT_PORT).to_string(), "127.0.0.1:7878");
}

#[test]
fn session_tokens_are_random_256_bit_hex_values() {
    let first = random_token();
    let second = random_token();
    assert_eq!(first.len(), TOKEN_HEX_LEN);
    assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_ne!(first, second);
}

#[test]
fn session_token_rotation_replaces_old_tokens_and_cleanup_is_generation_safe() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(TOKEN_FILE);
    let mut first = rotate_token_file(&path).unwrap();
    let mut second = rotate_token_file(&path).unwrap();
    assert_ne!(first, second);
    assert_eq!(fs::read_to_string(&path).unwrap(), second);

    remove_token_file_if_current(&path, &first);
    assert!(path.exists());
    remove_token_file_if_current(&path, &second);
    assert!(!path.exists());
    first.zeroize();
    second.zeroize();
}

#[cfg(unix)]
#[test]
fn session_token_files_have_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(TOKEN_FILE);
    write_token_file(&random_token(), &path).unwrap();
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[tokio::test]
async fn authenticated_tcp_protocol_decodes_complete_and_fragmented_commands() {
    for fragmented in [false, true] {
        let token = "a".repeat(TOKEN_HEX_LEN);
        let (mut client, mut server) = tcp_pair().await;
        let server_token = token.clone();
        let task = tokio::spawn(async move {
            TRANSPORT_RESPONSE_KEY
                .scope(RefCell::new(None), async {
                    let command = handler(&mut server, &server_token).await;
                    assert!(TRANSPORT_RESPONSE_KEY.with(|key| key.borrow().is_some()));
                    command
                })
                .await
        });
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
        let command = if fragmented {
            ServerCommand::StatusData
        } else {
            ServerCommand::Status
        };
        let encoded = rmp_serde::to_vec(&command).unwrap();
        let request = encrypt_record(&keys.request, &encoded).unwrap();
        let chunk_size = if fragmented { 3 } else { request.len() };
        for chunk in request.chunks(chunk_size) {
            client.write_all(chunk).await.unwrap();
            tokio::task::yield_now().await;
        }
        let parsed = task.await.unwrap();
        assert!(
            matches!(
                (fragmented, parsed),
                (false, Some(ServerCommand::Status)) | (true, Some(ServerCommand::StatusData))
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
    let task = tokio::spawn(async move {
        TRANSPORT_RESPONSE_KEY
            .scope(RefCell::new(None), async {
                handler(&mut server, &server_token).await
            })
            .await
    });
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
    let task = tokio::spawn(async move {
        TRANSPORT_RESPONSE_KEY
            .scope(RefCell::new(None), async {
                handler(&mut server, &server_token).await
            })
            .await
    });
    client.write_all(SECURE_PREFACE).await.unwrap();
    client.read_exact(&mut hello).await.unwrap();
    let keys = verify_server_hello(&token, &hello).unwrap();
    let mut command = rmp_serde::to_vec(&ServerCommand::Status).unwrap();
    command.push(0);
    let request = encrypt_record(&keys.request, &command).unwrap();
    client.write_all(&request).await.unwrap();
    assert!(task.await.unwrap().is_none());
}

#[tokio::test]
async fn browser_login_commands_check_lock_state_and_site_at_selection() {
    for (command, locked, expected_code, expected_secret) in [
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
            ServerCommand::BrowserLogins("https://example.com".into()),
            true,
            ResponseCode::Failure,
            false,
        ),
        (
            ServerCommand::BrowserLogin {
                domain: "https://example.com".into(),
                id: 1,
            },
            true,
            ResponseCode::Failure,
            false,
        ),
    ] {
        let vault = Vault {
            metadata: VaultMetadata::default(),
            entries: vec![VaultEntry {
                id: 1,
                password: "synthetic-secret".into(),
                url: Some("https://example.com".into()),
                ..VaultEntry::default()
            }],
            recovery: RecoveryData::default(),
        };
        let response = dispatch_test_command(vault, command, locked).await;
        assert_eq!(response.code, expected_code as i32);
        assert_eq!(
            response.message.contains("synthetic-secret"),
            expected_secret
        );
    }
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
async fn custom_field_commands_redact_reveal_select_and_enforce_lock_state() {
    let target = || Target::Id(1);
    for (command, locked, expected_code, visible) in [
        (
            ServerCommand::Get(target()),
            false,
            ResponseCode::Success,
            false,
        ),
        (
            ServerCommand::GetWithOptions {
                target: target(),
                copy_timeout: 0,
            },
            false,
            ResponseCode::Success,
            false,
        ),
        (
            ServerCommand::GetDetails {
                target: target(),
                copy_timeout: 0,
                reveal_secrets: false,
            },
            false,
            ResponseCode::Success,
            false,
        ),
        (
            ServerCommand::GetDetails {
                target: target(),
                copy_timeout: 0,
                reveal_secrets: true,
            },
            false,
            ResponseCode::Success,
            true,
        ),
        (
            ServerCommand::GetField {
                target: target(),
                name: "RECOVERY-CODE".into(),
                copy_timeout: None,
            },
            false,
            ResponseCode::Success,
            true,
        ),
        (
            ServerCommand::GetField {
                target: target(),
                name: "missing".into(),
                copy_timeout: None,
            },
            false,
            ResponseCode::NotFound,
            false,
        ),
        (
            ServerCommand::GetField {
                target: Target::Id(2),
                name: "recovery-code".into(),
                copy_timeout: None,
            },
            false,
            ResponseCode::NotFound,
            false,
        ),
        (
            ServerCommand::GetField {
                target: target(),
                name: "recovery-code".into(),
                copy_timeout: Some(0),
            },
            false,
            ResponseCode::InvalidInput,
            false,
        ),
        (
            ServerCommand::GetField {
                target: target(),
                name: "recovery-code".into(),
                copy_timeout: None,
            },
            true,
            ResponseCode::Failure,
            false,
        ),
        (
            ServerCommand::GetDetails {
                target: target(),
                copy_timeout: 0,
                reveal_secrets: true,
            },
            true,
            ResponseCode::Failure,
            false,
        ),
    ] {
        let vault = Vault {
            entries: vec![VaultEntry {
                id: 1,
                ..Default::default()
            }],
            recovery: RecoveryData {
                entry_metadata: vec![crate::vault::EntryMetadata {
                    entry_id: 1,
                    custom_fields: vec![CustomField {
                        name: "recovery-code".into(),
                        value: "synthetic-field-secret".into(),
                        secret: true,
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            },
            metadata: VaultMetadata::default(),
        };
        let response = dispatch_test_command(vault, command, locked).await;
        assert_eq!(response.code, expected_code as i32);
        assert_eq!(response.message.contains("synthetic-field-secret"), visible);
    }
}
