use super::*;
use crate::file::init_test_data_dir;
use crate::vault::{Vault, VaultEntry, VaultMetadata};

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
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
        ..Vault::default()
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
        ..Vault::default()
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
        ..Vault::default()
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
fn test_server_info_default() {
    let info = ServerInfo::default();
    assert!(info.locked);
    assert!(info.keypass.is_none());
}

#[test]
fn test_server_info_with_password() {
    let mut info = ServerInfo {
        locked: false,
        keypass: Some(PasswordType::Password("secret".to_string())),
    };
    info.zeroize();
    assert!(info.locked);
    assert!(info.keypass.is_none());
}

#[test]
fn test_server_info_with_key() {
    let mut info = ServerInfo {
        locked: false,
        keypass: Some(PasswordType::Key("key.pem".to_string())),
    };
    info.zeroize();
    assert!(info.locked);
    assert!(info.keypass.is_none());
}

#[test]
fn test_password_type_zeroize_password() {
    let mut pt = PasswordType::Password("secret_password".to_string());
    pt.zeroize();
    match pt {
        PasswordType::Password(s) => assert_eq!(s, ""),
        _ => panic!("Expected Password variant"),
    }
}

#[test]
fn test_password_type_zeroize_key() {
    let mut pt = PasswordType::Key("secret_key.pem".to_string());
    pt.zeroize();
    match pt {
        PasswordType::Key(s) => assert_eq!(s, ""),
        _ => panic!("Expected Key variant"),
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
async fn authenticated_tcp_protocol_decodes_a_complete_command() {
    let token = "a".repeat(TOKEN_HEX_LEN);
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
    let keys = verify_server_hello(&token, &hello).unwrap();
    let command = rmp_serde::to_vec(&ServerCommand::Status).unwrap();
    let request = encrypt_record(&keys.request, &command).unwrap();
    client.write_all(&request).await.unwrap();

    let parsed = task.await.unwrap();
    assert!(matches!(parsed, Some(ServerCommand::Status)));
}

#[tokio::test]
async fn tcp_protocol_authenticates_before_commands_and_rejects_invalid_messages() {
    let token = "a".repeat(TOKEN_HEX_LEN);
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
    let mut oversized = [0u8; SECURE_RECORD_HEADER_LEN];
    oversized[24..].copy_from_slice(&((MAX_TCP_MSG as u32) + 17).to_be_bytes());
    client.write_all(&oversized).await.unwrap();
    assert!(task.await.unwrap().is_none());

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
        let token = "ab".repeat(32);
        let (mut client, server) = tcp_pair().await;
        let (kill_tx, _kill_rx) = mpsc::channel(1);
        let state = ConnectionState {
            server_info: Arc::new(Mutex::new(ServerInfo {
                locked,
                keypass: None,
            })),
            vlt: Arc::new(Mutex::new(Some(Vault {
                entries: vec![VaultEntry {
                    id: 1,
                    password: "synthetic-secret".into(),
                    url: Some("https://example.com".into()),
                    ..VaultEntry::default()
                }],
                ..Vault::default()
            }))),
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
        assert_eq!(response.code, expected_code as i32);
        assert_eq!(
            response.message.contains("synthetic-secret"),
            expected_secret
        );
        task.await.unwrap();
    }
}
