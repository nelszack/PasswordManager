use super::*;
use crate::vault::{Vault, VaultEntry, VaultMetadata};

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

#[tokio::test]
async fn response_codes_are_explicit_and_independent_of_message_wording() {
    let (mut client, mut server) = tcp_pair().await;
    respond("Entry not found.", &mut server, false).await;
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
        false,
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
            respond("buffered", &mut server, false).await;
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

#[cfg(feature = "legacy-http")]
#[test]
fn test_browser_totp_command_requires_numeric_entry_id() {
    let command = browser_totp_command(&[Some("42".to_string())]).unwrap();
    assert!(matches!(
        command,
        ServerCommand::Totp(TotpCommand::Show {
            target: Target::Id(42),
            copy_timeout: None,
        })
    ));
    assert!(browser_totp_command(&[Some("not-an-id".to_string())]).is_none());
    assert!(browser_totp_command(&[]).is_none());
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
fn test_password_type_clone() {
    let pt1 = PasswordType::Password("test".to_string());
    let pt2 = pt1.clone();
    assert_eq!(pt1, pt2);
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
    let command = rmp_serde::to_vec(&ServerCommand::Status).unwrap();
    let mut request = token.as_bytes().to_vec();
    request.extend_from_slice(&(command.len() as u32).to_be_bytes());
    request.extend_from_slice(&command);

    let (mut client, mut server) = tcp_pair().await;
    client.write_all(&request).await.unwrap();

    let parsed = handler(&mut server, &token).await;
    assert!(matches!(parsed, Some((ServerCommand::Status, false))));
}

#[tokio::test]
async fn tcp_protocol_rejects_wrong_tokens_and_oversized_messages() {
    let token = "a".repeat(TOKEN_HEX_LEN);
    let (mut client, mut server) = tcp_pair().await;
    client
        .write_all(format!("{}{}", "b".repeat(TOKEN_HEX_LEN), "\0\0\0\0").as_bytes())
        .await
        .unwrap();
    assert!(handler(&mut server, &token).await.is_none());

    let (mut client, mut server) = tcp_pair().await;
    let mut request = token.as_bytes().to_vec();
    request.extend_from_slice(&((MAX_TCP_MSG as u32) + 1).to_be_bytes());
    client.write_all(&request).await.unwrap();
    assert!(handler(&mut server, &token).await.is_none());

    let (mut client, mut server) = tcp_pair().await;
    let mut command = rmp_serde::to_vec(&ServerCommand::Status).unwrap();
    command.push(0);
    let mut request = token.as_bytes().to_vec();
    request.extend_from_slice(&(command.len() as u32).to_be_bytes());
    request.extend_from_slice(&command);
    client.write_all(&request).await.unwrap();
    assert!(handler(&mut server, &token).await.is_none());
}

#[cfg(feature = "legacy-http")]
#[tokio::test]
async fn http_protocol_requires_a_valid_bearer_token() {
    let token = "c".repeat(TOKEN_HEX_LEN);
    let body = r#"{"command":"status","extra_info":[]}"#;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (mut client, mut server) = tcp_pair().await;
    client.write_all(request.as_bytes()).await.unwrap();

    assert!(handler(&mut server, &token).await.is_none());
    let mut response = [0u8; 128];
    let length = client.read(&mut response).await.unwrap();
    assert!(response[..length].starts_with(b"HTTP/1.1 401 Unauthorized"));
}

#[cfg(feature = "legacy-http")]
#[tokio::test]
async fn authenticated_http_protocol_decodes_extension_commands() {
    let token = "d".repeat(TOKEN_HEX_LEN);
    let body = r#"{"command":"totp","extra_info":["47"]}"#;
    let request = format!(
        "POST / HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (mut client, mut server) = tcp_pair().await;
    client.write_all(request.as_bytes()).await.unwrap();

    assert!(matches!(
        handler(&mut server, &token).await,
        Some((
            ServerCommand::Totp(TotpCommand::Show {
                target: Target::Id(47),
                copy_timeout: None,
            }),
            true,
        ))
    ));
}

#[cfg(feature = "legacy-http")]
#[tokio::test]
async fn http_protocol_rejects_privileged_and_oversized_requests() {
    let token = "e".repeat(TOKEN_HEX_LEN);
    let body = r#"{"command":"backup","extra_info":[]}"#;
    let request = format!(
        "POST / HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (mut client, mut server) = tcp_pair().await;
    client.write_all(request.as_bytes()).await.unwrap();
    assert!(handler(&mut server, &token).await.is_none());

    let request = format!(
        "POST / HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n",
        MAX_HTTP_REQ + 1
    );
    let (mut client, mut server) = tcp_pair().await;
    client.write_all(request.as_bytes()).await.unwrap();
    assert!(handler(&mut server, &token).await.is_none());
}
