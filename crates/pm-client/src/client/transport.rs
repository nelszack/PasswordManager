use crate::{
    file::{TOKEN_FILE, data_dir},
    protocol::{
        MAX_STATUS_EVENT_BYTES, ProtocolResponse, RequestEnvelope, ResponseCode, SECURE_HELLO_LEN,
        SECURE_PREFACE, SECURE_RECORD_HEADER_LEN, TransportKeys, decode_responses, decrypt_record,
        decrypt_record_stream, encrypt_record, server_addr, stream_record_key, verify_server_hello,
    },
    types::*,
};
use std::{
    fs,
    io::{self, Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

/// A sent request may have committed even when its reply was lost.
pub struct RequestFailure {
    pub message: String,
    pub sent: bool,
}

impl RequestFailure {
    pub fn describe(self, operation_id: Option<&str>) -> String {
        if self.sent
            && let Some(id) = operation_id
        {
            format!(
                "{} The change may have completed. Do not retry blindly. Inspect the vault and run pm operation --id {id} to check its recorded outcome.",
                self.message
            )
        } else {
            self.message
        }
    }
}

/// An authenticated local connection with explicit resource and timeout limits.
#[derive(Clone, Debug)]
pub struct AuthenticatedClient {
    pub port: u16,
    pub token_path: PathBuf,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_response: usize,
    pub breach_timeout: Duration,
}
impl AuthenticatedClient {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            token_path: data_dir().join(TOKEN_FILE),
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(5),
            max_response: 128 * 1024 * 1024,
            breach_timeout: Duration::from_secs(5 * 60),
        }
    }
    pub fn probe(port: u16) -> Self {
        Self {
            port,
            token_path: data_dir().join(TOKEN_FILE),
            connect_timeout: Duration::from_millis(500),
            io_timeout: Duration::from_millis(500),
            max_response: 1024 * 1024,
            breach_timeout: Duration::from_millis(500),
        }
    }
    pub fn request(&self, command: ServerCommand) -> Result<String, String> {
        let response = self.request_response(command)?;
        if response.code == ResponseCode::Success as i32 {
            match response.payload {
                crate::protocol::ResponsePayload::Message(value) => Ok(value),
                _ => Err("expected a mutation acknowledgement".into()),
            }
        } else {
            Err(response.error_message())
        }
    }

    pub fn request_response(&self, command: ServerCommand) -> Result<ProtocolResponse, String> {
        let envelope = RequestEnvelope::new(command);
        let operation_id = envelope.operation_id.clone();
        self.request_envelope_tracked(envelope)
            .map_err(|error| error.describe(operation_id.as_deref()))
    }

    pub fn request_response_tracked(
        &self,
        command: ServerCommand,
    ) -> Result<ProtocolResponse, RequestFailure> {
        self.request_envelope_tracked(RequestEnvelope::new(command))
    }
    pub fn request_envelope_tracked(
        &self,
        envelope: RequestEnvelope,
    ) -> Result<ProtocolResponse, RequestFailure> {
        let envelope = Zeroizing::new(envelope);
        let mut sent = false;
        self.exchange_response(&envelope, &mut sent)
            .map_err(|message| RequestFailure { message, sent })
    }

    fn exchange_response(
        &self,
        envelope: &RequestEnvelope,
        sent: &mut bool,
    ) -> Result<ProtocolResponse, String> {
        envelope.validate()?;
        let command = &envelope.command;
        let read_timeout = if matches!(
            command,
            ServerCommand::Audit(AuditOptions {
                check_breaches: true,
                ..
            })
        ) {
            self.breach_timeout
        } else if matches!(command, ServerCommand::Cloud(_)) {
            Duration::from_secs(120)
        } else if matches!(
            command,
            ServerCommand::Duo(_) | ServerCommand::Totp(TotpCommand::Duo { .. })
        ) {
            Duration::from_secs(60)
        } else {
            self.io_timeout
        };
        let (mut connection, keys) = self.open_secure(read_timeout)?;
        #[cfg(target_os = "windows")]
        let shutdown_wait = if matches!(command, ServerCommand::Kill) {
            super::shutdown::ShutdownWait::capture(&self.token_path)?
        } else {
            None
        };
        let mut data = crate::secret::SecretBuffer::default();
        rmp_serde::encode::write_named(&mut data, envelope)
            .map_err(|e| format!("could not encode command: {e}"))?;
        let mut encrypted_request = encrypt_record(&keys.request, &data)
            .ok_or_else(|| "could not encrypt command".to_string())?;
        *sent = true;
        let send_result = connection
            .write_all(&encrypted_request)
            .and_then(|_| connection.flush())
            .map_err(|e| format!("could not send encrypted command: {e}"));
        encrypted_request.zeroize();
        send_result?;

        let mut buf = vec![0u8; 64 * 1024];
        let mut total = Vec::new();
        loop {
            match connection.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if total.len().saturating_add(n) > self.max_response {
                        total.zeroize();
                        return Err(format!(
                            "server response exceeds the {} byte limit",
                            self.max_response
                        ));
                    }
                    total.extend_from_slice(&buf[..n]);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err("server response timed out".to_string());
                }
                Err(e) => return Err(format!("could not read server response: {e}")),
            }
        }
        let mut plaintext = decrypt_record_stream(&keys.response, &total, self.max_response)?;
        total.zeroize();
        let response = decode_responses(&plaintext).and_then(|response| {
            if response
                .request_id
                .as_ref()
                .is_some_and(|id| id != &envelope.request_id)
            {
                Err("server response refers to a different request".to_string())
            } else {
                Ok(response)
            }
        });
        plaintext.zeroize();
        #[cfg(target_os = "windows")]
        let response = response.and_then(|mut response| {
            if matches!(command, ServerCommand::Kill) && response.code == 0 {
                if let Some(waiter) = shutdown_wait {
                    waiter.wait()?;
                } else {
                    response.payload = crate::protocol::ResponsePayload::Message(
                        "Server shutdown requested. This older server does not support process-exit verification; restart it to enable shutdown waiting.".into(),
                    );
                }
            }
            Ok(response)
        });
        response
    }
}
impl AuthenticatedClient {
    /// Connect and authenticate the server, returning the connection's keys.
    fn open_secure(&self, read_timeout: Duration) -> Result<(TcpStream, TransportKeys), String> {
        let address = server_addr(self.port);
        let mut connection = TcpStream::connect_timeout(&address, self.connect_timeout)
            .map_err(|e| format!("could not connect to the password manager server: {e}"))?;
        connection
            .set_read_timeout(Some(read_timeout))
            .map_err(|e| format!("could not configure server connection: {e}"))?;
        connection
            .set_write_timeout(Some(self.io_timeout))
            .map_err(|e| format!("could not configure server connection: {e}"))?;
        let token = server_token(&self.token_path)?;
        connection
            .write_all(SECURE_PREFACE)
            .and_then(|_| connection.flush())
            .map_err(|e| format!("could not start secure server handshake: {e}"))?;
        let mut hello = [0u8; SECURE_HELLO_LEN];
        connection
            .read_exact(&mut hello)
            .map_err(|e| format!("could not authenticate the password manager server: {e}"))?;
        let keys = verify_server_hello(&token, &hello)
            .ok_or_else(|| "password manager server authentication failed".to_string())?;
        Ok((connection, keys))
    }

    /// Subscribe to pushed status records. Older servers close the connection,
    /// which surfaces as an error from the first [`StatusEvents::recv`].
    pub fn status_events(&self) -> Result<StatusEvents, String> {
        let envelope = RequestEnvelope::new(ServerCommand::StatusEvents);
        let (mut connection, keys) = self.open_secure(STATUS_EVENT_TIMEOUT)?;
        let mut data = crate::secret::SecretBuffer::default();
        rmp_serde::encode::write_named(&mut data, &envelope)
            .map_err(|e| format!("could not encode command: {e}"))?;
        let request = encrypt_record(&keys.request, &data)
            .ok_or_else(|| "could not encrypt command".to_string())?;
        connection
            .write_all(&request)
            .and_then(|_| connection.flush())
            .map_err(|e| format!("could not subscribe to server status: {e}"))?;
        Ok(StatusEvents {
            connection,
            response_key: Zeroizing::new(keys.response),
            sequence: 0,
            request_id: envelope.request_id,
        })
    }
}

/// The server sends a record at least every 20 seconds; silence beyond this
/// means it stopped or the connection broke.
const STATUS_EVENT_TIMEOUT: Duration = Duration::from_secs(45);

/// Authenticated, ordered status records pushed by the server.
pub struct StatusEvents {
    connection: TcpStream,
    response_key: Zeroizing<[u8; 32]>,
    sequence: u64,
    request_id: String,
}

/// Closes a [`StatusEvents`] connection from another thread, so a blocked
/// [`StatusEvents::recv`] returns at once instead of at the next heartbeat.
/// Linux wakes the read directly. Windows does not, but the server ends a
/// subscription when its client closes the send side, and that close wakes it.
pub struct StatusEventsShutdown(TcpStream);

impl StatusEventsShutdown {
    pub fn shutdown(&self) {
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

impl StatusEvents {
    /// A handle that ends this subscription from another thread.
    pub fn shutdown_handle(&self) -> Result<StatusEventsShutdown, String> {
        self.connection
            .try_clone()
            .map(StatusEventsShutdown)
            .map_err(|e| format!("could not share the status connection: {e}"))
    }

    /// Block until the next status record. Any error ends the subscription.
    pub fn recv(&mut self) -> Result<ProtocolResponse, String> {
        let mut header = [0u8; SECURE_RECORD_HEADER_LEN];
        self.connection
            .read_exact(&mut header)
            .map_err(|e| format!("status subscription ended: {e}"))?;
        let length =
            u32::from_be_bytes(header[24..].try_into().expect("four length bytes")) as usize;
        if !(16..=MAX_STATUS_EVENT_BYTES + 16).contains(&length) {
            return Err("server sent an invalid status record".into());
        }
        let mut ciphertext = vec![0u8; length];
        self.connection
            .read_exact(&mut ciphertext)
            .map_err(|e| format!("status subscription ended: {e}"))?;
        let key = stream_record_key(&self.response_key, self.sequence);
        let plaintext = Zeroizing::new(
            decrypt_record(&key, &header[..24], &ciphertext)
                .ok_or_else(|| "server sent an unauthenticated status record".to_string())?,
        );
        self.sequence += 1;
        let response = decode_responses(&plaintext)?;
        if response.request_id.as_deref() != Some(self.request_id.as_str()) {
            return Err("status record refers to a different request".into());
        }
        if response.code != ResponseCode::Success as i32 {
            return Err(response.error_message());
        }
        if !matches!(
            response.payload,
            crate::protocol::ResponsePayload::Status(_)
        ) {
            return Err("server sent a status record without status".into());
        }
        Ok(response)
    }
}

fn server_token(path: &Path) -> Result<Zeroizing<String>, String> {
    let contents = Zeroizing::new(
        fs::read_to_string(path)
            .map_err(|e| format!("could not read session token at {}: {e}", path.display()))?,
    );
    let token = Zeroizing::new(contents.trim().to_string());
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("invalid session token at {}", path.display()));
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        ResponsePayload, RpcResponse, SECURE_RECORD_HEADER_LEN, decrypt_record,
        encode_rpc_response, server_hello,
    };
    use std::{net::TcpListener, thread};

    #[test]
    fn shutdown_handle_wakes_a_blocked_status_read() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let connection = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        // Like the real server: silent between heartbeats, but it ends the
        // subscription once the client closes its side.
        let (mut server, _) = listener.accept().unwrap();
        let server = thread::spawn(move || {
            let _ = server.read(&mut [0u8; 1]);
        });
        let mut events = StatusEvents {
            connection,
            response_key: Zeroizing::new([0; 32]),
            sequence: 0,
            request_id: "status".into(),
        };
        let handle = events.shutdown_handle().unwrap();
        let reader = thread::spawn(move || events.recv().map(|_| ()));
        thread::sleep(Duration::from_millis(100));
        handle.shutdown();
        let started = std::time::Instant::now();
        while !reader.is_finished() {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the blocked read must return once the connection is shut down"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(reader.join().unwrap().is_err());
        server.join().unwrap();
    }

    fn fixture(
        reply: impl FnOnce(&RequestEnvelope) -> Option<RpcResponse> + Send + 'static,
    ) -> (
        AuthenticatedClient,
        thread::JoinHandle<()>,
        tempfile::TempDir,
    ) {
        let root = tempfile::tempdir().unwrap();
        let token = "ab".repeat(32);
        let token_path = root.path().join("token");
        fs::write(&token_path, &token).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = AuthenticatedClient::new(listener.local_addr().unwrap().port());
        client.token_path = token_path;
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut preface = [0; 4];
            stream.read_exact(&mut preface).unwrap();
            assert_eq!(&preface, SECURE_PREFACE);
            let (hello, keys) = server_hello(&token).unwrap();
            stream.write_all(&hello).unwrap();
            let mut header = [0; SECURE_RECORD_HEADER_LEN];
            if stream.read_exact(&mut header).is_err() {
                return;
            }
            let len = u32::from_be_bytes(header[24..].try_into().unwrap()) as usize;
            let mut bytes = vec![0; len];
            stream.read_exact(&mut bytes).unwrap();
            let plaintext =
                Zeroizing::new(decrypt_record(&keys.request, &header[..24], &bytes).unwrap());
            let envelope: RequestEnvelope = rmp_serde::from_slice(&plaintext).unwrap();
            envelope.validate().unwrap();
            if let Some(response) = reply(&envelope) {
                let response = encode_rpc_response(&response).unwrap();
                stream
                    .write_all(&encrypt_record(&keys.response, &response).unwrap())
                    .unwrap();
            }
        });
        (client, worker, root)
    }
    #[test]
    fn authenticated_exchange_carries_named_envelope_and_exact_typed_secrets() {
        let (client, worker, _root) = fixture(|envelope| {
            assert!(matches!(
                envelope.command,
                ServerCommand::GetSecret(Target::Id(9))
            ));
            let mut response =
                RpcResponse::success(ResponsePayload::Secret(" \nprivate key\n\n".into()));
            response.request_id = Some(envelope.request_id.clone());
            Some(response)
        });
        let response = client
            .request_response(ServerCommand::GetSecret(Target::Id(9)))
            .unwrap();
        assert_eq!(response.code, 0);
        assert!(
            matches!(response.payload,ResponsePayload::Secret(ref value)if value.expose()==" \nprivate key\n\n")
        );
        worker.join().unwrap();
    }
    #[test]
    fn lost_mutation_reply_is_uncertain_and_preserves_operation_identity() {
        let (client, worker, _root) = fixture(|envelope| {
            assert_eq!(envelope.operation_id.as_deref(), Some("stable-operation"));
            None
        });
        let envelope = RequestEnvelope::new(ServerCommand::Lock(true))
            .with_operation(Some("stable-operation".into()), None);
        let result = client.request_envelope_tracked(envelope);
        assert!(result.is_err());
        assert!(result.err().unwrap().sent);
        worker.join().unwrap();
    }
    #[test]
    fn convenience_requests_keep_duo_mutation_uncertainty_and_identity() {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
        let recorded = captured.clone();
        let (client, worker, _root) = fixture(move |envelope| {
            *recorded.lock().unwrap() = envelope.operation_id.clone();
            None
        });
        let error = client
            .request(ServerCommand::Duo(DuoCommand::Remove {
                target: Target::Id(9),
            }))
            .unwrap_err();
        worker.join().unwrap();
        let id = captured.lock().unwrap().clone().unwrap();
        assert!(error.contains(&id));
        assert!(error.contains("Do not retry blindly"));
    }

    #[test]
    fn correlation_mismatch_is_rejected_after_send() {
        let (client, worker, _root) = fixture(|_| {
            let mut response = RpcResponse::message(ResponseCode::Success, "ok");
            response.request_id = Some("different-request".into());
            Some(response)
        });
        let error = client
            .request_response_tracked(ServerCommand::Status)
            .err()
            .unwrap();
        assert!(error.sent);
        assert!(error.message.contains("different request"));
        worker.join().unwrap();
    }
    #[test]
    fn invalid_request_is_rejected_before_connecting() {
        let mut request = RequestEnvelope::new(ServerCommand::Lock(true));
        request.operation_id = None;
        let error = AuthenticatedClient::new(1)
            .request_envelope_tracked(request)
            .err()
            .unwrap();
        assert!(!error.sent);
        assert!(error.message.contains("operation identifier"));
    }
    #[test]
    fn session_tokens_validate_without_exposing_contents_in_errors() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("token");
        fs::write(&path, "  ".to_owned() + &"ab".repeat(32) + "\n").unwrap();
        assert_eq!(server_token(&path).unwrap().as_str(), "ab".repeat(32));
        fs::write(&path, "synthetic-secret").unwrap();
        let error = server_token(&path).unwrap_err();
        assert!(!error.contains("synthetic-secret"));
    }
}
