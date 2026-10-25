use password_manager::{
    client::AuthenticatedClient,
    protocol::{RequestEnvelope, ResponsePayload},
    types::ServerCommand,
};

/// Keep polling and decisions attached to the unlock that supplied their data.
pub(super) struct SessionClient<'a> {
    client: &'a AuthenticatedClient,
    session_id: Option<String>,
}

impl<'a> SessionClient<'a> {
    pub fn new(client: &'a AuthenticatedClient) -> Self {
        Self {
            client,
            session_id: None,
        }
    }

    pub fn request(&mut self, command: ServerCommand) -> Result<ResponsePayload, String> {
        let mut envelope = RequestEnvelope::new(command);
        envelope.expected_session = self.session_id.clone();
        let response = self
            .client
            .request_envelope_tracked(envelope)
            .map_err(|error| error.message)?;
        if response.code != 0 {
            return Err(response.error_message());
        }
        let session_id = response
            .session_id
            .filter(|id| id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let Some(session_id) = session_id else {
            return Err("server response is missing a valid unlock session".into());
        };
        if self
            .session_id
            .as_ref()
            .is_some_and(|expected| expected != &session_id)
        {
            return Err("Unlock session changed; restart the command before continuing".into());
        }
        self.session_id = Some(session_id);
        Ok(response.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use password_manager::{
        protocol::{
            ResponseCode, RpcResponse, SECURE_PREFACE, SECURE_RECORD_HEADER_LEN, decrypt_record,
            encode_rpc_response, encrypt_record, server_hello,
        },
        types::{DuoCommand, Target, TotpCommand},
    };
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::Duration,
    };
    use zeroize::Zeroizing;

    #[test]
    fn polls_copies_and_decisions_stay_bound_to_the_original_unlock() {
        let original = "ab".repeat(32);
        let changed = "cd".repeat(32);
        for duo in [false, true] {
            for (returned_session, code, accepted) in [
                (Some(original.clone()), ResponseCode::Success, true),
                (Some(changed.clone()), ResponseCode::Success, false),
                (None, ResponseCode::Success, false),
                (Some("invalid".into()), ResponseCode::Success, false),
                (Some(original.clone()), ResponseCode::Conflict, false),
            ] {
                let root = tempfile::tempdir().unwrap();
                let token_path = root.path().join("token");
                let token = "ef".repeat(32);
                std::fs::write(&token_path, &token).unwrap();
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let client = AuthenticatedClient {
                    port: listener.local_addr().unwrap().port(),
                    token_path,
                    connect_timeout: Duration::from_secs(2),
                    io_timeout: Duration::from_secs(2),
                    max_response: 1024 * 1024,
                    breach_timeout: Duration::from_secs(2),
                };
                let expected = original.clone();
                let server = thread::spawn(move || {
                    for second in [false, true] {
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
                        let plaintext = Zeroizing::new(
                            decrypt_record(&keys.request, &header[..24], &ciphertext).unwrap(),
                        );
                        let envelope: RequestEnvelope = rmp_serde::from_slice(&plaintext).unwrap();
                        envelope.validate().unwrap();
                        assert_eq!(
                            envelope.expected_session.as_ref(),
                            second.then_some(&expected)
                        );
                        assert_eq!(envelope.command.is_mutation(), second);
                        let mut response = RpcResponse::message(
                            if second { code } else { ResponseCode::Success },
                            "reply",
                        );
                        response.request_id = Some(envelope.request_id);
                        response.session_id = if second {
                            returned_session.clone()
                        } else {
                            Some(expected.clone())
                        };
                        let encoded = Zeroizing::new(encode_rpc_response(&response).unwrap());
                        stream
                            .write_all(&encrypt_record(&keys.response, &encoded).unwrap())
                            .unwrap();
                    }
                });
                let mut bound = SessionClient::new(&client);
                let poll = if duo {
                    ServerCommand::Duo(DuoCommand::Requests {
                        target: Target::Id(1),
                    })
                } else {
                    ServerCommand::Totp(TotpCommand::Watch {
                        target: Target::Id(1),
                        copy_timeout: None,
                    })
                };
                assert!(bound.request(poll).is_ok());
                let effect = if duo {
                    ServerCommand::Duo(DuoCommand::Respond {
                        target: Target::Id(1),
                        request_id: "reviewed-request".into(),
                        fingerprint: "reviewed-fingerprint".into(),
                        approve: false,
                        code: "".into(),
                    })
                } else {
                    ServerCommand::Totp(TotpCommand::Watch {
                        target: Target::Id(1),
                        copy_timeout: Some(15),
                    })
                };
                assert_eq!(bound.request(effect).is_ok(), accepted);
                server.join().unwrap();
            }
        }
    }
}
