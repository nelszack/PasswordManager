use crate::{
    file::{TOKEN_FILE, data_dir},
    protocol::{
        ProtocolResponse, ResponseCode, SECURE_HELLO_LEN, SECURE_PREFACE, decode_responses,
        decrypt_record_stream, encrypt_record, verify_server_hello,
    },
    server::server_addr,
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
            Ok(response.message)
        } else {
            Err(response.message.trim_end().to_string())
        }
    }

    pub fn request_response(&self, command: ServerCommand) -> Result<ProtocolResponse, String> {
        let command = Zeroizing::new(command);
        let read_timeout = if matches!(
            &*command,
            ServerCommand::Audit(AuditOptions {
                check_breaches: true,
                ..
            })
        ) {
            self.breach_timeout
        } else {
            self.io_timeout
        };
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
        let data = Zeroizing::new(
            rmp_serde::to_vec(&*command).map_err(|e| format!("could not encode command: {e}"))?,
        );
        let mut encrypted_request = encrypt_record(&keys.request, &data)
            .ok_or_else(|| "could not encrypt command".to_string())?;
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
        let response = decode_responses(&plaintext);
        plaintext.zeroize();
        response
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
        SECURE_RECORD_HEADER_LEN, decrypt_record, encode_response, server_hello,
    };
    use std::{net::TcpListener, thread};

    #[test]
    fn session_tokens_validate_without_exposing_contents_in_errors() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        let valid = "aB".repeat(32);
        fs::write(&path, format!("  {valid}\n")).unwrap();
        assert_eq!(&**server_token(&path).unwrap(), valid);
        for invalid in [
            "synthetic-secret".to_string(),
            "g".repeat(64),
            "a".repeat(63),
        ] {
            fs::write(&path, &invalid).unwrap();
            let error = server_token(&path).unwrap_err();
            assert!(error.starts_with("invalid session token at "));
            assert!(!error.contains(&invalid));
        }
    }

    fn fixture(
        token: &str,
        code: ResponseCode,
        message: &str,
        tamper: bool,
    ) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let token = token.to_owned();
        let message = message.to_owned();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut preface = [0; SECURE_PREFACE.len()];
            stream.read_exact(&mut preface).unwrap();
            assert_eq!(&preface, SECURE_PREFACE);
            let (hello, keys) = server_hello(&token).unwrap();
            stream.write_all(&hello).unwrap();
            let mut header = [0; SECURE_RECORD_HEADER_LEN];
            // A client rejects a wrong token before sending any command.
            if stream.read_exact(&mut header).is_err() {
                return;
            }
            let length = u32::from_be_bytes(header[24..].try_into().unwrap()) as usize;
            let mut ciphertext = vec![0; length];
            stream.read_exact(&mut ciphertext).unwrap();
            let request = decrypt_record(&keys.request, &header[..24], &ciphertext).unwrap();
            assert!(matches!(
                rmp_serde::from_slice::<ServerCommand>(&request).unwrap(),
                ServerCommand::StatusData
            ));
            let mut response =
                encrypt_record(&keys.response, &encode_response(code, &message)).unwrap();
            if tamper {
                *response.last_mut().unwrap() ^= 1;
            }
            stream.write_all(&response).unwrap();
        });
        (port, worker)
    }

    #[test]
    fn independent_clients_authenticate_bound_responses_and_preserve_codes() {
        let directory = tempfile::tempdir().unwrap();
        let token_path = directory.path().join("token");
        let token = "ab".repeat(32);
        fs::write(&token_path, &token).unwrap();
        let (first_port, first_worker) = fixture(&token, ResponseCode::Success, "first", false);
        let (second_port, second_worker) = fixture(&token, ResponseCode::NotFound, "second", false);
        let mut first = AuthenticatedClient::new(first_port);
        first.token_path = token_path.clone();
        let mut second = AuthenticatedClient::new(second_port);
        second.token_path = token_path;
        assert_eq!(first.request(ServerCommand::StatusData).unwrap(), "first\n");
        let response = second.request_response(ServerCommand::StatusData).unwrap();
        assert_eq!(response.code, ResponseCode::NotFound as i32);
        assert_eq!(response.message, "second\n");
        first_worker.join().unwrap();
        second_worker.join().unwrap();

        for (server_token, tamper, limit, expected) in [
            (token.as_str(), true, 1024, "unauthenticated"),
            (token.as_str(), false, 8, "8 byte limit"),
            (
                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                false,
                1024,
                "authentication failed",
            ),
        ] {
            let (port, worker) = fixture(server_token, ResponseCode::Success, "bounded", tamper);
            first.port = port;
            first.max_response = limit;
            let error = first.request(ServerCommand::StatusData).unwrap_err();
            assert!(error.contains(expected), "{error}");
            worker.join().unwrap();
        }
    }
}
