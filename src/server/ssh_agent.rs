//! A local SSH agent (draft-miller-ssh-agent) backed by the unlocked vault's
//! Ed25519 SSH-key items. It answers identity listings and signature requests
//! only; adding, removing, and agent locking are refused. Lookups go through the
//! vault worker without counting as activity, so SSH use never keeps a vault
//! unlocked, and a locked vault offers no keys.
//!
//! On Unix it listens on an owner-only socket; on Windows on a named pipe whose
//! DACL admits only the current user, which Windows OpenSSH reaches through
//! `SSH_AUTH_SOCK`.
// Elsewhere this code is still compiled (and tested) but has no caller.
#![cfg_attr(not(any(unix, windows)), allow(dead_code))]
use super::*;
use std::{path::PathBuf, time::Duration};
use tokio::sync::oneshot;

const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const FAILURE: u8 = 5;
/// OpenSSH's own agent limit for one message.
const MAX_MESSAGE: usize = 256 * 1024;
const MAX_CONNECTIONS: usize = 16;

/// Unix socket paths are limited to about 104–108 bytes.
const MAX_SOCKET_PATH: usize = 100;

/// Why the agent is not running, kept for the life of the service so status
/// keeps reporting it after unlocks and locks replace ordinary warnings.
pub(super) static UNAVAILABLE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Where the agent listens: a private directory beside the vaults, or, when that
/// path is too long for a socket, a private directory in the user's runtime (or
/// temporary) directory named after the data directory. On Windows it is a named
/// pipe named after the data directory.
#[cfg(not(windows))]
pub fn socket_path() -> PathBuf {
    socket_path_for(
        &data_dir(),
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or_else(std::env::temp_dir),
    )
}

#[cfg(windows)]
pub fn socket_path() -> PathBuf {
    pipe_name_for(&data_dir())
}

/// Pipe names share one namespace for every user and data directory, so the
/// name is derived from the data directory (which includes the user's profile).
#[cfg_attr(not(windows), allow(dead_code))]
fn pipe_name_for(data: &std::path::Path) -> PathBuf {
    let tag = blake3::hash(data.as_os_str().as_encoded_bytes()).to_hex();
    PathBuf::from(format!(r"\\.\pipe\pm-ssh-agent-{}", &tag[..16]))
}

#[cfg_attr(windows, allow(dead_code))]
fn socket_path_for(data: &std::path::Path, runtime: PathBuf) -> PathBuf {
    let preferred = data.join("agent").join("ssh-agent.sock");
    if preferred.as_os_str().len() <= MAX_SOCKET_PATH {
        return preferred;
    }
    let tag = blake3::hash(data.as_os_str().as_encoded_bytes()).to_hex();
    runtime
        .join(format!("pm-agent-{}", &tag[..16]))
        .join("ssh-agent.sock")
}

const EXTENSION: u8 = 27;
const SUCCESS: u8 = 6;
/// How long a signature waits for the person to allow it.
const DECISION_WAIT: Duration = Duration::from_secs(30);

/// Signatures waiting for a decision from the desktop app or `pm ssh-agent`.
#[derive(Default)]
pub(super) struct SshApprovals {
    pending: std::sync::Mutex<Vec<(crate::protocol::SshRequest, oneshot::Sender<bool>)>>,
    /// Wakes status subscribers so a request appears at once.
    pub(super) changed: tokio::sync::Notify,
}

impl SshApprovals {
    pub(super) fn list(&self) -> Vec<crate::protocol::SshRequest> {
        self.lock()
            .iter()
            .map(|(request, _)| request.clone())
            .collect()
    }
    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, Vec<(crate::protocol::SshRequest, oneshot::Sender<bool>)>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// Waits for a decision; no answer within the wait refuses the signature.
    async fn ask(&self, key: String, host: String) -> bool {
        let id = hex::encode(rand::random::<[u8; 6]>());
        let (send, receive) = oneshot::channel();
        {
            let mut pending = self.lock();
            if pending.len() >= 16 {
                return false;
            }
            pending.push((
                crate::protocol::SshRequest {
                    id: id.clone(),
                    key,
                    host,
                },
                send,
            ));
        }
        self.changed.notify_waiters();
        let allowed = tokio::time::timeout(DECISION_WAIT, receive).await;
        self.lock().retain(|(request, _)| request.id != id);
        self.changed.notify_waiters();
        matches!(allowed, Ok(Ok(true)))
    }
    /// Answers a pending request; false if it is no longer waiting.
    pub(super) fn decide(&self, id: &str, allow: bool) -> bool {
        let found = {
            let mut pending = self.lock();
            pending
                .iter()
                .position(|(request, _)| request.id == id)
                .map(|index| pending.remove(index))
        };
        self.changed.notify_waiters();
        found.is_some_and(|(_, answer)| answer.send(allow).is_ok())
    }
}

/// What the SSH client said about this connection through OpenSSH's
/// `session-bind@openssh.com` extension.
#[derive(Default)]
struct Binding {
    /// The destination host's name from known_hosts, or its key fingerprint.
    host: Option<String>,
    /// The request came through agent forwarding from another machine.
    forwarded: bool,
}

/// The `SHA256:` fingerprint OpenSSH shows for a host key.
fn fingerprint(blob: &[u8]) -> String {
    use base64::Engine;
    use ssh_key::sha2::{Digest, Sha256};
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(blob))
    )
}

/// The first plain (unhashed) known_hosts name for this host key.
fn known_host(known_hosts: &str, blob: &[u8]) -> Option<String> {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(blob);
    known_hosts.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let mut hosts = fields.next()?;
        if hosts.starts_with('@') {
            hosts = fields.next()?;
        }
        let _kind = fields.next()?;
        (fields.next()? == encoded)
            .then(|| hosts.split(',').find(|host| !host.starts_with('|')))
            .flatten()
            .map(|host| {
                host.trim_start_matches('[')
                    .split(']')
                    .next()
                    .unwrap_or(host)
                    .to_owned()
            })
    })
}

fn host_label(blob: &[u8]) -> String {
    let path =
        directories::BaseDirs::new().map(|dirs| dirs.home_dir().join(".ssh").join("known_hosts"));
    path.and_then(|path| fs::read_to_string(path).ok())
        .and_then(|text| known_host(&text, blob))
        .map(|name| format!("{name} ({})", fingerprint(blob)))
        .unwrap_or_else(|| fingerprint(blob))
}

/// Answers one agent message. Malformed requests get a failure reply.
async fn respond(
    message: &[u8],
    worker: &VaultWorker,
    approvals: &SshApprovals,
    binding: &mut Binding,
) -> Vec<u8> {
    match message.first() {
        Some(&REQUEST_IDENTITIES) if message.len() == 1 => {
            let identities = worker
                .with_session(|session| {
                    session
                        .vault()
                        .map(Vault::ssh_identities)
                        .unwrap_or_default()
                })
                .await
                .unwrap_or_default();
            let mut reply = vec![IDENTITIES_ANSWER];
            reply.extend_from_slice(&(identities.len() as u32).to_be_bytes());
            for identity in identities {
                crate::vault::ssh_agent::put_string(&mut reply, &identity.blob);
                crate::vault::ssh_agent::put_string(&mut reply, identity.comment.as_bytes());
            }
            reply
        }
        Some(&EXTENSION) => {
            let mut rest = &message[1..];
            if take_string(&mut rest) != Some(b"session-bind@openssh.com".as_slice()) {
                return vec![FAILURE];
            }
            let (Some(host_key), Some(_session), Some(_signature)) = (
                take_string(&mut rest),
                take_string(&mut rest),
                take_string(&mut rest),
            ) else {
                return vec![FAILURE];
            };
            let &[forwarding] = rest else {
                return vec![FAILURE];
            };
            // OpenSSH binds each hop; the last binding names the destination.
            binding.forwarded |= forwarding != 0;
            binding.host = Some(host_label(host_key));
            vec![SUCCESS]
        }
        Some(&SIGN_REQUEST) => {
            let mut rest = &message[1..];
            let (Some(blob), Some(data)) = (take_string(&mut rest), take_string(&mut rest)) else {
                return vec![FAILURE];
            };
            // Flags select RSA hash variants; Ed25519 has none.
            if rest.len() != 4 || binding.forwarded {
                return vec![FAILURE];
            }
            let (blob, data) = (blob.to_vec(), Zeroizing::new(data.to_vec()));
            let lookup = blob.clone();
            let Some(found) = worker
                .with_session(move |session| session.vault()?.ssh_key_for(&lookup))
                .await
                .ok()
                .flatten()
            else {
                return vec![FAILURE];
            };
            if found.policy == crate::vault::ssh_agent::SshUse::Confirm {
                let host = binding
                    .host
                    .clone()
                    .unwrap_or_else(|| "an unknown host".into());
                if !approvals.ask(found.name.clone(), host).await {
                    return vec![FAILURE];
                }
            }
            let signature = worker
                .with_session(move |session| session.vault()?.ssh_sign(found.id, &blob, &data))
                .await
                .ok()
                .flatten();
            match signature {
                Some(signature) => {
                    let mut reply = vec![SIGN_RESPONSE];
                    crate::vault::ssh_agent::put_string(&mut reply, &signature);
                    reply
                }
                None => vec![FAILURE],
            }
        }
        _ => vec![FAILURE],
    }
}

fn take_string<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
    let value = input.get(4..4usize.checked_add(length)?)?;
    *input = &input[4 + length..];
    Some(value)
}

async fn connection<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: S,
    worker: VaultWorker,
    approvals: Arc<SshApprovals>,
) {
    let mut binding = Binding::default();
    loop {
        let mut length = [0; 4];
        if stream.read_exact(&mut length).await.is_err() {
            return;
        }
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_MESSAGE {
            return;
        }
        let mut message = Zeroizing::new(vec![0; length]);
        if stream.read_exact(&mut message).await.is_err() {
            return;
        }
        let reply = respond(&message, &worker, &approvals, &mut binding).await;
        let mut framed = Vec::with_capacity(reply.len() + 4);
        framed.extend_from_slice(&(reply.len() as u32).to_be_bytes());
        framed.extend_from_slice(&reply);
        if stream.write_all(&framed).await.is_err() {
            return;
        }
    }
}

#[cfg(unix)]
pub(super) struct Agent {
    path: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(unix)]
impl Agent {
    /// Binds the socket in an owner-only directory and serves it. A stale socket
    /// is replaced: the caller holds the data directory's server lock.
    pub(super) fn start(worker: VaultWorker, approvals: Arc<SshApprovals>) -> Result<Self, String> {
        use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
        let path = socket_path();
        let directory = path.parent().expect("socket has a directory");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)
            .map_err(|e| format!("could not create {}: {e}", directory.display()))?;
        // The directory may be in a shared temporary directory: it must belong
        // to the same user as the vaults before anything listens in it.
        let user = fs::metadata(data_dir()).map_err(|e| e.to_string())?.uid();
        if fs::symlink_metadata(directory)
            .map_err(|e| e.to_string())?
            .uid()
            != user
        {
            return Err(format!("{} belongs to another user", directory.display()));
        }
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("could not secure {}: {e}", directory.display()))?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(&path)
                .map_err(|e| format!("could not replace stale agent socket: {e}"))?,
            Ok(_) => return Err(format!("{} exists and is not a socket", path.display())),
            Err(_) => {}
        }
        let listener = tokio::net::UnixListener::bind(&path)
            .map_err(|e| format!("could not listen on {}: {e}", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("could not secure {}: {e}", path.display()))?;
        let owner = fs::metadata(&path).map_err(|e| e.to_string())?.uid();
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    // A persistent error (such as no free file handles) must
                    // not spin.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                // The directory and socket are owner-only; also refuse any peer
                // running as another user.
                if stream.peer_cred().map(|cred| cred.uid()).ok() != Some(owner) {
                    continue;
                }
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    continue;
                };
                let (worker, approvals) = (worker.clone(), Arc::clone(&approvals));
                tokio::spawn(async move {
                    let _permit = permit;
                    connection(stream, worker, approvals).await;
                });
            }
        });
        Ok(Self { path, task })
    }

    pub(super) fn stop(self) {
        self.task.abort();
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(windows)]
pub(super) struct Agent {
    task: tokio::task::JoinHandle<()>,
}

#[cfg(windows)]
impl Agent {
    /// Creates the pipe with a DACL for the current user only and serves it.
    /// The first instance must be new, so the agent never shares its name with
    /// a pipe some other process created first.
    pub(super) fn start(worker: VaultWorker, approvals: Arc<SshApprovals>) -> Result<Self, String> {
        use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
        let name = socket_path();
        let shown = name.display().to_string();
        let security = crate::file::PrivateSecurityAttributes::new()
            .map_err(|e| format!("could not secure {shown}: {e}"))?;
        let create = move |first: bool| -> std::io::Result<NamedPipeServer> {
            let mut options = ServerOptions::new();
            options
                .first_pipe_instance(first)
                .reject_remote_clients(true);
            // SAFETY: the attributes are valid and outlive the call.
            unsafe { options.create_with_security_attributes_raw(&name, security.as_ptr()) }
        };
        let mut server = create(true).map_err(|e| format!("could not listen on {shown}: {e}"))?;
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let task = tokio::spawn(async move {
            loop {
                let connected = server.connect().await;
                // Another instance must be waiting before this one is handed
                // off, or new clients would find no pipe. A persistent error
                // (such as no free handles) must not spin.
                let next = loop {
                    match create(false) {
                        Ok(next) => break next,
                        Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                    }
                };
                let client = std::mem::replace(&mut server, next);
                if connected.is_err() {
                    continue;
                }
                // Dropping the instance disconnects a client over the limit.
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    continue;
                };
                let (worker, approvals) = (worker.clone(), Arc::clone(&approvals));
                tokio::spawn(async move {
                    let _permit = permit;
                    connection(client, worker, approvals).await;
                });
            }
        });
        Ok(Self { task })
    }

    /// The pipe disappears once its last instance closes.
    pub(super) fn stop(self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::ssh_agent::tests::{add_key, test_key};

    fn worker_with(vault: Option<Vault>) -> VaultWorker {
        let session = match vault {
            Some(vault) => VaultSession::unlock(
                vault,
                VaultCredentials::Session {
                    encryption_key: [1; 32],
                    salt: [1; 16],
                    kdf: 1,
                    memory_kib: 8192,
                    iterations: 1,
                    parallelism: 1,
                },
            ),
            None => VaultSession::Locked,
        };
        VaultWorker::start(
            session,
            Arc::new(AtomicU64::new(0)),
            Arc::new(Mutex::new(None)),
        )
    }

    fn string(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        crate::vault::ssh_agent::put_string(&mut out, bytes);
        out
    }

    fn sign_request(blob: &[u8]) -> Vec<u8> {
        let mut sign = vec![SIGN_REQUEST];
        sign.extend(string(blob));
        sign.extend(string(b"session data"));
        sign.extend(0u32.to_be_bytes());
        sign
    }

    fn bind(host_key: &[u8], forwarding: bool) -> Vec<u8> {
        let mut message = vec![EXTENSION];
        message.extend(string(b"session-bind@openssh.com"));
        message.extend(string(host_key));
        message.extend(string(b"session id"));
        message.extend(string(b"signature"));
        message.push(u8::from(forwarding));
        message
    }

    async fn exchange(
        worker: &VaultWorker,
        approvals: &Arc<SshApprovals>,
        messages: &[Vec<u8>],
    ) -> Vec<Vec<u8>> {
        let (client, server) = tokio::io::duplex(MAX_MESSAGE * 2);
        let serving = tokio::spawn(connection(server, worker.clone(), Arc::clone(approvals)));
        let (mut read, mut write) = tokio::io::split(client);
        let mut replies = Vec::new();
        for message in messages {
            write
                .write_all(&(message.len() as u32).to_be_bytes())
                .await
                .unwrap();
            write.write_all(message).await.unwrap();
            let mut length = [0; 4];
            read.read_exact(&mut length).await.unwrap();
            let mut reply = vec![0; u32::from_be_bytes(length) as usize];
            read.read_exact(&mut reply).await.unwrap();
            replies.push(reply);
        }
        drop(write);
        drop(read);
        let _ = serving.await;
        replies
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn agent_lists_and_signs_only_enabled_keys_while_unlocked() {
        let mut vault = Vault::memory();
        let (key, blob) = test_key(None);
        add_key(
            &mut vault,
            "Deploy",
            &key,
            None,
            ItemKind::SshKey,
            Some("on"),
        );
        let worker = worker_with(Some(vault));
        let approvals = Arc::new(SshApprovals::default());
        let mut unknown = vec![SIGN_REQUEST];
        unknown.extend(string(b"other key"));
        unknown.extend(string(b"data"));
        unknown.extend(0u32.to_be_bytes());
        let mut other_extension = vec![EXTENSION];
        other_extension.extend(string(b"query"));
        let replies = exchange(
            &worker,
            &approvals,
            &[
                vec![REQUEST_IDENTITIES],
                sign_request(&blob),
                unknown,
                vec![SIGN_REQUEST, 0, 0],
                vec![17],
                vec![REQUEST_IDENTITIES, 0],
                other_extension,
                vec![EXTENSION, 0, 0, 0, 24],
            ],
        )
        .await;
        let mut identities = replies[0][1..].to_vec();
        assert_eq!(replies[0][0], IDENTITIES_ANSWER);
        assert_eq!(&identities[..4], &1u32.to_be_bytes());
        identities.drain(..4);
        let mut rest = &identities[..];
        assert_eq!(take_string(&mut rest).unwrap(), blob);
        assert_eq!(take_string(&mut rest).unwrap(), b"Deploy");
        assert_eq!(replies[1][0], SIGN_RESPONSE);
        for reply in &replies[2..] {
            assert_eq!(reply, &[FAILURE]);
        }

        worker.lock().await;
        let replies = exchange(
            &worker,
            &approvals,
            &[vec![REQUEST_IDENTITIES], sign_request(&blob)],
        )
        .await;
        assert_eq!(replies[0], [IDENTITIES_ANSWER, 0, 0, 0, 0]);
        assert_eq!(replies[1], [FAILURE]);
        let locked = worker_with(None);
        assert_eq!(
            exchange(&locked, &approvals, &[vec![REQUEST_IDENTITIES]]).await[0],
            [IDENTITIES_ANSWER, 0, 0, 0, 0]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn forwarded_requests_are_refused_and_bindings_name_the_host() {
        let mut vault = Vault::memory();
        let (key, blob) = test_key(None);
        add_key(
            &mut vault,
            "Deploy",
            &key,
            None,
            ItemKind::SshKey,
            Some("on"),
        );
        let worker = worker_with(Some(vault));
        let approvals = Arc::new(SshApprovals::default());
        let replies = exchange(
            &worker,
            &approvals,
            &[bind(b"host key", false), sign_request(&blob)],
        )
        .await;
        assert_eq!(replies[0], [SUCCESS]);
        assert_eq!(replies[1][0], SIGN_RESPONSE, "a direct connection may sign");
        let replies = exchange(
            &worker,
            &approvals,
            &[
                bind(b"jump host", false),
                bind(b"inner host", true),
                sign_request(&blob),
            ],
        )
        .await;
        assert_eq!(
            replies[2],
            [FAILURE],
            "a request relayed by agent forwarding is refused"
        );
        let malformed = exchange(&worker, &approvals, &[bind(b"host", false)[..20].to_vec()]).await;
        assert_eq!(malformed[0], [FAILURE]);

        let host_key = b"synthetic host key";
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(host_key);
        let known = format!(
            "|1|hashed|entry ssh-ed25519 {encoded}\n@cert-authority *.corp ssh-ed25519 other\n[git.example.com]:2222,10.0.0.5 ssh-ed25519 {encoded} comment\n"
        );
        assert_eq!(
            known_host(&known, host_key).as_deref(),
            Some("git.example.com")
        );
        assert_eq!(known_host("github.com ssh-ed25519 nope", host_key), None);
        assert!(fingerprint(host_key).starts_with("SHA256:"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn confirm_keys_wait_for_a_decision_and_refuse_without_one() {
        let mut vault = Vault::memory();
        let (key, blob) = test_key(None);
        add_key(
            &mut vault,
            "Production",
            &key,
            None,
            ItemKind::SshKey,
            Some("confirm"),
        );
        let worker = worker_with(Some(vault));
        let approvals = Arc::new(SshApprovals::default());
        for allow in [true, false] {
            let decider = Arc::clone(&approvals);
            let deciding = tokio::spawn(async move {
                loop {
                    if let Some(request) = decider.list().into_iter().next() {
                        assert_eq!(request.key, "Production");
                        assert!(request.host.starts_with("SHA256:"), "{}", request.host);
                        assert!(decider.decide(&request.id, allow));
                        assert!(!decider.decide(&request.id, allow), "answered once");
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            });
            let replies = exchange(
                &worker,
                &approvals,
                &[bind(b"host", false), sign_request(&blob)],
            )
            .await;
            deciding.await.unwrap();
            assert_eq!(replies[1][0], if allow { SIGN_RESPONSE } else { FAILURE });
            assert!(approvals.list().is_empty());
        }
        assert!(!approvals.decide("missing", true));
    }

    #[test]
    fn pipe_names_are_stable_and_distinct_per_data_directory() {
        let data = std::path::Path::new(r"C:\Users\a\AppData\Roaming\password_manager");
        let name = pipe_name_for(data);
        let text = name.to_str().unwrap();
        assert!(text.starts_with(r"\\.\pipe\pm-ssh-agent-"), "{text}");
        assert_eq!(text.len(), r"\\.\pipe\pm-ssh-agent-".len() + 16);
        assert_eq!(name, pipe_name_for(data));
        assert_ne!(
            name,
            pipe_name_for(std::path::Path::new(
                r"C:\Users\b\AppData\Roaming\password_manager"
            ))
        );
    }

    #[test]
    fn long_data_directories_use_a_short_private_socket_path() {
        let short = std::path::Path::new("/home/user/.local/share/password_manager");
        assert_eq!(
            socket_path_for(short, "/run/user/1000".into()),
            short.join("agent").join("ssh-agent.sock")
        );
        let long = std::path::PathBuf::from(format!("/home/{}", "x".repeat(120)));
        let path = socket_path_for(&long, "/run/user/1000".into());
        assert!(path.starts_with("/run/user/1000"));
        assert!(path.as_os_str().len() <= MAX_SOCKET_PATH);
        assert_eq!(path, socket_path_for(&long, "/run/user/1000".into()));
        assert_ne!(
            path,
            socket_path_for(&long.join("other"), "/run/user/1000".into())
        );
    }

    #[tokio::test]
    async fn oversized_or_empty_frames_close_the_connection() {
        let worker = worker_with(None);
        for length in [0u32, (MAX_MESSAGE + 1) as u32] {
            let (client, server) = tokio::io::duplex(64);
            let serving = tokio::spawn(connection(server, worker.clone(), Arc::default()));
            let (mut read, mut write) = tokio::io::split(client);
            write.write_all(&length.to_be_bytes()).await.unwrap();
            serving.await.unwrap();
            let mut buffer = [0; 1];
            assert_eq!(read.read(&mut buffer).await.unwrap(), 0);
        }
    }
}
