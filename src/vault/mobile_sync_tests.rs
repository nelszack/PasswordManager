//! An isolated protocol peer exercises mobile synchronization and retry policy.
use super::test_support::*;
use super::*;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

#[derive(Default)]
struct Remote {
    bytes: Vec<u8>,
    version: u64,
    lose_ack: bool,
}
struct Peer {
    url: String,
    state: Arc<Mutex<Remote>>,
    stopped: Arc<AtomicBool>,
    /// Requests read so far, counted before the peer locks its state.
    requests: Arc<std::sync::atomic::AtomicUsize>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}
impl Peer {
    fn start() -> Self {
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", socket.local_addr().unwrap());
        let state = Arc::new(Mutex::new(Remote::default()));
        let stopped = Arc::new(AtomicBool::new(false));
        let data = state.clone();
        let stop = stopped.clone();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = requests.clone();
        let thread = thread::spawn(move || {
            for connection in socket.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let mut stream = connection.unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut headers = Vec::new();
                let mut byte = [0];
                while !headers.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).is_err() {
                        break;
                    }
                    headers.push(byte[0]);
                    assert!(headers.len() < 16384);
                }
                let headers = String::from_utf8(headers).unwrap();
                let mut lines = headers.lines();
                let first = lines.next().unwrap();
                let method = first.split_whitespace().next().unwrap();
                let lower = headers.to_lowercase();
                assert!(lower.contains(&format!("authorization: bearer {}", "1".repeat(64))));
                let length = lower
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                seen.fetch_add(1, Ordering::SeqCst);
                let mut remote = data.lock().unwrap();
                let (code, response) = match method {
                    "HEAD" | "GET" if remote.version == 0 => (404, vec![]),
                    "HEAD" => (200, vec![]),
                    "GET" => (200, remote.bytes.clone()),
                    "PUT" => {
                        let expected = if remote.version == 0 {
                            "if-none-match: *".into()
                        } else {
                            format!("if-match: \"{:032x}\"", remote.version)
                        };
                        if !lower.contains(&expected) {
                            (412, vec![])
                        } else {
                            remote.bytes = body;
                            remote.version += 1;
                            if remote.lose_ack {
                                remote.lose_ack = false;
                                continue;
                            }
                            (
                                200,
                                json!({"version":format!("{:032x}",remote.version)})
                                    .to_string()
                                    .into_bytes(),
                            )
                        }
                    }
                    _ => (400, vec![]),
                };
                let size = if method == "HEAD" {
                    remote.bytes.len()
                } else {
                    response.len()
                };
                let header = format!(
                    "HTTP/1.1 {code} Result\r\nConnection: close\r\nContent-Length: \
                     {size}\r\nETag: \"{:032x}\"\r\n\r\n",
                    remote.version
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&response);
            }
        });
        Self {
            url,
            state,
            stopped,
            requests,
            thread: Some(thread),
        }
    }
    fn call(&self, api: &mut MobileVault, op: &str, extra: Value) -> Result<Value, String> {
        self.call_shared(api, op, extra)
    }
    fn call_shared(&self, api: &MobileVault, op: &str, extra: Value) -> Result<Value, String> {
        let mut request = json!({"op":op,"server":self.url,"token":"1".repeat(64)});
        for (k, v) in extra.as_object().unwrap() {
            request[k] = v.clone();
        }
        api.call(&request.to_string())
    }
}
#[test]
fn offline_conflicts_stale_reviews_and_lost_ack_preserve_data() {
    let peer = Peer::start();
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    let mut a = MobileVault::new(left.path().into()).unwrap();
    let mut b = MobileVault::new(right.path().into()).unwrap();
    let created = a
        .call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
        .unwrap();
    save(
        &mut a,
        "Example",
        "alice",
        "original",
        "https://example.com",
    )
    .unwrap();
    peer.call(&mut a, "sync", json!({})).unwrap();
    let id = created["vault"].as_str().unwrap().trim_end_matches(".enc");
    let downloaded = peer
        .call(&mut b, "cloud_download", json!({"id":id}))
        .unwrap();
    b.call(
        &json!({"op":"unlock","vault":downloaded["vault"],"password":"Cedar-Lantern-Quartz-9274!"})
            .to_string(),
    )
    .unwrap();
    update(&mut a, 1, "Example", "remote-password").unwrap();
    peer.call(&mut a, "sync", json!({})).unwrap();
    update(&mut b, 1, "Example", "local-password").unwrap();
    assert!(
        peer.call(&mut b, "sync", json!({}))
            .unwrap_err()
            .contains("conflict")
    );
    let review = peer.call(&mut b, "cloud_conflicts", json!({})).unwrap();
    assert!(!review.to_string().contains("local-password"));
    assert!(!review.to_string().contains("remote-password"));
    let choices: Vec<Value> = review["items"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|item| {
            item["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(move |f| json!({"id":item["id"],"field":f["field"],"side":"remote"}))
        })
        .collect();
    peer.call(
        &mut b,
        "cloud_resolve",
        json!({"review_token":review["token"],"choices":choices}),
    )
    .unwrap();
    assert_eq!(
        b.call(r#"{"op":"login","id":1,"origin":"https://example.com"}"#)
            .unwrap()["password"],
        "remote-password"
    );
    assert!(fs::read_dir(right.path()).unwrap().any(|p| {
        p.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("recovery-local-")
    }));
    let review = peer.call(&mut b, "cloud_conflicts", json!({})).unwrap();
    update(&mut b, 1, "Changed", "local-new").unwrap();
    assert!(
        peer.call(
            &mut b,
            "cloud_resolve",
            json!({"review_token":review["token"],"choices":[]})
        )
        .unwrap_err()
        .contains("changed since review")
    );
    peer.call(&mut a, "sync", json!({})).unwrap();
    update(&mut a, 1, "Example", "acknowledgement-lost").unwrap();
    peer.state.lock().unwrap().lose_ack = true;
    assert!(peer.call(&mut a, "sync", json!({})).is_err());
    peer.call(&mut a, "sync", json!({})).unwrap();
    assert_eq!(
        a.call(r#"{"op":"login","id":1,"origin":"https://example.com"}"#)
            .unwrap()["password"],
        "acknowledgement-lost"
    );
}

#[test]
fn network_waits_release_the_vault_and_the_lock_signal_interrupts_them() {
    static CANCEL: Cancellation = Cancellation::new();
    // Accepts connections but never answers, like a stalled server.
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", socket.local_addr().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let mut api = MobileVault::new(directory.path().into()).unwrap();
    api.set_cancellation(&CANCEL);
    api.call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
        .unwrap();
    save(
        &mut api,
        "Example",
        "alice",
        "secret",
        "https://example.com",
    )
    .unwrap();
    let api = &api;
    thread::scope(|scope| {
        let syncing = scope.spawn(|| {
            api.call(&json!({"op":"sync","server":url,"token":"1".repeat(64)}).to_string())
        });
        let _held = socket.accept().unwrap();
        // The sync is now waiting on the network; autofill still answers.
        let started = Instant::now();
        let logins = api
            .call(r#"{"op":"logins","origin":"https://example.com"}"#)
            .unwrap();
        assert_eq!(logins.as_array().unwrap().len(), 1);
        assert!(started.elapsed() < Duration::from_secs(5));
        CANCEL.signal();
        let interrupted = syncing.join().unwrap().unwrap_err();
        assert!(interrupted.contains("interrupted"), "{interrupted}");
    });
    assert!(api.call(r#"{"op":"status"}"#).is_err());
    api.call(r#"{"op":"lock"}"#).unwrap();
    assert_eq!(api.call(r#"{"op":"status"}"#).unwrap()["unlocked"], false);
}

#[test]
fn background_syncs_finish_their_upload_after_the_app_locks() {
    static CANCEL: Cancellation = Cancellation::new();
    let peer = Peer::start();
    let directory = tempfile::tempdir().unwrap();
    let mut api = MobileVault::new(directory.path().into()).unwrap();
    api.set_cancellation(&CANCEL);
    let created = api
        .call(r#"{"op":"create","password":"Cedar-Lantern-Quartz-9274!"}"#)
        .unwrap();
    save(
        &mut api,
        "Example",
        "alice",
        "secret",
        "https://example.com",
    )
    .unwrap();
    let held = peer.state.lock().unwrap();
    let api = &api;
    thread::scope(|scope| {
        let syncing = scope
            .spawn(|| peer.call_shared(api, "sync", json!({"background":true,"if_enabled":true})));
        // Wait until the snapshot was taken and the request reached the peer.
        while peer.requests.load(Ordering::SeqCst) == 0 {
            thread::sleep(Duration::from_millis(5));
        }
        CANCEL.signal();
        api.call(r#"{"op":"lock"}"#).unwrap();
        drop(held);
        assert_eq!(syncing.join().unwrap().unwrap()["synced"], true);
    });
    assert_eq!(peer.state.lock().unwrap().version, 1);
    // A sync started after the lock is refused rather than run without a session.
    assert!(
        peer.call_shared(api, "sync", json!({"background":true}))
            .is_err()
    );
    let id = created["vault"].as_str().unwrap();
    assert!(
        directory
            .path()
            .join(id)
            .with_extension("sync.json")
            .exists()
    );
}
