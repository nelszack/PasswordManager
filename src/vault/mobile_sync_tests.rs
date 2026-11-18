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
            thread: Some(thread),
        }
    }
    fn call(&self, api: &mut MobileVault, op: &str, extra: Value) -> Result<Value, String> {
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
