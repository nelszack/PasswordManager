//! Browser passkey requests waiting for the person to confirm, in the desktop
//! app or CLI, that it is them. A confirmed request yields a one-time token
//! bound to the site and unlock session; redeeming it is the only way a
//! passkey response reports user verification.
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use crate::protocol::PasskeyRequest;

/// How long a request waits for an answer. Shorter than the browser's
/// passkey window and the native host's request timeout.
pub(super) const DECISION_WAIT: Duration = Duration::from_secs(90);
/// How long a granted token stays redeemable.
const TOKEN_LIFETIME: Duration = Duration::from_secs(60);
const MAX_PENDING: usize = 8;

struct Pending {
    request: PasskeyRequest,
    session: String,
    answer: oneshot::Sender<Option<String>>,
}

struct Granted {
    token: String,
    origin: String,
    session: String,
    expires: Instant,
}

#[derive(Default)]
pub(super) struct PasskeyApprovals {
    pending: std::sync::Mutex<Vec<Pending>>,
    granted: std::sync::Mutex<Vec<Granted>>,
    /// Wakes status subscribers so a request appears at once.
    pub(super) changed: tokio::sync::Notify,
}

fn guard<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl PasskeyApprovals {
    #[cfg(test)]
    fn list(&self) -> Vec<PasskeyRequest> {
        guard(&self.pending)
            .iter()
            .filter(|pending| !pending.answer.is_closed())
            .map(|pending| pending.request.clone())
            .collect()
    }

    /// Requests still waiting from this unlock session; none while locked.
    pub(super) fn list_for(&self, session: Option<&str>) -> Vec<PasskeyRequest> {
        guard(&self.pending)
            .iter()
            .filter(|pending| {
                !pending.answer.is_closed() && Some(pending.session.as_str()) == session
            })
            .map(|pending| pending.request.clone())
            .collect()
    }

    /// Waits for the person's answer. `Ok(token)` when confirmed.
    pub(super) async fn ask(&self, origin: String, session: String) -> Result<String, String> {
        let id = hex::encode(rand::random::<[u8; 6]>());
        let (send, receive) = oneshot::channel();
        {
            let mut pending = guard(&self.pending);
            pending.retain(|pending| !pending.answer.is_closed());
            if pending.len() >= MAX_PENDING {
                return Err("Too many passkey requests are waiting.".into());
            }
            pending.push(Pending {
                request: PasskeyRequest {
                    id: id.clone(),
                    site: origin,
                },
                session,
                answer: send,
            });
        }
        self.changed.notify_waiters();
        let answer = tokio::time::timeout(DECISION_WAIT, receive).await;
        guard(&self.pending).retain(|pending| pending.request.id != id);
        self.changed.notify_waiters();
        match answer {
            Ok(Ok(Some(token))) => Ok(token),
            Ok(Ok(None)) => Err("Refused in the desktop app.".into()),
            _ => Err("Nobody confirmed the passkey request in time.".into()),
        }
    }

    /// The unlock session a waiting request belongs to.
    pub(super) fn session_of(&self, id: &str) -> Option<String> {
        guard(&self.pending)
            .iter()
            .find(|pending| pending.request.id == id && !pending.answer.is_closed())
            .map(|pending| pending.session.clone())
    }

    /// Answers a waiting request: confirmed creates a token. False if it is no
    /// longer waiting.
    pub(super) fn decide(&self, id: &str, confirmed: bool) -> bool {
        let Some(pending) = ({
            let mut pending = guard(&self.pending);
            pending
                .iter()
                .position(|pending| pending.request.id == id)
                .map(|index| pending.remove(index))
        }) else {
            return false;
        };
        self.changed.notify_waiters();
        let token = confirmed.then(|| {
            let token = hex::encode(rand::random::<[u8; 32]>());
            let mut granted = guard(&self.granted);
            let now = Instant::now();
            granted.retain(|grant| grant.expires > now);
            granted.push(Granted {
                token: token.clone(),
                origin: pending.request.site.clone(),
                session: pending.session.clone(),
                expires: now + TOKEN_LIFETIME,
            });
            token
        });
        pending.answer.send(token).is_ok()
    }

    /// Consumes a token for this site and session; true only once.
    pub(super) fn redeem(&self, token: &str, origin: &str, session: Option<&str>) -> bool {
        let mut granted = guard(&self.granted);
        let now = Instant::now();
        granted.retain(|grant| grant.expires > now);
        let Some(index) = granted.iter().position(|grant| {
            bool::from(subtle::ConstantTimeEq::ct_eq(
                grant.token.as_bytes(),
                token.as_bytes(),
            ))
        }) else {
            return false;
        };
        let grant = granted.remove(index);
        grant.origin == origin && Some(grant.session.as_str()) == session
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Starts a request for example.com in session `s1` and returns its id
    /// with the pending answer.
    async fn asked(
        approvals: &Arc<PasskeyApprovals>,
    ) -> (String, tokio::task::JoinHandle<Result<String, String>>) {
        let waiting = {
            let approvals = Arc::clone(approvals);
            tokio::spawn(async move {
                approvals
                    .ask("https://example.com".into(), "s1".into())
                    .await
            })
        };
        loop {
            if let Some(request) = approvals.list().into_iter().next() {
                return (request.id, waiting);
            }
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn confirmed_requests_yield_one_time_tokens_for_their_site_and_session() {
        let approvals = Arc::new(PasskeyApprovals::default());
        let (id, waiting) = asked(&approvals).await;
        assert_eq!(approvals.session_of(&id).as_deref(), Some("s1"));
        assert_eq!(approvals.list_for(Some("s1")).len(), 1);
        assert!(
            approvals.list_for(Some("s2")).is_empty(),
            "other sessions see nothing"
        );
        assert!(approvals.list_for(None).is_empty(), "nothing while locked");
        assert!(approvals.decide(&id, true));
        assert!(!approvals.decide(&id, true), "answered once");
        let token = waiting.await.unwrap().unwrap();
        // A token offered for another site is spent, not reusable.
        assert!(!approvals.redeem(&token, "https://other.test", Some("s1")));
        assert!(
            !approvals.redeem(&token, "https://example.com", Some("s1")),
            "spent"
        );

        let (id, waiting) = asked(&approvals).await;
        approvals.decide(&id, true);
        let token = waiting.await.unwrap().unwrap();
        assert!(
            !approvals.redeem(&token, "https://example.com", Some("s2")),
            "other session"
        );
        assert!(!approvals.redeem("not-a-token", "https://example.com", Some("s1")));

        let (id, waiting) = asked(&approvals).await;
        approvals.decide(&id, false);
        assert!(waiting.await.unwrap().unwrap_err().contains("Refused"));
        assert!(approvals.list().is_empty());
    }
}
