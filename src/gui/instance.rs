//! One desktop window per user session. A second launch (the browser's "Open
//! desktop app", a desktop shortcut, or `pm gui --search` bound to a key) asks
//! the running window to come forward instead of opening another one.
//!
//! Unix only: the running app listens on a private socket in the runtime
//! directory. Elsewhere every launch opens its own window, as before.

/// What the second launch wants the running window to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    /// Come forward; when locked, focus the master password.
    Focus,
    /// Come forward with the vault search focused.
    Search,
    /// Come forward showing this item (after unlocking, if locked). Sent by the
    /// browser extension's "Open in desktop app".
    Open(usize),
}

// The wire format is only spoken over the Unix socket (and checked by tests).
#[cfg_attr(not(unix), allow(dead_code))]
impl Request {
    fn wire(self) -> String {
        match self {
            Self::Focus => "focus".into(),
            Self::Search => "search".into(),
            Self::Open(id) => format!("open {id}"),
        }
    }
    fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "focus" => Some(Self::Focus),
            "search" => Some(Self::Search),
            other => other
                .strip_prefix("open ")
                .and_then(|id| id.parse().ok())
                .filter(|id| *id > 0)
                .map(Self::Open),
        }
    }
}

#[cfg(unix)]
fn socket_path() -> std::path::PathBuf {
    let directory = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_dir())
        .unwrap_or_else(password_manager::file::data_dir);
    directory.join("password-manager-gui.sock")
}

/// Hand the request to a running window. Returns whether one accepted it.
pub fn forward(request: Request) -> bool {
    #[cfg(unix)]
    {
        use std::io::Write;
        let Ok(mut stream) = std::os::unix::net::UnixStream::connect(socket_path()) else {
            return false;
        };
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
        stream
            .write_all(format!("{}\n", request.wire()).as_bytes())
            .is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        false
    }
}

/// Requests from later launches, for as long as this window runs.
pub(super) fn requests() -> impl iced::futures::Stream<Item = super::Message> {
    iced::stream::channel(4, async move |output| {
        #[cfg(unix)]
        std::thread::spawn(move || listen(output));
        #[cfg(not(unix))]
        drop(output);
        std::future::pending::<()>().await
    })
}

#[cfg(unix)]
fn listen(mut output: iced::futures::channel::mpsc::Sender<super::Message>) {
    use std::io::BufRead;
    use std::os::unix::fs::PermissionsExt;
    let path = socket_path();
    // A socket left by a crashed window accepts no connection; replace it.
    if std::os::unix::net::UnixStream::connect(&path).is_err() {
        let _ = std::fs::remove_file(&path);
    }
    let Ok(listener) = std::os::unix::net::UnixListener::bind(&path) else {
        return;
    };
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    for stream in listener.incoming().flatten() {
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
        let mut line = String::new();
        if std::io::BufReader::new(stream).read_line(&mut line).is_ok()
            && let Some(request) = Request::parse(&line)
            && output
                .try_send(super::Message::Raise(request))
                .is_err_and(|error| error.is_disconnected())
        {
            break;
        }
    }
    let _ = std::fs::remove_file(&path);
}

#[cfg(test)]
mod tests {
    use super::Request;
    #[test]
    fn requests_round_trip_and_reject_unknown_lines() {
        for request in [Request::Focus, Request::Search, Request::Open(42)] {
            assert_eq!(
                Request::parse(&format!("{}\n", request.wire())),
                Some(request)
            );
        }
        assert_eq!(Request::parse("unlock-everything"), None);
        assert_eq!(Request::parse("open 0"), None);
        assert_eq!(Request::parse("open -1"), None);
    }
}
