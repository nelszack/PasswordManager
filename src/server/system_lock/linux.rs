use super::*;
use futures_lite::StreamExt;
use std::{collections::HashMap, num::NonZeroUsize, time::Duration};
use zbus::{
    Connection, MatchRule, MessageStream, Proxy, block_on,
    message::Type,
    wire::{OwnedFd, OwnedObjectPath, OwnedVariant},
};

pub(super) fn start(watch: Watch) {
    for (source, operation) in [
        (
            "logind",
            system as fn(&Watch) -> Result<(), Box<dyn std::error::Error>>,
        ),
        ("desktop", desktop),
    ] {
        let watch = watch.clone();
        std::thread::spawn(move || {
            // Block only on individual D-Bus operations: lock callbacks use
            // blocking_send and must run outside a Tokio async context.
            while !watch.stopped() {
                if let Err(error) = operation(&watch) {
                    watch.warning(source, error);
                }
                for _ in 0..50 {
                    if watch.stopped() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        });
    }
    // Standalone Wayland/X11 lockers do not all publish D-Bus lock hints.
    // Observe only same-user, known locker executables as a conservative fallback.
    std::thread::spawn(move || {
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata("/proc/self").map(|m| m.uid()).ok();
        while !watch.stopped() {
            if let Ok(processes) = std::fs::read_dir("/proc") {
                let locked = processes.flatten().any(|process| {
                    process
                        .metadata()
                        .ok()
                        .is_some_and(|m| Some(m.uid()) == uid)
                        && std::fs::read_link(process.path().join("exe"))
                            .ok()
                            .and_then(|p| p.file_name().map(|name| name.to_owned()))
                            .is_some_and(|name| {
                                matches!(
                                    name.to_str(),
                                    Some("hyprlock" | "swaylock" | "i3lock" | "xsecurelock")
                                )
                            })
                });
                if locked {
                    watch.lock();
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    });
}

fn inhibitor(manager: &Proxy<'_>) -> zbus::Result<OwnedFd> {
    block_on(manager.call(
        "Inhibit",
        &(
            "sleep",
            "Password Manager",
            "Lock vault before suspend",
            "delay",
        ),
    ))
}

fn resolve_session(
    by_pid: zbus::Result<OwnedObjectPath>,
    auto: impl FnOnce() -> zbus::Result<OwnedObjectPath>,
) -> zbus::Result<OwnedObjectPath> {
    match by_pid {
        // Apps launched in systemd user scopes are outside the login session.
        // Let logind resolve the calling user's display session, returning its
        // concrete object path so the signal filtering below still works.
        Err(zbus::Error::MethodError(ref name, _, _))
            if name.as_str() == "org.freedesktop.login1.NoSessionForPID" =>
        {
            auto()
        }
        result => result,
    }
}

fn system(watch: &Watch) -> Result<(), Box<dyn std::error::Error>> {
    let connection = block_on(Connection::system())?;
    let manager = block_on(Proxy::new(
        &connection,
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    ))?;
    let session: Option<OwnedObjectPath> = match resolve_session(
        block_on(manager.call("GetSessionByPID", &(std::process::id(),))),
        || block_on(manager.call("GetSession", &("auto",))),
    ) {
        Ok(path) => {
            watch.ready("session");
            Some(path)
        }
        Err(error) => {
            watch.warning("session", error);
            None
        }
    };
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender("org.freedesktop.login1")
        .build()?;
    let mut messages = block_on(MessageStream::for_match_rule(
        rule,
        &connection,
        NonZeroUsize::new(64),
    ))?;
    let mut delay = match inhibitor(&manager) {
        Ok(fd) => Some(fd),
        Err(error) => {
            watch.warning("suspend inhibitor", error);
            None
        }
    };
    let session_proxy = session
        .as_ref()
        .map(|path| {
            block_on(Proxy::new(
                &connection,
                "org.freedesktop.login1",
                path.as_str(),
                "org.freedesktop.login1.Session",
            ))
        })
        .transpose()?;
    if session_proxy
        .as_ref()
        .is_some_and(|proxy| block_on(proxy.get_property::<bool>("LockedHint")).unwrap_or(false))
    {
        watch.lock();
    }
    watch.ready("logind");
    while let Some(message) = block_on(messages.next()) {
        if watch.stopped() {
            break;
        }
        let message = match message {
            Ok(message) => message,
            Err(error) => {
                watch.lock();
                return Err(error.into());
            }
        };
        let header = message.header();
        let member = header.member().map(|v| v.as_str()).unwrap_or("");
        let path = header.path().map(|v| v.as_str()).unwrap_or("");
        let interface = header.interface().map(|v| v.as_str()).unwrap_or("");
        if path == "/org/freedesktop/login1"
            && interface == "org.freedesktop.login1.Manager"
            && member == "PrepareForSleep"
        {
            let sleeping: bool = message.body().deserialize()?;
            // Lock on resume as well, including missed/forced suspend events.
            watch.lock();
            if sleeping {
                delay.take();
            } else {
                match inhibitor(&manager) {
                    Ok(fd) => {
                        delay = Some(fd);
                        watch.ready("suspend inhibitor");
                    }
                    Err(error) => watch.warning("suspend inhibitor", error),
                }
            }
        } else if session
            .as_ref()
            .is_some_and(|session| path == session.as_str())
        {
            if interface == "org.freedesktop.login1.Session" && member == "Lock" {
                watch.lock();
            }
            if interface == "org.freedesktop.DBus.Properties" && member == "PropertiesChanged" {
                let (interface, properties, invalidated): (
                    String,
                    HashMap<String, OwnedVariant>,
                    Vec<String>,
                ) = message.body().deserialize()?;
                if interface == "org.freedesktop.login1.Session"
                    && (properties
                        .get("LockedHint")
                        .is_some_and(|value| bool::try_from(value).unwrap_or(false))
                        || invalidated.iter().any(|key| key == "LockedHint")
                            && session_proxy.as_ref().is_none_or(|proxy| {
                                block_on(proxy.get_property::<bool>("LockedHint")).unwrap_or(true)
                            }))
                {
                    watch.lock();
                }
            }
        }
    }
    Ok(())
}

fn desktop(watch: &Watch) -> Result<(), Box<dyn std::error::Error>> {
    let connection = block_on(Connection::session())?;
    // Separate authenticated bus sender matches prevent arbitrary website
    // metadata from being interpreted as an OS event.
    let names = [
        (
            "org.freedesktop.ScreenSaver",
            "/org/freedesktop/ScreenSaver",
        ),
        ("org.gnome.ScreenSaver", "/org/gnome/ScreenSaver"),
        ("org.kde.screensaver", "/ScreenSaver"),
    ];
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .member("ActiveChanged")
        .build()?;
    let mut messages = block_on(MessageStream::for_match_rule(
        rule,
        &connection,
        NonZeroUsize::new(16),
    ))?;
    watch.ready("desktop");
    while let Some(message) = block_on(messages.next()) {
        if watch.stopped() {
            break;
        }
        let message = message?;
        let header = message.header();
        let Some(sender) = header.sender() else {
            continue;
        };
        let Some(path) = header.path() else {
            continue;
        };
        let bus = block_on(zbus::fdo::DBusProxy::new(&connection))?;
        let trusted = names.iter().any(|(name, expected_path)| {
            (path.as_str() == *expected_path || path.as_str() == "/ScreenSaver")
                && zbus::names::BusName::try_from(*name)
                    .ok()
                    .and_then(|name| block_on(bus.get_name_owner(name)).ok())
                    .is_some_and(|owner| owner.as_str() == sender.as_str())
        });
        if trusted && message.body().deserialize::<bool>().unwrap_or(false) {
            watch.lock();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method_error(name: &str) -> zbus::Error {
        let call = zbus::Message::method_call("/org/freedesktop/login1", "GetSessionByPID")
            .build(&(123_u32,))
            .unwrap();
        let reply = zbus::Message::error(&call.header(), name)
            .build(&())
            .unwrap();
        zbus::Error::MethodError(name.try_into().unwrap(), None, reply)
    }

    #[test]
    fn process_session_takes_precedence_over_display_session() {
        let path = OwnedObjectPath::try_from("/org/freedesktop/login1/session/_32").unwrap();
        let result = resolve_session(Ok(path.clone()), || panic!("unneeded fallback"));
        assert_eq!(result.unwrap(), path);
    }

    #[test]
    fn user_scope_process_resolves_concrete_display_session_path() {
        let path = OwnedObjectPath::try_from("/org/freedesktop/login1/session/_32").unwrap();
        let result = resolve_session(
            Err(method_error("org.freedesktop.login1.NoSessionForPID")),
            || Ok(path.clone()),
        );
        assert_eq!(result.unwrap(), path);
    }

    #[test]
    fn other_lookup_errors_are_preserved_without_fallback() {
        let result = resolve_session(
            Err(method_error("org.freedesktop.DBus.Error.AccessDenied")),
            || panic!("must not hide an unrelated failure"),
        );
        assert!(result.unwrap_err().to_string().contains("AccessDenied"));
    }

    #[test]
    fn missing_display_session_still_reports_an_error() {
        let result = resolve_session(
            Err(method_error("org.freedesktop.login1.NoSessionForPID")),
            || Err(method_error("org.freedesktop.login1.NoSuchSession")),
        );
        assert!(result.unwrap_err().to_string().contains("NoSuchSession"));
    }
}
