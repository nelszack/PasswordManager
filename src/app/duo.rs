use super::remote::target_type;
use password_manager::{
    cli::DuoCommands,
    client::{self, AuthenticatedClient},
    types::{DuoCommand, DuoPushRequest, ServerCommand, Target},
};
use std::{
    collections::HashSet,
    io::{self, IsTerminal},
    time::Duration,
};
use zeroize::Zeroizing;

fn fetch(client: &AuthenticatedClient, target: &Target) -> Result<Vec<DuoPushRequest>, String> {
    let response = Zeroizing::new(client.request(ServerCommand::Duo(DuoCommand::Requests {
        target: target.clone(),
    }))?);
    serde_json::from_str(&response).map_err(|_| "invalid Duo request response".into())
}
fn review(r: &DuoPushRequest) -> String {
    format!(
        "Request: {}\nApplication: {}\nAccount: {}\nLocation: {}\nSummary: {}\nExpires: {}\n{}",
        r.id,
        r.application,
        r.username,
        r.location,
        r.summary,
        r.expires_at,
        r.unsupported
            .as_ref()
            .map(|s| format!("Approval unavailable: {s}\n"))
            .unwrap_or_else(|| r
                .code_digits
                .map(|n| format!("Requires the {n}-digit verification code on the login page.\n"))
                .unwrap_or_default())
    )
}
pub(super) fn run(command: DuoCommands, client: &AuthenticatedClient) {
    if let Err(error) = execute(command, client) {
        client::exit_error(&error, 1);
    }
}
fn execute(command: DuoCommands, client: &AuthenticatedClient) -> Result<(), String> {
    match command {
        DuoCommands::Enroll {
            target,
            replace,
            mode,
        } => {
            if !io::stdin().is_terminal() {
                return Err(
                    "Duo enrollment requires an interactive terminal for the activation link"
                        .into(),
                );
            }
            let activation = Zeroizing::new(
                rpassword::prompt_password("Fresh Duo activation link (hidden): ")
                    .map_err(|_| "could not read activation link")?,
            );
            let response = client.request(ServerCommand::Duo(DuoCommand::Enroll {
                target: target_type(target),
                activation: activation.to_string(),
                mode,
                replace,
            }))?;
            client::print_success(&response);
        }
        DuoCommands::Requests { target } => {
            let requests = fetch(client, &target_type(target))?;
            if requests.is_empty() {
                client::print_success("No pending Duo requests.");
            }
            for r in requests {
                client::print_success(&review(&r));
            }
        }
        DuoCommands::Watch {
            target,
            interval,
            notify,
            interactive,
        } => {
            if interactive && !io::stdin().is_terminal() {
                return Err("Interactive Duo watch requires a terminal to review requests".into());
            }
            let target = target_type(target);
            let mut seen = HashSet::new();
            client::print_success(if interactive {
                "Watching Duo requests. After review: a to approve, d to deny, Enter to skip, q to quit. Polling does not extend auto-lock. Ctrl+C to stop."
            } else {
                "Watching Duo requests. Use pm duo approve/deny in another terminal (--request ID if multiple requests are pending). Polling does not extend auto-lock. Ctrl+C to stop."
            });
            loop {
                let requests = fetch(client, &target)?;
                let pending: HashSet<_> = requests.iter().map(|r| r.fingerprint.clone()).collect();
                seen.retain(|fingerprint| pending.contains(fingerprint));
                for r in requests {
                    if seen.insert(r.fingerprint.clone()) {
                        client::print_success(&review(&r));
                        if notify {
                            // Passive alert only. No action callback can approve a request.
                            if std::process::Command::new("notify-send")
                                .args([
                                    "--app-name=Password Manager",
                                    "--",
                                    "Duo login request",
                                    if interactive {
                                        "Review this request in your watching terminal."
                                    } else {
                                        "Open pm duo requests to review the request."
                                    },
                                ])
                                .status()
                                .is_err()
                            {
                                client::print_warning(
                                    "notify-send is unavailable; requests will still be printed.",
                                );
                            }
                        }
                        if interactive {
                            match interactive_decision(&r, prompt)? {
                                WatchDecision::Respond { approve, code } => {
                                    respond(client, target.clone(), r, approve, code)?;
                                }
                                WatchDecision::Skip => {}
                                WatchDecision::Quit => return Ok(()),
                            }
                        }
                    }
                }
                std::thread::sleep(Duration::from_secs(interval));
            }
        }
        DuoCommands::Approve { target, request } => {
            decision(client, target_type(target), request, true)?
        }
        DuoCommands::Deny { target, request } => {
            decision(client, target_type(target), request, false)?
        }
        DuoCommands::Remove { target } => {
            client::print_success(&client.request(ServerCommand::Duo(DuoCommand::Remove {
                target: target_type(target),
            }))?)
        }
    }
    Ok(())
}
fn decision(
    client: &AuthenticatedClient,
    target: Target,
    id: Option<String>,
    approve: bool,
) -> Result<(), String> {
    if !io::stdin().is_terminal() {
        return Err(
            "Duo decisions require an interactive terminal to review and confirm the request"
                .into(),
        );
    }
    let requests = fetch(client, &target)?;
    let r = select_request(requests, id.as_deref())?;
    client::print_success(&review(&r));
    if approve && let Some(reason) = &r.unsupported {
        return Err(reason.clone());
    }
    let answer = if approve { "approve" } else { "deny" };
    let confirmation = Zeroizing::new(
        rpassword::prompt_password(format!("Type {answer} to confirm (hidden): "))
            .map_err(|_| "could not read confirmation")?,
    );
    if confirmation.as_str() != answer {
        return Err("Duo decision cancelled".into());
    }
    let code = verification_code(&r, approve, &mut prompt)?;
    respond(client, target, r, approve, code)
}

fn select_request(
    mut requests: Vec<DuoPushRequest>,
    id: Option<&str>,
) -> Result<DuoPushRequest, String> {
    if let Some(id) = id {
        return requests
            .into_iter()
            .find(|r| r.id == id)
            .ok_or_else(|| "request not found, expired, or already answered".into());
    }
    match requests.len() {
        0 => Err("No pending Duo requests.".into()),
        1 => Ok(requests.remove(0)),
        _ => Err("Multiple Duo requests are pending. Use --request ID or pm duo watch --interactive to review each request.".into()),
    }
}

fn prompt(message: &str) -> Result<Zeroizing<String>, String> {
    rpassword::prompt_password(message)
        .map(Zeroizing::new)
        .map_err(|_| "could not read Duo response".into())
}

enum WatchDecision {
    Respond {
        approve: bool,
        code: Zeroizing<String>,
    },
    Skip,
    Quit,
}

fn interactive_decision(
    r: &DuoPushRequest,
    mut read: impl FnMut(&str) -> Result<Zeroizing<String>, String>,
) -> Result<WatchDecision, String> {
    loop {
        let answer = read(if r.unsupported.is_some() {
            "Deny [d], skip [Enter], quit [q] (then Enter, hidden): "
        } else {
            "Approve [a], deny [d], skip [Enter], quit [q] (then Enter, hidden): "
        })?;
        let approve = match answer.trim() {
            "a" if r.unsupported.is_none() => true,
            "d" => false,
            "" => return Ok(WatchDecision::Skip),
            "q" => return Ok(WatchDecision::Quit),
            _ => {
                client::print_warning("Choose one of the displayed actions.");
                continue;
            }
        };
        let code = verification_code(r, approve, &mut read)?;
        return Ok(WatchDecision::Respond { approve, code });
    }
}

fn verification_code(
    r: &DuoPushRequest,
    approve: bool,
    read: &mut impl FnMut(&str) -> Result<Zeroizing<String>, String>,
) -> Result<Zeroizing<String>, String> {
    if approve && let Some(digits) = r.code_digits {
        loop {
            let code = read("Verification code from the login page (hidden): ")?;
            if code.is_empty() {
                return Err("Duo decision cancelled".into());
            }
            if code.len() == digits && code.bytes().all(|b| b.is_ascii_digit()) {
                return Ok(code);
            }
            client::print_warning(&format!(
                "Enter the {digits}-digit verification code shown on the login page, or Enter to cancel."
            ));
        }
    } else {
        Ok(Zeroizing::new(String::new()))
    }
}

fn respond(
    client: &AuthenticatedClient,
    target: Target,
    r: DuoPushRequest,
    approve: bool,
    code: Zeroizing<String>,
) -> Result<(), String> {
    let response = client.request(ServerCommand::Duo(DuoCommand::Respond {
        target,
        request_id: r.id,
        fingerprint: r.fingerprint,
        approve,
        code: code.to_string(),
    }))?;
    client::print_success(&response);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn request(id: &str) -> DuoPushRequest {
        DuoPushRequest {
            id: id.into(),
            application: "Example VPN".into(),
            username: "alice".into(),
            location: "Boise".into(),
            summary: "Login".into(),
            expires_at: u64::MAX,
            code_digits: None,
            unsupported: None,
            fingerprint: format!("review-{id}"),
        }
    }

    fn choose(r: &DuoPushRequest, answers: &[&str]) -> Result<WatchDecision, String> {
        let mut answers: VecDeque<_> = answers.iter().copied().collect();
        let decision = interactive_decision(r, |_| {
            Ok(Zeroizing::new(
                answers.pop_front().expect("unexpected extra prompt").into(),
            ))
        });
        assert!(answers.is_empty(), "some expected prompts were not shown");
        decision
    }

    #[test]
    fn implicit_selection_never_guesses_between_pending_requests() {
        assert!(select_request(vec![], None).is_err());
        assert_eq!(
            select_request(vec![request("one")], None).unwrap().id,
            "one"
        );
        let pending = vec![request("one"), request("two")];
        assert!(
            select_request(pending.clone(), None)
                .unwrap_err()
                .contains("--request")
        );
        assert_eq!(
            select_request(pending.clone(), Some("two")).unwrap().id,
            "two"
        );
        assert!(select_request(pending, Some("expired")).is_err());
        assert!(select_request(vec![request("one")], Some("other")).is_err());
    }

    #[test]
    fn interactive_decisions_require_explicit_choices_and_supported_verification() {
        enum Expected {
            Respond(bool, &'static str),
            Skip,
            Quit,
            Cancelled,
        }
        let plain = request("one");
        let mut verified = plain.clone();
        verified.code_digits = Some(3);
        let mut unsupported = verified.clone();
        unsupported.unsupported = Some("Requires proximity verification".into());
        let cases: [(_, _, &[&str], _); 10] = [
            ("empty choice skips", &plain, &[""], Expected::Skip),
            ("quit", &plain, &["q"], Expected::Quit),
            ("invalid choice retries", &plain, &["y", ""], Expected::Skip),
            ("approve once", &plain, &["a"], Expected::Respond(true, "")),
            ("deny once", &plain, &["d"], Expected::Respond(false, "")),
            (
                "verified approval retries invalid codes",
                &verified,
                &["a", "12", "abc", "012"],
                Expected::Respond(true, "012"),
            ),
            (
                "empty code cancels",
                &verified,
                &["a", ""],
                Expected::Cancelled,
            ),
            (
                "verified denial needs no code",
                &verified,
                &["d"],
                Expected::Respond(false, ""),
            ),
            (
                "unsupported approval can skip",
                &unsupported,
                &["a", ""],
                Expected::Skip,
            ),
            (
                "unsupported approval can deny",
                &unsupported,
                &["a", "d"],
                Expected::Respond(false, ""),
            ),
        ];
        for (name, request, answers, expected) in cases {
            let decision = choose(request, answers);
            match expected {
                Expected::Respond(expected_approve, expected_code) => {
                    let WatchDecision::Respond { approve, code } = decision.unwrap() else {
                        panic!("{name}: expected an explicit decision");
                    };
                    assert_eq!(approve, expected_approve, "{name}");
                    assert_eq!(code.as_str(), expected_code, "{name}");
                }
                Expected::Skip => assert!(matches!(decision, Ok(WatchDecision::Skip)), "{name}"),
                Expected::Quit => assert!(matches!(decision, Ok(WatchDecision::Quit)), "{name}"),
                Expected::Cancelled => assert!(decision.is_err(), "{name}"),
            }
        }
        assert!(interactive_decision(&unsupported, |_| Err("terminal closed".into())).is_err());
    }
}
