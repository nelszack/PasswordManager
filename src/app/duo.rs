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
        } => {
            let target = target_type(target);
            let mut seen = HashSet::new();
            client::print_success(
                "Watching Duo requests. Use pm duo approve/deny --request ID in another terminal. Polling does not extend auto-lock. Ctrl+C to stop.",
            );
            loop {
                let requests = fetch(client, &target)?;
                let pending: HashSet<_> = requests.iter().map(|r| r.id.clone()).collect();
                seen.retain(|id| pending.contains(id));
                for r in requests {
                    if seen.insert(r.id.clone()) {
                        client::print_success(&review(&r));
                        if notify {
                            // Passive alert only. No action callback can approve a request.
                            if std::process::Command::new("notify-send")
                                .args([
                                    "--app-name=Password Manager",
                                    "--",
                                    "Duo login request",
                                    "Open pm duo requests to review the request.",
                                ])
                                .status()
                                .is_err()
                            {
                                client::print_warning(
                                    "notify-send is unavailable; requests will still be printed.",
                                );
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
    id: String,
    approve: bool,
) -> Result<(), String> {
    if !io::stdin().is_terminal() {
        return Err(
            "Duo decisions require an interactive terminal to review and confirm the request"
                .into(),
        );
    }
    let requests = fetch(client, &target)?;
    let r = requests
        .into_iter()
        .find(|r| r.id == id)
        .ok_or("request not found, expired, or already answered")?;
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
    let code = if approve && r.code_digits.is_some() {
        Zeroizing::new(
            rpassword::prompt_password("Verification code from the login page (hidden): ")
                .map_err(|_| "could not read verification code")?,
        )
    } else {
        Zeroizing::new(String::new())
    };
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
