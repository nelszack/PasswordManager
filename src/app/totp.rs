use super::output::Output;
use password_manager::{
    client::AuthenticatedClient,
    protocol::AuthenticatorResponse,
    types::{ServerCommand, Target, TotpCommand},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

fn fetch(
    client: &AuthenticatedClient,
    target: &Target,
    copy_timeout: Option<u8>,
) -> Result<AuthenticatorResponse, String> {
    let response = client.request_response(ServerCommand::Totp(TotpCommand::Watch {
        target: target.clone(),
        copy_timeout,
    }))?;
    if response.code != 0 {
        return Err(response.error_message());
    }
    let password_manager::protocol::ResponsePayload::Authenticator(code) = response.payload else {
        return Err("invalid TOTP watch response".into());
    };
    if !code.valid() || code.mode != "totp" || code.expires_in == Some(0) {
        return Err("invalid TOTP watch response".into());
    }
    Ok(code)
}

pub(super) async fn watch(
    client: &AuthenticatedClient,
    target: Target,
    copy_timeout: Option<u8>,
    console: &Output,
) -> Result<(), String> {
    let stop = tokio::signal::ctrl_c();
    tokio::pin!(stop);
    let mut previous = Zeroizing::new(String::new());
    loop {
        // Fetch from the vault on every tick so locking or removing the entry
        // stops the watch. This command does not extend the auto-lock deadline.
        let mut code = fetch(client, &target, None)?;
        if copy_timeout.is_some() && code.code.expose() != previous.as_str() {
            code = fetch(client, &target, copy_timeout)?;
        }
        previous.zeroize();
        previous.push_str(&code.code);
        let output = Zeroizing::new(format!(
            "TOTP: {} ({}s remaining)",
            code.code.expose(),
            code.expires_in.expect("validated TOTP lifetime")
        ));
        if let Err(error) = console.print_watch_data(&code, &output) {
            return if error.kind() == std::io::ErrorKind::BrokenPipe {
                Ok(())
            } else {
                Err(format!("could not display TOTP code: {error}"))
            };
        }
        // Align each tick with the wall clock instead of accumulating request
        // latency in a relative one-second sleep. Generation uses the same clock.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch")?;
        let delay = Duration::from_secs(1) - Duration::from_nanos(now.subsec_nanos().into());
        tokio::select! {
            result = &mut stop => {
                return result.map_err(|error| format!("could not listen for Ctrl+C: {error}"));
            }
            _ = tokio::time::sleep(delay) => {}
        }
    }
}
