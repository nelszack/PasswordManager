//! Hidden terminal prompts, with an explicit standard-input channel for scripts.
//!
//! `pm --password-stdin …` reads every hidden value (master password, item
//! secret, custom field, TOTP secret) from standard input, one per line, in the
//! order the command would otherwise prompt for them.

use std::io::{self, BufRead};
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

static FROM_STDIN: AtomicBool = AtomicBool::new(false);

/// Read hidden values from standard input instead of the terminal.
pub fn use_stdin(enabled: bool) {
    FROM_STDIN.store(enabled, Ordering::Relaxed);
}

/// Whether hidden values come from standard input (`--password-stdin`).
pub fn from_stdin() -> bool {
    FROM_STDIN.load(Ordering::Relaxed)
}

pub const NO_TERMINAL: &str = "No terminal is available for a hidden prompt. Pipe the value \
                               with `pm --password-stdin …`, or use a key file with --key.";

/// Prompt for one hidden value. `what` names it in error messages.
pub fn hidden(prompt: &str, what: &str) -> Result<String, String> {
    if from_stdin() {
        let mut line = Zeroizing::new(String::new());
        let read = io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|error| format!("could not read {what} from standard input: {error}"))?;
        if read == 0 {
            return Err(format!(
                "standard input ended before the {what} was supplied (--password-stdin reads \
                 one value per line)"
            ));
        }
        let trimmed = line.trim_end_matches(['\n', '\r']);
        return Ok(trimmed.to_owned());
    }
    rpassword::prompt_password(prompt).map_err(|error| describe(&error, what))
}

fn describe(error: &io::Error, what: &str) -> String {
    // ENXIO (6) is what Unix reports when /dev/tty has no controlling terminal.
    if error.raw_os_error() == Some(6)
        || matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::Unsupported
        )
    {
        NO_TERMINAL.to_owned()
    } else {
        format!("could not read {what}: {error}")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn missing_terminal_errors_name_the_scripted_alternative() {
        let error = std::io::Error::from_raw_os_error(6);
        assert_eq!(super::describe(&error, "password"), super::NO_TERMINAL);
        let other = std::io::Error::other("boom");
        assert_eq!(
            super::describe(&other, "password"),
            "could not read password: boom"
        );
    }
}
