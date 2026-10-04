use crate::types::*;
use std::{
    io::{self, IsTerminal, Write},
    sync::atomic::{AtomicBool, Ordering},
};
mod transport;
pub use transport::AuthenticatedClient;

static JSON_OUTPUT: AtomicBool = AtomicBool::new(false);
static QUIET_OUTPUT: AtomicBool = AtomicBool::new(false);

pub fn configure_output(json: bool, quiet: bool) {
    JSON_OUTPUT.store(json, Ordering::Relaxed);
    QUIET_OUTPUT.store(quiet, Ordering::Relaxed);
}

pub fn print_error(error: &str) {
    if JSON_OUTPUT.load(Ordering::Relaxed) {
        println!("{}", serde_json::json!({ "ok": false, "error": error }));
    } else {
        eprintln!("Error: {}", crate::terminal::output(error).as_str());
    }
}

pub fn print_success(output: &str) {
    let rendered = if JSON_OUTPUT.load(Ordering::Relaxed) {
        format!(
            "{}\n",
            serde_json::json!({ "ok": true, "output": output.trim_end() })
        )
    } else if QUIET_OUTPUT.load(Ordering::Relaxed) {
        return;
    } else if output.ends_with('\n') {
        crate::terminal::output(output).to_string()
    } else {
        format!("{}\n", crate::terminal::output(output).as_str())
    };
    let _ = io::stdout().write_all(rendered.as_bytes());
}

pub fn print_warning(warning: &str) {
    if !QUIET_OUTPUT.load(Ordering::Relaxed) {
        eprintln!("Warning: {}", crate::terminal::output(warning).as_str());
    }
}

pub fn exit_error(error: &str, code: i32) -> ! {
    print_error(error);
    std::process::exit(code);
}

impl AuthenticatedClient {
    pub fn send_command(&self, command: ServerCommand) {
        let raw_secret = matches!(
            &command,
            ServerCommand::GetSecret(_)
                | ServerCommand::GetField {
                    copy_timeout: None,
                    ..
                }
        );
        match self.request_response(command) {
            Ok(response) => {
                let exit_code = response.code;
                if JSON_OUTPUT.load(Ordering::Relaxed) {
                    if exit_code == 0 {
                        println!(
                            "{}",
                            serde_json::json!({ "ok": true, "output": response.message.trim_end() })
                        );
                    } else {
                        println!(
                            "{}",
                            serde_json::json!({ "ok": false, "error": response.message.trim_end(), "code": exit_code })
                        );
                    }
                } else if !QUIET_OUTPUT.load(Ordering::Relaxed) || exit_code != 0 {
                    if exit_code == 0 {
                        if raw_secret && !io::stdout().is_terminal() {
                            print!("{}", response.message);
                        } else {
                            print!("{}", crate::terminal::output(&response.message).as_str());
                        }
                    } else {
                        eprint!("{}", crate::terminal::output(&response.message).as_str());
                    }
                }
                if exit_code != 0 {
                    std::process::exit(exit_code);
                }
            }
            Err(error) => exit_error(&error, 1),
        }
    }
}
