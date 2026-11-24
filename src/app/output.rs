use password_manager::{
    client::{AuthenticatedClient, Style, render_response, terminal_output},
    protocol::{RequestEnvelope, ResponsePayload},
    types::ServerCommand,
};
use std::io::{self, IsTerminal, Write};
/// A colored label on a terminal; plain with NO_COLOR, TERM=dumb, or in a pipe.
fn label(text: &str, color: &str) -> String {
    let plain = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty())
        || std::env::var("TERM").is_ok_and(|term| term == "dumb")
        || !io::stderr().is_terminal();
    if plain {
        text.to_owned()
    } else {
        format!("\x1b[1;{color}m{text}\x1b[0m")
    }
}

/// ASCII output: in a pipe, with TERM=dumb or PM_PLAIN, or outside a UTF-8 locale.
fn ascii_wanted() -> bool {
    let locale = ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()));
    std::env::var_os("PM_PLAIN").is_some()
        || std::env::var("TERM").is_ok_and(|term| term == "dumb")
        || !io::stdout().is_terminal()
        || locale.is_some_and(|value| {
            let value = value.to_lowercase();
            !(value.contains("utf-8") || value.contains("utf8"))
        })
}

/// The terminal's width in columns, for fitting list output.
fn terminal_width() -> Option<usize> {
    #[cfg(unix)]
    if let Ok(size) = rustix::termios::tcgetwinsize(io::stdout()) {
        return (size.ws_col > 0).then_some(usize::from(size.ws_col));
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{
            CONSOLE_SCREEN_BUFFER_INFO, GetConsoleScreenBufferInfo, GetStdHandle, STD_OUTPUT_HANDLE,
        };
        // SAFETY: the handle is the process's own stdout and `info` is a plain
        // out-parameter sized for this call.
        unsafe {
            let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
            if GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut info) != 0 {
                let columns = info.srWindow.Right - info.srWindow.Left + 1;
                if columns > 0 {
                    return Some(columns as usize);
                }
            }
        }
    }
    std::env::var("COLUMNS").ok()?.parse().ok()
}

/// Typographic punctuation in messages (never in secrets or item values) as ASCII.
fn plain_punctuation(style: Style, text: &str) -> String {
    if !style.ascii {
        return text.to_owned();
    }
    text.replace(['\u{201c}', '\u{201d}'], "\"")
        .replace(['\u{2018}', '\u{2019}'], "'")
        .replace(['\u{2013}', '\u{2014}'], "-")
        .replace('\u{2026}', "...")
        .replace(" \u{b7} ", " - ")
        .replace('\u{2022}', "*")
        .replace('\u{2713}', "OK")
}

/// Clipboard library errors in plain language.
fn copy_problem(notice: &str) -> String {
    let reason = password_manager::clipboard::describe_error(notice);
    if reason == notice {
        notice.to_owned()
    } else {
        format!("Could not copy: {reason}. Print the value with --password-only instead.")
    }
}

/// Add the CLI's next step to shared server messages.
fn cli_error(message: &str) -> String {
    if message == password_manager::protocol::VAULT_LOCKED {
        "The vault is locked. Run `pm unlock`, then try again.".into()
    } else {
        let mut chars = message.chars();
        // Server messages are often lower-case fragments; present a sentence.
        chars.next().map_or_else(String::new, |first| {
            first.to_uppercase().collect::<String>() + chars.as_str()
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Output {
    json: bool,
    quiet: bool,
    style: Style,
}
impl Output {
    pub fn new(json: bool, quiet: bool) -> Self {
        let mut style = Style::default();
        style.ascii = ascii_wanted();
        if let Some(width) = terminal_width() {
            style = style.with_width(width);
        }
        Self { json, quiet, style }
    }
    /// The same output, showing item notes in details (`get --reveal-secrets`).
    pub fn revealing_notes(mut self, reveal: bool) -> Self {
        self.style.reveal_notes = reveal;
        self
    }
    pub fn is_json(&self) -> bool {
        self.json
    }
    pub fn stdout_is_terminal(&self) -> bool {
        io::stdout().is_terminal()
    }
    pub fn can_prompt(&self) -> bool {
        !self.json && !self.quiet && io::stdin().is_terminal() && io::stdout().is_terminal()
    }
    pub fn print_error(&self, error: &str) {
        self.print_error_code(error, 1);
    }
    /// Every failure has the same shape: `{"ok":false,"error":…,"code":N}` in JSON.
    pub fn print_error_code(&self, error: &str, code: i32) {
        if self.json {
            self.print_json(serde_json::json!({"ok":false,"error":cli_error(error),"code":code}));
        } else {
            eprintln!(
                "{} {}",
                label("Error:", "31"),
                terminal_output(&plain_punctuation(self.style, &cli_error(error)))
            );
        }
    }
    fn write_stdout(&self, value: String) {
        let value = zeroize::Zeroizing::new(value);
        let mut stdout = io::stdout().lock();
        let result = stdout
            .write_all(value.as_bytes())
            .and_then(|()| stdout.flush());
        drop(stdout);
        drop(value);
        if let Err(error) = Self::stdout_result(result) {
            let _ = writeln!(
                io::stderr(),
                "Error: could not write command output: {error}"
            );
            std::process::exit(1);
        }
    }
    fn stdout_result(result: io::Result<()>) -> io::Result<()> {
        if result
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::BrokenPipe)
        {
            std::process::exit(0);
        }
        result
    }
    fn print_json(&self, value: serde_json::Value) {
        self.write_stdout(format!("{value}\n"));
    }
    pub fn print_success(&self, value: &str) {
        if let Some(rendered) = self.success_output(value) {
            self.write_stdout(rendered);
        }
    }
    pub fn print_data(&self, data: serde_json::Value, text: &str) {
        if self.json {
            self.print_json(serde_json::json!({"ok":true,"data":data}));
        } else {
            self.print_success(text);
        }
    }
    pub fn print_watch_data(&self, data: &impl serde::Serialize, text: &str) -> io::Result<()> {
        if self.json {
            let encoded = zeroize::Zeroizing::new(serde_json::to_string(data)?);
            let mut stdout = io::stdout().lock();
            let result = writeln!(stdout, "{{\"ok\":true,\"data\":{}}}", encoded.as_str())
                .and_then(|()| stdout.flush());
            drop(stdout);
            drop(encoded);
            Self::stdout_result(result)
        } else {
            self.print_watch(text)
        }
    }
    fn success_output(&self, value: &str) -> Option<String> {
        if self.json {
            Some(format!(
                "{}\n",
                serde_json::json!({"ok":true,"output":value.trim_end()})
            ))
        } else if self.quiet {
            None
        } else {
            Some(format!(
                "{}{}",
                terminal_output(value),
                if value.ends_with('\n') { "" } else { "\n" }
            ))
        }
    }
    fn watch_in_place(&self) -> bool {
        // TERM=dumb (and screen readers that use it) get one complete line per update.
        !self.json
            && !self.quiet
            && io::stdout().is_terminal()
            && !std::env::var("TERM").is_ok_and(|term| term == "dumb")
            && std::env::var_os("PM_PLAIN").is_none()
    }
    pub fn print_watch(&self, value: &str) -> io::Result<()> {
        let mut stdout = io::stdout().lock();
        let result = if self.watch_in_place() {
            write!(stdout, "\r{}\x1b[K", terminal_output(value))
        } else if let Some(rendered) = self.success_output(value) {
            stdout.write_all(rendered.as_bytes())
        } else {
            Ok(())
        };
        Self::stdout_result(result.and_then(|()| stdout.flush()))
    }
    pub fn finish_watch(&self) {
        if self.watch_in_place() {
            let _ = writeln!(io::stdout());
        }
    }
    /// Informational stderr line that keeps stdout clean for pipes and JSON.
    pub fn print_note(&self, note: &str) {
        if !self.quiet && !self.json {
            eprintln!("{}", terminal_output(&plain_punctuation(self.style, note)));
        }
    }
    pub fn print_warning(&self, warning: &str) {
        if !self.quiet {
            eprintln!(
                "{} {}",
                label("Warning:", "33"),
                terminal_output(&plain_punctuation(self.style, warning))
            );
        }
    }
    pub fn exit_error(&self, error: &str, code: i32) -> ! {
        self.print_error_code(error, code);
        std::process::exit(code);
    }
    pub fn send_command(
        &self,
        client: &AuthenticatedClient,
        command: ServerCommand,
    ) -> Result<(), i32> {
        self.send_command_with_hint(client, command, None)
    }

    /// Like [`Self::send_command`]; `empty_hint` replaces the empty-vault text
    /// when a search or filtered list returns nothing.
    pub fn send_command_with_hint(
        &self,
        client: &AuthenticatedClient,
        command: ServerCommand,
        empty_hint: Option<&str>,
    ) -> Result<(), i32> {
        let envelope = RequestEnvelope::new(command);
        let operation_id = envelope.operation_id.clone();
        let response = match client.request_envelope_tracked(envelope) {
            Ok(r) => r,
            Err(e) => {
                if e.sent
                    && let Some(id) = operation_id
                {
                    let message = format!(
                        "{} The change may have completed. Do not retry blindly. Inspect the vault and run pm operation --id {id} to check its recorded outcome.",
                        e.message
                    );
                    if self.json {
                        self.print_json(serde_json::json!({"ok":false,"error":message,"uncertain":true,"operationId":id}));
                    } else {
                        self.print_error(&message);
                    }
                } else {
                    self.print_error(&e.message);
                }
                return Err(1);
            }
        };
        let code = response.code;
        let notice = response.notice.clone();
        // A copy you asked for that failed is a failure in every output mode.
        if self.json
            && code == 0
            && let Some(problem) = notice
                .as_deref()
                .filter(|notice| notice.starts_with("Could not copy"))
        {
            self.print_json(serde_json::json!({
                "ok": false,
                "error": copy_problem(problem),
                "code": 1,
                "operation": response.operation,
            }));
            return Err(1);
        }
        if self.json {
            if code == 0 {
                let mut value = serde_json::json!({"ok":true,"data":response.payload.into_json(),"operation":response.operation});
                if let Some(notice) = &notice {
                    value["notice"] = serde_json::Value::String(notice.clone());
                }
                let document = password_manager::protocol::SecretJson::from(value);
                let encoded = zeroize::Zeroizing::new(
                    serde_json::to_string(&document).expect("response serializes"),
                );
                self.write_stdout(format!("{}\n", encoded.as_str()));
            } else {
                self.print_json(serde_json::json!({"ok":false,"error":response.error_message(),"code":code,"operation":response.operation,"data":response.payload.into_json()}));
            }
        } else if !self.quiet || code != 0 {
            if code != 0 {
                if !matches!(response.payload, ResponsePayload::Message(_)) {
                    let rendered =
                        zeroize::Zeroizing::new(render_response(self.style, &response.payload));
                    if !self.quiet {
                        self.print_success(&rendered);
                    }
                }
                eprintln!(
                    "Error: {}",
                    terminal_output(&cli_error(&response.error_message()))
                );
            } else if let ResponsePayload::Secret(secret) = &response.payload {
                if io::stdout().is_terminal() {
                    self.write_stdout(format!("{}\n", terminal_output(secret.expose())));
                } else {
                    self.write_stdout(secret.expose().to_owned());
                }
            } else if let ResponsePayload::Authenticator(code) = &response.payload
                && !io::stdout().is_terminal()
            {
                // In a pipe, print only the code; context goes to stderr.
                self.write_stdout(format!("{}\n", code.code.expose()));
                if let Some(counter) = code.counter {
                    self.print_note(&format!(
                        "HOTP counter {counter}; the next counter is saved."
                    ));
                }
            } else if let ResponsePayload::ItemPage(page) = &response.payload {
                self.print_success(&password_manager::client::presentation::item_page(
                    self.style, page, empty_hint,
                ));
            } else if let ResponsePayload::Message(message) = &response.payload {
                // Status messages carry no secrets, so their punctuation can be plain.
                self.print_success(&plain_punctuation(self.style, message));
            } else {
                let rendered =
                    zeroize::Zeroizing::new(render_response(self.style, &response.payload));
                self.print_success(&rendered);
            }
        }
        // Shown even with --quiet: it asks for action on other devices, or
        // reports a failed copy. A successful copy is an ordinary note.
        let mut copy_failed = false;
        if !self.json
            && let Some(notice) = notice
        {
            if notice.starts_with("Copied") {
                self.print_note(&notice);
            } else if notice.starts_with("Could not copy") {
                copy_failed = true;
                eprintln!(
                    "{} {}",
                    label("Error:", "31"),
                    terminal_output(&copy_problem(&notice))
                );
            } else {
                self.print_warning(&notice);
            }
        }
        // A copy you asked for that failed is a failure, not a success with a warning.
        if copy_failed {
            return Err(1);
        }
        if code == 0 { Ok(()) } else { Err(code) }
    }
}
