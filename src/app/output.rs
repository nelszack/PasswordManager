use password_manager::{
    client::{AuthenticatedClient, render_response, terminal_output},
    protocol::{RequestEnvelope, ResponsePayload},
    types::ServerCommand,
};
use std::io::{self, IsTerminal, Write};
#[derive(Clone, Copy, Debug, Default)]
pub struct Output {
    json: bool,
    quiet: bool,
}
impl Output {
    pub fn new(json: bool, quiet: bool) -> Self {
        Self { json, quiet }
    }
    pub fn can_prompt(&self) -> bool {
        !self.json && !self.quiet && io::stdin().is_terminal() && io::stdout().is_terminal()
    }
    pub fn print_error(&self, error: &str) {
        if self.json {
            self.print_json(serde_json::json!({"ok":false,"error":error}));
        } else {
            eprintln!("Error: {}", terminal_output(error));
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
        !self.json && !self.quiet && io::stdout().is_terminal()
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
    pub fn print_warning(&self, warning: &str) {
        if !self.quiet {
            eprintln!("Warning: {}", terminal_output(warning));
        }
    }
    pub fn exit_error(&self, error: &str, code: i32) -> ! {
        self.print_error(error);
        std::process::exit(code);
    }
    pub fn send_command(
        &self,
        client: &AuthenticatedClient,
        command: ServerCommand,
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
        if self.json {
            if code == 0 {
                let document = password_manager::protocol::SecretJson::from(
                    serde_json::json!({"ok":true,"data":response.payload.into_json(),"operation":response.operation}),
                );
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
                    let rendered = zeroize::Zeroizing::new(render_response(&response.payload));
                    if !self.quiet {
                        self.print_success(&rendered);
                    }
                }
                eprintln!("{}", terminal_output(&response.error_message()));
            } else if let ResponsePayload::Secret(secret) = &response.payload {
                if io::stdout().is_terminal() {
                    self.write_stdout(format!("{}\n", terminal_output(secret.expose())));
                } else {
                    self.write_stdout(secret.expose().to_owned());
                }
            } else {
                let rendered = zeroize::Zeroizing::new(render_response(&response.payload));
                self.print_success(&rendered);
            }
        }
        if code == 0 { Ok(()) } else { Err(code) }
    }
}
