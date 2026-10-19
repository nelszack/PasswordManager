use password_manager::{
    client::{AuthenticatedClient, render_response, terminal_output},
    protocol::ResponsePayload,
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
    pub fn print_error(&self, error: &str) {
        if self.json {
            println!("{}", serde_json::json!({"ok":false,"error":error}));
        } else {
            eprintln!("Error: {}", terminal_output(error));
        }
    }
    pub fn print_success(&self, value: &str) {
        if let Some(rendered) = self.success_output(value) {
            let rendered = zeroize::Zeroizing::new(rendered);
            let _ = io::stdout().write_all(rendered.as_bytes());
        }
    }
    pub fn print_data(&self, data: serde_json::Value, text: &str) {
        if self.json {
            println!("{}", serde_json::json!({"ok":true,"data":data}));
        } else {
            self.print_success(text);
        }
    }
    pub fn print_watch_data(&self, data: &impl serde::Serialize, text: &str) -> io::Result<()> {
        if self.json {
            let encoded = zeroize::Zeroizing::new(serde_json::to_string(data)?);
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "{{\"ok\":true,\"data\":{}}}", encoded.as_str())?;
            stdout.flush()
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
        if self.watch_in_place() {
            write!(stdout, "\r{}\x1b[K", terminal_output(value))?;
        } else if let Some(rendered) = self.success_output(value) {
            stdout.write_all(rendered.as_bytes())?;
        }
        stdout.flush()
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
        let response = match client.request_response(command) {
            Ok(r) => r,
            Err(e) => {
                self.print_error(&e);
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
                println!("{}", encoded.as_str());
            } else {
                println!(
                    "{}",
                    serde_json::json!({"ok":false,"error":response.error_message(),"code":code,"operation":response.operation,"data":response.payload.into_json()})
                );
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
                    println!("{}", terminal_output(secret.expose()));
                } else {
                    print!("{}", secret.expose());
                }
            } else {
                let rendered = zeroize::Zeroizing::new(render_response(&response.payload));
                self.print_success(&rendered);
            }
        }
        if code == 0 { Ok(()) } else { Err(code) }
    }
}
