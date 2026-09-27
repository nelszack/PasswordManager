use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

trait CommandTimeout {
    fn output_timeout(&mut self, context: &str) -> Output;
}

impl CommandTimeout for Command {
    fn output_timeout(&mut self, context: &str) -> Output {
        let mut child = self
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("could not start {context}: {error}"));
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    return child
                        .wait_with_output()
                        .unwrap_or_else(|error| panic!("could not collect {context}: {error}"));
                }
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(25));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("{context} did not exit within 20 seconds");
                }
                Err(error) => panic!("could not wait for {context}: {error}"),
            }
        }
    }
}

fn pm() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pm"))
}

fn isolated_pm(root: &Path) -> Command {
    let mut command = pm();
    command
        .current_dir(root)
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("PM_CONFIG_DIR", root.join("config"))
        .env("PM_DATA_DIR", root.join("data"));
    command
}

fn run(root: &Path, port: u16, args: &[&str]) -> Output {
    isolated_pm(root)
        .args(["--port", &port.to_string()])
        .args(args)
        .output_timeout(&format!("pm {}", args.join(" ")))
}

fn unused_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct ServerGuard {
    root: PathBuf,
    port: u16,
    active: bool,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = run(&self.root, self.port, &["kill"]);
        }
    }
}

#[test]
fn invalid_generator_input_exits_with_cli_error() {
    let output = pm()
        .args(["genpass", "--length", "0", "--no-copy"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid value '0'"));
}

#[test]
fn local_commands_honor_json_and_quiet_output() {
    let root = tempfile::tempdir().unwrap();
    let json = isolated_pm(root.path())
        .args([
            "--json",
            "genpass",
            "--length",
            "4",
            "--no-copy",
            "--no-stats",
        ])
        .output()
        .unwrap();
    assert!(
        json.status.success(),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value["ok"], true);
    assert!(value["output"].as_str().unwrap().starts_with("Password: "));

    let quiet = isolated_pm(root.path())
        .args(["--quiet", "passcheck", "--password", "test-password"])
        .output()
        .unwrap();
    assert!(quiet.status.success());
    assert!(quiet.stdout.is_empty());
    assert!(quiet.stderr.is_empty());
}

#[test]
fn unavailable_server_returns_a_stable_failure_exit_code() {
    let root = tempfile::tempdir().unwrap();
    let output = run(root.path(), unused_port(), &["status"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Server is not running"));
}

#[test]
fn config_and_completion_commands_persist_in_an_isolated_home() {
    let root = tempfile::tempdir().unwrap();
    let updated = isolated_pm(root.path())
        .args([
            "config",
            "--length",
            "24",
            "--copy",
            "false",
            "--server-port",
            "49123",
        ])
        .output()
        .unwrap();
    assert!(
        updated.status.success(),
        "{}",
        String::from_utf8_lossy(&updated.stderr)
    );

    let displayed = isolated_pm(root.path())
        .args(["--json", "config"])
        .output()
        .unwrap();
    assert!(displayed.status.success());
    let json: serde_json::Value = serde_json::from_slice(&displayed.stdout).unwrap();
    let output = json["output"].as_str().unwrap();
    assert!(output.contains("length = 24"));
    assert!(output.contains("copy = false"));
    assert!(output.contains("port = 49123"));

    let completion = root.path().join("pm.bash");
    let generated = isolated_pm(root.path())
        .args(["completions", "bash", "--output"])
        .arg(&completion)
        .output()
        .unwrap();
    assert!(generated.status.success());
    assert!(std::fs::read_to_string(completion).unwrap().contains("_pm"));
}

#[test]
fn executable_drives_a_key_vault_through_a_complete_lifecycle() {
    let root = tempfile::tempdir().unwrap();
    let port = unused_port();
    let key = root.path().join("vault.key");

    // A detached Windows server can retain an inherited capture pipe after the
    // short-lived `pm start` process exits. Use inherited output here so the
    // test waits for the launcher process rather than the detached server.
    let started = isolated_pm(root.path())
        .args(["--port", &port.to_string(), "start"])
        .status()
        .unwrap();
    assert!(started.success(), "pm start exited with status {started}");
    let mut server = ServerGuard {
        root: root.path().to_path_buf(),
        port,
        active: true,
    };

    let mut ready = false;
    for _ in 0..100 {
        if run(root.path(), port, &["status"]).status.success() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert!(ready, "server did not become ready");

    let created = isolated_pm(root.path())
        .args(["--port", &port.to_string(), "new", "--key"])
        .arg(&key)
        .output_timeout("pm new --key");
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );

    let unlocked = isolated_pm(root.path())
        .args(["--port", &port.to_string(), "unlock", "--key"])
        .arg(&key)
        .args(["--timeout", "0"])
        .output_timeout("pm unlock --key");
    assert!(
        unlocked.status.success(),
        "{}",
        String::from_utf8_lossy(&unlocked.stderr)
    );

    let added = run(
        root.path(),
        port,
        &[
            "add",
            "--name",
            "example",
            "--username",
            "alice",
            "--url",
            "https://example.com",
            "--generate-password",
            "--no-copy",
        ],
    );
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );

    let viewed = run(root.path(), port, &["view"]);
    assert!(viewed.status.success());
    assert!(String::from_utf8_lossy(&viewed.stdout).contains("example"));

    let secret = run(
        root.path(),
        port,
        &["get", "--entry-name", "example", "--password-only"],
    );
    assert!(secret.status.success());
    assert!(!secret.stdout.is_empty());

    let updated = run(
        root.path(),
        port,
        &[
            "update",
            "--entry-name",
            "example",
            "--username",
            "bob",
            "--notes",
            "updated through the executable",
            "--password",
            "--generate-password",
        ],
    );
    assert!(
        updated.status.success(),
        "{}",
        String::from_utf8_lossy(&updated.stderr)
    );

    let json_export = root.path().join("vault.json");
    let csv_export = root.path().join("vault.csv");
    for path in [&json_export, &csv_export] {
        let exported = isolated_pm(root.path())
            .args(["--port", &port.to_string(), "export", "--path"])
            .arg(path)
            .output_timeout("pm export");
        assert!(exported.status.success());
        assert!(path.is_file());
    }

    let previewed = isolated_pm(root.path())
        .args(["--port", &port.to_string(), "import", "--path"])
        .arg(&json_export)
        .arg("--preview")
        .output_timeout("pm import --preview");
    assert!(previewed.status.success());

    assert!(
        run(root.path(), port, &["delete", "--entry-name", "example"])
            .status
            .success()
    );
    assert!(run(root.path(), port, &["trash"]).status.success());

    let imported = isolated_pm(root.path())
        .args(["--port", &port.to_string(), "import", "--path"])
        .arg(&json_export)
        .output_timeout("pm import");
    assert!(imported.status.success());
    assert!(String::from_utf8_lossy(&run(root.path(), port, &["view"]).stdout).contains("bob"));

    let backup = root.path().join("vault.pmbackup");
    let backed_up = isolated_pm(root.path())
        .args(["--port", &port.to_string(), "backup", "create", "--path"])
        .arg(&backup)
        .arg("--key")
        .arg(&key)
        .output_timeout("pm backup create");
    assert!(backed_up.status.success());
    assert!(backup.is_file());

    assert!(run(root.path(), port, &["lock"]).status.success());
    let restored = isolated_pm(root.path())
        .args(["--port", &port.to_string(), "backup", "restore", "--path"])
        .arg(&backup)
        .arg("--key")
        .arg(&key)
        .arg("--force")
        .output_timeout("pm backup restore");
    assert!(restored.status.success());

    let unlocked = isolated_pm(root.path())
        .args(["--port", &port.to_string(), "unlock", "--key"])
        .arg(&key)
        .args(["--timeout", "0"])
        .output_timeout("pm unlock restored backup");
    assert!(unlocked.status.success());
    assert!(String::from_utf8_lossy(&run(root.path(), port, &["view"]).stdout).contains("example"));

    assert!(run(root.path(), port, &["kill"]).status.success());
    server.active = false;
}
