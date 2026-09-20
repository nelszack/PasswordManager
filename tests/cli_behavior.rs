use std::process::Command;

fn pm() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pm"))
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
    let json = pm()
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
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value["ok"], true);
    assert!(value["output"].as_str().unwrap().starts_with("Password: "));

    let quiet = pm()
        .args(["--quiet", "passcheck", "--password", "test-password"])
        .output()
        .unwrap();
    assert!(quiet.status.success());
    assert!(quiet.stdout.is_empty());
    assert!(quiet.stderr.is_empty());
}
