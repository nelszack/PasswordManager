//! SSH provisioning. Server sources travel inside pm; Go builds only on this device.
use super::{CloudClient, validate_server_url};
use crate::{
    config::{self, Config, ConfigChanges},
    file::read_bounded_file,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const PROBE: &str = include_str!("probe.sh");
const INSTALL: &str = include_str!("install.sh");
const ENROLL: &str = include_str!("enroll.sh");
const SOURCE: &str = include_str!("../../sync-server/main.go");
const MODULE: &str = include_str!("../../sync-server/go.mod");
const UNIT: &str = include_str!("../../sync-server/pm-sync.service");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Setup,
    Connect,
    Update,
}
#[derive(Clone, Debug)]
pub struct Request {
    pub operation: Operation,
    pub ssh_target: Option<String>,
    pub binary: Option<PathBuf>,
    pub device_name: Option<String>,
}
pub struct Outcome {
    pub config: Config,
    pub message: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Deployment {
    schema: u8,
    listen_port: u16,
    https_port: u16,
    server_url: String,
}
struct Plan {
    deployment: Deployment,
    new_route: bool,
}

pub fn validate_ssh_target(target: &str) -> Result<(), String> {
    if target.is_empty()
        || target.len() > 255
        || target.starts_with('-')
        || target.matches('@').count() > 1
        || !target
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b))
        || target
            .split('@')
            .any(|part| part.is_empty() || part.starts_with('-'))
    {
        return Err("Enter an SSH hostname or user@hostname, such as user@server. Use an SSH config alias for custom ports.".into());
    }
    Ok(())
}
fn quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}
fn remote_command(script: &str, args: &[String], stdin_is_binary: bool) -> String {
    if stdin_is_binary {
        format!("sh -c {}", quote(script))
    } else {
        format!(
            "sh -s -- {}",
            args.iter().map(|s| quote(s)).collect::<Vec<_>>().join(" ")
        )
    }
}
fn run(
    mut command: Command,
    input: Option<&[u8]>,
    label: &str,
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, String> {
    // File captures prevent pipe deadlocks, and credentials never reach terminal output.
    let stdout = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    let stderr = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    crate::file::set_private_perms(stdout.path()).map_err(|e| e.to_string())?;
    crate::file::set_private_perms(stderr.path()).map_err(|e| e.to_string())?;
    command
        .stdout(stdout.reopen().map_err(|e| e.to_string())?)
        .stderr(stderr.reopen().map_err(|e| e.to_string())?);
    command.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child=command.spawn().map_err(|e|format!("{label}: {e}. Install OpenSSH and Go locally, or supply --binary for a prebuilt server."))?;
    let writer = input.map(|bytes| {
        let bytes = Zeroizing::new(bytes.to_vec());
        let mut stdin = child.stdin.take().expect("piped stdin");
        thread::spawn(move || stdin.write_all(&bytes))
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{label} timed out; no further steps were attempted"
                ));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{label}: {e}"));
            }
        }
    };
    if !status.success() {
        let message = read_bounded_file(stderr.path(), 64 * 1024)
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .chars()
                    .take(3000)
                    .collect::<String>()
            })
            .unwrap_or_default();
        return Err(format!("{label} failed: {}", message.trim()));
    }
    if let Some(writer) = writer {
        writer
            .join()
            .map_err(|_| format!("{label}: input worker failed"))?
            .map_err(|e| format!("{label}: {e}"))?;
    }
    read_bounded_file(stdout.path(), 128 * 1024).map_err(|e| format!("{label}: {e}"))
}
fn process(program: &str) -> Command {
    #[cfg(target_os = "windows")]
    {
        crate::file::hidden_windows_command(program)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new(program)
    }
}
fn ssh(
    target: &str,
    script: &str,
    args: &[String],
    binary: Option<&[u8]>,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    validate_ssh_target(target)?;
    let mut command = process("ssh");
    command.args([
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "ServerAliveCountMax=3",
        target,
    ]);
    command.arg(remote_command(script, args, binary.is_some()));
    run(
        command,
        Some(binary.unwrap_or(script.as_bytes())),
        label,
        Duration::from_secs(120),
    )
}
fn probe(target: &str, kind: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    ssh(
        target,
        PROBE,
        &[kind.into()],
        None,
        "Checking SSH host (requires key/agent access, user systemd, Tailscale, and ss)",
    )
}
fn json(bytes: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("Invalid response from sync host: {e}"))
}
fn deployment(value: Value) -> Result<Option<Deployment>, String> {
    if value.as_object().is_some_and(|v| v.is_empty()) {
        return Ok(None);
    }
    let saved: Deployment = serde_json::from_value(value)
        .map_err(|e| format!("Invalid saved server installation: {e}"))?;
    validate_server_url(&saved.server_url)?;
    if saved.schema != 1 || saved.listen_port == 0 || saved.https_port == 0 {
        return Err("Unsupported saved server installation".into());
    }
    Ok(Some(saved))
}
fn reserve_ports(value: &Value, occupied: &mut BTreeSet<u16>, depth: u8) -> Result<(), String> {
    if depth > 2 || !value.is_object() {
        return Err("Invalid Tailscale Serve configuration".into());
    }
    for key in ["TCP", "Web", "Foreground", "AllowFunnel"] {
        if value
            .get(key)
            .is_some_and(|v| !v.is_null() && !v.is_object())
        {
            return Err(format!("Invalid Tailscale {key} configuration"));
        }
    }
    if let Some(tcp) = value.get("TCP").and_then(Value::as_object) {
        for port in tcp.keys() {
            occupied.insert(
                port.parse::<u16>()
                    .map_err(|_| "Invalid Tailscale TCP port")?,
            );
        }
    }
    if let Some(web) = value.get("Web").and_then(Value::as_object) {
        for endpoint in web.keys() {
            let (_, port) = endpoint
                .rsplit_once(':')
                .ok_or("Invalid Tailscale HTTPS endpoint")?;
            occupied.insert(
                port.parse::<u16>()
                    .map_err(|_| "Invalid Tailscale HTTPS port")?,
            );
        }
    }
    if let Some(funnel) = value.get("AllowFunnel").and_then(Value::as_object) {
        for (endpoint, allowed) in funnel {
            if allowed.as_bool() == Some(true) {
                let (_, port) = endpoint.rsplit_once(':').ok_or("Invalid Funnel endpoint")?;
                occupied.insert(port.parse::<u16>().map_err(|_| "Invalid Funnel port")?);
            }
        }
    }
    if let Some(foreground) = value.get("Foreground").and_then(Value::as_object) {
        for config in foreground.values() {
            reserve_ports(config, occupied, depth + 1)?;
        }
    }
    Ok(())
}
fn plan(dns: &str, serve: &Value, ports: &str, saved: Option<Deployment>) -> Result<Plan, String> {
    // Tailscale may encode an absent Serve configuration as JSON null.
    let empty = Value::Object(Default::default());
    let serve = if serve.is_null() { &empty } else { serve };
    let dns = dns.trim_end_matches('.');
    if dns.is_empty()
        || !dns
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        || !dns.ends_with(".ts.net")
    {
        return Err("Tailscale must be connected and provide this host's .ts.net DNS name".into());
    }
    if !serve.is_object() {
        return Err("Invalid Tailscale Serve configuration".into());
    }
    let mut occupied = BTreeSet::new();
    reserve_ports(serve, &mut occupied, 0)?;
    let (listen_port, https_port) = if let Some(saved) = saved {
        let expected = format!("https://{dns}:{}", saved.https_port);
        if saved.server_url != expected {
            return Err("Saved server address differs from this Tailscale host; refusing to change the connection automatically".into());
        }
        (saved.listen_port, saved.https_port)
    } else {
        let used = ports
            .split_whitespace()
            .filter_map(|s| s.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()))
            .collect::<BTreeSet<_>>();
        let listen = (8788..=8888)
            .find(|p| !used.contains(p))
            .ok_or("No unused local sync port available")?;
        let https = [8443, 9443, 10443, 11443, 12443, 13443]
            .into_iter()
            .find(|p| !occupied.contains(p))
            .ok_or("No unused Tailscale HTTPS port available")?;
        (listen, https)
    };
    let endpoint = format!("{dns}:{https_port}");
    if serve
        .get("AllowFunnel")
        .and_then(|v| v.get(&endpoint))
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Err(
            "The sync endpoint has public Funnel access enabled; disable it before setup".into(),
        );
    }
    let new_route = !occupied.contains(&https_port);
    if !new_route {
        if let Some(foreground) = serve.get("Foreground").and_then(Value::as_object) {
            let mut foreground_ports = BTreeSet::new();
            for value in foreground.values() {
                reserve_ports(value, &mut foreground_ports, 0)?;
            }
            if foreground_ports.contains(&https_port) {
                return Err(
                    "The saved HTTPS port is held by a foreground Tailscale service".into(),
                );
            }
        }
        let handlers = serve
            .get("Web")
            .and_then(|v| v.get(&endpoint))
            .and_then(|v| v.get("Handlers"))
            .and_then(Value::as_object);
        let expected = format!("http://127.0.0.1:{listen_port}");
        if !handlers.is_some_and(|h| {
            h.len() == 1
                && h.get("/")
                    .and_then(|v| v.get("Proxy"))
                    .and_then(Value::as_str)
                    == Some(&expected)
        }) {
            return Err("The saved HTTPS port belongs to another service; refusing to replace its Tailscale configuration".into());
        }
    }
    Ok(Plan {
        deployment: Deployment {
            schema: 1,
            listen_port,
            https_port,
            server_url: format!("https://{endpoint}"),
        },
        new_route,
    })
}
fn architecture(machine: &str) -> Result<&'static str, String> {
    match machine.trim() {
        "x86_64" | "amd64" => Ok("amd64"),
        "aarch64" | "arm64" => Ok("arm64"),
        _ => Err("The sync server currently supports Linux x86_64 and ARM64 hosts".into()),
    }
}
fn validate_binary(path: &Path, arch: &str) -> Result<Vec<u8>, String> {
    let bytes = read_bounded_file(path, 32 * 1024 * 1024)
        .map_err(|e| format!("Read sync server binary: {e}"))?;
    let machine = match arch {
        "amd64" => 62,
        "arm64" => 183,
        _ => return Err("Unsupported server architecture".into()),
    };
    if bytes.len() < 20
        || &bytes[..4] != b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
        || u16::from_le_bytes([bytes[18], bytes[19]]) != machine
    {
        return Err(format!(
            "The server binary must be a 64-bit Linux {arch} executable"
        ));
    }
    Ok(bytes.to_vec())
}
fn build(arch: &str, provided: Option<&Path>) -> Result<Vec<u8>, String> {
    if let Some(path) = provided {
        return validate_binary(path, arch);
    }
    let directory = tempfile::tempdir().map_err(|e| e.to_string())?;
    fs::write(directory.path().join("main.go"), SOURCE).map_err(|e| e.to_string())?;
    fs::write(directory.path().join("go.mod"), MODULE).map_err(|e| e.to_string())?;
    let destination = directory.path().join("pm-sync");
    let build_id = blake3::hash(SOURCE.as_bytes()).to_hex().to_string();
    let mut command = process("go");
    command
        .current_dir(directory.path())
        .env("CGO_ENABLED", "0")
        .env("GOOS", "linux")
        .env("GOARCH", arch)
        .args([
            "build",
            "-trimpath",
            "-ldflags",
            &format!(
                "-s -w -X main.version={} -X main.buildID={build_id}",
                env!("CARGO_PKG_VERSION")
            ),
            "-o",
        ])
        .arg(&destination)
        .arg(".");
    run(
        command,
        None,
        "Building sync server locally",
        Duration::from_secs(300),
    )?;
    validate_binary(&destination, arch)
}
fn install_script(port: u16) -> String {
    let unit = format!(
        "# Managed by Password Manager sync setup v1\n{}",
        UNIT.replace("127.0.0.1:8788", &format!("127.0.0.1:{port}"))
    );
    INSTALL.replace(
        "@WRITE_UNIT@",
        &format!("cat > \"$unit.new-$nonce\" <<'PM_SYNC_UNIT'\n{unit}PM_SYNC_UNIT"),
    )
}
fn deploy(target: &str, plan: &Plan, bytes: &[u8], update: bool) -> Result<(), String> {
    let nonce = hex::encode(rand::random::<[u8; 16]>());
    let upload = format!(
        "set -eu; umask 077; mkdir -p \"$HOME/.local/bin\"; stage=\"$HOME/.local/bin/.pm-sync-upload-{nonce}\"; trap '[ ! -f \"$stage\" ] || rm \"$stage\"' EXIT; cat > \"$stage\"; chmod 700 \"$stage\"; trap - EXIT"
    );
    ssh(target, &upload, &[], Some(bytes), "Uploading sync server")?;
    let result = (|| {
        let version = ssh(
            target,
            "set -eu\n\"$HOME/.local/bin/.pm-sync-upload-$1\" --version\n",
            std::slice::from_ref(&nonce),
            None,
            "Verifying uploaded server version",
        )?;
        let info = json(&version)?;
        if info.get("protocol").and_then(Value::as_u64) != Some(1) {
            return Err("The uploaded sync server uses an unsupported protocol; existing installation was preserved".into());
        }
        ssh(
            target,
            &install_script(plan.deployment.listen_port),
            &[
                nonce.clone(),
                plan.deployment.listen_port.to_string(),
                plan.deployment.https_port.to_string(),
                plan.deployment.server_url.clone(),
                u8::from(plan.new_route).to_string(),
                u8::from(update).to_string(),
            ],
            None,
            "Installing sync server and private Tailscale endpoint",
        )
    })();
    if result.is_err() {
        let _ = ssh(
            target,
            "set -eu\nfile=\"$HOME/.local/bin/.pm-sync-upload-$1\"\n[ ! -f \"$file\" ] || rm \"$file\"\n",
            &[nonce],
            None,
            "Removing incomplete upload",
        );
    }
    result.map(|_| ())
}
fn validate_device_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err("Device name must contain 1–128 bytes with no control characters".into());
    }
    Ok(name.to_owned())
}
fn device_name_from_status(status: &Value) -> Result<String, String> {
    if status.get("BackendState").and_then(Value::as_str) != Some("Running") {
        return Err("Connect this device to Tailscale before setting up sync".into());
    }
    let local = status
        .get("Self")
        .ok_or("Tailscale did not report this device")?;
    // DNSName reflects names changed in Tailscale; HostName can still be the OS name.
    let dns = local
        .get("DNSName")
        .and_then(Value::as_str)
        .and_then(|name| name.trim_end_matches('.').split('.').next())
        .filter(|name| !name.is_empty());
    let name = dns
        .or_else(|| local.get("HostName").and_then(Value::as_str))
        .ok_or("Tailscale did not report this device's name")?;
    validate_device_name(name)
}
fn enrollment_name(override_name: Option<&str>) -> Result<String, String> {
    if let Some(name) = override_name.filter(|name| !name.trim().is_empty()) {
        return validate_device_name(name);
    }
    let mut command = process("tailscale");
    command.args(["status", "--json", "--peers=false"]);
    let fallback = "Could not read this device's Tailscale name. Make sure Tailscale is connected and its CLI is installed, or enter a device name under Manual connection options (CLI: --name NAME).";
    let status = run(
        command,
        None,
        "Reading this device's Tailscale name",
        Duration::from_secs(10),
    )
    .map_err(|_| fallback.to_owned())?;
    let status = json(&status).map_err(|_| fallback.to_owned())?;
    device_name_from_status(&status)
}

fn connect(target: &str, url: &str, name: Option<&str>, path: &Path) -> Result<Config, String> {
    let current = config::try_read_config(path)?;
    if current.sync.server_url == url
        && CloudClient::new(&current.sync)
            .and_then(|c| c.list())
            .is_ok()
    {
        return config::try_update(
            current,
            ConfigChanges {
                sync_ssh_target: Some(target.into()),
                ..Default::default()
            },
            path,
        );
    }
    let name = validate_device_name(name.ok_or("Device name was not resolved before enrollment")?)?;
    let response = ssh(
        target,
        ENROLL,
        &[name],
        None,
        "Authorizing this device over SSH",
    )?;
    #[derive(Deserialize)]
    struct Credential {
        token: crate::secret::SecretString,
        device_id: String,
    }
    let credential: Credential = serde_json::from_slice(&response)
        .map_err(|_| "Invalid enrollment response from sync host")?;
    let result = super::connect_with_token(
        current,
        url,
        credential.token.expose(),
        Some(target.into()),
        path,
    )
    .map_err(|e| format!("The server is installed, but this device could not connect: {e}"));
    if result.is_err()
        && credential.device_id.len() == 64
        && credential.device_id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        let _ = ssh(
            target,
            "set -eu\n\"$HOME/.local/bin/pm-sync\" --data \"$HOME/.local/share/pm-sync\" --revoke-device \"$1\"\n",
            &[credential.device_id],
            None,
            "Revoking incomplete device enrollment",
        );
    }
    result
}
pub fn execute(request: Request, path: &Path) -> Result<Outcome, String> {
    let current = config::try_read_config(path)?;
    let target = request
        .ssh_target
        .or_else(|| current.sync.ssh_target.clone())
        .ok_or("Enter the server SSH address, such as user@server")?;
    validate_ssh_target(&target)?;
    let device_name = if request.operation == Operation::Update {
        None
    } else {
        Some(enrollment_name(request.device_name.as_deref())?)
    };
    let saved = deployment(json(&probe(&target, "deployment")?)?)?;
    if request.operation == Operation::Connect {
        let saved = saved.ok_or(
            "No managed sync server exists on this host. Run pm sync setup --ssh HOST first",
        )?;
        let config = connect(&target, &saved.server_url, device_name.as_deref(), path)?;
        return Ok(Outcome {
            config,
            message: format!(
                "Connected to {}. Choose a cloud vault to download, or enable sync for your open vault.",
                saved.server_url
            ),
        });
    }
    if request.operation == Operation::Update && saved.is_none() {
        return Err("No managed sync installation exists; run pm sync setup first".into());
    }
    let machine = probe(&target, "machine")?;
    let arch = architecture(std::str::from_utf8(&machine).map_err(|e| e.to_string())?)?;
    let status = json(&probe(&target, "tailscale")?)?;
    if status.get("BackendState").and_then(Value::as_str) != Some("Running") {
        return Err("Tailscale is not connected on the sync host".into());
    }
    let dns = status
        .get("Self")
        .and_then(|v| v.get("DNSName"))
        .and_then(Value::as_str)
        .ok_or("Tailscale host has no DNS name")?;
    let serve = json(&probe(&target, "serve")?)?;
    let ports = probe(&target, "ports")?;
    plan(dns, &serve, &String::from_utf8_lossy(&ports), saved)?;
    let bytes = build(arch, request.binary.as_deref())?;
    let latest_saved = deployment(json(&probe(&target, "deployment")?)?)?;
    let latest_serve = json(&probe(&target, "serve")?)?;
    let latest_ports = probe(&target, "ports")?;
    let plan = plan(
        dns,
        &latest_serve,
        &String::from_utf8_lossy(&latest_ports),
        latest_saved,
    )?;
    deploy(
        &target,
        &plan,
        &bytes,
        request.operation == Operation::Update,
    )?;
    if request.operation == Operation::Update {
        let config = config::try_update(
            current,
            ConfigChanges {
                sync_ssh_target: Some(target),
                ..Default::default()
            },
            path,
        )?;
        Ok(Outcome {
            config,
            message: format!(
                "Sync server updated at {}. The previous binary is retained for rollback.",
                plan.deployment.server_url
            ),
        })
    } else {
        let config = connect(
            &target,
            &plan.deployment.server_url,
            device_name.as_deref(),
            path,
        )?;
        Ok(Outcome {
            config,
            message: format!(
                "Sync server is ready at {}. This device is connected; open a vault and enable sync.",
                plan.deployment.server_url
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn tailscale_device_name_uses_this_devices_assigned_name() {
        let status = json!({"BackendState":"Running","Self":{"DNSName":"renamed-laptop.tail123.ts.net.","HostName":"old-os-name"},"Peer":{"other":{"DNSName":"other-device.tail123.ts.net."}}});
        assert_eq!(device_name_from_status(&status).unwrap(), "renamed-laptop");
        assert_eq!(
            device_name_from_status(
                &json!({"BackendState":"Running","Self":{"HostName":"fallback-host"}})
            )
            .unwrap(),
            "fallback-host"
        );
        for invalid in [
            json!({"BackendState":"NeedsLogin","Self":{"HostName":"host"}}),
            json!({"BackendState":"Running","Self":null}),
            json!({"BackendState":"Running","Self":{"DNSName":"bad\nname.tail.ts.net."}}),
        ] {
            assert!(device_name_from_status(&invalid).is_err());
        }
        assert_eq!(
            enrollment_name(Some("  custom-device  ")).unwrap(),
            "custom-device"
        );
        assert!(enrollment_name(Some("bad\nname")).is_err());
    }
    #[test]
    fn ssh_destinations_are_data_and_cannot_supply_options_or_shell_commands() {
        for value in ["user@server", "sync-server", "alice@100.64.1.2"] {
            assert!(validate_ssh_target(value).is_ok());
        }
        for value in [
            "-oProxyCommand=evil",
            "user@host;touch /tmp/evil",
            "user@host\ncommand",
            "user@@host",
            "user@-host",
            "user@host $(id)",
        ] {
            assert!(validate_ssh_target(value).is_err(), "{value}");
        }
        assert_eq!(quote("laptop's name"), "'laptop'\\''s name'");
    }
    #[test]
    fn installation_avoids_existing_services_and_reuses_only_its_own_route() {
        assert_eq!(
            plan("sync-server.test.ts.net", &Value::Null, "", None)
                .unwrap()
                .deployment
                .https_port,
            8443
        );
        let serve = json!({"TCP":{"8443":{"HTTPS":true}},"Web":{"sync-server.test.ts.net:8443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}}});
        let planned = plan(
            "sync-server.test.ts.net.",
            &serve,
            "LISTEN 0 128 0.0.0.0:8788 0.0.0.0:*",
            None,
        )
        .unwrap();
        assert_eq!(planned.deployment.listen_port, 8789);
        assert_eq!(planned.deployment.https_port, 9443);
        assert!(planned.new_route);
        let saved = Deployment {
            schema: 1,
            listen_port: 8789,
            https_port: 9443,
            server_url: "https://sync-server.test.ts.net:9443".into(),
        };
        assert!(
            plan("sync-server.test.ts.net", &serve, "", Some(saved.clone()))
                .unwrap()
                .new_route
        );
        let own = json!({"TCP":{"9443":{"HTTPS":true}},"Web":{"sync-server.test.ts.net:9443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:8789"}}}}});
        assert!(
            !plan("sync-server.test.ts.net", &own, "", Some(saved.clone()))
                .unwrap()
                .new_route
        );
        let collision = json!({"TCP":{"9443":{"HTTPS":true}},"Web":{"sync-server.test.ts.net:9443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:9999"}}}}});
        assert!(
            plan(
                "sync-server.test.ts.net",
                &collision,
                "",
                Some(saved.clone())
            )
            .is_err()
        );
        let mut public = own.clone();
        public["AllowFunnel"] = json!({"sync-server.test.ts.net:9443":true});
        assert!(plan("sync-server.test.ts.net", &public, "", Some(saved)).is_err());
        let foreground = json!({"Foreground":{"session":{"TCP":{"8443":{"HTTPS":true}}}}});
        assert_eq!(
            plan("sync-server.test.ts.net", &foreground, "", None)
                .unwrap()
                .deployment
                .https_port,
            9443
        );
        assert!(
            plan(
                "sync-server.test.ts.net",
                &json!({"TCP":"invalid"}),
                "",
                None
            )
            .is_err()
        );
    }
    #[test]
    fn architecture_and_prebuilt_executable_must_match() {
        assert_eq!(architecture("x86_64\n").unwrap(), "amd64");
        assert_eq!(architecture("aarch64").unwrap(), "arm64");
        assert!(architecture("armv7l").is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server");
        let mut bytes = vec![0; 20];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[18] = 62;
        fs::write(&path, &bytes).unwrap();
        assert!(validate_binary(&path, "amd64").is_ok());
        assert!(validate_binary(&path, "arm64").is_err());
        fs::write(&path, b"not a server").unwrap();
        assert!(validate_binary(&path, "amd64").is_err());
    }
    #[cfg(unix)]
    fn executable(path: &Path, source: &str) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, source).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(unix)]
    fn simulated_install(
        fail_health: bool,
        new_route: bool,
        previous: &str,
    ) -> (tempfile::TempDir, Result<Zeroizing<Vec<u8>>, String>) {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let tools = home.join("tools");
        fs::create_dir(&tools).unwrap();
        executable(
            &tools.join("systemctl"),
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$HOME/systemctl.log\"\nexit 0\n",
        );
        executable(
            &tools.join("tailscale"),
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$HOME/tailscale.log\"\nexit 0\n",
        );
        executable(&tools.join("sleep"), "#!/bin/sh\nexit 0\n");
        let bin = home.join(".local/bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join("pm-sync"), b"previous-server-binary").unwrap();
        let stage = format!(
            "#!/bin/sh\nif [ \"$1\" = --health-check ]; then exit {}; fi\nexit 0\n",
            u8::from(fail_health)
        );
        executable(&bin.join(".pm-sync-upload-test"), &stage);
        let root = home.join(".local/share/pm-sync");
        fs::create_dir_all(root.join("vaults")).unwrap();
        fs::write(root.join("vaults/keep.vault"), b"encrypted-vault").unwrap();
        fs::write(root.join("deployment.json"), b"previous-installation").unwrap();
        let unit = home.join(".config/systemd/user");
        fs::create_dir_all(&unit).unwrap();
        fs::write(
            unit.join("pm-sync.service"),
            b"# Managed by Password Manager sync setup v1\nExecStart=pm-sync --listen 127.0.0.1:8789 --keep 7\n",
        )
        .unwrap();
        if previous == "fresh" {
            for path in [
                bin.join("pm-sync"),
                unit.join("pm-sync.service"),
                root.join("deployment.json"),
            ] {
                fs::remove_file(path).unwrap();
            }
        } else if previous == "unmanaged" {
            fs::write(unit.join("pm-sync.service"), b"other-service").unwrap();
        }
        let mut paths = vec![tools];
        paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        let mut command = Command::new("sh");
        command
            .args([
                "-s",
                "--",
                "test",
                "8789",
                "9443",
                "https://sync-server.test.ts.net:9443",
                if new_route { "1" } else { "0" },
                if previous == "fresh" { "0" } else { "1" },
            ])
            .env("HOME", home)
            .env("PATH", std::env::join_paths(paths).unwrap());
        let result = run(
            command,
            Some(install_script(8789).as_bytes()),
            "Simulated deployment",
            Duration::from_secs(10),
        );
        (temp, result)
    }
    #[cfg(unix)]
    #[test]
    fn installer_retains_previous_binary_and_configures_only_the_selected_port() {
        let (home, result) = simulated_install(false, true, "managed");
        result.unwrap();
        assert_eq!(
            fs::read(home.path().join(".local/bin/pm-sync.previous")).unwrap(),
            b"previous-server-binary"
        );
        let unit =
            fs::read_to_string(home.path().join(".config/systemd/user/pm-sync.service")).unwrap();
        assert!(unit.contains("127.0.0.1:8789"));
        assert!(!unit.contains("$listen_port"));
        assert!(unit.contains("--keep 7"));
        let route = fs::read_to_string(home.path().join("tailscale.log")).unwrap();
        assert!(route.contains("--https=9443"));
        assert!(!route.contains("8443"));
        assert_eq!(
            fs::read(home.path().join(".local/share/pm-sync/vaults/keep.vault")).unwrap(),
            b"encrypted-vault"
        );
        assert!(
            !home
                .path()
                .join(".local/share/pm-sync/deploy.lock")
                .exists()
        );
    }
    #[cfg(unix)]
    #[test]
    fn failed_health_check_restores_the_previous_service_and_preserves_vault_data() {
        let (home, result) = simulated_install(true, false, "managed");
        assert!(result.is_err());
        assert_eq!(
            fs::read(home.path().join(".local/bin/pm-sync")).unwrap(),
            b"previous-server-binary"
        );
        assert_eq!(
            fs::read(home.path().join(".config/systemd/user/pm-sync.service")).unwrap(),
            b"# Managed by Password Manager sync setup v1\nExecStart=pm-sync --listen 127.0.0.1:8789 --keep 7\n"
        );
        assert_eq!(
            fs::read(home.path().join(".local/share/pm-sync/deployment.json")).unwrap(),
            b"previous-installation"
        );
        assert_eq!(
            fs::read(home.path().join(".local/share/pm-sync/vaults/keep.vault")).unwrap(),
            b"encrypted-vault"
        );
        assert!(!home.path().join("tailscale.log").exists());
        assert!(
            !home
                .path()
                .join(".local/share/pm-sync/deploy.lock")
                .exists()
        );
    }
    #[cfg(unix)]
    #[test]
    fn fresh_install_renders_the_unit_and_unmanaged_services_are_never_overwritten() {
        let (home, result) = simulated_install(false, true, "fresh");
        result.unwrap();
        let unit =
            fs::read_to_string(home.path().join(".config/systemd/user/pm-sync.service")).unwrap();
        assert!(unit.contains("127.0.0.1:8789"));
        assert!(unit.contains("Managed by Password Manager"));
        assert!(!unit.contains("@WRITE_UNIT@"));
        let (home, result) = simulated_install(false, true, "unmanaged");
        assert!(result.unwrap_err().contains("unmanaged"));
        assert_eq!(
            fs::read(home.path().join(".config/systemd/user/pm-sync.service")).unwrap(),
            b"other-service"
        );
        assert_eq!(
            fs::read(home.path().join(".local/bin/pm-sync")).unwrap(),
            b"previous-server-binary"
        );
        assert!(!home.path().join("tailscale.log").exists());
    }
}
