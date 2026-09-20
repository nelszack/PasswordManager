use crate::{
    cli::NativeBrowser,
    client,
    file::data_dir,
    types::{EntryUpdate, PasswordEntry, ServerCommand, Target, TotpCommand},
};
use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(target_os = "windows")]
use std::process::Command;
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

use crate::cli::UpdateArgs;

const HOST_NAME: &str = "com.myproject.password_manager";
#[cfg(not(target_os = "windows"))]
const HOST_BINARY_NAME: &str = "pm-native-host";
#[cfg(target_os = "windows")]
const HOST_BINARY_NAME: &str = "pm-native-host.exe";
const MAX_NATIVE_MESSAGE: usize = 1024 * 1024;

#[derive(Deserialize, Default)]
struct NativeRequest {
    id: u64,
    action: String,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "entryId")]
    entry_id: Option<usize>,
}

impl Zeroize for NativeRequest {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.action.zeroize();
        self.domain.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.name.zeroize();
        self.entry_id.zeroize();
        *self = Self::default();
    }
}

#[derive(Serialize)]
struct NativeResponse {
    id: u64,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl Zeroize for NativeResponse {
    fn zeroize(&mut self) {
        self.id.zeroize();
        if let Some(data) = self.data.as_mut() {
            zeroize_json(data);
        }
        self.data = None;
        self.error.zeroize();
        self.success.zeroize();
    }
}

fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(string) => string.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json),
        Value::Object(values) => values.values_mut().for_each(zeroize_json),
        _ => {}
    }
    *value = Value::Null;
}

impl NativeResponse {
    fn success(id: u64, data: Value) -> Self {
        Self {
            id,
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(id: u64, error: impl Into<String>) -> Self {
        Self {
            id,
            success: false,
            data: None,
            error: Some(error.into()),
        }
    }
}

pub fn invoked_directly() -> bool {
    std::env::args_os()
        .next()
        .and_then(|path| PathBuf::from(path).file_name().map(|name| name.to_owned()))
        .is_some_and(|name| name == HOST_BINARY_NAME)
}

pub fn install(extension_id: &str, browser: NativeBrowser) -> Result<PathBuf, String> {
    validate_extension_id(extension_id)?;
    let base_dirs =
        BaseDirs::new().ok_or_else(|| "could not locate the user config directory".to_string())?;
    let host_dir = data_dir().join("native-messaging");
    fs::create_dir_all(&host_dir)
        .map_err(|error| format!("could not create {}: {error}", host_dir.display()))?;
    let host_path = host_dir.join(HOST_BINARY_NAME);
    install_host_link(&host_path)?;

    let manifest_dir = native_manifest_dir(&base_dirs, browser, &host_dir);
    fs::create_dir_all(&manifest_dir)
        .map_err(|error| format!("could not create {}: {error}", manifest_dir.display()))?;
    let manifest_path = manifest_dir.join(format!("{HOST_NAME}.json"));
    let manifest = json!({
        "name": HOST_NAME,
        "description": "Password Manager browser bridge",
        "path": host_path,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{extension_id}/")]
    });
    let encoded = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("could not encode native host manifest: {error}"))?;
    fs::write(&manifest_path, encoded)
        .map_err(|error| format!("could not write {}: {error}", manifest_path.display()))?;
    register_manifest(&manifest_path, browser)?;
    Ok(manifest_path)
}

#[derive(Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
enum NativePlatform {
    Linux,
    Macos,
    Windows,
}

fn native_manifest_dir(base_dirs: &BaseDirs, browser: NativeBrowser, host_dir: &Path) -> PathBuf {
    #[cfg(target_os = "linux")]
    let platform = NativePlatform::Linux;
    #[cfg(target_os = "macos")]
    let platform = NativePlatform::Macos;
    #[cfg(target_os = "windows")]
    let platform = NativePlatform::Windows;
    native_manifest_dir_for(base_dirs.config_dir(), browser, host_dir, platform)
}

fn native_manifest_dir_for(
    config_dir: &Path,
    browser: NativeBrowser,
    host_dir: &Path,
    platform: NativePlatform,
) -> PathBuf {
    let browser_dir = match (platform, browser) {
        (NativePlatform::Linux, NativeBrowser::Chrome) => PathBuf::from("google-chrome"),
        (NativePlatform::Linux, NativeBrowser::Chromium) => PathBuf::from("chromium"),
        (NativePlatform::Linux, NativeBrowser::Helium) => PathBuf::from("net.imput.helium"),
        (NativePlatform::Macos, NativeBrowser::Chrome) => Path::new("Google").join("Chrome"),
        (NativePlatform::Macos, NativeBrowser::Chromium) => PathBuf::from("Chromium"),
        (NativePlatform::Macos, NativeBrowser::Helium) => PathBuf::from("net.imput.helium"),
        (NativePlatform::Windows, _) => return host_dir.to_path_buf(),
    };
    config_dir.join(browser_dir).join("NativeMessagingHosts")
}

#[cfg(unix)]
fn install_host_link(host_path: &Path) -> Result<(), String> {
    use std::os::unix::fs::symlink;

    let executable = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| format!("could not locate the pm executable: {error}"))?;
    if let Ok(metadata) = fs::symlink_metadata(host_path) {
        if metadata.file_type().is_symlink()
            && fs::read_link(host_path).ok().as_deref() == Some(executable.as_path())
        {
            return Ok(());
        }
        if !metadata.file_type().is_symlink() {
            return Err(format!(
                "refusing to replace non-symlink host executable at {}",
                host_path.display()
            ));
        }
        fs::remove_file(host_path)
            .map_err(|error| format!("could not update {}: {error}", host_path.display()))?;
    }
    symlink(&executable, host_path)
        .map_err(|error| format!("could not link {}: {error}", host_path.display()))
}

#[cfg(target_os = "windows")]
fn install_host_link(host_path: &Path) -> Result<(), String> {
    let executable = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| format!("could not locate the pm executable: {error}"))?;
    fs::copy(&executable, host_path)
        .map(|_| ())
        .map_err(|error| format!("could not install {}: {error}", host_path.display()))
}

#[cfg(not(target_os = "windows"))]
fn register_manifest(_manifest_path: &Path, _browser: NativeBrowser) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn register_manifest(manifest_path: &Path, browser: NativeBrowser) -> Result<(), String> {
    let vendor = windows_registry_vendor(browser);
    let registry_key = format!(r"HKCU\Software\{vendor}\NativeMessagingHosts\{HOST_NAME}");
    let absolute_manifest = fs::canonicalize(manifest_path)
        .map_err(|error| format!("could not resolve {}: {error}", manifest_path.display()))?;
    let status = Command::new("reg.exe")
        .args(["ADD", &registry_key, "/ve", "/t", "REG_SZ", "/d"])
        .arg(&absolute_manifest)
        .arg("/f")
        .status()
        .map_err(|error| format!("could not run reg.exe: {error}"))?;
    if !status.success() {
        return Err(format!(
            "could not register the native host in {registry_key}"
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "windows", test))]
fn windows_registry_vendor(browser: NativeBrowser) -> &'static str {
    match browser {
        NativeBrowser::Chrome => "Google\\Chrome",
        NativeBrowser::Chromium => "Chromium",
        // Helium currently discovers native hosts through Chromium's registry
        // location rather than a Helium-specific vendor key.
        NativeBrowser::Helium => "Chromium",
    }
}

fn validate_extension_id(extension_id: &str) -> Result<(), String> {
    if extension_id.len() == 32
        && extension_id
            .bytes()
            .all(|byte| (b'a'..=b'p').contains(&byte))
    {
        Ok(())
    } else {
        Err("extension ID must be 32 lowercase letters in the range a-p".to_string())
    }
}

pub fn run() -> Result<(), String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_with_io(&mut stdin.lock(), &mut stdout.lock())
}

fn run_with_io(reader: &mut impl Read, writer: &mut impl Write) -> Result<(), String> {
    loop {
        let Some(mut payload) = read_message(reader)? else {
            return Ok(());
        };
        let request = serde_json::from_slice::<NativeRequest>(&payload);
        payload.zeroize();
        let mut response = match request {
            Ok(request) => handle_request(request),
            Err(error) => NativeResponse::error(0, format!("invalid request: {error}")),
        };
        let write_result = write_message(writer, &response);
        response.zeroize();
        write_result?;
    }
}

fn read_message(reader: &mut impl Read) -> Result<Option<Vec<u8>>, String> {
    let mut length = [0u8; 4];
    match reader.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(format!("could not read message length: {error}")),
    }
    let length = u32::from_ne_bytes(length) as usize;
    if length > MAX_NATIVE_MESSAGE {
        return Err("native message exceeds the 1 MiB limit".to_string());
    }
    let mut payload = vec![0u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| format!("could not read native message: {error}"))?;
    Ok(Some(payload))
}

fn write_message(writer: &mut impl Write, response: &NativeResponse) -> Result<(), String> {
    let mut payload = serde_json::to_vec(response)
        .map_err(|error| format!("could not encode native response: {error}"))?;
    if payload.len() > MAX_NATIVE_MESSAGE {
        return Err("native response exceeds Chrome's 1 MiB limit".to_string());
    }
    let result = writer
        .write_all(&(payload.len() as u32).to_ne_bytes())
        .and_then(|_| writer.write_all(&payload))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("could not write native response: {error}"));
    payload.zeroize();
    result
}

fn required(value: Option<String>, field: &str, max_length: usize) -> Result<String, String> {
    let value = value.ok_or_else(|| format!("missing {field}"))?;
    if value.is_empty() || value.len() > max_length || value.contains(['\0', '\r', '\n']) {
        return Err(format!("invalid {field}"));
    }
    Ok(value)
}

fn optional_text(value: Option<String>, field: &str, max_length: usize) -> Result<String, String> {
    let value = value.unwrap_or_default();
    if value.len() > max_length || value.contains(['\0', '\r', '\n']) {
        return Err(format!("invalid {field}"));
    }
    Ok(value)
}

fn handle_request(mut request: NativeRequest) -> NativeResponse {
    let id = request.id;
    let result = command_for_request(&mut request)
        .and_then(client::request)
        .and_then(|output| response_data(&request.action, output));
    request.zeroize();
    match result {
        Ok(data) => NativeResponse::success(id, data),
        Err(error) => NativeResponse::error(id, error),
    }
}

fn command_for_request(request: &mut NativeRequest) -> Result<ServerCommand, String> {
    match request.action.as_str() {
        "status" => Ok(ServerCommand::Status),
        "getCredentials" => Ok(ServerCommand::Get(Target::Url(required(
            request.domain.take(),
            "domain",
            2048,
        )?))),
        "getAutofillItems" => Ok(ServerCommand::BrowserAutofill),
        "getAutofillItem" => Ok(ServerCommand::BrowserAutofillItem(
            request
                .entry_id
                .ok_or_else(|| "missing entry ID".to_string())?,
        )),
        "getTotp" => Ok(ServerCommand::Totp(TotpCommand::Show {
            target: Target::Id(
                request
                    .entry_id
                    .ok_or_else(|| "missing entry ID".to_string())?,
            ),
            copy_timeout: None,
        })),
        "saveCredentials" => Ok(ServerCommand::Add(PasswordEntry {
            name: required(request.name.take(), "name", 4096)?,
            username: Some(optional_text(request.username.take(), "username", 4096)?),
            password: required(request.password.take(), "password", 64 * 1024)?,
            url: Some(required(request.domain.take(), "domain", 2048)?),
            notes: None,
            copy: false,
        })),
        "updateCredentials" => {
            let entry_id = request
                .entry_id
                .ok_or_else(|| "missing entry ID".to_string())?;
            Ok(ServerCommand::Update(EntryUpdate {
                target: Target::Id(entry_id),
                update: UpdateArgs {
                    name: None,
                    username: Some(optional_text(request.username.take(), "username", 4096)?),
                    password: true,
                    generate_password: false,
                    url: Some(required(request.domain.take(), "domain", 2048)?),
                    notes: None,
                },
                password: Some(required(request.password.take(), "password", 64 * 1024)?),
            }))
        }
        "lock" => Ok(ServerCommand::Lock(true)),
        _ => Err("unsupported native messaging action".to_string()),
    }
}

fn response_data(action: &str, mut output: String) -> Result<Value, String> {
    let result = if action == "getTotp" {
        let parse = || {
            let output = output.trim();
            let value = output
                .strip_prefix("TOTP: ")
                .ok_or_else(|| output.to_string())?;
            let (code, lifetime) = value
                .split_once(" (")
                .ok_or_else(|| "invalid TOTP response from server".to_string())?;
            let expires_in = lifetime
                .strip_suffix("s remaining)")
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| "invalid TOTP lifetime from server".to_string())?;
            Ok(json!({ "code": code, "expires_in": expires_in }))
        };
        parse()
    } else {
        Ok(Value::String(output.trim().to_string()))
    };
    output.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn validates_chrome_extension_ids() {
        assert!(validate_extension_id("abcdefghijklmnopabcdefghijklmnop").is_ok());
        assert!(validate_extension_id("too-short").is_err());
        assert!(validate_extension_id("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    #[test]
    fn native_host_uses_the_platform_executable_name() {
        #[cfg(target_os = "windows")]
        assert_eq!(HOST_BINARY_NAME, "pm-native-host.exe");
        #[cfg(not(target_os = "windows"))]
        assert_eq!(HOST_BINARY_NAME, "pm-native-host");
    }

    #[test]
    fn native_manifest_directory_matches_the_current_platform() {
        let base_dirs = BaseDirs::new().unwrap();
        let host_dir = data_dir().join("native-messaging");
        let chrome = native_manifest_dir(&base_dirs, NativeBrowser::Chrome, &host_dir);
        let chromium = native_manifest_dir(&base_dirs, NativeBrowser::Chromium, &host_dir);
        let helium = native_manifest_dir(&base_dirs, NativeBrowser::Helium, &host_dir);

        #[cfg(target_os = "linux")]
        {
            assert!(chrome.ends_with("google-chrome/NativeMessagingHosts"));
            assert!(chromium.ends_with("chromium/NativeMessagingHosts"));
            assert!(helium.ends_with("net.imput.helium/NativeMessagingHosts"));
        }
        #[cfg(target_os = "macos")]
        {
            assert!(chrome.ends_with("Google/Chrome/NativeMessagingHosts"));
            assert!(chromium.ends_with("Chromium/NativeMessagingHosts"));
            assert!(helium.ends_with("net.imput.helium/NativeMessagingHosts"));
        }
        #[cfg(target_os = "windows")]
        {
            assert_eq!(chrome, host_dir);
            assert_eq!(chromium, host_dir);
            assert_eq!(helium, host_dir);
        }
    }

    #[test]
    fn native_manifest_directories_cover_every_supported_platform() {
        let config_dir = Path::new("config");
        let host_dir = Path::new("host");

        let cases = [
            (
                NativePlatform::Linux,
                NativeBrowser::Chrome,
                "config/google-chrome/NativeMessagingHosts",
            ),
            (
                NativePlatform::Linux,
                NativeBrowser::Chromium,
                "config/chromium/NativeMessagingHosts",
            ),
            (
                NativePlatform::Linux,
                NativeBrowser::Helium,
                "config/net.imput.helium/NativeMessagingHosts",
            ),
            (
                NativePlatform::Macos,
                NativeBrowser::Chrome,
                "config/Google/Chrome/NativeMessagingHosts",
            ),
            (
                NativePlatform::Macos,
                NativeBrowser::Chromium,
                "config/Chromium/NativeMessagingHosts",
            ),
            (
                NativePlatform::Macos,
                NativeBrowser::Helium,
                "config/net.imput.helium/NativeMessagingHosts",
            ),
        ];
        for (platform, browser, expected) in cases {
            assert_eq!(
                native_manifest_dir_for(config_dir, browser, host_dir, platform),
                PathBuf::from(expected)
            );
        }
        for browser in [
            NativeBrowser::Chrome,
            NativeBrowser::Chromium,
            NativeBrowser::Helium,
        ] {
            assert_eq!(
                native_manifest_dir_for(config_dir, browser, host_dir, NativePlatform::Windows),
                host_dir
            );
        }
    }

    #[test]
    fn windows_registry_locations_cover_supported_browsers() {
        assert_eq!(
            windows_registry_vendor(NativeBrowser::Chrome),
            "Google\\Chrome"
        );
        assert_eq!(windows_registry_vendor(NativeBrowser::Chromium), "Chromium");
        assert_eq!(windows_registry_vendor(NativeBrowser::Helium), "Chromium");
    }

    #[test]
    fn native_message_round_trip_uses_native_endian_framing() {
        let response = NativeResponse::success(7, json!({ "ok": true }));
        let mut encoded = Vec::new();
        write_message(&mut encoded, &response).unwrap();
        let length = u32::from_ne_bytes(encoded[..4].try_into().unwrap()) as usize;
        assert_eq!(length, encoded.len() - 4);
        let decoded: Value = serde_json::from_slice(&encoded[4..]).unwrap();
        assert_eq!(decoded["id"], 7);
        assert_eq!(decoded["data"]["ok"], true);

        let mut input = Cursor::new(encoded[4..].to_vec());
        let mut framed = (length as u32).to_ne_bytes().to_vec();
        framed.extend(input.get_mut().iter());
        assert_eq!(
            read_message(&mut Cursor::new(framed))
                .unwrap()
                .unwrap()
                .len(),
            length
        );
    }

    #[test]
    fn parses_totp_server_response() {
        let data = response_data("getTotp", "TOTP: 287082 (19s remaining)\n".into()).unwrap();
        assert_eq!(data["code"], "287082");
        assert_eq!(data["expires_in"], 19);
    }

    #[test]
    fn native_requests_are_whitelisted_and_use_stable_ids() {
        let mut autofill = NativeRequest {
            action: "getAutofillItems".into(),
            ..NativeRequest::default()
        };
        assert!(matches!(
            command_for_request(&mut autofill).unwrap(),
            ServerCommand::BrowserAutofill
        ));

        let mut selected_autofill = NativeRequest {
            action: "getAutofillItem".into(),
            entry_id: Some(9),
            ..NativeRequest::default()
        };
        assert!(matches!(
            command_for_request(&mut selected_autofill).unwrap(),
            ServerCommand::BrowserAutofillItem(9)
        ));

        let mut request = NativeRequest {
            action: "getTotp".into(),
            entry_id: Some(17),
            ..NativeRequest::default()
        };
        assert!(matches!(
            command_for_request(&mut request).unwrap(),
            ServerCommand::Totp(TotpCommand::Show {
                target: Target::Id(17),
                copy_timeout: None
            })
        ));

        let mut unsupported = NativeRequest {
            action: "export".into(),
            ..NativeRequest::default()
        };
        assert!(command_for_request(&mut unsupported).is_err());
    }

    #[test]
    fn rejects_oversized_native_messages() {
        let mut input = Cursor::new(((MAX_NATIVE_MESSAGE + 1) as u32).to_ne_bytes());
        assert!(read_message(&mut input).is_err());
    }

    #[test]
    fn native_bridge_rejects_control_characters_and_oversized_fields() {
        let mut newline = NativeRequest {
            action: "saveCredentials".into(),
            domain: Some("https://example.com\nforged".into()),
            username: Some("alice".into()),
            password: Some("secret".into()),
            name: Some("example".into()),
            ..NativeRequest::default()
        };
        assert!(command_for_request(&mut newline).is_err());

        let mut oversized = NativeRequest {
            action: "getCredentials".into(),
            domain: Some("x".repeat(2049)),
            ..NativeRequest::default()
        };
        assert!(command_for_request(&mut oversized).is_err());
    }

    #[test]
    fn native_bridge_does_not_echo_rejected_credentials() {
        let secret = "never-echo-this-password";
        let request = json!({
            "id": 91,
            "action": "saveCredentials",
            "domain": "https://example.com\ninvalid",
            "username": "alice",
            "password": secret,
            "name": "example"
        });
        let payload = serde_json::to_vec(&request).unwrap();
        let mut framed = (payload.len() as u32).to_ne_bytes().to_vec();
        framed.extend_from_slice(&payload);
        let mut output = Vec::new();

        run_with_io(&mut Cursor::new(framed), &mut output).unwrap();

        let length = u32::from_ne_bytes(output[..4].try_into().unwrap()) as usize;
        let response: Value = serde_json::from_slice(&output[4..4 + length]).unwrap();
        assert_eq!(response["id"], 91);
        assert_eq!(response["success"], false);
        assert!(!String::from_utf8_lossy(&output).contains(secret));
    }

    #[test]
    fn native_bridge_rejects_truncated_frames() {
        let mut framed = 12u32.to_ne_bytes().to_vec();
        framed.extend_from_slice(b"short");
        assert!(read_message(&mut Cursor::new(framed)).is_err());
    }
}
