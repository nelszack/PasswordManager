#[cfg(target_os = "windows")]
use crate::file::hidden_windows_command;
use crate::{
    cli::NativeBrowser,
    client::AuthenticatedClient,
    file::data_dir,
    types::{DuoCommand, EntryUpdate, PasswordEntry, ServerCommand, Target},
};
use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::{
    OperationReceipt, OperationState, RequestEnvelope, ResponsePayload,
    native_contract::NativeAction,
};
use crate::secret::SecretString;
use crate::types::EntryChanges;

const HOST_NAME: &str = "com.myproject.password_manager";
#[cfg(not(target_os = "windows"))]
const HOST_BINARY_NAME: &str = "pm-native-host";
#[cfg(target_os = "windows")]
const HOST_BINARY_NAME: &str = "pm-native-host.exe";
#[cfg(any(feature = "desktop", target_os = "windows", test))]
const DESKTOP_EXECUTABLE_FILE: &str = "desktop-executable.json";
const MAX_NATIVE_MESSAGE: usize = 1024 * 1024;

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct NativeRequest {
    id: u64,
    action: NativeAction,
    #[serde(default, rename = "operationId")]
    operation_id: Option<String>,
    #[serde(default, rename = "expectedRevision")]
    expected_revision: Option<u64>,
    #[serde(default, rename = "expectedSession")]
    expected_session: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<SecretString>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "entryId")]
    entry_id: Option<usize>,
    #[serde(default, rename = "requestId")]
    request_id: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    approve: Option<bool>,
    #[serde(default, rename = "verificationCode")]
    verification_code: Option<SecretString>,
    #[serde(default, rename = "passkeyRequest")]
    passkey_request: Option<String>,
    #[serde(default, rename = "verificationToken")]
    verification_token: Option<String>,
    #[serde(default)]
    field: Option<crate::types::BrowserCopyField>,
    #[serde(default)]
    query: Option<String>,
    #[serde(default, rename = "addDomain")]
    add_domain: Option<bool>,
}

impl NativeRequest {
    fn validate(&self) -> Result<(), String> {
        let policy = self.action.policy();
        let supplied = [
            ("operationId", self.operation_id.is_some()),
            ("expectedRevision", self.expected_revision.is_some()),
            ("expectedSession", self.expected_session.is_some()),
            ("domain", self.domain.is_some()),
            ("username", self.username.is_some()),
            ("password", self.password.is_some()),
            ("name", self.name.is_some()),
            ("entryId", self.entry_id.is_some()),
            ("requestId", self.request_id.is_some()),
            ("fingerprint", self.fingerprint.is_some()),
            ("approve", self.approve.is_some()),
            ("verificationCode", self.verification_code.is_some()),
            ("passkeyRequest", self.passkey_request.is_some()),
            ("verificationToken", self.verification_token.is_some()),
            ("field", self.field.is_some()),
            ("query", self.query.is_some()),
            ("addDomain", self.add_domain.is_some()),
        ];
        if self
            .expected_session
            .as_ref()
            .is_some_and(|id| id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("invalid unlock session identifier".into());
        }
        if self.id == 0 || self.id > 9_007_199_254_740_991 {
            return Err("invalid native request identifier".into());
        }
        for (field, present) in supplied {
            if present
                && !(policy.required_fields.contains(&field)
                    || policy.optional_fields.contains(&field)
                    || policy.mutates && field == "operationId")
            {
                return Err("unexpected field for native operation".into());
            }
        }
        for required in policy.required_fields {
            if !supplied
                .iter()
                .any(|(field, present)| field == required && *present)
            {
                return Err("missing field for native operation".into());
            }
        }
        if policy.mutates && self.operation_id.is_none() {
            return Err("mutations require an operation identifier".into());
        }
        if self
            .entry_id
            .is_some_and(|id| id == 0 || id as u64 > 9_007_199_254_740_991)
        {
            return Err("invalid item identifier".into());
        }
        if self
            .passkey_request
            .as_ref()
            .is_some_and(|r| r.len() > 64 * 1024)
        {
            return Err("WebAuthn request exceeds limit".into());
        }
        if self.verification_token.as_ref().is_some_and(|token| {
            token.len() != 64
                || !token
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        }) {
            return Err("invalid passkey verification token".into());
        }
        Ok(())
    }
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
        self.request_id.zeroize();
        self.fingerprint.zeroize();
        self.verification_code.zeroize();
        self.approve.zeroize();
        self.passkey_request.zeroize();
        self.verification_token.zeroize();
        self.query.zeroize();
        self.add_domain.zeroize();
        *self = Self::default();
    }
}

#[derive(Serialize)]
struct NativeResponse {
    id: u64,
    success: bool,
    #[serde(rename = "nativeVersion")]
    native_version: String,
    #[serde(rename = "sessionId", skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(rename = "protocolVersion")]
    protocol_version: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    uncertain: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<OperationReceipt>,
    #[serde(rename = "operationId", skip_serializing_if = "Option::is_none")]
    operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<i32>,
}

impl Zeroize for NativeResponse {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.native_version.zeroize();
        if let Some(data) = self.data.as_mut() {
            zeroize_json(data);
        }
        self.data = None;
        self.error.zeroize();
        self.success.zeroize();
        self.uncertain.zeroize();
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
            native_version: env!("CARGO_PKG_VERSION").to_string(),
            session_id: None,
            protocol_version: crate::protocol::PROTOCOL_VERSION,
            data: Some(data),
            error: None,
            uncertain: false,
            operation: None,
            operation_id: None,
            code: None,
        }
    }

    fn error(id: u64, error: impl Into<String>) -> Self {
        Self {
            id,
            success: false,
            native_version: env!("CARGO_PKG_VERSION").to_string(),
            session_id: None,
            protocol_version: crate::protocol::PROTOCOL_VERSION,
            data: None,
            error: Some(error.into()),
            uncertain: false,
            operation: None,
            operation_id: None,
            code: None,
        }
    }
}

pub fn invoked_directly() -> bool {
    std::env::args_os()
        .next()
        .and_then(|path| PathBuf::from(path).file_name().map(|name| name.to_owned()))
        .is_some_and(|name| name == HOST_BINARY_NAME)
}

/// The add-on ID in the packaged Firefox manifest (`scripts/firefox_manifest.cjs`).
pub const FIREFOX_EXTENSION_ID: &str = "password-manager@nelszack.dev";
/// Chrome-family ID fixed by the public `key` in extension/manifest.json, so an
/// unpacked install has the same ID on every machine and path.
pub const CHROME_EXTENSION_ID: &str = "gcbamiglphlendkfgibjnnnfgldalnci";

/// The browser-specific allow list for a native host manifest.
fn manifest_allow_list(extension_id: &str, browser: NativeBrowser) -> (&'static str, Value) {
    match browser {
        NativeBrowser::Firefox => ("allowed_extensions", json!([extension_id])),
        _ => (
            "allowed_origins",
            json!([format!("chrome-extension://{extension_id}/")]),
        ),
    }
}

pub fn install(extension_id: Option<&str>, browser: NativeBrowser) -> Result<PathBuf, String> {
    let extension_id = match (extension_id, browser) {
        (Some(id), _) => id,
        (None, NativeBrowser::Firefox) => FIREFOX_EXTENSION_ID,
        (None, _) => CHROME_EXTENSION_ID,
    };
    validate_extension_id(extension_id, browser)?;
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
    let manifest_path = manifest_dir.join(manifest_file_name(browser));
    let (allow_key, allowed) = manifest_allow_list(extension_id, browser);
    let mut manifest = json!({
        "name": HOST_NAME,
        "description": "Password Manager browser bridge",
        "path": host_path,
        "type": "stdio",
    });
    manifest[allow_key] = allowed;
    let encoded = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("could not encode native host manifest: {error}"))?;
    fs::write(&manifest_path, encoded)
        .map_err(|error| format!("could not write {}: {error}", manifest_path.display()))?;
    register_manifest(&manifest_path, browser)?;
    Ok(manifest_path)
}

pub fn update() -> Result<PathBuf, String> {
    update_host_in(&data_dir().join("native-messaging"))
}

fn update_host_in(host_dir: &Path) -> Result<PathBuf, String> {
    let host_path = host_dir.join(HOST_BINARY_NAME);
    fs::symlink_metadata(&host_path).map_err(|error| {
        format!(
            "could not find registered native host at {}: {error}; run pm native-host install \
             first",
            host_path.display()
        )
    })?;
    install_host_link(&host_path)?;
    Ok(host_path)
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
    native_manifest_dir_for(
        base_dirs.config_dir(),
        base_dirs.home_dir(),
        browser,
        host_dir,
        platform,
    )
}

/// On Windows every browser's manifest lives in the host directory, so the
/// Firefox manifest (with its different allow list) gets its own name.
fn manifest_file_name(browser: NativeBrowser) -> String {
    match browser {
        NativeBrowser::Firefox => format!("{HOST_NAME}.firefox.json"),
        _ => format!("{HOST_NAME}.json"),
    }
}

fn native_manifest_dir_for(
    config_dir: &Path,
    home_dir: &Path,
    browser: NativeBrowser,
    host_dir: &Path,
    platform: NativePlatform,
) -> PathBuf {
    match (platform, browser) {
        (NativePlatform::Linux, NativeBrowser::Firefox) => {
            return home_dir.join(".mozilla").join("native-messaging-hosts");
        }
        (NativePlatform::Macos, NativeBrowser::Firefox) => {
            return config_dir.join("Mozilla").join("NativeMessagingHosts");
        }
        _ => {}
    }
    let browser_dir = match (platform, browser) {
        (NativePlatform::Linux, NativeBrowser::Chrome) => PathBuf::from("google-chrome"),
        (NativePlatform::Linux, NativeBrowser::Chromium) => PathBuf::from("chromium"),
        (NativePlatform::Linux, NativeBrowser::Helium) => PathBuf::from("net.imput.helium"),
        (NativePlatform::Macos, NativeBrowser::Chrome) => Path::new("Google").join("Chrome"),
        (NativePlatform::Macos, NativeBrowser::Chromium) => PathBuf::from("Chromium"),
        (NativePlatform::Macos, NativeBrowser::Helium) => PathBuf::from("net.imput.helium"),
        (NativePlatform::Windows, _) => return host_dir.to_path_buf(),
        (_, NativeBrowser::Firefox) => unreachable!("handled above"),
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
    }
    let staged = host_path.with_extension(format!("update-{}", std::process::id()));
    symlink(&executable, &staged)
        .map_err(|error| format!("could not stage {}: {error}", host_path.display()))?;
    let result = fs::rename(&staged, host_path);
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result.map_err(|error| format!("could not update {}: {error}", host_path.display()))
}

#[cfg(target_os = "windows")]
fn install_host_link(host_path: &Path) -> Result<(), String> {
    let executable = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| format!("could not locate the pm executable: {error}"))?;
    fs::copy(&executable, host_path).map_err(|error| {
        format!(
            "could not install {}: {error}; fully close the browser, then rerun pm native-host \
             update",
            host_path.display()
        )
    })?;
    record_desktop_executable(host_path, &executable)
}

#[cfg(any(target_os = "windows", test))]
fn record_desktop_executable(host_path: &Path, executable: &Path) -> Result<(), String> {
    let path = host_path.with_file_name(DESKTOP_EXECUTABLE_FILE);
    let encoded = serde_json::to_vec(executable)
        .map_err(|error| format!("could not encode desktop executable path: {error}"))?;
    fs::write(&path, encoded).map_err(|error| {
        format!(
            "could not record desktop executable at {}: {error}",
            path.display()
        )
    })
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
    let status = hidden_windows_command("reg.exe")
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
        NativeBrowser::Firefox => "Mozilla",
    }
}

fn validate_extension_id(extension_id: &str, browser: NativeBrowser) -> Result<(), String> {
    if browser == NativeBrowser::Firefox {
        // Firefox add-on IDs are email-like or a braced UUID.
        let email = extension_id.split_once('@').is_some_and(|(local, domain)| {
            let allowed = |part: &str| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
            };
            allowed(local) && allowed(domain)
        });
        let uuid = extension_id.len() == 38
            && extension_id.starts_with('{')
            && extension_id.ends_with('}')
            && extension_id[1..37].bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            });
        return if extension_id.len() <= 80 && (email || uuid) {
            Ok(())
        } else {
            Err("Firefox add-on IDs look like name@example.com or {UUID}".to_string())
        };
    }
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

pub fn run(client: &AuthenticatedClient) -> Result<(), String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_with_io(client, &mut stdin.lock(), &mut stdout.lock())
}

fn run_with_io(
    client: &AuthenticatedClient,
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<(), String> {
    loop {
        let Some(mut payload) = read_message(reader)? else {
            return Ok(());
        };
        let request = serde_json::from_slice::<NativeRequest>(&payload);
        payload.zeroize();
        let response = Zeroizing::new(match request {
            Ok(request) => handle_request(client, request),
            // Deserialization errors can contain rejected string values. Keep
            // credential material out of errors returned to the browser.
            Err(error) => NativeResponse::error(
                0,
                format!(
                    "invalid request at line {}, column {}",
                    error.line(),
                    error.column()
                ),
            ),
        });
        write_message(writer, &response)?;
    }
}

fn read_message(reader: &mut impl Read) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    let mut length = [0u8; 4];
    // EOF between frames is normal. EOF after any header byte is a truncated
    // message and must not silently look like a clean browser disconnect.
    match reader.read_exact(&mut length[..1]) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(format!("could not read message length: {error}")),
    }
    reader
        .read_exact(&mut length[1..])
        .map_err(|error| format!("could not read message length: {error}"))?;
    let length = u32::from_ne_bytes(length) as usize;
    if length > MAX_NATIVE_MESSAGE {
        return Err("native message exceeds the 1 MiB limit".to_string());
    }
    let mut payload = Zeroizing::new(vec![0u8; length]);
    reader
        .read_exact(&mut payload)
        .map_err(|error| format!("could not read native message: {error}"))?;
    Ok(Some(payload))
}

fn write_message(writer: &mut impl Write, response: &NativeResponse) -> Result<(), String> {
    let mut payload = crate::secret::SecretBuffer::default();
    serde_json::to_writer(&mut payload, response)
        .map_err(|error| format!("could not encode native response: {error}"))?;
    if payload.len() > MAX_NATIVE_MESSAGE {
        // Keep the host connected and return an actionable, bounded error.
        // A mutation may already have committed before its result was encoded;
        // preserve the receipt and require review instead of inviting a retry.
        let mut fallback = Zeroizing::new(NativeResponse::error(
            response.id,
            "This result exceeds the browser's 1 MiB limit. Use the desktop app or CLI to view it.",
        ));
        fallback.session_id = response.session_id.clone();
        fallback.operation = response.operation.clone();
        fallback.operation_id = response.operation_id.clone();
        fallback.uncertain = response.uncertain || response.operation_id.is_some();
        if fallback.uncertain {
            fallback.error.as_mut().unwrap().push_str(
                " The change may already have completed. Review its operation outcome before \
                 retrying.",
            );
        }
        payload = crate::secret::SecretBuffer::default();
        serde_json::to_writer(&mut payload, &*fallback)
            .map_err(|error| format!("could not encode native response: {error}"))?;
    }
    writer
        .write_all(&(payload.len() as u32).to_ne_bytes())
        .and_then(|_| writer.write_all(&payload))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("could not write native response: {error}"))
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

fn launch_desktop(item: Option<usize>) -> Result<(), String> {
    #[cfg(not(feature = "desktop"))]
    let _ = item;
    #[cfg(not(feature = "desktop"))]
    return Err(
        "This build has no desktop interface. Install a build with desktop support.".into(),
    );
    #[cfg(feature = "desktop")]
    {
        let executable = std::env::current_exe()
            .map_err(|error| format!("could not locate the desktop executable: {error}"))?;
        let executable = desktop_executable(&executable)?;
        let mut command = desktop_command(&executable);
        if let Some(id) = item {
            command.arg("--open").arg(id.to_string());
        }
        let mut child = command
            .spawn()
            .map_err(|error| format!("could not open the desktop app: {error}"))?;
        // Reap the GUI when it exits without blocking the native message loop.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }
}

#[cfg(any(feature = "desktop", test))]
fn desktop_executable(host_executable: &Path) -> Result<PathBuf, String> {
    let update_hint = "Run pm native-host update using the normal pm executable.";
    // Resolve Unix's native-host symlink before choosing the GUI executable.
    let executable = fs::canonicalize(host_executable)
        .map_err(|error| format!("could not resolve desktop executable: {error}. {update_hint}"))?;
    if executable
        .file_name()
        .is_none_or(|name| name != HOST_BINARY_NAME)
    {
        return Ok(executable);
    }
    // Windows uses a copy of pm for the bridge. The install/update command
    // records the original application path beside that copy.
    let registered = fs::read(executable.with_file_name(DESKTOP_EXECUTABLE_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<PathBuf>(&bytes).ok())
        .filter(|path| path.is_absolute())
        .and_then(|path| fs::canonicalize(path).ok())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name != HOST_BINARY_NAME)
        })
        .filter(|path| path.is_file());
    registered.ok_or_else(|| format!("The normal pm executable could not be found. {update_hint}"))
}

#[cfg(feature = "desktop")]
fn desktop_command(executable: &Path) -> std::process::Command {
    #[cfg(target_os = "windows")]
    let mut command = hidden_windows_command(executable);
    #[cfg(not(target_os = "windows"))]
    let mut command = std::process::Command::new(executable);
    // The GUI must never inherit native messaging's framed stdin/stdout pipes.
    command
        .arg("gui")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command
}

fn handle_request(client: &AuthenticatedClient, request: NativeRequest) -> NativeResponse {
    handle_request_with_launcher(client, request, launch_desktop)
}

fn handle_request_with_launcher(
    client: &AuthenticatedClient,
    mut request: NativeRequest,
    launch: impl FnOnce(Option<usize>) -> Result<(), String>,
) -> NativeResponse {
    let id = request.id;
    let operation_id = request.operation_id.clone();
    let mut uncertain = false;
    let mut receipt = None;
    let mut error_code = None;
    let mut session_id = None;
    let result = (|| {
        request.validate()?;
        if request.action == NativeAction::OpenDesktop {
            launch(request.entry_id)?;
            return Ok(json!(if request.entry_id.is_some() {
                "Opening the item in the desktop app."
            } else {
                "Desktop app launch requested."
            }));
        }
        command_for_request(&mut request).and_then(|command| {
            let mut envelope = RequestEnvelope::new(command)
                .with_operation(operation_id.clone(), request.expected_revision);
            envelope.expected_session = request.expected_session.clone();
            envelope.validate()?;
            if matches!(request.action, NativeAction::UpdateCredentials)
                && request.expected_revision.is_none()
            {
                return Err("item edits require the revision that was reviewed".into());
            }
            client
                .request_envelope_tracked(envelope)
                .map_err(|e| {
                    uncertain = e.sent && request.action.policy().mutates;
                    e.message
                })
                .and_then(|response| {
                    session_id = response.session_id.clone();
                    receipt = response.operation.clone();
                    if let ResponsePayload::Operation(operation) = &response.payload
                        && request.action.policy().mutates
                    {
                        receipt = Some(operation.clone());
                        if matches!(
                            operation.state,
                            OperationState::Pending | OperationState::Unknown
                        ) {
                            uncertain = true;
                            return Err("Operation outcome is unresolved. Review before another \
                                        change."
                                .into());
                        }
                        if operation.state == OperationState::Failed {
                            return Err(
                                "The previous operation failed. Refresh before retrying.".into()
                            );
                        }
                    }
                    if response.code != 0 {
                        error_code = Some(response.code);
                        uncertain = response.code
                            == crate::protocol::ResponseCode::Durability as i32
                            && request.action.policy().mutates;
                        return Err(
                            if response.code == crate::protocol::ResponseCode::Durability as i32 {
                                format!(
                                    "{} The operation committed; durability could not be \
                                     confirmed.",
                                    response.error_message()
                                )
                            } else {
                                response.error_message()
                            },
                        );
                    }
                    Ok(response.payload.into_json())
                })
        })
    })();
    request.zeroize();
    let mut response = match result {
        Ok(data) => NativeResponse::success(id, data),
        Err(error) => {
            let mut response = NativeResponse::error(
                id,
                if uncertain {
                    format!("{error}. Review the operation outcome before retrying.")
                } else {
                    error
                },
            );
            response.uncertain = uncertain;
            response
        }
    };
    response.session_id = session_id;
    response.code = error_code;
    response.operation = receipt;
    response.operation_id = operation_id;
    response
}

fn command_for_request(request: &mut NativeRequest) -> Result<ServerCommand, String> {
    match request.action.as_str() {
        "status" => Ok(ServerCommand::Status),
        "operationStatus" => Ok(ServerCommand::OperationStatus(
            request.operation_id.clone().ok_or("missing operation ID")?,
        )),
        "duoRequests" => Ok(ServerCommand::Duo(DuoCommand::Requests {
            target: Target::Id(item_id(request)?),
        })),
        "duoRespond" => {
            let target = Target::Id(item_id(request)?);
            let id = request
                .request_id
                .take()
                .ok_or("missing Duo request identifier")?;
            let fingerprint = request
                .fingerprint
                .take()
                .ok_or("missing Duo review fingerprint")?;
            let approve = request.approve.ok_or("missing Duo decision")?;
            let code = Zeroizing::new(request.verification_code.take().unwrap_or_default());
            if id.is_empty()
                || id.len() > 256
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || fingerprint.len() != 128
                || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
                || code.len() > 6
                || !code.bytes().all(|b| b.is_ascii_digit())
                || (!approve && !code.is_empty())
            {
                return Err("invalid Duo decision fields".into());
            }
            Ok(ServerCommand::Duo(DuoCommand::Respond {
                target,
                request_id: id,
                fingerprint,
                approve,
                code: code.expose().to_owned().into(),
            }))
        }
        "getAutofillItems" => Ok(ServerCommand::BrowserAutofill),
        "getLoginItems" => Ok(ServerCommand::BrowserLogins(required(
            request.domain.take(),
            "domain",
            2048,
        )?)),
        "getDuoItems" => Ok(ServerCommand::BrowserDuoItems(required(
            request.domain.take(),
            "domain",
            2048,
        )?)),
        "checkSavedLogin" => Ok(ServerCommand::BrowserLoginSaved {
            domain: required(request.domain.take(), "domain", 2048)?,
            username: optional_text(request.username.take(), "username", 4096)?,
            password: required(
                request.password.take().map(SecretString::expose_owned),
                "password",
                64 * 1024,
            )?
            .into(),
        }),
        "getLoginItem" => Ok(ServerCommand::BrowserLogin {
            domain: required(request.domain.take(), "domain", 2048)?,
            id: request
                .entry_id
                .filter(|id| *id > 0)
                .ok_or_else(|| "invalid entry ID".to_string())?,
        }),
        "getAutofillItem" => Ok(ServerCommand::BrowserAutofillItem(
            request
                .entry_id
                .ok_or_else(|| "missing entry ID".to_string())?,
        )),
        "getTotp" => Ok(ServerCommand::BrowserAuthenticatorData {
            domain: required(request.domain.take(), "domain", 2048)?,
            id: request
                .entry_id
                .ok_or_else(|| "missing entry ID".to_string())?,
        }),
        "saveCredentials" => Ok(ServerCommand::Add {
            entry: crate::types::TypedEntry {
                entry: PasswordEntry {
                    name: required(request.name.take(), "name", 4096)?,
                    username: Some(optional_text(request.username.take(), "username", 4096)?),
                    password: required(
                        request.password.take().map(SecretString::expose_owned),
                        "password",
                        64 * 1024,
                    )?
                    .into(),
                    url: Some(required(request.domain.take(), "domain", 2048)?),
                    notes: None,
                    copy: false,
                },
                kind: crate::types::ItemKind::Login,
                additional_urls: vec![],
                custom_fields: vec![],
                tags: vec![],
                favorite: false,
            },
            copy_timeout: 0,
        }),
        "updateCredentials" => {
            // The page origin authorizes the browser selection; updating a
            // password must not replace the item's saved primary URL. A login
            // chosen for another site gains this site as an additional address.
            let domain = required(request.domain.take(), "domain", 2048)?;
            let entry_id = request
                .entry_id
                .ok_or_else(|| "missing entry ID".to_string())?;
            let mut update = crate::types::TypedUpdate::from(EntryUpdate {
                target: Target::Id(entry_id),
                update: EntryChanges {
                    name: None,
                    username: Some(optional_text(request.username.take(), "username", 4096)?),
                    url: None,
                    notes: None,
                },
                password: Some(
                    required(
                        request.password.take().map(SecretString::expose_owned),
                        "password",
                        64 * 1024,
                    )?
                    .into(),
                ),
            });
            if request.add_domain == Some(true) {
                update.add_url = vec![domain];
            }
            Ok(ServerCommand::Update(update))
        }
        "lock" => Ok(ServerCommand::Lock(true)),
        "getPasskeys" => Ok(ServerCommand::BrowserPasskeys {
            origin: required(request.domain.take(), "domain", 2048)?,
            request: required(
                request.passkey_request.take(),
                "WebAuthn request",
                64 * 1024,
            )?,
        }),
        "createPasskey" => Ok(ServerCommand::BrowserPasskeyCreate {
            origin: required(request.domain.take(), "domain", 2048)?,
            request: required(
                request.passkey_request.take(),
                "WebAuthn request",
                64 * 1024,
            )?,
            verification: request.verification_token.take(),
            verified: false,
        }),
        "verifyPasskeyUser" => Ok(ServerCommand::PasskeyVerification {
            origin: required(request.domain.take(), "domain", 2048)?,
        }),
        "getPasskeyAssertion" => Ok(ServerCommand::BrowserPasskeyGet {
            origin: required(request.domain.take(), "domain", 2048)?,
            id: item_id(request)?,
            request: required(
                request.passkey_request.take(),
                "WebAuthn request",
                64 * 1024,
            )?,
            verification: request.verification_token.take(),
            verified: false,
        }),
        "copyLoginValue" => Ok(ServerCommand::BrowserCopy {
            domain: required(request.domain.take(), "domain", 2048)?,
            id: item_id(request)?,
            field: request.field.ok_or("missing copy field")?,
            timeout: clipboard_timeout(),
        }),
        "searchItems" => Ok(ServerCommand::List(crate::types::SearchFilter {
            query: Some(required(request.query.take(), "query", 256)?),
            list: crate::types::ListOptions {
                sort: crate::types::SortField::Name,
                ..Default::default()
            },
            ..Default::default()
        })),
        "copyItem" => Ok(ServerCommand::BrowserCopyItem {
            id: item_id(request)?,
            field: request.field.ok_or("missing copy field")?,
            timeout: clipboard_timeout(),
        }),
        "copyGenerated" => Ok(ServerCommand::CopyGenerated {
            value: required(
                request.password.take().map(SecretString::expose_owned),
                "password",
                64 * 1024,
            )?
            .into(),
            timeout: clipboard_timeout(),
        }),
        _ => Err("unsupported native messaging action".to_string()),
    }
}

/// The configured clipboard timeout, read without creating or rewriting the
/// configuration file. A missing or unreadable file uses the default.
fn clipboard_timeout() -> u8 {
    let path = crate::file::config_dir().join("config.toml");
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| toml::from_str::<crate::config::Config>(&text).ok())
        .unwrap_or_default()
        .clipboard
        .timeout
}

fn item_id(request: &NativeRequest) -> Result<usize, String> {
    request
        .entry_id
        .filter(|id| *id > 0)
        .ok_or_else(|| "invalid entry ID".into())
}

#[cfg(test)]
#[path = "native_messaging_tests.rs"]
mod tests;

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_message(data: &[u8]) {
    if let Ok(Some(mut payload)) = read_message(&mut std::io::Cursor::new(data)) {
        if let Ok(mut request) = serde_json::from_slice::<NativeRequest>(&payload) {
            if request.validate().is_ok()
                && let Ok(mut command) = command_for_request(&mut request)
            {
                command.zeroize();
            }
            request.zeroize();
        }
        payload.zeroize();
    }
}
