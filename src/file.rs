use directories::ProjectDirs;
use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};

#[cfg(target_os = "windows")]
pub(crate) const WINDOWS_CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(target_os = "windows")]
pub(crate) fn hidden_windows_command(
    program: impl AsRef<std::ffi::OsStr>,
) -> std::process::Command {
    use std::os::windows::process::CommandExt;

    let mut command = std::process::Command::new(program);
    command.creation_flags(WINDOWS_CREATE_NO_WINDOW);
    command
}

pub const TOKEN_FILE: &str = "session.key";
pub const CONFIG_DIR_ENV: &str = "PM_CONFIG_DIR";
pub const DATA_DIR_ENV: &str = "PM_DATA_DIR";

#[cfg(unix)]
pub fn set_private_perms(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(unix)]
pub fn set_private_dir_perms(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
#[cfg(not(target_os = "windows"))]
pub fn set_private_perms(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
#[cfg(not(target_os = "windows"))]
pub fn set_private_dir_perms(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn current_user_sid() -> std::io::Result<String> {
    use std::io;
    let output = hidden_windows_command("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(
            "whoami.exe could not determine the user SID",
        ));
    }
    let output = String::from_utf8_lossy(&output.stdout);
    output
        .split([',', '"', '\r', '\n'])
        .map(str::trim)
        .find(|field| field.starts_with("S-1-"))
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("whoami.exe returned no user SID"))
}

#[cfg(target_os = "windows")]
fn set_windows_acl(path: &Path, directory: bool) -> std::io::Result<()> {
    use std::io;
    let sid = current_user_sid()?;
    let grant = if directory {
        format!("*{sid}:(OI)(CI)(F)")
    } else {
        format!("*{sid}:(F)")
    };
    // Native-messaging stdout is a binary protocol channel. Capture icacls'
    // normal "processed files" summary so it can never corrupt that channel.
    let output = hidden_windows_command("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &grant])
        .output()?;
    output.status.success().then_some(()).ok_or_else(|| {
        let detail = String::from_utf8_lossy(&output.stderr);
        io::Error::other(format!(
            "icacls.exe failed for {}: {}",
            path.display(),
            detail.trim()
        ))
    })
}

#[cfg(target_os = "windows")]
pub fn set_private_perms(path: &Path) -> std::io::Result<()> {
    set_windows_acl(path, false)
}

#[cfg(target_os = "windows")]
pub fn set_private_dir_perms(path: &Path) -> std::io::Result<()> {
    use std::{collections::HashSet, sync::Mutex};

    static PROTECTED_DIRS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    let protected = PROTECTED_DIRS.get_or_init(|| Mutex::new(HashSet::new()));
    let mut protected = protected
        .lock()
        .map_err(|_| std::io::Error::other("private-directory ACL cache is poisoned"))?;
    if protected.contains(path) {
        return Ok(());
    }
    set_windows_acl(path, true)?;
    protected.insert(path.to_path_buf());
    Ok(())
}

#[cfg(unix)]
pub fn sync_parent(path: &Path) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
pub fn sync_parent(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

pub fn file_exists(file_path: impl AsRef<Path>) -> bool {
    file_path.as_ref().exists()
}

pub fn key_file_path(name: &str) -> Result<PathBuf, String> {
    let path = Path::new(name);
    if !path.is_absolute() {
        return Err("key file path must be absolute".to_string());
    }
    Ok(path.to_path_buf())
}

pub fn resolve_new_key_path(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("key file path cannot be empty".to_string());
    }
    let path = std::path::absolute(name)
        .map_err(|error| format!("could not resolve key file path: {error}"))?;
    path.into_os_string()
        .into_string()
        .map_err(|_| "key file path must contain valid Unicode".to_string())
}

pub fn resolve_key_path(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("key file path cannot be empty".to_string());
    }
    let path = Path::new(name);
    if path.is_absolute() {
        return Ok(name.to_string());
    }
    resolve_new_key_path(name)
}

pub fn new_key_file_path(name: &str) -> Result<PathBuf, String> {
    let path = Path::new(name);
    if !path.is_absolute() {
        return Err("new key file paths must be absolute and outside application data".to_string());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| "key file path has no parent directory".to_string())?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| format!("could not resolve key file directory: {error}"))?;
    let candidate = parent.join(
        path.file_name()
            .ok_or_else(|| "key file path must include a filename".to_string())?,
    );
    let application_data = fs::canonicalize(data_dir())
        .map_err(|error| format!("could not resolve application data directory: {error}"))?;
    if candidate.starts_with(&application_data) {
        return Err("new key files must be stored outside the application data directory".into());
    }
    Ok(candidate)
}

pub fn data_dir() -> PathBuf {
    let data_dir = TEST_DATA_DIR
        .get()
        .map(|d| d.path().to_path_buf())
        .unwrap_or_else(project_data_dir);
    if let Err(error) = fs::create_dir_all(&data_dir).and_then(|_| set_private_dir_perms(&data_dir))
    {
        eprintln!(
            "Error: could not initialize data directory {}: {error}",
            data_dir.display()
        );
        std::process::exit(1);
    }
    data_dir
}

pub fn config_dir() -> PathBuf {
    env::var_os(CONFIG_DIR_ENV)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(project_config_dir)
}

fn project_data_dir() -> PathBuf {
    if let Some(path) = env::var_os(DATA_DIR_ENV).filter(|path| !path.is_empty()) {
        return PathBuf::from(path);
    }
    let Some(proj_dir) = ProjectDirs::from("com", "myproject", "password_manager") else {
        eprintln!("Error: could not locate the application data directory.");
        std::process::exit(1);
    };
    proj_dir.data_dir().to_path_buf()
}

fn project_config_dir() -> PathBuf {
    let Some(proj_dir) = ProjectDirs::from("com", "myproject", "password_manager") else {
        eprintln!("Error: could not locate the application config directory.");
        std::process::exit(1);
    };
    proj_dir.config_dir().to_path_buf()
}

static TEST_DATA_DIR: OnceLock<&'static tempfile::TempDir> = OnceLock::new();

#[cfg(test)]
pub(crate) fn init_test_data_dir() {
    let _ = TEST_DATA_DIR.get_or_init(|| Box::leak(Box::new(tempfile::TempDir::new().unwrap())));
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::File;
    use tempfile::TempDir;

    #[test]
    fn file_exists_recognizes_files_directories_and_missing_paths() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_file.txt");
        File::create(&file_path).unwrap();
        assert!(file_exists(&file_path));
        assert!(file_exists(temp_dir.path()));
        assert!(!file_exists(temp_dir.path().join("missing")));
    }

    #[test]
    fn new_key_files_require_an_external_absolute_path() {
        init_test_data_dir();
        let external = TempDir::new().unwrap();
        assert!(new_key_file_path(external.path().join("vault.key").to_str().unwrap()).is_ok());
        assert!(new_key_file_path("vault.key").is_err());
        assert!(new_key_file_path(data_dir().join("vault.key").to_str().unwrap()).is_err());
    }

    #[test]
    fn relative_new_key_paths_resolve_from_the_client_working_directory() {
        let resolved = resolve_new_key_path("keys/vault.key").unwrap();
        assert!(Path::new(&resolved).is_absolute());
        assert!(Path::new(&resolved).ends_with(Path::new("keys/vault.key")));
        assert!(resolve_new_key_path("").is_err());
    }

    #[test]
    fn relative_existing_keys_resolve_from_the_client_working_directory() {
        let resolved = resolve_key_path("keys/vault.key").unwrap();
        assert!(Path::new(&resolved).is_absolute());
        assert!(Path::new(&resolve_key_path("vault.key").unwrap()).is_absolute());
        assert!(resolve_key_path("").is_err());
    }
}
