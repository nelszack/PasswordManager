use directories::ProjectDirs;
use std::{
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::OnceLock,
};
use zeroize::Zeroizing;

/// Check the opened file and bound the actual read, even if it grows after
/// metadata inspection. Returned and partial buffers are zeroized on drop.
pub(crate) fn read_bounded_file(path: &Path, max_bytes: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    fn validate(metadata: &fs::Metadata, max_bytes: u64) -> io::Result<()> {
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a regular file",
            ));
        }
        if metadata.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("file exceeds the {max_bytes} byte limit"),
            ));
        }
        Ok(())
    }
    validate(&fs::metadata(path)?, max_bytes)?;
    let file = fs::File::open(path)?;
    validate(&file.metadata()?, max_bytes)?;
    read_bounded(file, max_bytes)
}

fn read_bounded(reader: impl Read, max_bytes: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut contents = Zeroizing::new(Vec::new());
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut contents)?;
    if contents.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds the {max_bytes} byte limit"),
        ));
    }
    Ok(contents)
}

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
pub(crate) const SERVER_LOCK_FILE: &str = "server.lock";
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
fn set_windows_acl(path: &Path, directory: bool) -> std::io::Result<()> {
    // Pass paths as environment data rather than interpolating PowerShell code.
    // Build a fresh protected DACL so explicit grants to other principals are
    // removed as well as inherited grants, then read back and verify it.
    let output = hidden_windows_command("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            include_str!("windows_private_acl.ps1"),
        ])
        .env("PM_PRIVATE_ACL_PATH", std::path::absolute(path)?)
        .env(
            "PM_PRIVATE_ACL_DIRECTORY",
            if directory { "1" } else { "0" },
        )
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "could not protect ACL for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
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
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
pub fn sync_parent(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

pub fn file_exists(file_path: impl AsRef<Path>) -> bool {
    file_path.as_ref().exists()
}

/// Export and backup destinations must not replace application-owned files.
/// Resolve parent symlinks and existing destination symlinks before checking.
pub(crate) fn validate_external_output_path(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let candidate = fs::canonicalize(parent)?.join(path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination must name a file")
    })?);
    let existing = match fs::canonicalize(path) {
        Ok(path) => Some(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    for directory in [data_dir(), config_dir()] {
        let protected = match fs::canonicalize(directory) {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if candidate.starts_with(&protected)
            || existing
                .as_ref()
                .is_some_and(|path| path.starts_with(&protected))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "export and backup destinations must be outside application data and configuration directories",
            ));
        }
    }
    Ok(())
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

    #[cfg(target_os = "windows")]
    #[test]
    fn private_windows_acls_remove_explicit_grants_to_other_principals() {
        let root = TempDir::new().unwrap();
        let directory = root.path().join("private directory");
        fs::create_dir(&directory).unwrap();
        let file = directory.join("private file.txt");
        fs::write(&file, b"synthetic-secret").unwrap();
        for (path, is_directory) in [(&directory, true), (&file, false)] {
            let output = hidden_windows_command("icacls.exe")
                .arg(path)
                .args(["/grant", "*S-1-1-0:(F)"])
                .output()
                .unwrap();
            assert!(output.status.success());
            // This includes read-back verification that only our SID remains.
            set_windows_acl(path, is_directory).unwrap();
            let output = hidden_windows_command("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", r#"
                    $ErrorActionPreference = 'Stop'
                    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                    if ($env:PM_TEST_ACL_DIRECTORY -eq '1') {
                        $acl = [System.IO.Directory]::GetAccessControl($env:PM_TEST_ACL_PATH)
                    } else {
                        $acl = [System.IO.File]::GetAccessControl($env:PM_TEST_ACL_PATH)
                    }
                    $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
                    if (-not $acl.AreAccessRulesProtected -or $rules.Count -ne 1 -or
                        $rules[0].IdentityReference.Value -ne $sid) { exit 1 }
                "#])
                .env("PM_TEST_ACL_PATH", path)
                .env("PM_TEST_ACL_DIRECTORY", if is_directory { "1" } else { "0" })
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn file_exists_recognizes_files_directories_and_missing_paths() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_file.txt");
        File::create(&file_path).unwrap();
        assert!(file_exists(&file_path));
        assert!(file_exists(temp_dir.path()));
        assert!(!file_exists(temp_dir.path().join("missing")));
    }

    #[cfg(unix)]
    #[test]
    fn directory_sync_accepts_a_bare_filename() {
        sync_parent(Path::new("relative-export.json")).unwrap();
        sync_parent(Path::new("./relative-backup.pmbackup")).unwrap();
    }

    #[test]
    fn bounded_reads_validate_files_and_enforce_the_limit_on_actual_bytes() {
        for contents in [vec![], vec![7; 7], vec![7; 8]] {
            assert_eq!(&*read_bounded(contents.as_slice(), 8).unwrap(), &contents);
        }
        // Models bytes added after metadata was checked. Read at most one
        // extra byte to detect overflow, rather than buffering the whole input.
        let mut input = io::Cursor::new(vec![7; 64]);
        assert_eq!(
            read_bounded(&mut input, 8).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(input.position(), 9);

        let directory = TempDir::new().unwrap();
        let path = directory.path().join("input");
        fs::write(&path, b"12345678").unwrap();
        assert_eq!(&*read_bounded_file(&path, 8).unwrap(), b"12345678");
        assert_eq!(
            read_bounded_file(&path, 7).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_bounded_file(directory.path(), 8).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
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
    fn relative_key_paths_resolve_from_the_client_working_directory() {
        for (label, resolve) in [
            (
                "new key",
                resolve_new_key_path as fn(&str) -> Result<String, String>,
            ),
            (
                "existing key",
                resolve_key_path as fn(&str) -> Result<String, String>,
            ),
        ] {
            let resolved = resolve("keys/vault.key").unwrap();
            assert!(Path::new(&resolved).is_absolute(), "{label}");
            assert!(
                Path::new(&resolved).ends_with(Path::new("keys/vault.key")),
                "{label}"
            );
            assert!(
                Path::new(&resolve("vault.key").unwrap()).is_absolute(),
                "{label}"
            );
            assert!(resolve("").is_err(), "{label}");
        }
    }
}
