use directories::ProjectDirs;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};

pub const TOKEN_FILE: &str = "session.key";

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
    use std::{io, process::Command};
    let output = Command::new("whoami.exe")
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
    use std::{io, process::Command};
    let sid = current_user_sid()?;
    let grant = if directory {
        format!("*{sid}:(OI)(CI)(F)")
    } else {
        format!("*{sid}:(F)")
    };
    let status = Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &grant])
        .status()?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| io::Error::other(format!("icacls.exe failed for {}", path.display())))
}

#[cfg(target_os = "windows")]
pub fn set_private_perms(path: &Path) -> std::io::Result<()> {
    set_windows_acl(path, false)
}

#[cfg(target_os = "windows")]
pub fn set_private_dir_perms(path: &Path) -> std::io::Result<()> {
    set_windows_acl(path, true)
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

fn project_data_dir() -> PathBuf {
    let Some(proj_dir) = ProjectDirs::from("com", "myproject", "password_manager") else {
        eprintln!("Error: could not locate the application data directory.");
        std::process::exit(1);
    };
    proj_dir.data_dir().to_path_buf()
}

static TEST_DATA_DIR: OnceLock<&'static tempfile::TempDir> = OnceLock::new();

#[cfg(test)]
pub(crate) fn init_test_data_dir() {
    let _ = TEST_DATA_DIR.get_or_init(|| Box::leak(Box::new(tempfile::TempDir::new().unwrap())));
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::{self, File};
    use tempfile::TempDir;

    #[test]
    fn test_file_exists_returns_true_for_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_file.txt");
        File::create(&file_path).unwrap();
        assert!(file_exists(&file_path));
    }

    #[test]
    fn test_file_exists_returns_false_for_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("nonexistent_file.txt");
        assert!(!file_exists(&file_path));
    }

    #[test]
    fn test_file_exists_returns_true_for_directory() {
        let temp_dir = TempDir::new().unwrap();
        assert!(file_exists(temp_dir.path()));
    }

    #[test]
    fn test_file_exists_with_nested_path() {
        let temp_dir = TempDir::new().unwrap();
        let nested = temp_dir.path().join("nested").join("deep");
        fs::create_dir_all(&nested).unwrap();
        let file_path = nested.join("test.txt");
        File::create(&file_path).unwrap();
        assert!(file_exists(&file_path));
    }
}
