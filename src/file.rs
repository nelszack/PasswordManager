use directories::ProjectDirs;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};

pub const TOKEN_FILE: &str = "session.key";

#[cfg(unix)]
pub fn set_private_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(unix)]
pub fn set_private_dir_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(not(unix))]
pub fn set_private_perms(_path: &Path) {}

#[cfg(not(unix))]
pub fn set_private_dir_perms(_path: &Path) {}

pub fn file_exists(file_path: impl AsRef<Path>) -> bool {
    file_path.as_ref().exists()
}

pub fn data_dir() -> PathBuf {
    let data_dir = TEST_DATA_DIR
        .get()
        .map(|d| d.path().to_path_buf())
        .unwrap_or_else(project_data_dir);
    fs::create_dir_all(&data_dir).unwrap();
    set_private_dir_perms(&data_dir);
    data_dir
}

fn project_data_dir() -> PathBuf {
    let proj_dir = ProjectDirs::from("com", "myproject", "password_manager").unwrap();
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
