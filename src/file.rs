use std::path::Path;
pub fn file_exists(file_path: &str) -> bool {
    if Path::new(file_path).exists() {
        return true;
    }
    return false;
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
        assert!(file_exists(file_path.to_str().unwrap()));
    }

    #[test]
    fn test_file_exists_returns_false_for_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("nonexistent_file.txt");
        assert!(!file_exists(file_path.to_str().unwrap()));
    }

    #[test]
    fn test_file_exists_returns_true_for_directory() {
        let temp_dir = TempDir::new().unwrap();
        assert!(file_exists(temp_dir.path().to_str().unwrap()));
    }

    #[test]
    fn test_file_exists_with_nested_path() {
        let temp_dir = TempDir::new().unwrap();
        let nested = temp_dir.path().join("nested").join("deep");
        fs::create_dir_all(&nested).unwrap();
        let file_path = nested.join("test.txt");
        File::create(&file_path).unwrap();
        assert!(file_exists(file_path.to_str().unwrap()));
    }
}
