use std::path::Path;
pub fn file_exists(file_path: &str) -> bool {
    if Path::new(file_path).exists() {
        return true;
    }
    return false;
}
