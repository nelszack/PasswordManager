use super::*;

pub(super) fn random_token() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rng().fill(&mut *bytes);
    Zeroizing::new(hex::encode(bytes.as_slice()))
}

pub(super) fn write_token_file(token: &str, path: &Path) -> Result<(), String> {
    crate::file::atomic_write_private(
        path,
        token.as_bytes(),
        crate::file::AtomicWriteMode::Replace,
    )
    .map_err(|error| format!("could not save session token: {error}"))
}

pub(super) fn rotate_token_file(path: &Path) -> Result<Zeroizing<String>, String> {
    let token = random_token();
    write_token_file(&token, path)?;
    Ok(token)
}

pub(super) fn remove_token_file_if_current(path: &Path, token: &str) {
    let Ok(mut current) = fs::read_to_string(path) else {
        return;
    };
    current.truncate(current.trim_end().len());
    let matches = ct_eq(current.as_bytes(), token.as_bytes());
    current.zeroize();
    if matches && fs::remove_file(path).is_ok() {
        let _ = sync_parent(path);
    }
}
