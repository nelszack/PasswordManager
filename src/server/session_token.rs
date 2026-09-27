use super::*;

pub(super) fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

pub(super) fn write_token_file(token: &str, path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "session token path has no parent directory".to_string())?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("could not create session token: {error}"))?;
    set_private_perms(temporary.path())
        .map_err(|error| format!("could not protect session token: {error}"))?;
    temporary
        .write_all(token.as_bytes())
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| format!("could not write session token: {error}"))?;
    temporary
        .persist(path)
        .map_err(|error| format!("could not replace session token: {}", error.error))?;
    sync_parent(path)
        .map_err(|error| format!("could not sync session token directory: {error}"))?;
    Ok(())
}

pub(super) fn rotate_token_file(path: &Path) -> Result<String, String> {
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
