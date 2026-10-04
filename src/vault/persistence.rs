use super::*;

impl Vault {
    pub fn rekey(
        &mut self,
        server_info: &mut ServerInfo,
        mut new_key: PasswordType,
    ) -> Result<(), VaultError> {
        if let PasswordType::Password(password) = &new_key
            && let Err(error) = validate_new_password(password)
        {
            new_key.zeroize();
            return Err((error.to_string()).into());
        }
        if let PasswordType::Key(path) = &new_key
            && new_key_file_path(path)?.exists()
        {
            return Err(VaultError::Conflict(
                "the new key file already exists".to_string(),
            ));
        }
        let old_filename = self.metadata.filename.clone();
        if matches!(&new_key, PasswordType::Key(_)) {
            let mut key = try_gen_master_key(&mut new_key, true)?;
            key.zeroize();
        } else if let Some((_, mut existing)) = find_vault(&mut new_key) {
            existing.zeroize();
            new_key.zeroize();
            return Err(VaultError::Conflict(
                "a vault already exists for the new password".to_string(),
            ));
        }
        let new_filename = random_vault_filename();
        let new_path = data_dir().join(&new_filename);
        if new_path.exists() {
            if let PasswordType::Key(path) = &new_key {
                let _ = fs::remove_file(new_key_file_path(path)?);
            }
            return Err(VaultError::Conflict(
                "a vault already exists for the new password or key".to_string(),
            ));
        }

        self.metadata.filename = new_filename.clone();
        let mut replacement = ServerInfo {
            locked: false,
            keypass: Some(new_key.clone()),
        };
        if let Err(error) = write_vault(self, &mut replacement) {
            replacement.zeroize();
            self.metadata.filename = old_filename;
            if let PasswordType::Key(path) = &new_key {
                let _ = fs::remove_file(new_key_file_path(path)?);
            }
            return Err(error);
        }
        if let Err(error) = fs::remove_file(data_dir().join(&old_filename)) {
            replacement.zeroize();
            let _ = fs::remove_file(&new_path);
            if let PasswordType::Key(path) = &new_key {
                let _ = fs::remove_file(new_key_file_path(path)?);
            }
            self.metadata.filename = old_filename;
            return Err(VaultError::Persistence(format!(
                "could not replace the old vault: {error}"
            )));
        }
        let cached_new_key = replacement.keypass.take().unwrap_or(new_key);
        replacement.zeroize();
        if let Some(mut old_key) = server_info.keypass.replace(cached_new_key) {
            old_key.zeroize();
        }
        Ok(())
    }

    pub fn lock_vault(&self, key_pass: &mut ServerInfo) -> Result<(), VaultError> {
        // Every mutation is persisted before it succeeds. Locking must not
        // depend on storage availability or leave keys resident after an I/O error.
        key_pass.zeroize();
        Ok(())
    }
}

pub(super) fn random_vault_filename() -> String {
    loop {
        let filename = format!("{}.enc", hex::encode(rand::random::<[u8; 16]>()));
        if !data_dir().join(&filename).exists() {
            return filename;
        }
    }
}

pub(super) fn find_vault(key_pass: &mut PasswordType) -> Option<(String, Vault)> {
    let candidates = fs::read_dir(data_dir())
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let filename = entry.file_name().into_string().ok()?;
            filename.ends_with(".enc").then_some(filename)
        });

    for filename in candidates {
        let path = data_dir().join(&filename);
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.file_type().is_file() || metadata.len() > MAX_VAULT_BYTES {
            continue;
        }
        let Ok(contents) = read(path) else {
            continue;
        };
        let Some(mut decrypted) = decrypt_file(key_pass, &contents) else {
            continue;
        };
        let decoded = rmp_serde::from_slice::<Vault>(&decrypted);
        decrypted.zeroize();
        let Ok(mut vault) = decoded else {
            continue;
        };
        if vault.ensure_next_entry_id().is_err() {
            vault.zeroize();
            continue;
        }
        vault.metadata.filename = filename.clone();
        return Some((filename, vault));
    }
    None
}

pub(crate) fn create_vault(
    vlt: &mut Option<Vault>,
    server_info: &mut ServerInfo,
    lock: bool,
) -> Result<(), VaultError> {
    if let Some(PasswordType::Password(password)) = server_info.keypass.as_ref()
        && let Err(error) = validate_new_password(password)
    {
        server_info.zeroize();
        return Err((error.to_string()).into());
    }
    let generated_key_path = match server_info.keypass.as_ref() {
        Some(PasswordType::Key(path)) if !new_key_file_path(path)?.exists() => {
            Some(new_key_file_path(path)?)
        }
        _ => None,
    };
    if matches!(server_info.keypass, Some(PasswordType::Key(_))) {
        let mut key = try_gen_master_key(server_info.keypass.as_mut().unwrap(), true)?;
        key.zeroize();
    } else if let Some((_, mut existing)) = find_vault(server_info.keypass.as_mut().unwrap()) {
        existing.zeroize();
        server_info.zeroize();
        return Err(VaultError::Conflict(
            "A vault file with this password already exists.".to_string(),
        ));
    }
    let fname = random_vault_filename();
    let file_path = data_dir().join(&fname);
    if file_exists(&file_path) {
        if let Some(path) = generated_key_path {
            let _ = fs::remove_file(path);
        }
        return Err(VaultError::Conflict(
            "A vault file with this key already exists.".to_string(),
        ));
    }
    *vlt = Some(Vault {
        entries: Vec::new(),
        metadata: VaultMetadata {
            filename: fname.clone(),
        },
        recovery: RecoveryData::default(),
    });
    if let Err(error) = write_vault(
        vlt.as_ref().expect("vault was just initialized"),
        server_info,
    ) {
        vlt.zeroize();
        if let Some(path) = generated_key_path {
            let _ = fs::remove_file(path);
        }
        return Err(error);
    }
    if lock {
        vlt.zeroize();
        server_info.zeroize();
    }
    Ok(())
}
pub(super) fn write_vault(vlt: &Vault, key_pass: &mut ServerInfo) -> Result<(), VaultError> {
    if key_pass.keypass.is_none() {
        // This permits detached in-memory vault values used by callers and tests;
        // the running server never mutates a vault without an active key.
        return Ok(());
    }
    write_vault_with_key(vlt, key_pass.keypass.as_mut().unwrap())
}

pub(super) fn write_vault_with_key(
    vlt: &Vault,
    key_pass: &mut PasswordType,
) -> Result<(), VaultError> {
    let fname = vlt.metadata.filename.clone();
    let file_path = data_dir().join(&fname);
    let buf = run_blocking_io(|| rmp_serde::to_vec(&vlt))
        .map_err(|e| VaultError::Persistence(format!("could not encode vault: {e}")))?;
    let mut txt = try_encrypt_file_in_place(key_pass, buf)?;
    let result = run_blocking_io(|| {
        let mut temporary = NamedTempFile::new_in(data_dir()).map_err(|e| {
            VaultError::Persistence(format!("could not create vault temp file: {e}"))
        })?;
        set_private_perms(temporary.path()).map_err(|e| {
            VaultError::Persistence(format!("could not protect vault temp file: {e}"))
        })?;
        temporary.write_all(&txt).map_err(|e| {
            VaultError::Persistence(format!("could not write encrypted vault: {e}"))
        })?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|e| VaultError::Persistence(format!("could not sync encrypted vault: {e}")))?;
        temporary.persist(&file_path).map_err(|e| {
            VaultError::Persistence(format!(
                "could not atomically replace vault file: {}",
                e.error
            ))
        })?;
        sync_parent(&file_path)
            .map_err(|e| VaultError::Persistence(format!("could not sync vault directory: {e}")))?;
        Ok(())
    });
    txt.zeroize();
    result
}

pub(super) fn persist_private_file(
    path: &Path,
    contents: &[u8],
    force: bool,
) -> Result<(), VaultError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    run_blocking_io(|| {
        let mut temporary = NamedTempFile::new_in(parent).map_err(|error| {
            VaultError::Persistence(format!("could not create private temp file: {error}"))
        })?;
        set_private_perms(temporary.path()).map_err(|error| {
            VaultError::Persistence(format!("could not protect private temp file: {error}"))
        })?;
        temporary
            .write_all(contents)
            .and_then(|_| temporary.as_file().sync_all())
            .map_err(|error| {
                VaultError::Persistence(format!("could not write private file: {error}"))
            })?;
        if force {
            temporary.persist(path).map_err(|error| {
                VaultError::Persistence(format!("could not replace private file: {}", error.error))
            })?;
        } else {
            temporary.persist_noclobber(path).map_err(|error| {
                if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                    VaultError::Conflict(format!(
                        "destination file {:?} already exists; use --force to replace it",
                        path
                    ))
                } else {
                    VaultError::Persistence(format!(
                        "could not create private file: {}",
                        error.error
                    ))
                }
            })?;
        }
        sync_parent(path).map_err(|error| {
            VaultError::Persistence(format!("could not sync private file directory: {error}"))
        })?;
        Ok(())
    })
}

pub(super) fn unlock_vault(key_pass: &mut ServerInfo) -> Option<Vault> {
    let kp = key_pass.keypass.as_mut()?;
    if let PasswordType::Key(key) = kp
        && !key_file_path(key).ok()?.is_file()
    {
        return None;
    }
    let (_, vault) = find_vault(key_pass.keypass.as_mut().unwrap())?;
    key_pass.locked = false;
    Some(vault)
}

pub(crate) fn delete_vault(mut key: PasswordType, keep_key: bool) -> Result<(), VaultError> {
    let data = data_dir();
    let key_to_remove = match &key {
        PasswordType::Key(path) if !keep_key => Some(path.clone()),
        _ => None,
    };
    if let PasswordType::Key(key_path) = &key
        && !key_file_path(key_path)?.is_file()
    {
        return Err(("key file does not exist or is not a regular file".to_string()).into());
    }
    let (filename, mut vault) = find_vault(&mut key)
        .ok_or_else(|| "could not delete vault (is the key correct?)".to_string())?;
    vault.zeroize();
    fs::remove_file(data.join(filename)).map_err(|e| {
        VaultError::Persistence(format!("could not delete vault (is the key correct?): {e}"))
    })?;
    if let Some(mut key) = key_to_remove {
        fs::remove_file(key_file_path(&key)?).map_err(|e| {
            VaultError::Persistence(format!(
                "vault deleted, but could not delete its key file: {e}"
            ))
        })?;
        key.zeroize();
    }
    key.zeroize();
    Ok(())
}
