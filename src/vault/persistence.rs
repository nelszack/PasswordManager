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
        let generated_key_path = match &new_key {
            PasswordType::Key(path) => Some(new_key_file_path(path)?),
            _ => None,
        };
        if generated_key_path.is_some() {
            let mut key = try_gen_master_key(&mut new_key, true)?;
            key.zeroize();
        } else if let Some((_, mut existing)) = lookup_vault(&mut new_key, None)? {
            existing.zeroize();
            return Err(VaultError::Conflict(
                "a vault already exists for the new password".to_string(),
            ));
        }
        // Keep the same random filename. One atomic replacement is the commit
        // point: recovery sees either the old ciphertext or the new ciphertext.
        let mut replacement = ServerInfo {
            locked: false,
            keypass: Some(new_key),
        };
        let result = write_vault(self, &mut replacement);
        if result.as_ref().is_err_and(|error| !error.committed()) {
            if let Some(path) = generated_key_path {
                let _ = fs::remove_file(path);
            }
            replacement.zeroize();
            return result;
        }
        if let Some(mut old_key) = server_info.keypass.take() {
            old_key.zeroize();
        }
        server_info.keypass = replacement.keypass.take();
        replacement.zeroize();
        result?;
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

/// List opaque vault IDs without opening or decrypting their contents.
pub fn list_vaults() -> Result<Vec<String>, VaultError> {
    list_vaults_in(&data_dir())
}

fn list_vaults_in(directory: &Path) -> Result<Vec<String>, VaultError> {
    let mut names = Vec::new();
    for entry in fs::read_dir(directory).map_err(|error| {
        VaultError::Persistence(format!("could not list vault directory: {error}"))
    })? {
        let entry = entry.map_err(|error| VaultError::Persistence(error.to_string()))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.ends_with(".enc")
            && entry
                .file_type()
                .map_err(|error| {
                    VaultError::Persistence(format!("could not inspect vault {name:?}: {error}"))
                })?
                .is_file()
        {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

pub fn validate_vault_filename(name: &str) -> Result<(), VaultError> {
    if name.is_empty()
        || !name.ends_with(".enc")
        || name.contains(['/', '\\', ':', '\0'])
        || Path::new(name).components().count() != 1
    {
        return Err(VaultError::InvalidInput(
            "vault ID must be a single .enc filename from `pm vaults`".into(),
        ));
    }
    Ok(())
}

pub(super) fn lookup_vault(
    key_pass: &mut PasswordType,
    selected: Option<&str>,
) -> Result<Option<(String, Vault)>, VaultError> {
    lookup_vault_in(&data_dir(), key_pass, selected)
}

fn lookup_vault_in(
    directory: &Path,
    key_pass: &mut PasswordType,
    selected: Option<&str>,
) -> Result<Option<(String, Vault)>, VaultError> {
    if let PasswordType::Key(path) = key_pass {
        let mut key = try_gen_master_key(&mut PasswordType::Key(path.clone()), false)
            .map_err(VaultError::Persistence)?;
        key.zeroize();
    }
    let candidates = match selected {
        Some(name) => {
            validate_vault_filename(name)?;
            vec![name.to_owned()]
        }
        None => list_vaults_in(directory)?,
    };
    for filename in candidates {
        let path = directory.join(&filename);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if selected.is_none() && error.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(VaultError::NotFound(format!(
                    "vault {filename:?} does not exist"
                )));
            }
            Err(error) => {
                return Err(VaultError::Persistence(format!(
                    "could not inspect vault {filename:?}: {error}"
                )));
            }
        };
        if !metadata.file_type().is_file() || metadata.len() > MAX_VAULT_BYTES {
            if selected.is_none() {
                continue;
            }
            return Err(VaultError::Validation(format!(
                "vault {filename:?} must be a regular file within the 128 MiB limit"
            )));
        }
        // Bound the actual read too, in case the file grew after metadata().
        let mut contents = Vec::new();
        let read = fs::File::open(&path)
            .and_then(|file| file.take(MAX_VAULT_BYTES + 1).read_to_end(&mut contents));
        match read {
            Ok(_) => {}
            Err(error) if selected.is_none() && error.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(error) => {
                return Err(VaultError::Persistence(format!(
                    "could not read vault {filename:?}: {error}"
                )));
            }
        }
        if contents.len() as u64 > MAX_VAULT_BYTES {
            return Err(VaultError::Validation(format!(
                "vault {filename:?} exceeds the 128 MiB limit"
            )));
        }
        if let Err(error) = crate::encryption::validate_vault_header(&contents) {
            if selected.is_none() {
                continue;
            }
            return Err(VaultError::Validation(format!(
                "vault {filename:?}: {error}"
            )));
        }
        let Some(decrypted) = decrypt_file(key_pass, &contents) else {
            if selected.is_none() {
                continue;
            }
            return Err(VaultError::Validation(format!(
                "vault {filename:?}: incorrect password/key or modified encrypted contents"
            )));
        };
        let decrypted = Zeroizing::new(decrypted);
        let mut vault: Vault = rmp_serde::from_slice(&decrypted).map_err(|error| {
            VaultError::Validation(format!(
                "vault {filename:?} authenticated but its data is invalid: {error}"
            ))
        })?;
        if let Err(error) = validate_backup_vault(&mut vault) {
            vault.zeroize();
            return Err(error.context(format!("vault {filename:?} contains invalid records")));
        }
        vault.metadata.filename = filename.clone();
        return Ok(Some((filename, vault)));
    }
    Ok(None)
}

#[cfg(test)]
pub(super) fn find_vault(key_pass: &mut PasswordType) -> Option<(String, Vault)> {
    lookup_vault(key_pass, None).ok().flatten()
}

#[cfg(test)]
thread_local! {
    static WRITE_FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

fn before_vault_replace() -> Result<(), VaultError> {
    #[cfg(test)]
    if WRITE_FAULT.get() == 3 {
        std::process::exit(71);
    }
    #[cfg(test)]
    if WRITE_FAULT.get() == 1 {
        return Err(VaultError::Persistence(
            "injected failure before replacement".into(),
        ));
    }
    Ok(())
}

fn sync_vault_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if WRITE_FAULT.get() == 4 {
        std::process::exit(72);
    }
    #[cfg(test)]
    if WRITE_FAULT.get() == 2 {
        return Err(std::io::Error::other("injected failure after replacement"));
    }
    sync_parent(path)
}

#[cfg(test)]
fn with_write_fault<T>(fault: u8, operation: impl FnOnce() -> T) -> T {
    struct Reset(u8);
    impl Drop for Reset {
        fn drop(&mut self) {
            WRITE_FAULT.set(self.0);
        }
    }
    let _reset = Reset(WRITE_FAULT.replace(fault));
    operation()
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
    } else if let Some((_, mut existing)) =
        lookup_vault(server_info.keypass.as_mut().unwrap(), None)?
    {
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
        if !error.committed()
            && let Some(path) = generated_key_path
        {
            let _ = fs::remove_file(path);
        }
        vlt.zeroize();
        server_info.zeroize();
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
    #[cfg(test)]
    let max_bytes = TEST_MAX_VAULT_BYTES.get();
    #[cfg(not(test))]
    let max_bytes = MAX_VAULT_BYTES;
    write_vault_with_limit(vlt, key_pass, max_bytes)
}

#[cfg(test)]
thread_local! {
    static TEST_MAX_VAULT_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(MAX_VAULT_BYTES) };
}

fn write_vault_with_limit(
    vlt: &Vault,
    key_pass: &mut PasswordType,
    max_bytes: u64,
) -> Result<(), VaultError> {
    let fname = vlt.metadata.filename.clone();
    let file_path = data_dir().join(&fname);
    let mut buf = Zeroizing::new(
        run_blocking_io(|| rmp_serde::to_vec(&vlt))
            .map_err(|e| VaultError::Persistence(format!("could not encode vault: {e}")))?,
    );
    validate_encrypted_size(buf.len(), 0, max_bytes, "vault")?;
    let mut txt = try_encrypt_file_in_place(key_pass, std::mem::take(&mut *buf))?;
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
        before_vault_replace()?;
        temporary.persist(&file_path).map_err(|e| {
            VaultError::Persistence(format!(
                "could not atomically replace vault file: {}",
                e.error
            ))
        })?;
        sync_vault_parent(&file_path).map_err(|e| {
            VaultError::Durability(format!(
                "vault replacement committed, but durability could not be confirmed: {e}; \
                 the new state is active; do not blindly retry this operation"
            ))
        })?;
        Ok(())
    });
    txt.zeroize();
    result
}

pub(super) fn validate_encrypted_size(
    plaintext_bytes: usize,
    prefix_bytes: usize,
    max_bytes: u64,
    label: &str,
) -> Result<(), VaultError> {
    let encrypted_bytes = plaintext_bytes
        .checked_add(crate::encryption::ENCRYPTED_FILE_OVERHEAD)
        .and_then(|size| size.checked_add(prefix_bytes));
    if encrypted_bytes.is_none_or(|size| size as u64 > max_bytes) {
        return Err(VaultError::Validation(format!(
            "{label} exceeds the {max_bytes} byte encrypted-file limit; reduce its size before saving"
        )));
    }
    Ok(())
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
            VaultError::Durability(format!("file replacement committed, but durability could not be confirmed: {error}; do not blindly retry"))
        })?;
        Ok(())
    })
}

pub(super) fn unlock_selected_vault(
    key_pass: &mut ServerInfo,
    selected: Option<&str>,
) -> Result<Vault, VaultError> {
    let kp = key_pass.keypass.as_mut().ok_or(VaultError::Locked)?;
    let (_, vault) = lookup_vault(kp, selected)?.ok_or_else(|| VaultError::Validation(
        "no matching vault: incorrect password/key, no vault exists, or encrypted contents were modified; use `pm vaults` and `pm unlock --vault-file ID` to inspect a specific vault".into()
    ))?;
    key_pass.locked = false;
    Ok(vault)
}

#[cfg(test)]
pub(super) fn unlock_vault(key_pass: &mut ServerInfo) -> Option<Vault> {
    unlock_selected_vault(key_pass, None).ok()
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
    let (filename, mut vault) = lookup_vault(&mut key, None)?
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_mutation_rolls_back_and_keeps_the_saved_vault_and_key() {
        let (mut vault, mut info) = stored_vault();
        let before = vault.clone();
        let path = data_dir().join(&vault.metadata.filename);
        let ciphertext = fs::read(&path).unwrap();
        struct RestoreLimit(u64);
        impl Drop for RestoreLimit {
            fn drop(&mut self) {
                TEST_MAX_VAULT_BYTES.set(self.0);
            }
        }
        let _restore = RestoreLimit(TEST_MAX_VAULT_BYTES.replace(ciphertext.len() as u64));
        let result = vault.transaction(TransactionScope::Entry(1), &mut info, |vault| {
            vault.entries[0].notes = Some("x".repeat(1024));
            Ok((true, ()))
        });
        assert!(matches!(result, Err(VaultError::Validation(_))));
        assert_eq!(vault, before);
        assert_eq!(fs::read(&path).unwrap(), ciphertext);
        let mut key = session(42);
        let (_, reopened) = lookup_vault_in(&data_dir(), &mut key, Some(&vault.metadata.filename))
            .unwrap()
            .unwrap();
        assert_eq!(reopened.entries, before.entries);
        let mut replacement = PasswordType::Password("new-master-password-for-size-test".into());
        assert!(write_vault_with_limit(&vault, &mut replacement, 1).is_err());
        assert!(
            matches!(replacement, PasswordType::Password(ref password) if password == "new-master-password-for-size-test")
        );
        assert_eq!(fs::read(&path).unwrap(), ciphertext);
        // A file exactly at the limit remains writable and reopenable.
        write_vault_with_limit(
            &vault,
            info.keypass.as_mut().unwrap(),
            ciphertext.len() as u64,
        )
        .unwrap();
    }

    #[test]
    fn size_validation_includes_header_tag_and_backup_prefix() {
        let overhead = crate::encryption::ENCRYPTED_FILE_OVERHEAD as u64;
        assert!(validate_encrypted_size(10, 0, overhead + 10, "vault").is_ok());
        assert!(validate_encrypted_size(10, 0, overhead + 9, "vault").is_err());
        assert!(validate_encrypted_size(10, 9, overhead + 19, "backup").is_ok());
        assert!(validate_encrypted_size(10, 9, overhead + 18, "backup").is_err());
        assert!(validate_encrypted_size(usize::MAX, 9, u64::MAX, "backup").is_err());
    }

    fn session(byte: u8) -> PasswordType {
        PasswordType::Session {
            encryption_key: [byte; 32],
            salt: [byte; 16],
            kdf: 1,
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn stored_vault() -> (Vault, ServerInfo) {
        crate::file::init_test_data_dir();
        let vault = Vault {
            entries: vec![VaultEntry {
                id: 1,
                password: "before".into(),
                ..Default::default()
            }],
            metadata: VaultMetadata {
                filename: random_vault_filename(),
            },
            recovery: RecoveryData::default(),
        };
        let mut info = ServerInfo {
            locked: false,
            keypass: Some(session(42)),
        };
        write_vault(&vault, &mut info).unwrap();
        (vault, info)
    }

    #[test]
    fn write_failures_before_and_after_commit_keep_memory_and_disk_consistent() {
        let (mut vault, mut info) = stored_vault();
        let path = data_dir().join(&vault.metadata.filename);
        for (fault, expected) in [(1, "before"), (2, "after")] {
            let result = with_write_fault(fault, || {
                vault.transaction(TransactionScope::Entry(1), &mut info, |vault| {
                    vault.entries[0].password = "after".into();
                    Ok((true, ()))
                })
            });
            let error = result.unwrap_err();
            assert_eq!(error.committed(), fault == 2);
            assert_eq!(vault.entries[0].password, expected);
            let bytes = fs::read(&path).unwrap();
            let plaintext = Zeroizing::new(decrypt_file(&mut session(42), &bytes).unwrap());
            let mut stored: Vault = rmp_serde::from_slice(&plaintext).unwrap();
            assert_eq!(stored.entries[0].password, expected);
            stored.zeroize();
        }
        // A later write and restart recover the committed state normally.
        write_vault(&vault, &mut info).unwrap();
        let (_, mut restarted) = lookup_vault(&mut session(42), Some(&vault.metadata.filename))
            .unwrap()
            .unwrap();
        assert_eq!(restarted.entries, vault.entries);
        restarted.zeroize();
        vault.zeroize();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn interrupted_rekey_has_one_vault_and_only_the_committed_key_works() {
        let (mut vault, mut info) = stored_vault();
        let path = data_dir().join(&vault.metadata.filename);
        let directory = tempfile::tempdir().unwrap();
        let new_key_path = directory.path().join("replacement.key");
        let replacement = PasswordType::Key(new_key_path.display().to_string());
        let before = fs::read(&path).unwrap();
        let result = with_write_fault(1, || vault.rekey(&mut info, replacement.clone()));
        assert!(!result.unwrap_err().committed());
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(!new_key_path.exists());
        assert!(decrypt_file(&mut session(42), &before).is_some());

        let result = with_write_fault(2, || vault.rekey(&mut info, replacement.clone()));
        assert!(result.unwrap_err().committed());
        assert_eq!(data_dir().join(&vault.metadata.filename), path);
        assert!(new_key_path.exists());
        let after = fs::read(&path).unwrap();
        assert!(decrypt_file(&mut session(42), &after).is_none());
        let mut key = replacement;
        let plaintext = Zeroizing::new(decrypt_file(&mut key, &after).unwrap());
        assert_eq!(
            rmp_serde::from_slice::<Vault>(&plaintext).unwrap().entries,
            vault.entries
        );
        // The running session adopted the committed new key even though sync failed.
        assert!(decrypt_file(info.keypass.as_mut().unwrap(), &after).is_some());
        write_vault(&vault, &mut info).unwrap();
        fs::remove_file(path).unwrap();
        vault.zeroize();
        info.zeroize();
    }

    #[test]
    fn creation_keeps_a_generated_key_when_the_vault_has_committed() {
        crate::file::init_test_data_dir();
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("creation.key");
        let mut info = ServerInfo {
            locked: false,
            keypass: Some(PasswordType::Key(key_path.display().to_string())),
        };
        let mut vault = None;
        let error = with_write_fault(2, || create_vault(&mut vault, &mut info, false)).unwrap_err();
        assert!(error.committed());
        assert!(key_path.exists());
        assert!(vault.is_none());
        assert!(info.keypass.is_none());
        let (filename, mut reopened) =
            lookup_vault(&mut PasswordType::Key(key_path.display().to_string()), None)
                .unwrap()
                .unwrap();
        reopened.zeroize();
        fs::remove_file(data_dir().join(filename)).unwrap();
    }

    #[test]
    fn selected_lookup_skips_unrelated_files_and_reports_structural_errors() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Vault {
            metadata: VaultMetadata {
                filename: "selected.enc".into(),
            },
            entries: Vec::new(),
            recovery: RecoveryData::default(),
        };
        let plaintext = rmp_serde::to_vec(&vault).unwrap();
        let ciphertext = try_encrypt_file_in_place(&mut session(42), plaintext).unwrap();
        fs::write(directory.path().join("selected.enc"), &ciphertext).unwrap();
        fs::write(directory.path().join("unrelated.enc"), b"broken").unwrap();
        let (name, mut opened) =
            lookup_vault_in(directory.path(), &mut session(42), Some("selected.enc"))
                .unwrap()
                .unwrap();
        assert_eq!(name, "selected.enc");
        opened.zeroize();
        assert!(matches!(
            lookup_vault_in(directory.path(), &mut session(42), Some("missing.enc")),
            Err(VaultError::NotFound(_))
        ));
        let invalid =
            lookup_vault_in(directory.path(), &mut session(42), Some("unrelated.enc")).unwrap_err();
        assert!(invalid.to_string().contains("truncated"));
        let wrong_key =
            lookup_vault_in(directory.path(), &mut session(43), Some("selected.enc")).unwrap_err();
        assert!(
            wrong_key
                .to_string()
                .contains("incorrect password/key or modified")
        );
        let mut future = ciphertext;
        future[8] = 99;
        fs::write(directory.path().join("future.enc"), future).unwrap();
        assert!(
            lookup_vault_in(directory.path(), &mut session(42), Some("future.enc"))
                .unwrap_err()
                .to_string()
                .contains("unsupported")
        );
        for name in [
            "../selected.enc",
            "/selected.enc",
            "x\\selected.enc",
            "C:selected.enc",
            "selected",
            "",
        ] {
            assert!(matches!(
                lookup_vault_in(directory.path(), &mut session(42), Some(name)),
                Err(VaultError::InvalidInput(_))
            ));
        }
    }

    #[test]
    fn selected_lookup_reports_unreadable_keys_and_authenticated_invalid_records() {
        let directory = tempfile::tempdir().unwrap();
        let mut missing_key =
            PasswordType::Key(directory.path().join("missing.key").display().to_string());
        assert!(matches!(
            lookup_vault_in(directory.path(), &mut missing_key, None),
            Err(VaultError::Persistence(_))
        ));
        let ciphertext =
            try_encrypt_file_in_place(&mut session(42), b"not a vault".to_vec()).unwrap();
        fs::write(directory.path().join("invalid.enc"), ciphertext).unwrap();
        assert!(
            lookup_vault_in(directory.path(), &mut session(42), Some("invalid.enc"))
                .unwrap_err()
                .to_string()
                .contains("authenticated")
        );
    }

    #[cfg(unix)]
    #[test]
    fn selected_lookup_rejects_symlinks_and_lists_only_regular_files() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("b.enc"), b"synthetic").unwrap();
        fs::write(directory.path().join("a.enc"), b"synthetic").unwrap();
        std::os::unix::fs::symlink(
            directory.path().join("b.enc"),
            directory.path().join("link.enc"),
        )
        .unwrap();
        fs::create_dir(directory.path().join("directory.enc")).unwrap();
        assert_eq!(
            list_vaults_in(directory.path()).unwrap(),
            ["a.enc", "b.enc"]
        );
        assert!(lookup_vault_in(directory.path(), &mut session(42), Some("link.enc")).is_err());
    }

    #[test]
    fn rekey_process_crash_helper() {
        let Ok(key_path) = std::env::var("PM_TEST_REKEY_CRASH_KEY") else {
            return;
        };
        let fault: u8 = std::env::var("PM_TEST_REKEY_CRASH_STAGE")
            .unwrap()
            .parse()
            .unwrap();
        let (mut vault, mut info) = {
            let mut key = session(42);
            let (_, vault) = lookup_vault(&mut key, Some("crash.enc")).unwrap().unwrap();
            (
                vault,
                ServerInfo {
                    locked: false,
                    keypass: Some(key),
                },
            )
        };
        with_write_fault(fault, || {
            vault.rekey(&mut info, PasswordType::Key(key_path))
        })
        .unwrap();
        panic!("crash injection did not exit");
    }

    #[test]
    fn abrupt_process_exit_during_rekey_leaves_a_complete_old_or_new_vault() {
        for (fault, code) in [(3, 71), (4, 72)] {
            let directory = tempfile::tempdir().unwrap();
            let data = directory.path().join("data");
            fs::create_dir(&data).unwrap();
            let key_path = directory.path().join("replacement.key");
            let vault = Vault {
                entries: vec![VaultEntry {
                    id: 1,
                    password: "synthetic-secret".into(),
                    ..Default::default()
                }],
                metadata: VaultMetadata {
                    filename: "crash.enc".into(),
                },
                recovery: RecoveryData::default(),
            };
            let ciphertext =
                try_encrypt_file_in_place(&mut session(42), rmp_serde::to_vec(&vault).unwrap())
                    .unwrap();
            fs::write(data.join("crash.enc"), &ciphertext).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "vault::persistence::tests::rekey_process_crash_helper",
                ])
                .env(crate::file::DATA_DIR_ENV, &data)
                .env("PM_TEST_REKEY_CRASH_KEY", &key_path)
                .env("PM_TEST_REKEY_CRASH_STAGE", fault.to_string())
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(code),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(list_vaults_in(&data).unwrap(), ["crash.enc"]);
            let mut old_key = session(42);
            let mut new_key = PasswordType::Key(key_path.display().to_string());
            let reopened = if fault == 3 {
                assert_eq!(fs::read(data.join("crash.enc")).unwrap(), ciphertext);
                assert!(lookup_vault_in(&data, &mut new_key, Some("crash.enc")).is_err());
                lookup_vault_in(&data, &mut old_key, Some("crash.enc"))
            } else {
                assert!(lookup_vault_in(&data, &mut old_key, Some("crash.enc")).is_err());
                lookup_vault_in(&data, &mut new_key, Some("crash.enc"))
            }
            .unwrap()
            .unwrap()
            .1;
            assert_eq!(reopened.entries, vault.entries);
        }
    }
}
