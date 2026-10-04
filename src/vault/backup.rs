use super::*;

impl Vault {
    pub fn encrypted_backup(
        &self,
        path: String,
        key_pass: &mut PasswordType,
        force: bool,
    ) -> Result<(), VaultError> {
        if let PasswordType::Password(password) = &key_pass
            && let Err(error) = validate_new_password(password)
        {
            key_pass.zeroize();
            return Err((error.to_string()).into());
        }
        let vault_path = data_dir().join(&self.metadata.filename);
        let backup_path = Path::new(&path);
        if backup_path.exists()
            && fs::canonicalize(backup_path).ok() == fs::canonicalize(&vault_path).ok()
        {
            return Err(("backup path cannot overwrite the active vault file".to_string()).into());
        }
        let envelope = BackupEnvelopeRef {
            version: BACKUP_VERSION,
            created: chrono::Utc::now().to_rfc3339(),
            vault: self,
        };
        let plaintext = rmp_serde::to_vec(&envelope)
            .map_err(|error| format!("could not encode backup: {error}"))?;
        let mut output = try_encrypt_file_in_place(key_pass, plaintext)?;
        let prefix_len = BACKUP_MAGIC.len() + 1;
        let encrypted_len = output.len();
        output.reserve(prefix_len);
        output.resize(encrypted_len + prefix_len, 0);
        output.copy_within(..encrypted_len, prefix_len);
        output[..BACKUP_MAGIC.len()].copy_from_slice(BACKUP_MAGIC);
        output[BACKUP_MAGIC.len()] = BACKUP_VERSION;
        let result = persist_private_file(backup_path, &output, force);
        output.zeroize();
        result
    }
}

pub(super) fn validate_backup_vault(vault: &mut Vault) -> Result<(), VaultError> {
    let mut ids = HashSet::new();
    for id in vault
        .entries
        .iter()
        .map(|entry| entry.id)
        .chain(vault.recovery.trash.iter().map(|item| item.entry.id))
    {
        if id == 0 || !ids.insert(id) {
            return Err(("backup contains invalid or duplicate entry IDs".to_string()).into());
        }
    }
    if vault
        .recovery
        .password_history
        .iter()
        .any(|revision| !ids.contains(&revision.entry_id))
        || vault
            .recovery
            .totp
            .iter()
            .any(|record| !ids.contains(&record.entry_id))
        || vault
            .recovery
            .entry_metadata
            .iter()
            .any(|record| !ids.contains(&record.entry_id))
    {
        return Err(("backup contains recovery records for unknown entries".to_string()).into());
    }
    if vault.recovery.trash.iter().any(|item| {
        item.history
            .iter()
            .any(|revision| revision.entry_id != item.entry.id)
    }) {
        return Err(("backup contains mismatched trash history".to_string()).into());
    }
    let mut totp_ids = HashSet::new();
    if vault
        .recovery
        .totp
        .iter()
        .any(|record| !totp_ids.insert(record.entry_id))
    {
        return Err(("backup contains duplicate TOTP records".to_string()).into());
    }
    let mut metadata_ids = HashSet::new();
    if vault
        .recovery
        .entry_metadata
        .iter()
        .any(|record| !metadata_ids.insert(record.entry_id))
    {
        return Err(("backup contains duplicate item metadata records".to_string()).into());
    }
    vault.ensure_next_entry_id()
}

pub(crate) fn restore_encrypted_backup(
    path: &str,
    key_pass: &mut PasswordType,
    force: bool,
) -> Result<String, VaultError> {
    let mut vault_lookup_key = Zeroizing::new(key_pass.clone());
    let metadata = fs::metadata(path)
        .map_err(|error| format!("could not open backup file {path:?}: {error}"))?;
    if metadata.len() > MAX_BACKUP_BYTES {
        return Err(("backup file exceeds the 128 MiB limit".to_string()).into());
    }
    let mut contents =
        fs::read(path).map_err(|error| format!("could not read backup file {path:?}: {error}"))?;
    if contents.len() < BACKUP_MAGIC.len() + 1
        || &contents[..BACKUP_MAGIC.len()] != BACKUP_MAGIC
        || contents[BACKUP_MAGIC.len()] != BACKUP_VERSION
    {
        contents.zeroize();
        return Err(("unsupported or invalid encrypted backup format".to_string()).into());
    }
    let mut plaintext = match decrypt_file(key_pass, &contents[BACKUP_MAGIC.len() + 1..]) {
        Some(plaintext) => plaintext,
        None => {
            contents.zeroize();
            return Err(("wrong backup password/key, or corrupted backup".to_string()).into());
        }
    };
    contents.zeroize();
    let decoded = rmp_serde::from_slice::<BackupEnvelope>(&plaintext)
        .map_err(|error| format!("could not decode backup: {error}"));
    plaintext.zeroize();
    let mut backup = decoded?;
    if backup.version != BACKUP_VERSION {
        backup.vault.zeroize();
        backup.created.zeroize();
        return Err(("unsupported encrypted backup version".to_string()).into());
    }
    let result = (|| {
        validate_backup_vault(&mut backup.vault)?;
        let existing = lookup_vault(&mut vault_lookup_key, None)?.map(|(filename, mut vault)| {
            vault.zeroize();
            filename
        });
        if existing.is_some() && !force {
            return Err(
                ("a vault already exists for this backup password/key; use --force to replace it"
                    .to_string())
                .into(),
            );
        }
        let filename = existing.unwrap_or_else(random_vault_filename);
        backup.vault.metadata.filename = filename.clone();
        write_vault_with_key(&backup.vault, key_pass)?;
        Ok(filename)
    })();
    backup.vault.zeroize();
    backup.created.zeroize();
    result
}
