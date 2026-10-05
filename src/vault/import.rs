use super::totp::normalize_totp_configuration;
use super::*;
mod formats;

#[derive(Default)]
struct ImportLosses {
    unsupported: usize,
    count: usize,
    messages: Vec<String>,
    source_positions: Vec<usize>,
}

impl ImportLosses {
    fn warn(&mut self, item: usize, message: &str) {
        self.count += 1;
        if self.messages.len() < 100 {
            self.messages.push(format!("Source item {item}: {message}"));
        }
    }
}

fn normalized_header(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn csv_field(headers: &[String], record: &csv::StringRecord, aliases: &[&str]) -> Option<String> {
    headers
        .iter()
        .position(|header| aliases.contains(&header.as_str()))
        .and_then(|index| record.get(index))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(any(test, feature = "fuzzing"))]
pub(super) fn import_csv(contents: &str, path: &str) -> Result<Vec<ImportedItem>, String> {
    formats::csv_with_losses(contents, path).map(|(items, _)| items)
}

fn json_text(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(serde_json::Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(any(test, feature = "fuzzing"))]
pub(super) fn import_json(contents: &str, path: &str) -> Result<Vec<ImportedItem>, String> {
    import_json_with_losses(contents, path).map(|(items, _)| items)
}

fn import_json_with_losses(
    contents: &str,
    path: &str,
) -> Result<(Vec<ImportedItem>, ImportLosses), String> {
    let root: serde_json::Value =
        serde_json::from_str(contents).map_err(|e| format!("invalid JSON in {path:?}: {e}"))?;
    if root.get("format").and_then(serde_json::Value::as_str) == Some(PORTABLE_FORMAT) {
        let portable: PortableExport = serde_json::from_value(root)
            .map_err(|e| format!("invalid portable JSON in {path:?}: {e}"))?;
        if portable.version != PORTABLE_VERSION {
            return Err(format!(
                "unsupported portable JSON version {} in {path:?}",
                portable.version
            ));
        }
        let items = portable
            .items
            .into_iter()
            .map(|mut item| {
                if item.name.trim().is_empty() {
                    return Err(format!("a portable JSON item in {path:?} has no name"));
                }
                if let Some(configuration) = item.totp.as_deref() {
                    let (normalized, _) =
                        normalize_totp_configuration(configuration).map_err(|error| {
                            format!("invalid TOTP configuration for {:?}: {error}", item.name)
                        })?;
                    item.totp = Some(normalized);
                }
                Ok(ImportedItem {
                    portable: true,
                    entry: VaultEntry {
                        id: 0,
                        name: item.name,
                        username: item.username,
                        password: item.password,
                        url: item.url,
                        notes: item.notes,
                        created: item.created,
                        modified: item.modified,
                    },
                    kind: item.kind,
                    additional_urls: item.additional_urls,
                    custom_fields: item.custom_fields,
                    password_changed: item.password_changed,
                    password_history: item.password_history,
                    totp: item.totp,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        return Ok((items, ImportLosses::default()));
    }
    formats::external_json(root, path)
}

impl Vault {
    pub(super) fn replace_portable_records(
        &mut self,
        entry_id: usize,
        imported: &mut ImportedItem,
        old_password: Option<String>,
        password_history_limit: usize,
    ) {
        self.remove_metadata_records(&[entry_id]);
        self.remove_totp_records(&[entry_id]);

        let mut retained = Vec::with_capacity(self.recovery.password_history.len());
        for mut revision in std::mem::take(&mut self.recovery.password_history) {
            if revision.entry_id == entry_id {
                revision.zeroize();
            } else {
                retained.push(revision);
            }
        }
        self.recovery.password_history = retained;

        let mut history = std::mem::take(&mut imported.password_history)
            .into_iter()
            .map(|revision| PasswordRevision {
                entry_id,
                password: revision.password,
                changed: revision.changed,
            })
            .collect::<Vec<_>>();
        if let Some(password) = old_password {
            history.push(PasswordRevision {
                entry_id,
                password,
                changed: chrono::Local::now().to_string(),
            });
        }
        if history.len() > password_history_limit {
            let mut removed = history.drain(..history.len() - password_history_limit);
            removed.by_ref().for_each(|revision| {
                let mut revision = revision;
                revision.zeroize();
            });
        }
        self.recovery.password_history.extend(history);

        if imported.kind != ItemKind::Login
            || !imported.additional_urls.is_empty()
            || !imported.custom_fields.is_empty()
            || imported.password_changed.is_some()
        {
            self.recovery.entry_metadata.push(EntryMetadata {
                entry_id,
                kind: imported.kind,
                additional_urls: std::mem::take(&mut imported.additional_urls),
                password_changed: imported.password_changed.take(),
                custom_fields: std::mem::take(&mut imported.custom_fields),
            });
        }
        if let Some(configuration) = imported.totp.take() {
            self.recovery.totp.push(TotpRecord {
                entry_id,
                configuration,
            });
        }
    }

    pub fn import_with_options(
        &mut self,
        path: String,
        conflicts: ConflictPolicy,
        preview: bool,
        password_history_limit: usize,
        key_pass: &mut VaultCredentials,
    ) -> Result<ImportReport, VaultError> {
        let metadata = fs::metadata(&path).map_err(|error| {
            VaultError::Persistence(format!("could not open import file {path:?}: {error}"))
        })?;
        if !metadata.is_file() {
            return Err((format!("import path {path:?} is not a regular file")).into());
        }
        if metadata.len() > MAX_IMPORT_BYTES {
            return Err((format!(
                "import file {path:?} exceeds the {} MiB limit",
                MAX_IMPORT_BYTES / (1024 * 1024)
            ))
            .into());
        }
        let file = fs::File::open(&path).map_err(|error| {
            VaultError::Persistence(format!("could not open import file {path:?}: {error}"))
        })?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            usize::try_from(metadata.len().min(MAX_IMPORT_BYTES)).unwrap_or_default(),
        ));
        file.take(MAX_IMPORT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                VaultError::Persistence(format!("could not read import file {path:?}: {error}"))
            })?;
        if bytes.len() as u64 > MAX_IMPORT_BYTES {
            bytes.zeroize();
            return Err((format!(
                "import file {path:?} exceeds the {} MiB limit",
                MAX_IMPORT_BYTES / (1024 * 1024)
            ))
            .into());
        }
        let contents = match String::from_utf8(std::mem::take(&mut *bytes)) {
            Ok(contents) => Zeroizing::new(contents),
            Err(error) => {
                let mut bytes = error.into_bytes();
                bytes.zeroize();
                return Err((format!("import file {path:?} is not valid UTF-8")).into());
            }
        };
        let trimmed = contents.trim_start();
        let (imported, mut losses) = if trimmed.starts_with('{') || trimmed.starts_with('[') {
            import_json_with_losses(&contents, &path)?
        } else {
            formats::csv_with_losses(&contents, &path)?
        };
        if imported.len() + losses.unsupported > MAX_IMPORT_ITEMS {
            return Err(
                (format!("import contains more than the {MAX_IMPORT_ITEMS} item limit")).into(),
            );
        }
        for (position, item) in imported.iter().enumerate() {
            if item.password_history.len() > password_history_limit {
                losses.warn(losses.source_positions.get(position).copied().unwrap_or(position + 1), "password history exceeds the configured retention limit; oldest revisions will be omitted");
            }
        }
        let mut plan = self.plan_import(imported, conflicts, preview);
        plan.report.unsupported = losses.unsupported;
        plan.report.loss_count = losses.count;
        plan.report.losses = losses.messages;
        if preview {
            return Ok(plan.report);
        }
        self.transaction(TransactionScope::All, key_pass, |vault| {
            let changed = !plan.operations.is_empty();
            if plan.operations.iter().any(|(index, _)| index.is_none()) {
                vault.ensure_next_entry_id()?;
            }
            for (index, mut imported) in plan.operations {
                if let Some(index) = index {
                    let id = vault.entries[index].id;
                    let created = vault.entries[index].created.clone();
                    let old_password = (vault.entries[index].password != imported.entry.password)
                        .then(|| vault.entries[index].password.clone());
                    imported.entry.id = id;
                    imported.entry.created = created;
                    imported.entry.modified = chrono::Local::now().to_string();
                    vault.entries[index].zeroize();
                    vault.entries[index] = std::mem::take(&mut imported.entry);
                    if imported.portable {
                        if old_password.is_some() {
                            imported.password_changed = Some(vault.entries[index].modified.clone());
                        }
                        vault.replace_portable_records(
                            id,
                            &mut imported,
                            old_password,
                            password_history_limit,
                        );
                    } else if let Some(password) = old_password {
                        vault.apply_metadata_update(
                            id,
                            MetadataUpdate {
                                password_changed: true,
                                kind: None,
                                add_urls: &[],
                                remove_urls: &[],
                                clear_urls: false,
                                primary_url: None,
                                set_fields: &[],
                                remove_fields: &[],
                                clear_fields: false,
                            },
                        );
                        vault.push_password_history_with_limit(
                            id,
                            password,
                            password_history_limit,
                        );
                    }
                } else {
                    let id = vault.allocate_validated_entry_id()?;
                    imported.entry.id = id;
                    vault.entries.push(std::mem::take(&mut imported.entry));
                    if imported.portable {
                        vault.replace_portable_records(
                            id,
                            &mut imported,
                            None,
                            password_history_limit,
                        );
                    }
                }
            }
            Ok((changed, plan.report))
        })
    }

    /// Plan using only names, usernames and URLs. Previews never copy live secrets
    /// or mutate the vault, and use exactly the same conflict decisions as imports.
    fn plan_import(
        &self,
        imported: Vec<ImportedItem>,
        conflicts: ConflictPolicy,
        preview: bool,
    ) -> ImportPlan {
        let mut report = ImportReport {
            total: imported.len(),
            preview,
            ..Default::default()
        };
        let mut duplicates = HashMap::new();
        for (index, entry) in self.entries.iter().enumerate() {
            duplicates
                .entry((
                    entry.name.clone(),
                    entry.username.clone(),
                    entry.url.clone(),
                ))
                .or_insert(index);
        }
        let mut names: HashSet<_> = self
            .entries
            .iter()
            .map(|e| (e.name.clone(), e.username.clone()))
            .collect();
        let mut operations = Vec::new();
        let mut next_index = self.entries.len();
        for mut item in imported {
            let key = (
                item.entry.name.clone(),
                item.entry.username.clone(),
                item.entry.url.clone(),
            );
            let duplicate = duplicates.get(&key).copied();
            match (duplicate, conflicts) {
                (Some(_), ConflictPolicy::Skip) => {
                    report.skipped += 1;
                    continue;
                }
                (Some(index), ConflictPolicy::Replace) => {
                    report.replaced += 1;
                    operations.push((Some(index), item));
                    continue;
                }
                (Some(_), ConflictPolicy::KeepBoth) => {
                    report.renamed += 1;
                    let base = item.entry.name.clone();
                    let mut suffix = 1usize;
                    loop {
                        let candidate = if suffix == 1 {
                            format!("{base} (imported)")
                        } else {
                            format!("{base} (imported {suffix})")
                        };
                        if !names.contains(&(candidate.clone(), item.entry.username.clone())) {
                            item.entry.name = candidate;
                            break;
                        }
                        suffix += 1;
                    }
                }
                (None, _) => {}
            }
            report.added += 1;
            names.insert((item.entry.name.clone(), item.entry.username.clone()));
            duplicates.insert(
                (
                    item.entry.name.clone(),
                    item.entry.username.clone(),
                    item.entry.url.clone(),
                ),
                next_index,
            );
            next_index += 1;
            operations.push((None, item));
        }
        ImportPlan { operations, report }
    }
}

struct ImportPlan {
    operations: Vec<(Option<usize>, ImportedItem)>,
    report: ImportReport,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rich_preview_and_execution_report_the_same_losses_and_keep_source_positions() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", json!({ "items": [
            { "type": 99, "password": "synthetic-unsupported" },
            { "type": 1, "name": "Account", "login": {
                "password": "synthetic-password", "totp": "JBSWY3DPEHPK3PXP",
                "uris": [{ "uri": "https://one.example" }, { "uri": "https://two.example" }] },
                "passwordHistory": [{ "password": "synthetic-newer" }, { "password": "synthetic-older" }],
                "fields": [{ "name": "token", "value": "synthetic-token", "type": 1 }] }
        ] })).unwrap();
        let mut vault = Vault::default();
        let before = vault.clone();
        let path = file.path().display().to_string();
        let preview = vault
            .import_with_options(
                path.clone(),
                ConflictPolicy::Skip,
                true,
                1,
                &mut VaultCredentials::default(),
            )
            .unwrap();
        assert_eq!(vault, before);
        assert_eq!(preview.added, 1);
        assert_eq!(preview.unsupported, 1);
        assert_eq!(preview.loss_count, 2);
        assert!(preview.losses[1].starts_with("Source item 2:"));
        assert!(!preview.to_string().contains("synthetic-"));
        let imported = vault
            .import_with_options(
                path,
                ConflictPolicy::Skip,
                false,
                1,
                &mut VaultCredentials::default(),
            )
            .unwrap();
        assert_eq!(imported.losses, preview.losses);
        assert_eq!(imported.unsupported, preview.unsupported);
        assert_eq!(vault.entries[0].password, "synthetic-password");
        assert_eq!(
            vault.recovery.entry_metadata[0].additional_urls,
            ["https://two.example"]
        );
        assert!(vault.recovery.entry_metadata[0].custom_fields[0].secret);
        assert_eq!(vault.recovery.password_history.len(), 1);
        assert_eq!(
            vault.recovery.password_history[0].password,
            "synthetic-newer"
        );
        assert_eq!(vault.recovery.totp.len(), 1);
    }

    fn batch() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            "name,password\nfirst,synthetic-one\nsecond,synthetic-two"
        )
        .unwrap();
        file
    }

    #[test]
    fn batch_ids_respect_active_trash_and_reserved_counters() {
        let file = batch();
        for (counter, expected) in [(0, 91), (5, 91), (200, 200)] {
            let mut vault = Vault::default();
            vault.entries.push(VaultEntry {
                id: 42,
                ..Default::default()
            });
            vault.recovery.trash.push(TrashedEntry {
                entry: VaultEntry {
                    id: 90,
                    ..Default::default()
                },
                history: Vec::new(),
                deleted: "synthetic".into(),
            });
            vault.recovery.next_entry_id = counter;
            let before = vault.clone();
            let preview = vault
                .import_with_options(
                    file.path().display().to_string(),
                    ConflictPolicy::Skip,
                    true,
                    1,
                    &mut VaultCredentials::default(),
                )
                .unwrap();
            assert_eq!(preview.added, 2);
            assert_eq!(vault, before);
            vault
                .import_with_options(
                    file.path().display().to_string(),
                    ConflictPolicy::Skip,
                    false,
                    1,
                    &mut VaultCredentials::default(),
                )
                .unwrap();
            assert_eq!(
                vault
                    .entries
                    .iter()
                    .map(|entry| entry.id)
                    .collect::<Vec<_>>(),
                vec![42, expected, expected + 1]
            );
            assert_eq!(vault.recovery.next_entry_id, expected + 2);
            assert_eq!(vault.recovery.trash, before.recovery.trash);
        }
    }

    #[test]
    fn counter_overflow_rolls_back_the_entire_batch() {
        let file = batch();
        let mut vault = Vault::default();
        vault.recovery.next_entry_id = usize::MAX - 1;
        let before = vault.clone();
        let error = vault
            .import_with_options(
                file.path().display().to_string(),
                ConflictPolicy::Skip,
                false,
                1,
                &mut VaultCredentials::default(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("ID space is exhausted"));
        assert_eq!(vault, before);
    }
}
