use super::totp::normalize_totp_configuration;
use super::*;
mod formats;

/// Third-party JSON has no secret-typed fields. Erase its transient strings too
/// after conversion, including validation/error paths.
struct SensitiveJson(serde_json::Value);
impl std::ops::Deref for SensitiveJson {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        fn wipe(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::String(value) => value.zeroize(),
                serde_json::Value::Array(values) => values.iter_mut().for_each(wipe),
                serde_json::Value::Object(values) => values.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

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

fn imported_timestamp(
    value: Option<String>,
    index: usize,
    label: &str,
    losses: &mut ImportLosses,
) -> Timestamp {
    match value {
        None => Timestamp::now(),
        Some(value) => match Timestamp::parse(&value) {
            Ok(timestamp) => timestamp,
            Err(_) => {
                losses.warn(
                    index,
                    &format!("unrecognized {label} replaced with import time"),
                );
                Timestamp::now()
            }
        },
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
    let mut root = SensitiveJson(
        serde_json::from_str(contents).map_err(|e| format!("invalid JSON in {path:?}: {e}"))?,
    );
    if root.get("format").and_then(serde_json::Value::as_str) == Some(PORTABLE_FORMAT) {
        let portable: PortableExport = serde_json::from_str(contents)
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
                    item.totp = Some(normalized.into());
                }
                if let Some(credentials) = &item.duo {
                    crate::duo::validate_credentials(credentials).map_err(|e| e.to_string())?;
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
                    duo: item.duo,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        return Ok((items, ImportLosses::default()));
    }
    formats::external_json(std::mem::take(&mut root.0), path)
}

impl Vault {
    fn replace_portable_records(
        &mut self,
        id: usize,
        imported: &mut ImportedItem,
        old_password: Option<SecretString>,
        limit: usize,
    ) -> Result<(), VaultError> {
        let authenticator = imported
            .totp
            .as_ref()
            .map(|s| Authenticator::parse(s))
            .transpose()?;
        let item = self.item_mut(id).unwrap();
        item.metadata = EntryMetadata {
            kind: imported.kind,
            additional_urls: std::mem::take(&mut imported.additional_urls),
            password_changed: imported.password_changed.take(),
            custom_fields: std::mem::take(&mut imported.custom_fields),
        };
        item.duo = imported.duo.take().map(|credentials| DuoRecord {
            credentials,
            review_key: None,
        });
        item.authenticator = authenticator;
        item.history = std::mem::take(&mut imported.password_history)
            .into_iter()
            .map(|r| PasswordRevision {
                password: r.password,
                changed: r.changed,
            })
            .collect();
        if let Some(password) = old_password {
            item.history.push(PasswordRevision {
                password,
                changed: Timestamp::now(),
            });
        }
        let excess = item.history.len().saturating_sub(limit);
        item.history.drain(..excess);
        Ok(())
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
        let mut plan = self.plan_import(imported, conflicts, preview)?;
        plan.report.unsupported = losses.unsupported;
        plan.report.loss_count = losses.count;
        plan.report.losses = losses.messages;
        if preview {
            return Ok(plan.report);
        }
        let affected: HashSet<ItemId> = plan
            .operations
            .iter()
            .filter_map(|(id, _)| *id)
            .map(ItemId::from_public)
            .collect::<Result<_, _>>()?;
        self.transaction(TransactionScope::Items(affected), key_pass, |vault| {
            let changed = !plan.operations.is_empty();
            for (selected, mut imported) in plan.operations {
                let (id, old_password) = if let Some(id) = selected {
                    let item = vault
                        .item_mut(id)
                        .ok_or_else(|| VaultError::Conflict("import target changed".into()))?;
                    let old = (item.entry.password != imported.entry.password)
                        .then(|| item.entry.password.clone());
                    imported.entry.id = id;
                    imported.entry.created = item.entry.created.clone();
                    imported.entry.modified = Timestamp::now();
                    item.entry = std::mem::take(&mut imported.entry);
                    (id, old)
                } else {
                    let id = vault.allocate_entry_id()?;
                    imported.entry.id = id;
                    vault.data.items.insert(
                        ItemId::from_public(id)?,
                        Item::new(
                            std::mem::take(&mut imported.entry),
                            EntryMetadata::default(),
                        ),
                    );
                    (id, None)
                };
                if imported.portable {
                    if old_password.is_some() {
                        imported.password_changed = Some(Timestamp::now());
                    }
                    vault.replace_portable_records(
                        id,
                        &mut imported,
                        old_password,
                        password_history_limit,
                    )?;
                } else {
                    // External provider import data is also complete item data. Preserve
                    // existing metadata on a replacement only when the source omits it.
                    let item = vault.item_mut(id).unwrap();
                    item.metadata.kind = imported.kind;
                    if !imported.additional_urls.is_empty() {
                        item.metadata.additional_urls =
                            std::mem::take(&mut imported.additional_urls);
                    }
                    if !imported.custom_fields.is_empty() {
                        item.metadata.custom_fields = std::mem::take(&mut imported.custom_fields);
                    }
                    if let Some(config) = imported.totp.take() {
                        item.authenticator = Some(Authenticator::parse(&config)?);
                    }
                    if let Some(credentials) = imported.duo.take() {
                        item.duo = Some(DuoRecord {
                            credentials,
                            review_key: None,
                        });
                    }
                    if let Some(password) = old_password {
                        item.metadata.password_changed = Some(Timestamp::now());
                        vault.push_password_history_with_limit(
                            id,
                            password,
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
    ) -> Result<ImportPlan, VaultError> {
        let mut report = ImportReport {
            total: imported.len(),
            preview,
            ..Default::default()
        };
        let mut duplicates = HashMap::new();
        for entry in self.active_entries() {
            duplicates
                .entry((
                    entry.name.clone(),
                    entry.username.clone(),
                    entry.url.clone(),
                ))
                .or_insert(entry.id);
        }
        let mut names: HashSet<_> = self
            .active_entries()
            .map(|e| (e.name.clone(), e.username.clone()))
            .collect();
        let mut operations = Vec::new();
        let mut next_index = self.next_entry_id()?;
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
            next_index = next_index
                .checked_add(1)
                .ok_or_else(|| VaultError::InvalidInput("item ID space exhausted".into()))?;
            operations.push((None, item));
        }
        Ok(ImportPlan { operations, report })
    }
}

struct ImportPlan {
    operations: Vec<(Option<usize>, ImportedItem)>,
    report: ImportReport,
}
