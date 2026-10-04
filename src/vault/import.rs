use super::totp::normalize_totp_configuration;
use super::*;

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

pub(super) fn import_csv(contents: &str, path: &str) -> Result<Vec<ImportedItem>, String> {
    let mut reader = csv::Reader::from_reader(contents.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| format!("invalid CSV headers in {path:?}: {e}"))?
        .iter()
        .map(normalized_header)
        .collect();
    let mut entries = Vec::new();
    for row in reader.records() {
        let row = row.map_err(|e| format!("invalid CSV data in {path:?}: {e}"))?;
        let name = csv_field(&headers, &row, &["name", "title"])
            .or_else(|| csv_field(&headers, &row, &["url", "website", "loginuri"]))
            .ok_or_else(|| format!("an imported CSV row in {path:?} has no name or URL"))?;
        let password = csv_field(&headers, &row, &["password"])
            .ok_or_else(|| format!("an imported CSV row in {path:?} has no password"))?;
        let now = chrono::Local::now().to_string();
        entries.push(ImportedItem::login(VaultEntry {
            id: 0,
            name,
            username: csv_field(&headers, &row, &["username", "loginusername", "login"]),
            password,
            url: csv_field(
                &headers,
                &row,
                &["url", "website", "loginuri", "formactionorigin"],
            ),
            notes: csv_field(&headers, &row, &["notes", "note", "extra", "comments"]),
            created: csv_field(&headers, &row, &["created", "timecreated"])
                .unwrap_or_else(|| now.clone()),
            modified: csv_field(
                &headers,
                &row,
                &["modified", "timemodified", "timepasswordchanged"],
            )
            .unwrap_or(now),
        }));
    }
    Ok(entries)
}

fn json_text(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(serde_json::Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(super) fn import_json(contents: &str, path: &str) -> Result<Vec<ImportedItem>, String> {
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
        return portable
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
            .collect();
    }
    let bitwarden = root.get("items").is_some();
    let values = root
        .get("items")
        .and_then(serde_json::Value::as_array)
        .or_else(|| root.as_array())
        .ok_or_else(|| {
            "JSON import must be an array or a Bitwarden object with items".to_string()
        })?;
    let mut entries = Vec::new();
    for value in values {
        if bitwarden && value.get("type").and_then(serde_json::Value::as_u64) != Some(1) {
            continue;
        }
        let login = value.get("login").unwrap_or(value);
        let url = json_text(value, &["url", "website"]).or_else(|| {
            login
                .get("uris")
                .and_then(serde_json::Value::as_array)
                .and_then(|uris| uris.first())
                .and_then(|uri| json_text(uri, &["uri"]))
        });
        let name = json_text(value, &["name", "title"])
            .or_else(|| url.clone())
            .ok_or_else(|| format!("an imported JSON item in {path:?} has no name or URL"))?;
        let password = json_text(login, &["password"])
            .or_else(|| json_text(value, &["password"]))
            .ok_or_else(|| format!("an imported JSON item in {path:?} has no password"))?;
        let now = chrono::Local::now().to_string();
        entries.push(ImportedItem::login(VaultEntry {
            id: 0,
            name,
            username: json_text(login, &["username", "login"]),
            password,
            url,
            notes: json_text(value, &["notes", "note"]),
            created: json_text(value, &["created", "creationDate"]).unwrap_or_else(|| now.clone()),
            modified: json_text(value, &["modified", "revisionDate"]).unwrap_or(now),
        }));
    }
    if entries.is_empty() {
        return Err(format!("no supported login entries were found in {path:?}"));
    }
    Ok(entries)
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
        key_pass: &mut ServerInfo,
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
        let imported = if trimmed.starts_with('{') || trimmed.starts_with('[') {
            import_json(&contents, &path)?
        } else {
            import_csv(&contents, &path)?
        };
        if imported.len() > MAX_IMPORT_ITEMS {
            return Err(
                (format!("import contains more than the {MAX_IMPORT_ITEMS} item limit")).into(),
            );
        }
        let plan = self.plan_import(imported, conflicts, preview);
        if preview {
            return Ok(plan.report);
        }
        self.transaction(TransactionScope::All, key_pass, |vault| {
            let changed = !plan.operations.is_empty();
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
                        vault.replace_portable_records(
                            id,
                            &mut imported,
                            old_password,
                            password_history_limit,
                        );
                    } else if let Some(password) = old_password {
                        vault.push_password_history_with_limit(
                            id,
                            password,
                            password_history_limit,
                        );
                    }
                } else {
                    let id = vault.allocate_entry_id()?;
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
