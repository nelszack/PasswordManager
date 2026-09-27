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
