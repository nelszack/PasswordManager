use super::*;
use serde_json::Value;

fn raw(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn unknown_properties(value: &Value, known: &[&str]) -> serde_json::Map<String, Value> {
    value
        .as_object()
        .into_iter()
        .flat_map(|object| object.iter())
        .filter(|(key, value)| !known.contains(&key.as_str()) && !value.is_null())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn field(item: &mut ImportedItem, name: &str, value: Option<String>, secret: bool) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        item.custom_fields.push(CustomField {
            name: name.into(),
            value,
            secret,
        });
    }
}

fn totp(item: &mut ImportedItem, value: Option<String>, index: usize, losses: &mut ImportLosses) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        match normalize_totp_configuration(&value) {
            Ok((normalized, _)) => item.totp = Some(normalized),
            Err(_) => {
                // Retain unsupported providers (for example Steam) as a secret
                // field. Never echo the seed or parser error into the report.
                field(item, "imported authenticator", Some(value), true);
                losses.warn(index, "authenticator configuration retained as a secret field; code generation is unavailable");
            }
        }
    }
}

pub(super) fn external_json(
    root: Value,
    path: &str,
) -> Result<(Vec<ImportedItem>, ImportLosses), String> {
    if root.get("encrypted").and_then(Value::as_bool) == Some(true)
        || root.get("passwordProtected").and_then(Value::as_bool) == Some(true)
    {
        return Err(
            "encrypted Bitwarden exports are unsupported; export unencrypted JSON first".into(),
        );
    }
    let bitwarden = root.get("items").is_some();
    let values = root
        .get("items")
        .and_then(Value::as_array)
        .or_else(|| root.as_array())
        .ok_or_else(|| {
            "JSON import must be an array or a Bitwarden object with items".to_string()
        })?;
    if values.len() > MAX_IMPORT_ITEMS {
        return Err(format!(
            "import contains more than the {MAX_IMPORT_ITEMS} item limit"
        ));
    }
    let folders: HashMap<_, _> = root
        .get("folders")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|folder| Some((folder.get("id")?.as_str()?, folder.get("name")?.as_str()?)))
        .collect();
    let mut items = Vec::new();
    let mut losses = ImportLosses::default();
    for (position, value) in values.iter().enumerate() {
        let index = position + 1;
        let kind = if bitwarden {
            match value.get("type").and_then(Value::as_u64) {
                Some(1) => ItemKind::Login,
                Some(2) => ItemKind::SecureNote,
                Some(3) => ItemKind::PaymentCard,
                Some(4) => ItemKind::Identity,
                Some(5) => ItemKind::SshKey,
                _ => {
                    losses.unsupported += 1;
                    losses.warn(index, "unsupported item type; item was not imported");
                    continue;
                }
            }
        } else {
            match value.get("type").or_else(|| value.get("kind")) {
                None => ItemKind::Login,
                Some(kind) => match serde_json::from_value::<ItemKind>(kind.clone()) {
                    Ok(kind) => kind,
                    Err(_) => {
                        losses.unsupported += 1;
                        losses.warn(index, "unsupported item type; item was not imported");
                        continue;
                    }
                },
            }
        };
        let login = value.get("login").unwrap_or(value);
        let mut urls = Vec::new();
        if let Some(url) = json_text(value, &["url", "website"]) {
            urls.push(url);
        }
        for uri in login
            .get("uris")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(url) = json_text(uri, &["uri"]) {
                urls.push(url);
            }
            if uri.get("match").is_some_and(|m| !m.is_null()) {
                losses.warn(index, "URL match policy omitted; imported URLs use this application's origin matching");
            }
        }
        for url in value
            .get("additional_urls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(url) = url.as_str() {
                urls.push(url.to_owned());
            }
        }
        let mut seen = HashSet::new();
        urls.retain(|url| seen.insert(url.clone()));
        let name = json_text(value, &["name", "title"])
            .or_else(|| urls.first().cloned())
            .ok_or_else(|| format!("source item {index} in {path:?} has no name or URL"))?;
        let now = chrono::Local::now().to_string();
        let password = match kind {
            ItemKind::Login => raw(login, "password")
                .or_else(|| raw(value, "password"))
                .or_else(|| bitwarden.then(String::new))
                .ok_or_else(|| format!("source item {index} in {path:?} has no password"))?,
            ItemKind::SecureNote => raw(value, "password")
                .or_else(|| raw(value, "notes"))
                .or_else(|| raw(value, "note"))
                .unwrap_or_default(),
            ItemKind::PaymentCard => raw(value.get("card").unwrap_or(value), "number")
                .or_else(|| raw(value, "password"))
                .unwrap_or_default(),
            ItemKind::SshKey => raw(value.get("sshKey").unwrap_or(value), "privateKey")
                .or_else(|| raw(value, "password"))
                .unwrap_or_default(),
            _ => raw(value, "password").unwrap_or_default(),
        };
        let mut item = ImportedItem::login(VaultEntry {
            id: 0,
            name,
            username: json_text(login, &["username", "login"]).or_else(|| raw(value, "username")),
            password,
            url: urls.first().cloned(),
            notes: raw(value, "notes").or_else(|| raw(value, "note")),
            created: json_text(value, &["created", "creationDate"]).unwrap_or_else(|| now.clone()),
            modified: json_text(value, &["modified", "revisionDate"]).unwrap_or(now),
        });
        if kind == ItemKind::SecureNote && (bitwarden || raw(value, "password").is_none()) {
            // The note body is the primary secret, never searchable/listed notes.
            item.entry.notes = None;
        }
        // Rich external imports replace metadata just like portable imports.
        item.kind = kind;
        item.additional_urls = urls.into_iter().skip(1).collect();
        item.password_changed =
            raw(value, "password_changed").or_else(|| raw(login, "passwordRevisionDate"));
        if let Some(history) = value
            .get("passwordHistory")
            .or_else(|| value.get("password_history"))
            .and_then(Value::as_array)
        {
            for revision in history {
                if let Some(password) = raw(revision, "password") {
                    item.password_history.push(PortableRevision {
                        password,
                        changed: json_text(revision, &["changed", "lastUsedDate"])
                            .unwrap_or_else(|| item.entry.modified.clone()),
                    });
                } else {
                    losses.warn(index, "unsupported password history record omitted");
                }
            }
            // Bitwarden exports newest first; local history is oldest first.
            if value.get("passwordHistory").is_some() {
                item.password_history.reverse();
            }
        }
        totp(
            &mut item,
            raw(login, "totp").or_else(|| raw(value, "totp")),
            index,
            &mut losses,
        );
        for custom in value
            .get("fields")
            .or_else(|| value.get("custom_fields"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(name) = json_text(custom, &["name"]) else {
                losses.warn(index, "unnamed custom field omitted");
                continue;
            };
            let field_type = custom.get("type").and_then(Value::as_u64).unwrap_or(0);
            if field_type == 3 {
                losses.warn(
                    index,
                    "linked custom field omitted; linked-field behavior is unsupported",
                );
                continue;
            }
            if field_type > 3 {
                losses.warn(
                    index,
                    "unknown custom-field type retained as a secret field",
                );
            }
            let secret = custom
                .get("secret")
                .and_then(Value::as_bool)
                .unwrap_or(field_type == 1 || field_type > 3);
            let value = match custom.get("value") {
                None | Some(Value::Null) => String::new(),
                Some(Value::String(value)) => value.clone(),
                Some(value) => {
                    losses.warn(index, "non-text custom field retained as JSON text");
                    value.to_string()
                }
            };
            item.custom_fields.push(CustomField {
                name,
                value,
                secret,
            });
        }
        if kind == ItemKind::PaymentCard {
            let card = value.get("card").unwrap_or(value);
            item.entry.username = raw(card, "cardholderName").or(item.entry.username.take());
            for (key, label, secret) in [
                ("brand", "brand", false),
                ("expMonth", "expiration month", false),
                ("expYear", "expiration year", false),
                ("code", "cvv", true),
            ] {
                field(&mut item, label, raw(card, key), secret);
            }
        }
        if kind == ItemKind::Identity {
            let identity = value.get("identity").unwrap_or(value);
            item.entry.username = raw(identity, "email").or(item.entry.username.take());
            for (key, label, secret) in [
                ("title", "title", false),
                ("firstName", "first name", false),
                ("middleName", "middle name", false),
                ("lastName", "last name", false),
                ("address1", "address line 1", false),
                ("address2", "address line 2", false),
                ("address3", "address line 3", false),
                ("city", "city", false),
                ("state", "state", false),
                ("postalCode", "postal code", false),
                ("country", "country", false),
                ("company", "organization", false),
                ("email", "email", false),
                ("phone", "phone number", false),
                ("username", "username", false),
                ("ssn", "ssn", true),
                ("passportNumber", "passport number", true),
                ("licenseNumber", "license number", true),
            ] {
                field(&mut item, label, raw(identity, key), secret);
            }
        }
        if kind == ItemKind::SshKey {
            let key = value.get("sshKey").unwrap_or(value);
            field(&mut item, "public key", raw(key, "publicKey"), false);
            field(
                &mut item,
                "key fingerprint",
                raw(key, "keyFingerprint"),
                false,
            );
        }
        if let Some(folder_id) = value.get("folderId").and_then(Value::as_str) {
            if let Some(folder) = folders.get(folder_id) {
                field(&mut item, "folder", Some((*folder).into()), false);
            } else {
                losses.warn(index, "folder reference could not be resolved");
            }
        }
        if value.get("favorite").and_then(Value::as_bool) == Some(true) {
            field(&mut item, "favorite", Some("true".into()), false);
        }
        for (object, key, message) in [
            (
                login,
                "fido2Credentials",
                "passkeys omitted; passkey storage is unsupported",
            ),
            (
                value,
                "attachments",
                "attachments omitted; file attachments are unsupported",
            ),
            (value, "collectionIds", "collection membership omitted"),
        ] {
            if object
                .get(key)
                .and_then(Value::as_array)
                .is_some_and(|values| !values.is_empty())
            {
                losses.warn(index, message);
            }
        }
        if value
            .get("reprompt")
            .and_then(Value::as_u64)
            .is_some_and(|v| v != 0)
        {
            losses.warn(index, "per-item master-password reprompt policy omitted");
        }
        if value.get("organizationId").is_some_and(|v| !v.is_null()) {
            losses.warn(index, "organization ownership and access policies omitted");
        }
        // Preserve additional export data in an encrypted secret field instead
        // of silently dropping properties added by an exporter or provider.
        let known = [
            "id",
            "type",
            "kind",
            "name",
            "title",
            "username",
            "password",
            "url",
            "website",
            "notes",
            "note",
            "created",
            "creationDate",
            "modified",
            "revisionDate",
            "login",
            "card",
            "identity",
            "sshKey",
            "secureNote",
            "fields",
            "custom_fields",
            "additional_urls",
            "password_changed",
            "passwordHistory",
            "password_history",
            "totp",
            "folderId",
            "favorite",
            "reprompt",
            "organizationId",
            "collectionIds",
            "attachments",
        ];
        let mut extra = unknown_properties(value, &known);
        // Exporters can add data inside supported structures too. Preserve
        // unknown nested properties without exposing their values in reports.
        for (key, expected_kind, known) in [
            (
                "login",
                ItemKind::Login,
                &[
                    "username",
                    "password",
                    "totp",
                    "uris",
                    "passwordRevisionDate",
                    "fido2Credentials",
                ][..],
            ),
            (
                "card",
                ItemKind::PaymentCard,
                &[
                    "number",
                    "cardholderName",
                    "brand",
                    "expMonth",
                    "expYear",
                    "code",
                ][..],
            ),
            (
                "identity",
                ItemKind::Identity,
                &[
                    "title",
                    "firstName",
                    "middleName",
                    "lastName",
                    "address1",
                    "address2",
                    "address3",
                    "city",
                    "state",
                    "postalCode",
                    "country",
                    "company",
                    "email",
                    "phone",
                    "username",
                    "ssn",
                    "passportNumber",
                    "licenseNumber",
                ][..],
            ),
            (
                "sshKey",
                ItemKind::SshKey,
                &["privateKey", "publicKey", "keyFingerprint"][..],
            ),
            ("secureNote", ItemKind::SecureNote, &["type"][..]),
        ] {
            if let Some(nested) = value.get(key).filter(|value| !value.is_null()) {
                let unknown = unknown_properties(nested, known);
                if kind != expected_kind || !nested.is_object() {
                    extra.insert(key.into(), nested.clone());
                } else if !unknown.is_empty() {
                    extra.insert(key.into(), Value::Object(unknown));
                }
            }
        }
        for (key, records, known) in [
            ("uris", login.get("uris"), &["uri", "match"][..]),
            (
                "fields",
                value.get("fields").or_else(|| value.get("custom_fields")),
                &["name", "value", "type", "secret", "linkedId"][..],
            ),
            (
                "password_history",
                value
                    .get("passwordHistory")
                    .or_else(|| value.get("password_history")),
                &["password", "changed", "lastUsedDate"][..],
            ),
        ] {
            if let Some(records) = records.and_then(Value::as_array) {
                let unknown: Vec<_> = records
                    .iter()
                    .enumerate()
                    .filter_map(|(position, record)| {
                        let properties = unknown_properties(record, known);
                        (!properties.is_empty())
                            .then(|| json!({ "position": position + 1, "properties": properties }))
                    })
                    .collect();
                if !unknown.is_empty() {
                    extra.insert(key.into(), Value::Array(unknown));
                }
            }
        }
        if !extra.is_empty() {
            field(
                &mut item,
                "imported extra data",
                Some(Value::Object(extra).to_string()),
                true,
            );
            losses.warn(index, "additional JSON properties retained as a secret field; their behavior is unsupported");
        }
        let mut field_names = HashSet::new();
        for field in &mut item.custom_fields {
            if !field_names.insert(field.name.to_lowercase()) {
                let base = field.name.clone();
                let mut suffix = 2;
                loop {
                    let name = format!("{base} (imported {suffix})");
                    if field_names.insert(name.to_lowercase()) {
                        field.name = name;
                        break;
                    }
                    suffix += 1;
                }
                losses.warn(
                    index,
                    "duplicate custom field renamed to preserve both values",
                );
            }
        }
        item.portable = bitwarden
            || value.get("type").is_some()
            || value.get("kind").is_some()
            || !item.additional_urls.is_empty()
            || !item.custom_fields.is_empty()
            || item.password_changed.is_some()
            || !item.password_history.is_empty()
            || item.totp.is_some();
        losses.source_positions.push(index);
        items.push(item);
    }
    if items.is_empty() && losses.unsupported == 0 {
        return Err(format!("no supported entries were found in {path:?}"));
    }
    Ok((items, losses))
}

pub(super) fn csv_with_losses(
    contents: &str,
    path: &str,
) -> Result<(Vec<ImportedItem>, ImportLosses), String> {
    let mut reader = csv::Reader::from_reader(contents.as_bytes());
    let source_headers = reader
        .headers()
        .map_err(|e| format!("invalid CSV headers in {path:?}: {e}"))?
        .clone();
    let headers: Vec<_> = reader
        .headers()
        .map_err(|e| format!("invalid CSV headers in {path:?}: {e}"))?
        .iter()
        .map(normalized_header)
        .collect();
    let mut items = Vec::new();
    let mut losses = ImportLosses::default();
    for (position, row) in reader.records().enumerate() {
        let index = position + 1;
        if index > MAX_IMPORT_ITEMS {
            return Err(format!(
                "import contains more than the {MAX_IMPORT_ITEMS} item limit"
            ));
        }
        let row = row.map_err(|e| format!("invalid CSV data in {path:?}: {e}"))?;
        let kind = match csv_field(&headers, &row, &["type", "kind"]).as_deref() {
            None | Some("login") | Some("1") => ItemKind::Login,
            Some("note") | Some("secure-note") | Some("2") => ItemKind::SecureNote,
            Some("card") | Some("payment-card") | Some("3") => ItemKind::PaymentCard,
            Some("identity") | Some("4") => ItemKind::Identity,
            Some("ssh-key") | Some("5") => ItemKind::SshKey,
            Some("wifi") => ItemKind::Wifi,
            Some("software-license") => ItemKind::SoftwareLicense,
            Some("api-secret") => ItemKind::ApiSecret,
            Some(_) => {
                losses.unsupported += 1;
                losses.warn(index, "unsupported item type; row was not imported");
                continue;
            }
        };
        let name = csv_field(&headers, &row, &["name", "title"])
            .or_else(|| csv_field(&headers, &row, &["url", "website", "loginuri"]))
            .ok_or_else(|| format!("source item {index} in {path:?} has no name or URL"))?;
        let primary_aliases: &[&str] = match kind {
            ItemKind::PaymentCard => &["password", "loginpassword", "number", "cardnumber"],
            ItemKind::SshKey => &["password", "loginpassword", "privatekey"],
            _ => &["password", "loginpassword"],
        };
        let note = headers
            .iter()
            .position(|h| ["notes", "note", "extra", "comments"].contains(&h.as_str()))
            .and_then(|i| row.get(i))
            .filter(|note| !note.is_empty())
            .map(str::to_owned);
        let mut password = headers
            .iter()
            .position(|h| primary_aliases.contains(&h.as_str()))
            .and_then(|i| row.get(i))
            .map(str::to_owned)
            .or_else(|| (kind == ItemKind::SecureNote).then(|| note.clone().unwrap_or_default()))
            .or_else(|| (kind == ItemKind::Identity).then(String::new))
            .ok_or_else(|| format!("source item {index} in {path:?} has no password"))?;
        if kind == ItemKind::SecureNote && password.is_empty() {
            password = note.clone().unwrap_or_default();
        }
        let now = chrono::Local::now().to_string();
        let mut item = ImportedItem::login(VaultEntry {
            id: 0,
            name,
            password,
            username: csv_field(&headers, &row, &["username", "loginusername", "login"]),
            url: csv_field(
                &headers,
                &row,
                &["url", "website", "loginuri", "formactionorigin"],
            ),
            notes: note,
            created: csv_field(&headers, &row, &["created", "timecreated"])
                .unwrap_or_else(|| now.clone()),
            modified: csv_field(
                &headers,
                &row,
                &["modified", "timemodified", "timepasswordchanged"],
            )
            .unwrap_or(now),
        });
        item.kind = kind;
        if kind == ItemKind::SecureNote
            && let Some(notes) = item
                .entry
                .notes
                .take()
                .filter(|notes| !notes.is_empty() && notes != &item.entry.password)
        {
            field(&mut item, "imported note", Some(notes), true);
        }
        totp(
            &mut item,
            csv_field(&headers, &row, &["totp", "logintotp"]),
            index,
            &mut losses,
        );
        for (column, header) in headers.iter().enumerate() {
            if [
                "id",
                "name",
                "title",
                "password",
                "loginpassword",
                "username",
                "loginusername",
                "login",
                "url",
                "website",
                "loginuri",
                "formactionorigin",
                "notes",
                "note",
                "extra",
                "comments",
                "created",
                "timecreated",
                "modified",
                "timemodified",
                "timepasswordchanged",
                "type",
                "kind",
                "totp",
                "logintotp",
            ]
            .contains(&header.as_str())
                || primary_aliases.contains(&header.as_str())
            {
                continue;
            }
            if let Some(value) = row.get(column).filter(|v| !v.is_empty()) {
                // Unknown columns can contain arbitrary secrets. Retain them in
                // encrypted secret fields rather than expose or discard them.
                field(
                    &mut item,
                    &format!("CSV {}", source_headers.get(column).unwrap_or("field")),
                    Some(value.into()),
                    true,
                );
                losses.warn(index, "additional CSV column retained as a secret field; column-specific behavior is unavailable");
            }
        }
        item.portable =
            kind != ItemKind::Login || !item.custom_fields.is_empty() || item.totp.is_some();
        losses.source_positions.push(index);
        items.push(item);
    }
    Ok((items, losses))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitwarden_preserves_all_supported_types_and_reports_unsupported_data_without_secrets() {
        let document = json!({ "encrypted": false, "folders": [{ "id": "folder", "name": "Work" }], "items": [
            { "type": 1, "name": "Account", "folderId": "folder", "favorite": true,
                "fields": [{ "name": "token", "value": "synthetic-token", "type": 1 }],
                "login": { "username": "alice", "password": " padded-password ", "totp": "JBSWY3DPEHPK3PXP",
                    "uris": [{ "uri": "https://one.example" }, { "uri": "https://two.example", "match": 1 }],
                    "fido2Credentials": [{ "keyValue": "synthetic-passkey" }] },
                "passwordHistory": [{ "password": "newer", "lastUsedDate": "2025-02-01" }, { "password": "older", "lastUsedDate": "2025-01-01" }] },
            { "type": 2, "name": "Note", "notes": "synthetic-note" },
            { "type": 3, "name": "Card", "card": { "number": "synthetic-number", "cardholderName": "Alice", "expMonth": "09", "expYear": "2030", "code": "synthetic-cvv" } },
            { "type": 4, "name": "Identity", "identity": { "email": "alice@example.com", "firstName": "Alice", "address1": "Example St", "ssn": "synthetic-ssn" } },
            { "type": 5, "name": "SSH", "sshKey": { "privateKey": "synthetic-private-key", "publicKey": "public-key", "keyFingerprint": "fingerprint" }, "attachments": [{ "id": "attachment" }] },
            { "type": 999, "name": "Future", "password": "synthetic-future-secret" }
        ] });
        let (items, losses) = external_json(document, "synthetic.json").unwrap();
        assert_eq!(items.len(), 5);
        assert_eq!(losses.unsupported, 1);
        assert_eq!(items[0].entry.password, " padded-password ");
        assert_eq!(items[0].additional_urls, ["https://two.example"]);
        assert!(items[0].totp.is_some());
        assert_eq!(items[0].password_history[0].password, "older");
        assert!(
            items[0]
                .custom_fields
                .iter()
                .any(|f| f.name == "folder" && f.value == "Work")
        );
        assert!(
            items[0]
                .custom_fields
                .iter()
                .any(|f| f.name == "token" && f.secret)
        );
        assert_eq!(items[1].entry.password, "synthetic-note");
        assert!(
            items[1].entry.notes.is_none(),
            "note bodies must not appear in ordinary listings"
        );
        assert_eq!(items[2].entry.password, "synthetic-number");
        assert!(
            items[2]
                .custom_fields
                .iter()
                .any(|f| f.name == "cvv" && f.secret)
        );
        assert!(
            items[3]
                .custom_fields
                .iter()
                .any(|f| f.name == "ssn" && f.secret)
        );
        assert_eq!(items[4].entry.password, "synthetic-private-key");
        let report = losses.messages.join("\n");
        assert!(report.contains("passkeys"));
        assert!(report.contains("attachments"));
        assert!(!report.contains("synthetic-"));
        assert!(!report.contains("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn unsupported_authenticators_and_extra_columns_are_retained_without_echoing_values() {
        let (items, losses) = external_json(json!([{ "name": "Account", "password": "secret", "totp": "steam://synthetic-seed", "newFeature": "synthetic-extra" }]), "synthetic.json").unwrap();
        assert!(items[0].totp.is_none());
        assert_eq!(items[0].custom_fields.len(), 2);
        assert!(items[0].custom_fields.iter().all(|f| f.secret));
        assert_eq!(losses.count, 2);
        assert!(!losses.messages.join("\n").contains("synthetic"));
        let (items, losses) = csv_with_losses("name,login_username,login_password,login_totp,api_token\nAccount,alice, padded ,JBSWY3DPEHPK3PXP,synthetic-token\n", "synthetic.csv").unwrap();
        assert_eq!(items[0].entry.password, " padded ");
        assert!(items[0].totp.is_some());
        assert_eq!(items[0].custom_fields[0].name, "CSV api_token");
        assert!(items[0].custom_fields[0].secret);
        assert_eq!(losses.count, 1);
        assert!(!losses.messages[0].contains("synthetic-token"));
    }

    #[test]
    fn encrypted_exports_are_rejected_and_loss_output_is_bounded() {
        assert!(
            external_json(json!({ "encrypted": true, "items": [] }), "synthetic.json").is_err()
        );
        let (items, losses) = external_json(
            json!({ "items": (0..150).map(|_| json!({ "type": 999 })).collect::<Vec<_>>() }),
            "synthetic.json",
        )
        .unwrap();
        assert!(items.is_empty());
        assert_eq!(losses.unsupported, 150);
        assert_eq!(losses.count, 150);
        assert_eq!(losses.messages.len(), 100);
    }

    #[test]
    fn nested_export_extensions_and_boolean_fields_are_preserved() {
        let (items, losses) = external_json(json!({ "items": [{
            "type": 1, "name": "Account",
            "login": { "password": "secret", "futureSecret": "synthetic-nested",
                "uris": [{ "uri": "https://example.com", "futurePolicy": "synthetic-policy" }] },
            "fields": [{ "name": "enabled", "type": 2, "value": false, "futureFlag": "synthetic-flag" }]
        }] }), "synthetic.json").unwrap();
        assert_eq!(items[0].custom_fields[0].value, "false");
        let extra = items[0]
            .custom_fields
            .iter()
            .find(|field| field.name == "imported extra data")
            .unwrap();
        assert!(extra.secret);
        let data: Value = serde_json::from_str(&extra.value).unwrap();
        assert_eq!(data["login"]["futureSecret"], "synthetic-nested");
        assert_eq!(
            data["uris"][0]["properties"]["futurePolicy"],
            "synthetic-policy"
        );
        assert_eq!(
            data["fields"][0]["properties"]["futureFlag"],
            "synthetic-flag"
        );
        assert_eq!(losses.count, 2);
        assert!(!losses.messages.join("\n").contains("synthetic"));
    }

    #[test]
    fn typed_csv_preserves_multiline_notes_and_card_or_key_secrets() {
        let (items, _) = csv_with_losses("name,type,notes,password\nNote,secure-note,\"  first\nsecond  \",\nSeparate,secure-note,additional note,primary secret\n", "synthetic.csv").unwrap();
        assert_eq!(items[0].entry.password, "  first\nsecond  ");
        assert!(items[0].entry.notes.is_none());
        assert_eq!(items[1].entry.password, "primary secret");
        assert_eq!(items[1].custom_fields[0].value, "additional note");
        assert!(items[1].custom_fields[0].secret);
        let (items, losses) = csv_with_losses(
            "name,type,number,cvv\nCard,payment-card,synthetic-number,synthetic-code\n",
            "synthetic.csv",
        )
        .unwrap();
        assert_eq!(items[0].entry.password, "synthetic-number");
        assert_eq!(items[0].kind, ItemKind::PaymentCard);
        assert_eq!(losses.count, 1);
        assert_eq!(items[0].custom_fields[0].value, "synthetic-code");
        let (items, _) = csv_with_losses(
            "name,type,private_key\nKey,ssh-key,\"line one\nline two\"\n",
            "synthetic.csv",
        )
        .unwrap();
        assert_eq!(items[0].entry.password, "line one\nline two");
    }
}
