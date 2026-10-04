use super::*;

impl Vault {
    pub(crate) fn browser_logins_json(&self, domain: &str) -> String {
        let metadata_by_id: HashMap<_, _> = self
            .recovery
            .entry_metadata
            .iter()
            .map(|record| (record.entry_id, record))
            .collect();
        let totp_ids: HashSet<_> = self
            .recovery
            .totp
            .iter()
            .map(|record| record.entry_id)
            .collect();
        let items = self
            .entries
            .iter()
            .filter(|entry| {
                login_matches_site(entry, metadata_by_id.get(&entry.id).copied(), domain)
            })
            .map(|entry| {
                json!({
                    "id": entry.id,
                    "name": entry.name,
                    "username": entry.username,
                    "has_totp": totp_ids.contains(&entry.id),
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_string(&items).expect("login summaries are serializable")
    }

    pub(crate) fn browser_login_json(&self, domain: &str, id: usize) -> Option<String> {
        let entry = self.entries.iter().find(|entry| entry.id == id)?;
        let metadata = self
            .recovery
            .entry_metadata
            .iter()
            .find(|record| record.entry_id == id);
        if !login_matches_site(entry, metadata, domain) {
            return None;
        }
        Some(
            serde_json::to_string(&BrowserLogin {
                id: entry.id,
                name: &entry.name,
                username: entry.username.as_deref(),
                password: &entry.password,
                has_totp: self
                    .recovery
                    .totp
                    .iter()
                    .any(|record| record.entry_id == id),
            })
            .expect("browser login is serializable"),
        )
    }

    pub(crate) fn browser_autofill_json(&self) -> String {
        let metadata_by_id: HashMap<_, _> = self
            .recovery
            .entry_metadata
            .iter()
            .map(|record| (record.entry_id, record))
            .collect();
        let items = self
            .entries
            .iter()
            .filter_map(|entry| {
                let kind = metadata_by_id
                    .get(&entry.id)
                    .map_or(ItemKind::Login, |metadata| metadata.kind);
                matches!(kind, ItemKind::PaymentCard | ItemKind::Identity).then(|| {
                    json!({
                        "id": entry.id,
                        "name": entry.name,
                        "kind": kind,
                        "username": entry.username,
                    })
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_string(&items).expect("browser autofill items are serializable")
    }

    pub(crate) fn browser_autofill_item_json(&self, id: usize) -> Option<String> {
        let entry = self.entries.iter().find(|entry| entry.id == id)?;
        let kind = self.item_kind(entry.id);
        if !matches!(kind, ItemKind::PaymentCard | ItemKind::Identity) {
            return None;
        }
        Some(
            serde_json::to_string(&AutofillItem {
                id: entry.id,
                name: &entry.name,
                kind,
                username: entry.username.as_deref(),
                primary_secret: &entry.password,
                custom_fields: self.custom_fields(entry.id),
            })
            .expect("autofill item is serializable"),
        )
    }
}

pub(super) fn url_match_json(
    entries: &[VaultEntry],
    totp_records: &[TotpRecord],
    metadata: &[EntryMetadata],
    url: &str,
) -> Option<String> {
    let metadata_by_id: HashMap<_, _> = metadata
        .iter()
        .map(|record| (record.entry_id, record))
        .collect();
    let totp_ids: HashSet<_> = totp_records.iter().map(|record| record.entry_id).collect();
    let mut results = Vec::new();
    for e in entries {
        let item_metadata = metadata_by_id.get(&e.id).copied();
        if item_metadata.is_some_and(|record| record.kind != ItemKind::Login) {
            continue;
        }
        let matches = login_matches_site(e, item_metadata, url);
        if matches {
            results.push(BrowserLogin {
                id: e.id,
                username: Some(e.username.as_deref().unwrap_or("None")),
                password: &e.password,
                name: &e.name,
                has_totp: totp_ids.contains(&e.id),
            });
        }
    }
    if results.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&results).expect("matching logins are serializable"))
    }
}

pub(super) fn login_matches_site(
    entry: &VaultEntry,
    metadata: Option<&EntryMetadata>,
    domain: &str,
) -> bool {
    metadata.is_none_or(|record| record.kind == ItemKind::Login)
        && (entry
            .url
            .as_deref()
            .is_some_and(|saved| hosts_match(saved, domain))
            || metadata.is_some_and(|record| {
                record
                    .additional_urls
                    .iter()
                    .any(|saved| hosts_match(saved, domain))
            }))
}

pub(super) fn hostname(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let authority = value
        .split_once("://")
        .map_or(value, |(_, remainder)| remainder)
        .split(['/', '?', '#'])
        .next()?;
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if host_port.starts_with('[') {
        host_port
            .split_once(']')
            .map_or(host_port, |(host, _)| host)
    } else {
        host_port
            .split_once(':')
            .map_or(host_port, |(host, _)| host)
    };
    let host = host.trim_matches(['[', ']']).trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

pub(super) fn url_scheme(value: &str) -> Option<&str> {
    let (scheme, _) = value.trim().split_once("://")?;
    (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")).then_some(scheme)
}

pub(super) fn hosts_match(saved_url: &str, requested_url: &str) -> bool {
    let (Some(saved), Some(requested)) = (hostname(saved_url), hostname(requested_url)) else {
        return false;
    };
    if url_scheme(requested_url).is_some_and(|scheme| scheme.eq_ignore_ascii_case("http"))
        && !url_scheme(saved_url).is_some_and(|scheme| scheme.eq_ignore_ascii_case("http"))
    {
        return false;
    }
    if let Some(base) = saved.strip_prefix("*.") {
        // Wildcards must be rooted at a registrable domain, never a public
        // suffix such as "com", "co.uk", or "github.io".
        return psl::domain_str(base) == Some(base)
            && requested != base
            && requested.ends_with(&format!(".{base}"));
    }
    saved == requested
}

// Borrow secrets during serialization instead of creating plaintext copies in JSON values.
#[derive(Serialize)]
struct BrowserLogin<'a> {
    id: usize,
    name: &'a str,
    username: Option<&'a str>,
    password: &'a str,
    has_totp: bool,
}
#[derive(Serialize)]
struct AutofillItem<'a> {
    id: usize,
    name: &'a str,
    kind: ItemKind,
    username: Option<&'a str>,
    primary_secret: &'a str,
    custom_fields: &'a [CustomField],
}
