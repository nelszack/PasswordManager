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

struct Site {
    scheme: String,
    host: String,
    port: u16,
    wildcard: bool,
}

fn parse_site(value: &str, allow_wildcard: bool) -> Option<Site> {
    // URL parsers normalize backslashes and strip some controls. Reject them
    // rather than silently changing the meaning of a saved site identity.
    if value.chars().any(|c| c.is_control() || c == '\\') {
        return None;
    }
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (scheme, remainder) = value.split_once("://").unwrap_or(("https", value));
    let wildcard = remainder.starts_with("*.");
    if wildcard && !allow_wildcard {
        return None;
    }
    let remainder = if wildcard { &remainder[2..] } else { remainder };
    let parsed = url::Url::parse(&format!("{scheme}://{remainder}")).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return None;
    }
    let host = parsed.host_str()?.trim_end_matches('.').to_string();
    if host.is_empty() || host.contains('*') {
        return None;
    }
    if wildcard
        && (!matches!(parsed.host(), Some(url::Host::Domain(_)))
            || psl::domain_str(&host) != Some(host.as_str()))
    {
        return None;
    }
    Some(Site {
        scheme: parsed.scheme().to_string(),
        host,
        port: parsed.port_or_known_default()?,
        wildcard,
    })
}

pub(super) fn hostname(value: &str) -> Option<String> {
    let site = parse_site(value, true)?;
    Some(if site.wildcard {
        format!("*.{}", site.host)
    } else {
        site.host
    })
}

pub(super) fn hosts_match(saved_url: &str, requested_url: &str) -> bool {
    let (Some(saved), Some(requested)) = (
        parse_site(saved_url, true),
        parse_site(requested_url, false),
    ) else {
        return false;
    };
    if saved.scheme != requested.scheme || saved.port != requested.port {
        return false;
    }
    if saved.wildcard {
        return requested.host != saved.host
            && requested.host.ends_with(&format!(".{}", saved.host));
    }
    saved.host == requested.host
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
