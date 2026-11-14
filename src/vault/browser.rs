use super::*;
impl Vault {
    pub fn browser_duo_items(&self, origin: &str) -> Vec<ItemSummary> {
        let Ok(url) = url::Url::parse(origin) else {
            return vec![];
        };
        let Some(host) = url.host_str() else {
            return vec![];
        };
        if url.scheme() != "https"
            || url.port_or_known_default() != Some(443)
            || !url.username().is_empty()
            || url.password().is_some()
            || !crate::duo::valid_host(host, "api-")
        {
            return vec![];
        }
        self.active_items()
            .filter(|i| {
                i.duo
                    .as_ref()
                    .is_some_and(|d| d.credentials.host.eq_ignore_ascii_case(host))
            })
            .map(|i| self.summary(i))
            .collect()
    }
    pub fn browser_logins(&self, domain: &str) -> Vec<ItemSummary> {
        let Some(requested) = parse_site(domain, false) else {
            return vec![];
        };
        self.active_items()
            .filter(|i| item_matches_site(i, &requested))
            .map(|i| self.summary(i))
            .collect()
    }
    pub(crate) fn browser_login_revision(&self, origin: &str, id: usize) -> Option<u64> {
        let requested = parse_site(origin, false)?;
        let item = self.item(id).filter(|item| item.active())?;
        item_matches_site(item, &requested).then_some(item.revision)
    }
    pub fn browser_login(&self, domain: &str, id: usize) -> Option<BrowserLogin> {
        let requested = parse_site(domain, false)?;
        let item = self.item(id).filter(|i| i.active())?;
        if !item_matches_site(item, &requested) {
            return None;
        }
        Some(BrowserLogin {
            id,
            revision: item.revision,
            name: item.entry.name.clone(),
            username: item.entry.username.clone(),
            password: item.entry.password.clone(),
            has_totp: item.authenticator.is_some(),
        })
    }
    pub fn browser_autofill(&self) -> Vec<ItemSummary> {
        self.active_items()
            .filter(|i| matches!(i.metadata.kind, ItemKind::PaymentCard | ItemKind::Identity))
            .map(|i| self.summary(i))
            .collect()
    }
    pub fn browser_autofill_item(&self, id: usize) -> Option<AutofillItem> {
        let item = self.item(id).filter(|i| {
            i.active() && matches!(i.metadata.kind, ItemKind::PaymentCard | ItemKind::Identity)
        })?;
        Some(AutofillItem {
            id,
            revision: item.revision,
            name: item.entry.name.clone(),
            kind: item.metadata.kind,
            username: item.entry.username.clone(),
            primary_secret: item.entry.password.clone(),
            custom_fields: item.metadata.custom_fields.clone(),
        })
    }
}
// Normalized sites contain metadata only and are erased with the item/session.
#[derive(Debug, Default, Clone)]
pub(super) struct CachedSites(std::sync::Arc<std::sync::OnceLock<Vec<Site>>>);
impl PartialEq for CachedSites {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
fn item_matches_site(item: &Item, requested: &Site) -> bool {
    item.metadata.kind == ItemKind::Login
        && item
            .sites
            .0
            .get_or_init(|| {
                item.entry
                    .url
                    .as_deref()
                    .into_iter()
                    .chain(item.metadata.additional_urls.iter().map(String::as_str))
                    .filter_map(|value| parse_site(value, true))
                    .collect()
            })
            .iter()
            .any(|saved| site_matches(saved, requested))
}

#[derive(Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
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
        site.host.clone()
    })
}

#[cfg(test)]
pub(super) fn hosts_match(saved_url: &str, requested_url: &str) -> bool {
    parse_site(requested_url, false)
        .is_some_and(|requested| saved_matches_site(saved_url, &requested))
}

#[cfg(test)]
fn saved_matches_site(saved_url: &str, requested: &Site) -> bool {
    let Some(saved) = parse_site(saved_url, true) else {
        return false;
    };
    site_matches(&saved, requested)
}

fn site_matches(saved: &Site, requested: &Site) -> bool {
    if saved.scheme != requested.scheme || saved.port != requested.port {
        return false;
    }
    if saved.wildcard {
        return requested.host != saved.host
            && requested
                .host
                .strip_suffix(saved.host.as_str())
                .is_some_and(|prefix| prefix.ends_with('.'));
    }
    saved.host == requested.host
}
