use super::*;
impl Vault {
    pub(super) fn apply_list_options<'a>(
        &'a self,
        mut items: Vec<&'a Item>,
        options: &ListOptions,
    ) -> Vec<&'a Item> {
        let now = crate::clock::now();
        items.retain(|item| {
            options.kind.is_none_or(|kind| item.metadata.kind == kind)
                && options
                    .has_totp
                    .is_none_or(|expected| item.authenticator.is_some() == expected)
                && (!options.weak
                    || (!item.entry.password.is_empty()
                        && item.password_score() <= zxcvbn::Score::Two))
                && options
                    .stale_days
                    .is_none_or(|days| password_is_stale_at(item.password_changed(), days, now))
        });
        match options.sort {
            SortField::Name => {
                items.sort_by(|a, b| a.search_metadata().name.cmp(&b.search_metadata().name));
            }
            // Search traverses the ID-ordered item map and retain preserves order.
            SortField::Id => {}
            _ => items.sort_by_cached_key(|item| {
                crate::clock::parse(match options.sort {
                    SortField::Created => &item.entry.created,
                    SortField::Modified => &item.entry.modified,
                    _ => item.password_changed(),
                })
            }),
        }
        if options.descending {
            items.reverse();
        }
        items
    }
    pub(super) fn search_items(&self, filter: &SearchFilter) -> Vec<&Item> {
        let lower = |value: Option<&str>| value.map(|v| Zeroizing::new(v.to_lowercase()));
        let query = lower(filter.query.as_deref());
        let name = lower(filter.name.as_deref());
        let username = lower(filter.username.as_deref());
        let url = lower(filter.url.as_deref());
        let notes = lower(filter.notes.as_ref().map(SecretString::expose));
        // An unfiltered list needs neither an index nor copies of metadata.
        let metadata_needed =
            query.is_some() || name.is_some() || username.is_some() || url.is_some();
        self.active_items()
            .filter(|item| {
                let metadata = metadata_needed.then(|| item.search_metadata());
                let contains = |value: Option<&str>, needle: &Option<Zeroizing<String>>| {
                    needle
                        .as_ref()
                        .is_none_or(|n| value.is_some_and(|v| v.contains(n.as_str())))
                };
                let normalized_notes = std::cell::OnceCell::new();
                let notes_match = |needle: &str| {
                    normalized_notes
                        .get_or_init(|| lower(item.entry.notes.as_ref().map(SecretString::expose)))
                        .as_ref()
                        .is_some_and(|value| value.contains(needle))
                };
                metadata.is_none_or(|m| {
                    query.as_ref().is_none_or(|q| {
                        m.name.contains(q.as_str())
                            || m.username.as_ref().is_some_and(|v| v.contains(q.as_str()))
                            || m.urls.iter().any(|v| v.contains(q.as_str()))
                            || notes_match(q)
                            || m.fields.iter().any(|(name, value)| {
                                name.contains(q.as_str())
                                    || value.as_ref().is_some_and(|v| v.contains(q.as_str()))
                            })
                    }) && contains(Some(&m.name), &name)
                        && contains(m.username.as_deref().map(String::as_str), &username)
                        && url
                            .as_ref()
                            .is_none_or(|q| m.urls.iter().any(|v| v.contains(q.as_str())))
                }) && notes.as_ref().is_none_or(|q| notes_match(q))
            })
            .collect()
    }
    pub fn get_secret(&self, target: &Target) -> Result<Zeroizing<String>, VaultError> {
        Ok(Zeroizing::new(
            self.require_target(target)?
                .entry
                .password
                .expose()
                .to_owned(),
        ))
    }
    pub fn get_custom_field(
        &self,
        target: &Target,
        name: &str,
    ) -> Result<Zeroizing<String>, VaultError> {
        self.require_target(target)?
            .metadata
            .custom_fields
            .iter()
            .filter(|f| !item_rules::is_reserved_field(&f.name))
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .map(|f| Zeroizing::new(f.value.expose().to_owned()))
            .ok_or_else(|| VaultError::NotFound("custom field not found".into()))
    }
    pub fn target_revision(&self, target: &Target) -> Option<u64> {
        self.target_item(target).map(|item| item.revision)
    }
}

// Only normalized metadata is retained. Notes and secret field values are never
// indexed; even the metadata index is wiped when an item changes or locks.
#[derive(Default)]
pub(super) struct CachedSearch(pub std::sync::OnceLock<SearchMetadata>);
// Staged mutations don't need copies of the normalized index they invalidate.
impl Clone for CachedSearch {
    fn clone(&self) -> Self {
        Self::default()
    }
}
impl std::fmt::Debug for CachedSearch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CachedSearch(<redacted>)")
    }
}
impl PartialEq for CachedSearch {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
#[derive(Clone)]
pub(super) struct SearchMetadata {
    pub(super) name: Zeroizing<String>,
    username: Option<Zeroizing<String>>,
    urls: Vec<Zeroizing<String>>,
    fields: Vec<(Zeroizing<String>, Option<Zeroizing<String>>)>,
}
impl Item {
    /// Lowercased searchable fields, computed once until the item changes.
    pub(super) fn search_metadata(&self) -> &SearchMetadata {
        self.search.0.get_or_init(|| SearchMetadata::new(self))
    }
}
impl SearchMetadata {
    fn new(item: &Item) -> Self {
        let lower = |v: &str| Zeroizing::new(v.to_lowercase());
        Self {
            name: lower(&item.entry.name),
            username: item.entry.username.as_deref().map(lower),
            urls: item.urls().map(lower).collect(),
            fields: item
                .metadata
                .custom_fields
                .iter()
                .map(|f| (lower(&f.name), (!f.secret).then(|| lower(&f.value))))
                .collect(),
        }
    }
}
