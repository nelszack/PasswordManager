use super::*;
impl Vault {
    fn is_weak(&self, entry: &VaultEntry) -> bool {
        !entry.password.is_empty()
            && self.item(entry.id).unwrap().password_score() <= zxcvbn::Score::Two
    }
    fn password_changed<'a>(&'a self, entry: &'a VaultEntry) -> &'a str {
        self.metadata(entry.id)
            .and_then(|m| m.password_changed.as_ref())
            .map_or(entry.created.as_str(), Timestamp::as_str)
    }
    pub(super) fn password_changed_with_metadata<'a>(
        &'a self,
        entry: &'a VaultEntry,
        metadata: Option<&'a EntryMetadata>,
    ) -> &'a str {
        metadata
            .and_then(|m| m.password_changed.as_ref())
            .map_or(entry.created.as_str(), Timestamp::as_str)
    }
    pub(super) fn apply_list_options<'a>(
        &'a self,
        mut entries: Vec<&'a VaultEntry>,
        options: &ListOptions,
    ) -> Vec<&'a VaultEntry> {
        let now = chrono::Utc::now();
        entries.retain(|e| {
            options.kind.is_none_or(|k| self.item_kind(e.id) == k)
                && options.has_totp.is_none_or(|expected| {
                    self.item(e.id).unwrap().authenticator.is_some() == expected
                })
                && (!options.weak || self.is_weak(e))
                && options
                    .stale_days
                    .is_none_or(|days| password_is_stale_at(self.password_changed(e), days, now))
        });
        match options.sort {
            SortField::Name => entries.sort_by_cached_key(|e| e.name.to_lowercase()),
            // Search traverses the ID-ordered item map and retain preserves order.
            SortField::Id => {}
            _ => entries.sort_by_cached_key(|e| {
                parse_entry_timestamp(match options.sort {
                    SortField::Created => &e.created,
                    SortField::Modified => &e.modified,
                    _ => self.password_changed(e),
                })
            }),
        }
        if options.descending {
            entries.reverse();
        }
        entries
    }
    pub(super) fn search_entries(&self, filter: &SearchFilter) -> Vec<&VaultEntry> {
        let lower =
            |value: &Option<String>| value.as_ref().map(|v| Zeroizing::new(v.to_lowercase()));
        let query = lower(&filter.query);
        let name = lower(&filter.name);
        let username = lower(&filter.username);
        let url = lower(&filter.url);
        let notes = filter
            .notes
            .as_ref()
            .map(|v| Zeroizing::new(v.to_lowercase()));
        // An unfiltered list needs neither an index nor copies of metadata.
        let metadata_needed =
            query.is_some() || name.is_some() || username.is_some() || url.is_some();
        self.active_items()
            .filter(|item| {
                let metadata = metadata_needed
                    .then(|| item.search.0.get_or_init(|| SearchMetadata::new(item)));
                let contains = |value: Option<&str>, needle: &Option<Zeroizing<String>>| {
                    needle
                        .as_ref()
                        .is_none_or(|n| value.is_some_and(|v| v.contains(n.as_str())))
                };
                let normalized_notes = std::cell::OnceCell::new();
                let notes_match = |needle: &str| {
                    normalized_notes
                        .get_or_init(|| {
                            item.entry
                                .notes
                                .as_ref()
                                .map(|value| Zeroizing::new(value.to_lowercase()))
                        })
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
            .map(|item| &item.entry)
            .collect()
    }
    pub fn get_secret(&self, target: &Target) -> Result<Zeroizing<String>, VaultError> {
        let id = self
            .entry_id(target)
            .ok_or_else(|| VaultError::NotFound("entry not found".into()))?;
        Ok(Zeroizing::new(
            self.item(id).unwrap().entry.password.expose().to_owned(),
        ))
    }
    pub fn get_custom_field(
        &self,
        target: &Target,
        name: &str,
    ) -> Result<Zeroizing<String>, VaultError> {
        let id = self
            .entry_id(target)
            .ok_or_else(|| VaultError::NotFound("entry not found".into()))?;
        self.custom_fields(id)
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .map(|f| Zeroizing::new(f.value.expose().to_owned()))
            .ok_or_else(|| VaultError::NotFound("custom field not found".into()))
    }
    pub fn target_revision(&self, target: &Target) -> Option<u64> {
        self.entry_id(target).and_then(|id| self.revision(id))
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
    name: Zeroizing<String>,
    username: Option<Zeroizing<String>>,
    urls: Vec<Zeroizing<String>>,
    fields: Vec<(Zeroizing<String>, Option<Zeroizing<String>>)>,
}
impl SearchMetadata {
    fn new(item: &Item) -> Self {
        let lower = |v: &str| Zeroizing::new(v.to_lowercase());
        Self {
            name: lower(&item.entry.name),
            username: item.entry.username.as_deref().map(lower),
            urls: item
                .entry
                .url
                .as_deref()
                .into_iter()
                .chain(item.metadata.additional_urls.iter().map(String::as_str))
                .map(lower)
                .collect(),
            fields: item
                .metadata
                .custom_fields
                .iter()
                .map(|f| (lower(&f.name), (!f.secret).then(|| lower(&f.value))))
                .collect(),
        }
    }
}
