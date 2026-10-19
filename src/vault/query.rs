use super::*;
impl Vault {
    fn is_weak(&self, entry: &VaultEntry) -> bool {
        !entry.password.is_empty()
            && run_blocking_io(|| zxcvbn::zxcvbn(&entry.password, &[]).score())
                <= zxcvbn::Score::Two
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
            SortField::Id => entries.sort_by_key(|e| e.id),
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
    fn entry_views<'a>(&'a self, entries: Vec<&'a VaultEntry>) -> Vec<EntryView<'a>> {
        entries
            .into_iter()
            .filter_map(|e| self.view_id(e.id))
            .collect()
    }
    pub fn view_entries(&self, options: ListOptions) -> Result<Vec<EntryView<'_>>, VaultError> {
        let entries = self.apply_list_options(self.active_entries().collect(), &options);
        if entries.is_empty() && self.active_entries().next().is_some() {
            return Err(VaultError::NotFound("no matching entries".into()));
        }
        Ok(self.entry_views(entries))
    }
    pub(super) fn search_entries(&self, filter: &SearchFilter) -> Vec<&VaultEntry> {
        fn contains(value: Option<&str>, needle: Option<&String>) -> bool {
            needle
                .is_none_or(|n| value.is_some_and(|v| v.to_lowercase().contains(&n.to_lowercase())))
        }
        self.active_entries()
            .filter(|e| {
                let m = self.metadata(e.id).unwrap();
                let query = filter.query.as_ref().map(|q| q.to_lowercase());
                query.as_ref().is_none_or(|q| {
                    e.name.to_lowercase().contains(q)
                        || contains(e.username.as_deref(), Some(q))
                        || self.all_urls(e).any(|u| u.to_lowercase().contains(q))
                        || contains(e.notes.as_ref().map(|s| s.as_str()), Some(q))
                        || m.custom_fields.iter().any(|f| {
                            f.name.to_lowercase().contains(q)
                                || (!f.secret && f.value.to_lowercase().contains(q))
                        })
                }) && contains(Some(&e.name), filter.name.as_ref())
                    && contains(e.username.as_deref(), filter.username.as_ref())
                    && filter.url.as_ref().is_none_or(|q| {
                        self.all_urls(e)
                            .any(|u| u.to_lowercase().contains(&q.to_lowercase()))
                    })
                    && contains(
                        e.notes.as_ref().map(|s| s.as_str()),
                        filter.notes.as_deref(),
                    )
            })
            .collect()
    }
    pub fn search(&self, filter: SearchFilter) -> Result<Vec<EntryView<'_>>, VaultError> {
        let entries = self.apply_list_options(self.search_entries(&filter), &filter.list);
        if entries.is_empty() {
            return Err(VaultError::NotFound("no matching entries".into()));
        }
        Ok(self.entry_views(entries))
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
