use super::browser::url_match_json;
use super::*;

impl Vault {
    pub(super) fn is_weak(&self, entry: &VaultEntry) -> bool {
        !entry.password.is_empty()
            && run_blocking_io(|| zxcvbn::zxcvbn(&entry.password, &[]).score())
                <= zxcvbn::Score::Two
    }

    pub(super) fn apply_list_options<'a>(
        &'a self,
        mut entries: Vec<&'a VaultEntry>,
        options: &ListOptions,
    ) -> Vec<&'a VaultEntry> {
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
        entries.retain(|entry| {
            options.kind.is_none_or(|kind| {
                metadata_by_id
                    .get(&entry.id)
                    .map_or(ItemKind::Login, |metadata| metadata.kind)
                    == kind
            }) && options
                .has_totp
                .is_none_or(|expected| totp_ids.contains(&entry.id) == expected)
                && (!options.weak || self.is_weak(entry))
                && options
                    .stale_days
                    .is_none_or(|days| self.password_is_stale(entry, days))
        });
        if options.sort == SortField::Name {
            if options.descending {
                entries.sort_by_cached_key(|entry| std::cmp::Reverse(entry.name.to_lowercase()));
            } else {
                entries.sort_by_cached_key(|entry| entry.name.to_lowercase());
            }
        } else if options.sort == SortField::Id {
            entries.sort_by_key(|entry| entry.id);
            if options.descending {
                entries.reverse();
            }
        } else {
            let timestamp = |entry: &&VaultEntry| {
                let value = match options.sort {
                    SortField::Created => &entry.created,
                    SortField::Modified => &entry.modified,
                    SortField::PasswordAge => self.password_changed_with_metadata(
                        entry,
                        metadata_by_id.get(&entry.id).copied(),
                    ),
                    _ => unreachable!("name and ID sorting are handled separately"),
                };
                // Unknown imported dates sort before known dates in ascending order.
                parse_entry_timestamp(value)
            };
            if options.descending {
                entries.sort_by_cached_key(|entry| std::cmp::Reverse(timestamp(entry)));
            } else {
                entries.sort_by_cached_key(timestamp);
            }
        }
        entries
    }

    pub(super) fn password_changed_with_metadata<'a>(
        &'a self,
        entry: &'a VaultEntry,
        metadata: Option<&'a EntryMetadata>,
    ) -> &'a str {
        metadata
            .and_then(|record| record.password_changed.as_deref())
            .unwrap_or(&entry.created)
    }

    fn entry_views<'a>(&'a self, entries: Vec<&'a VaultEntry>) -> Vec<EntryView<'a>> {
        let metadata: HashMap<_, _> = self
            .recovery
            .entry_metadata
            .iter()
            .map(|r| (r.entry_id, r))
            .collect();
        let totp: HashSet<_> = self.recovery.totp.iter().map(|r| r.entry_id).collect();
        entries
            .into_iter()
            .map(|entry| EntryView {
                entry,
                metadata: metadata.get(&entry.id).copied(),
                has_totp: totp.contains(&entry.id),
                urls: entry
                    .url
                    .as_deref()
                    .into_iter()
                    .chain(
                        metadata
                            .get(&entry.id)
                            .into_iter()
                            .flat_map(|r| r.additional_urls.iter().map(String::as_str)),
                    )
                    .collect(),
            })
            .collect()
    }

    pub fn view_entries(&self, options: ListOptions) -> Result<Vec<EntryView<'_>>, VaultError> {
        if self.entries.is_empty() {
            return Ok(Vec::new());
        }
        let entries = self.apply_list_options(self.entries.iter().collect(), &options);
        if entries.is_empty() {
            return Err(VaultError::NotFound("No matching entries.".into()));
        }
        Ok(self.entry_views(entries))
    }

    pub(super) fn search_entries(&self, filter: &SearchFilter) -> Vec<&VaultEntry> {
        fn field_matches(value: Option<&str>, needle: Option<&String>) -> bool {
            needle.is_none_or(|needle| {
                value.is_some_and(|value| value.to_lowercase().contains(needle))
            })
        }

        let query = filter.query.as_ref().map(|query| query.to_lowercase());
        let name = filter.name.as_ref().map(|value| value.to_lowercase());
        let username = filter.username.as_ref().map(|value| value.to_lowercase());
        let url = filter.url.as_ref().map(|value| value.to_lowercase());
        let notes = filter.notes.as_ref().map(|value| value.to_lowercase());
        let metadata_by_id: HashMap<_, _> = self
            .recovery
            .entry_metadata
            .iter()
            .map(|record| (record.entry_id, record))
            .collect();
        self.entries
            .iter()
            .filter(|entry| {
                let query_matches =
                    query.as_ref().is_none_or(|query| {
                        entry.name.to_lowercase().contains(query)
                            || entry
                                .username
                                .as_deref()
                                .is_some_and(|value| value.to_lowercase().contains(query))
                            || entry
                                .url
                                .as_deref()
                                .into_iter()
                                .chain(metadata_by_id.get(&entry.id).into_iter().flat_map(
                                    |record| record.additional_urls.iter().map(String::as_str),
                                ))
                                .any(|value| value.to_lowercase().contains(query))
                            || entry
                                .notes
                                .as_deref()
                                .is_some_and(|value| value.to_lowercase().contains(query))
                            || metadata_by_id
                                .get(&entry.id)
                                .into_iter()
                                .flat_map(|record| &record.custom_fields)
                                .any(|field| {
                                    field.name.to_lowercase().contains(query)
                                        || (!field.secret
                                            && field.value.to_lowercase().contains(query))
                                })
                    });
                query_matches
                    && field_matches(Some(&entry.name), name.as_ref())
                    && field_matches(entry.username.as_deref(), username.as_ref())
                    && url.as_ref().is_none_or(|needle| {
                        entry
                            .url
                            .as_deref()
                            .into_iter()
                            .chain(
                                metadata_by_id
                                    .get(&entry.id)
                                    .into_iter()
                                    .flat_map(|record| {
                                        record.additional_urls.iter().map(String::as_str)
                                    }),
                            )
                            .any(|url| url.to_lowercase().contains(needle))
                    })
                    && field_matches(entry.notes.as_deref(), notes.as_ref())
            })
            .collect()
    }

    pub fn search(&self, filter: SearchFilter) -> Result<Vec<EntryView<'_>>, VaultError> {
        let entries = self.apply_list_options(self.search_entries(&filter), &filter.list);
        if entries.is_empty() {
            return Err(VaultError::NotFound("No matching entries.".into()));
        }
        Ok(self.entry_views(entries))
    }

    pub fn get_entry(&self, target: &Target) -> Result<EntryOutput<'_>, VaultError> {
        match target {
            Target::Id(_) | Target::Name(_) => {
                let index = self.entry_index(target).ok_or_else(|| {
                    VaultError::NotFound(
                        if matches!(target, Target::Id(_)) {
                            "Invalid id."
                        } else {
                            "Not found.\n"
                        }
                        .into(),
                    )
                })?;
                let entry = &self.entries[index];
                Ok(EntryOutput::Details(EntryView {
                    entry,
                    metadata: self.metadata(entry.id),
                    has_totp: !self.totp_marker(entry.id).is_empty(),
                    urls: self.all_urls(entry).collect(),
                }))
            }
            Target::Url(url) => {
                let text = url_match_json(
                    &self.entries,
                    &self.recovery.totp,
                    &self.recovery.entry_metadata,
                    url,
                )
                .ok_or_else(|| VaultError::NotFound("Not found.\n".into()))?;
                Ok(EntryOutput::SiteLogins(Zeroizing::new(text)))
            }
            Target::Vault { .. } => Err(VaultError::InvalidInput("Invalid entry selector.".into())),
        }
    }

    pub fn get_secret(&self, target: &Target) -> Result<Zeroizing<String>, VaultError> {
        let index = self
            .entry_index(target)
            .ok_or_else(|| VaultError::NotFound("Not found.\n".into()))?;
        Ok(Zeroizing::new(self.entries[index].password.clone()))
    }

    pub fn get_custom_field(
        &self,
        target: &Target,
        name: &str,
    ) -> Result<Zeroizing<String>, VaultError> {
        let index = self
            .entry_index(target)
            .ok_or_else(|| VaultError::NotFound("Entry not found.".into()))?;
        self.custom_fields(self.entries[index].id)
            .iter()
            .find(|field| field.name.eq_ignore_ascii_case(name))
            .map(|field| Zeroizing::new(field.value.clone()))
            .ok_or_else(|| VaultError::NotFound("Custom field not found.".into()))
    }
}
