use super::browser::url_match_json;
use super::*;

struct EntryIndexes<'a> {
    metadata: HashMap<usize, &'a EntryMetadata>,
    totp: HashSet<usize>,
}

impl<'a> EntryIndexes<'a> {
    fn new(recovery: &'a RecoveryData) -> Self {
        Self {
            metadata: recovery
                .entry_metadata
                .iter()
                .map(|r| (r.entry_id, r))
                .collect(),
            totp: recovery.totp.iter().map(|r| r.entry_id).collect(),
        }
    }
}

impl Vault {
    pub(super) fn is_weak(&self, entry: &VaultEntry) -> bool {
        !entry.password.is_empty()
            && run_blocking_io(|| zxcvbn::zxcvbn(&entry.password, &[]).score())
                <= zxcvbn::Score::Two
    }

    #[cfg(test)]
    pub(super) fn apply_list_options<'a>(
        &'a self,
        entries: Vec<&'a VaultEntry>,
        options: &ListOptions,
    ) -> Vec<&'a VaultEntry> {
        self.apply_list_options_indexed(entries, options, &EntryIndexes::new(&self.recovery))
    }

    fn apply_list_options_indexed<'a>(
        &'a self,
        mut entries: Vec<&'a VaultEntry>,
        options: &ListOptions,
        indexes: &EntryIndexes<'a>,
    ) -> Vec<&'a VaultEntry> {
        let metadata_by_id = &indexes.metadata;
        let totp_ids = &indexes.totp;
        let now = chrono::Utc::now();
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
                && options.stale_days.is_none_or(|days| {
                    password_is_stale_at(
                        self.password_changed_with_metadata(
                            entry,
                            metadata_by_id.get(&entry.id).copied(),
                        ),
                        days,
                        now,
                    )
                })
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

    fn entry_views<'a>(
        &'a self,
        entries: Vec<&'a VaultEntry>,
        indexes: &EntryIndexes<'a>,
    ) -> Vec<EntryView<'a>> {
        let metadata = &indexes.metadata;
        let totp = &indexes.totp;
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
        let indexes = EntryIndexes::new(&self.recovery);
        let entries =
            self.apply_list_options_indexed(self.entries.iter().collect(), &options, &indexes);
        if entries.is_empty() {
            return Err(VaultError::NotFound("No matching entries.".into()));
        }
        Ok(self.entry_views(entries, &indexes))
    }

    #[cfg(test)]
    pub(super) fn search_entries(&self, filter: &SearchFilter) -> Vec<&VaultEntry> {
        self.search_entries_indexed(filter, &EntryIndexes::new(&self.recovery))
    }

    fn search_entries_indexed<'a>(
        &'a self,
        filter: &SearchFilter,
        indexes: &EntryIndexes<'a>,
    ) -> Vec<&'a VaultEntry> {
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
        let metadata_by_id = &indexes.metadata;
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
        let indexes = EntryIndexes::new(&self.recovery);
        let entries = self.apply_list_options_indexed(
            self.search_entries_indexed(&filter, &indexes),
            &filter.list,
            &indexes,
        );
        if entries.is_empty() {
            return Err(VaultError::NotFound("No matching entries.".into()));
        }
        Ok(self.entry_views(entries, &indexes))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_search_and_views_preserve_metadata_filters_and_secret_redaction() {
        let mut vault = Vault::default();
        vault.entries = (1..=3)
            .map(|id| VaultEntry {
                id,
                name: format!("Login {id}"),
                created: "2020-01-01T00:00:00Z".into(),
                ..Default::default()
            })
            .collect();
        vault.recovery.entry_metadata = vec![
            EntryMetadata {
                entry_id: 1,
                password_changed: Some("2999-01-01T00:00:00Z".into()),
                ..Default::default()
            },
            EntryMetadata {
                entry_id: 2,
                additional_urls: vec!["https://indexed.example".into()],
                custom_fields: vec![CustomField {
                    name: "recovery".into(),
                    value: "secret-value".into(),
                    secret: true,
                }],
                ..Default::default()
            },
        ];
        vault.recovery.totp.push(TotpRecord {
            entry_id: 2,
            configuration: "synthetic".into(),
        });
        let options = ListOptions {
            stale_days: Some(365),
            has_totp: Some(true),
            ..Default::default()
        };
        let views = vault.view_entries(options.clone()).unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].entry.id, 2);
        assert!(views[0].has_totp);
        assert_eq!(views[0].urls, vec!["https://indexed.example"]);
        let results = vault
            .search(SearchFilter {
                query: Some("indexed.example".into()),
                list: options,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry.id, 2);
        assert!(
            vault
                .search(SearchFilter {
                    query: Some("secret-value".into()),
                    ..Default::default()
                })
                .is_err()
        );
        assert_eq!(
            vault
                .search(SearchFilter {
                    query: Some("recovery".into()),
                    ..Default::default()
                })
                .unwrap()[0]
                .entry
                .id,
            2
        );
    }
}
