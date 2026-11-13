//! Explicit two-way merging: without a retained common ancestor no differing
//! field can safely be selected automatically, including deletion and ID reuse.
use super::*;
use crate::cloud::{Choice, ConflictField, ConflictItem, Side};

fn fields(a: &Item, b: &Item) -> Vec<ConflictField> {
    let mut result = Vec::new();
    macro_rules! field {
        ($name:literal, $a:expr, $b:expr, $left:expr, $right:expr) => {
            if $a != $b {
                result.push(ConflictField {
                    field: $name.into(),
                    local: $left,
                    remote: $right,
                });
            }
        };
    }
    field!(
        "name",
        a.entry.name,
        b.entry.name,
        a.entry.name.clone(),
        b.entry.name.clone()
    );
    field!(
        "username",
        a.entry.username,
        b.entry.username,
        a.entry.username.clone().unwrap_or_default(),
        b.entry.username.clone().unwrap_or_default()
    );
    field!(
        "url",
        a.entry.url,
        b.entry.url,
        a.entry.url.clone().unwrap_or_default(),
        b.entry.url.clone().unwrap_or_default()
    );
    field!(
        "created",
        a.entry.created,
        b.entry.created,
        a.entry.created.to_string(),
        b.entry.created.to_string()
    );
    macro_rules! protected {
        ($name:literal, $a:expr, $b:expr) => {
            field!(
                $name,
                $a,
                $b,
                "Protected value differs".into(),
                "Protected value differs".into()
            );
        };
    }
    field!(
        "password",
        (&a.entry.password, password_date(a)),
        (&b.entry.password, password_date(b)),
        format!("Protected · changed {}", password_date(a)),
        format!("Protected · changed {}", password_date(b))
    );
    protected!("notes", a.entry.notes, b.entry.notes);
    protected!(
        "metadata",
        (
            &a.metadata.kind,
            &a.metadata.additional_urls,
            &a.metadata.custom_fields
        ),
        (
            &b.metadata.kind,
            &b.metadata.additional_urls,
            &b.metadata.custom_fields
        )
    );
    protected!("history", a.history, b.history);
    protected!("authenticator", a.authenticator, b.authenticator);
    // Runtime review keys must never create a spurious conflict.
    protected!(
        "duo",
        a.duo.as_ref().map(|d| &d.credentials),
        b.duo.as_ref().map(|d| &d.credentials)
    );
    field!(
        "lifecycle",
        a.lifecycle,
        b.lifecycle,
        lifecycle(a),
        lifecycle(b)
    );
    result
}
fn password_date(item: &Item) -> &Timestamp {
    item.metadata
        .password_changed
        .as_ref()
        .unwrap_or(&item.entry.created)
}
fn lifecycle(item: &Item) -> String {
    match &item.lifecycle {
        Lifecycle::Active => "Active".into(),
        Lifecycle::Trashed { deleted_at } => format!("Deleted {deleted_at}"),
    }
}
fn label(item: Option<&Item>) -> String {
    item.map_or_else(
        || "Absent (selecting this side removes the item)".into(),
        |i| {
            format!(
                "{} · {} · {} · modified {}",
                i.entry.name,
                i.entry.username.as_deref().unwrap_or(""),
                lifecycle(i),
                i.entry.modified
            )
        },
    )
}
fn compare(local: &VaultData, remote: &VaultData) -> Vec<ConflictItem> {
    let ids: std::collections::BTreeSet<_> = local
        .items
        .keys()
        .chain(remote.items.keys())
        .copied()
        .collect();
    ids.into_iter()
        .filter_map(|id| {
            let a = local.items.get(&id);
            let b = remote.items.get(&id);
            let fields = match (a, b) {
                (Some(a), Some(b)) => fields(a, b),
                _ => vec![ConflictField {
                    field: "item".into(),
                    local: label(a),
                    remote: label(b),
                }],
            };
            (!fields.is_empty()).then(|| ConflictItem {
                id: id.0,
                local: label(a),
                remote: label(b),
                fields,
            })
        })
        .collect()
}
fn merge(local: &VaultData, remote: &VaultData, choices: &[Choice]) -> Result<VaultData, String> {
    let review = compare(local, remote);
    let mut selected = BTreeMap::new();
    for choice in choices {
        if selected
            .insert((choice.id, choice.field.as_str()), choice.side)
            .is_some()
        {
            return Err("Duplicate conflict choice".into());
        }
    }
    if selected.len() != review.iter().map(|i| i.fields.len()).sum::<usize>() {
        return Err("Choose a side for every differing field".into());
    }
    let revision = local
        .revision
        .max(remote.revision)
        .checked_add(1)
        .filter(|r| *r <= MAX_ITEM_ID)
        .ok_or("Vault revision exhausted")?;
    let mut data = VaultData {
        items: local.items.clone(),
        vault_id: local.vault_id,
        next_item_id: local.next_item_id.max(remote.next_item_id),
        revision,
    };
    for row in review {
        let id = ItemId::try_from(row.id).map_err(str::to_owned)?;
        // Freeze the selected secret's effective age before independently
        // selecting a creation date or the other side's general metadata.
        if let Some(item) = data.items.get_mut(&id) {
            item.metadata.password_changed = Some(password_date(item).clone());
        }
        for field in row.fields {
            let side = selected
                .get(&(row.id, field.field.as_str()))
                .ok_or("Missing or unknown conflict choice")?;
            if field.field == "item" {
                let source = if *side == Side::Local { local } else { remote };
                if let Some(item) = source.items.get(&id) {
                    data.items.insert(id, item.clone());
                } else {
                    data.items.remove(&id);
                }
            } else if *side == Side::Remote {
                let dest = data.items.get_mut(&id).ok_or("Missing local item")?;
                let src = remote.items.get(&id).ok_or("Missing remote item")?;
                match field.field.as_str() {
                    "name" => dest.entry.name = src.entry.name.clone(),
                    "username" => dest.entry.username = src.entry.username.clone(),
                    "password" => {
                        dest.entry.password = src.entry.password.clone();
                        dest.metadata.password_changed = Some(password_date(src).clone());
                    }
                    "url" => dest.entry.url = src.entry.url.clone(),
                    "notes" => dest.entry.notes = src.entry.notes.clone(),
                    "created" => dest.entry.created = src.entry.created.clone(),
                    "metadata" => {
                        let changed = dest.metadata.password_changed.clone();
                        dest.metadata = src.metadata.clone();
                        dest.metadata.password_changed = changed;
                    }
                    "history" => dest.history = src.history.clone(),
                    "authenticator" => dest.authenticator = src.authenticator.clone(),
                    "duo" => dest.duo = src.duo.clone(),
                    "lifecycle" => dest.lifecycle = src.lifecycle.clone(),
                    _ => return Err("Unknown conflict field".into()),
                }
            }
        }
        if let Some(item) = data.items.get_mut(&id) {
            item.revision = local
                .items
                .get(&id)
                .map_or(0, |i| i.revision)
                .max(remote.items.get(&id).map_or(0, |i| i.revision))
                .checked_add(1)
                .filter(|r| *r <= MAX_ITEM_ID)
                .ok_or("Item revision exhausted")?;
            item.entry.modified = Timestamp::now();
            item.strength = CachedStrength::default();
            item.search = query::CachedSearch::default();
            if let Some(duo) = &mut item.duo {
                duo.review_key = None;
            }
        }
    }
    Ok(data)
}
impl Vault {
    fn conflict_data(
        &self,
        credentials: &VaultCredentials,
        bytes: &[u8],
    ) -> Result<VaultData, String> {
        let mut key = credentials.clone();
        let plaintext = Zeroizing::new(decrypt_file(&mut key, bytes).ok_or(
            "Cannot decrypt cloud copy with this session key. Download a comparison copy and unlock with its current credentials; both copies preserved.")?);
        let data = persistence::decode_document(&plaintext).map_err(|e| e.to_string())?;
        if data.vault_id != self.vault_id() {
            return Err("Cloud copy has the wrong vault identity".into());
        }
        Ok(data)
    }
    pub(crate) fn cloud_conflicts(
        &self,
        credentials: &VaultCredentials,
        bytes: &[u8],
    ) -> Result<Vec<ConflictItem>, String> {
        Ok(compare(
            &self.data,
            &self.conflict_data(credentials, bytes)?,
        ))
    }
    pub(crate) fn merge_cloud(
        &self,
        credentials: &VaultCredentials,
        bytes: &[u8],
        choices: &[Choice],
    ) -> Result<Vec<u8>, String> {
        let data = merge(
            &self.data,
            &self.conflict_data(credentials, bytes)?,
            choices,
        )?;
        let mut plaintext = persistence::encode_document(&data, None).map_err(|e| e.to_string())?;
        let mut key = credentials.clone();
        let encrypted = try_encrypt_file_in_place(&mut key, std::mem::take(&mut *plaintext))
            .map_err(|e| e.to_string())?;
        if encrypted.len() as u64 > crate::cloud::MAX_BYTES {
            return Err("Merged vault exceeds size limit".into());
        }
        Ok(encrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair() -> (Vault, Vault) {
        let local = Vault::from_entries(
            vec![VaultEntry {
                id: 1,
                name: "Local name".into(),
                password: "local-secret".into(),
                username: Some("local-user".into()),
                ..Default::default()
            }],
            None,
        );
        let mut remote = local.clone();
        let item = remote.data.items.get_mut(&ItemId(1)).unwrap();
        item.entry.name = "Cloud name".into();
        item.entry.password = "cloud-secret".into();
        item.lifecycle = Lifecycle::Trashed {
            deleted_at: Timestamp::now(),
        };
        (local, remote)
    }
    fn choices(local: &VaultData, remote: &VaultData, side: Side) -> Vec<Choice> {
        compare(local, remote)
            .iter()
            .flat_map(|i| {
                i.fields.iter().map(move |f| Choice {
                    id: i.id,
                    field: f.field.clone(),
                    side,
                })
            })
            .collect()
    }
    #[test]
    fn mixed_choices_preserve_selected_fields_and_redact_secrets() {
        let (local, remote) = pair();
        let serialized = serde_json::to_string(&compare(&local.data, &remote.data)).unwrap();
        assert!(serialized.contains("Local name") && serialized.contains("Cloud name"));
        assert!(!serialized.contains("local-secret") && !serialized.contains("cloud-secret"));
        let mut choices = choices(&local.data, &remote.data, Side::Local);
        choices
            .iter_mut()
            .find(|c| c.field == "password")
            .unwrap()
            .side = Side::Remote;
        let merged = merge(&local.data, &remote.data, &choices).unwrap();
        let item = &merged.items[&ItemId(1)];
        assert_eq!(item.entry.name, "Local name");
        assert_eq!(item.entry.password.expose(), "cloud-secret");
        assert!(item.active());
        assert!(merged.revision > local.data.revision && merged.revision > remote.data.revision);
        assert!(item.revision > remote.data.items[&ItemId(1)].revision);
        assert_eq!(
            local.data.items[&ItemId(1)].entry.password.expose(),
            "local-secret"
        );
    }
    #[test]
    fn incomplete_duplicate_unknown_and_absent_item_choices_are_checked() {
        let (local, mut remote) = pair();
        let mut selected = choices(&local.data, &remote.data, Side::Local);
        assert!(merge(&local.data, &remote.data, &[]).is_err());
        selected.push(selected[0].clone());
        assert!(merge(&local.data, &remote.data, &selected).is_err());
        selected.pop();
        selected[0].field = "unknown".into();
        assert!(merge(&local.data, &remote.data, &selected).is_err());
        remote.data.items.clear();
        let selected = choices(&local.data, &remote.data, Side::Remote);
        assert!(
            merge(&local.data, &remote.data, &selected)
                .unwrap()
                .items
                .is_empty()
        );
        let selected = choices(&local.data, &remote.data, Side::Local);
        assert!(
            merge(&local.data, &remote.data, &selected)
                .unwrap()
                .items
                .contains_key(&ItemId(1))
        );
        let mut data = remote.data;
        data.items = local.data.items.clone();
        data.items.get_mut(&ItemId(1)).unwrap().entry.password = "independent-entry".into();
        data.next_item_id = 12;
        assert!(
            compare(&local.data, &data)
                .iter()
                .any(|i| i.fields.iter().any(|f| f.field == "password"))
        );
        assert_eq!(
            merge(
                &local.data,
                &data,
                &choices(&local.data, &data, Side::Remote)
            )
            .unwrap()
            .next_item_id,
            12
        );
    }
    #[test]
    fn password_age_follows_the_selected_secret_independently_of_other_metadata() {
        for explicit_date in [true, false] {
            let (mut local, mut remote) = pair();
            let old = Timestamp::parse("2020-01-01T00:00:00Z").unwrap();
            let new = Timestamp::parse("2026-01-01T00:00:00Z").unwrap();
            let item = local.data.items.get_mut(&ItemId(1)).unwrap();
            item.entry.created = old.clone();
            item.metadata.password_changed = explicit_date.then_some(old);
            let item = remote.data.items.get_mut(&ItemId(1)).unwrap();
            item.entry.created = new.clone();
            item.metadata.password_changed = explicit_date.then_some(new);
            item.metadata
                .additional_urls
                .push("https://cloud.example".into());
            for secret_side in [Side::Local, Side::Remote] {
                let other = if secret_side == Side::Local {
                    Side::Remote
                } else {
                    Side::Local
                };
                let mut selected = choices(&local.data, &remote.data, Side::Local);
                for choice in &mut selected {
                    choice.side = if choice.field == "password" {
                        secret_side
                    } else {
                        other
                    };
                }
                let merged = merge(&local.data, &remote.data, &selected).unwrap();
                let expected = if secret_side == Side::Local {
                    &local.data
                } else {
                    &remote.data
                };
                assert_eq!(
                    merged.items[&ItemId(1)].entry.password,
                    expected.items[&ItemId(1)].entry.password
                );
                assert_eq!(
                    password_date(&merged.items[&ItemId(1)]),
                    password_date(&expected.items[&ItemId(1)])
                );
            }
        }
    }
    #[test]
    fn equivalent_contents_can_reconcile_without_arbitrary_field_choices() {
        let (local, _) = pair();
        let mut remote = local.data.clone();
        remote.revision += 2;
        let item = remote.items.get_mut(&ItemId(1)).unwrap();
        item.revision += 1;
        item.entry.modified = Timestamp::now();
        assert!(compare(&local.data, &remote).is_empty());
        let data = merge(&local.data, &remote, &[]).unwrap();
        assert!(compare(&data, &local.data).is_empty());
        assert!(data.revision > remote.revision);
    }
    #[test]
    fn encrypted_merge_checks_identity_and_key_and_roundtrips() {
        let (local, remote) = pair();
        let credentials = VaultCredentials::Session {
            encryption_key: [42; 32],
            salt: [7; 16],
            kdf: 1,
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
        };
        let encrypt = |data: &VaultData| {
            let plaintext = persistence::encode_document(data, None).unwrap();
            try_encrypt_file_in_place(&mut credentials.clone(), plaintext.to_vec()).unwrap()
        };
        let bytes = encrypt(&remote.data);
        let selected = choices(&local.data, &remote.data, Side::Remote);
        let merged = local.merge_cloud(&credentials, &bytes, &selected).unwrap();
        let data = local.conflict_data(&credentials, &merged).unwrap();
        assert_eq!(
            data.items[&ItemId(1)].entry.password.expose(),
            "cloud-secret"
        );
        assert!(!data.items[&ItemId(1)].active());
        let mut wrong = remote.data;
        wrong.vault_id = [99; 16];
        assert!(
            local
                .cloud_conflicts(&credentials, &encrypt(&wrong))
                .is_err()
        );
        let mut corrupt = bytes;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(
            local
                .merge_cloud(&credentials, &corrupt, &selected)
                .is_err()
        );
    }
}
