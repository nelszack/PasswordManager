//! Synthetic in-memory workloads. No user profile, key files, network, or KDF.
use super::*;
use crate::benchmarks::Config;
use std::hint::black_box;

fn fixture(size: usize) -> Vault {
    let entries = (1..=size)
        .map(|id| VaultEntry {
            id,
            name: format!("École account {id:06}"),
            username: Some(format!("person-{id}@example.invalid")),
            password: format!("synthetic-password-{id:06}").into(),
            url: Some(format!(
                "https://service-{}.example.invalid/login",
                id % 100
            )),
            notes: Some(format!("Synthetic private note {id}: {}", "note ".repeat(40)).into()),
            created: "2026-01-01T00:00:00Z".into(),
            modified: "2026-01-01T00:00:00Z".into(),
        })
        .collect();
    let mut vault = Vault::from_entries(entries, None);
    vault.data.vault_id = [7; 16];
    for item in vault.data.items.values_mut() {
        item.metadata.additional_urls = vec!["https://alternate.example.invalid".into()];
        item.metadata.custom_fields = vec![
            CustomField {
                name: "Environment".into(),
                value: "production synthetic".into(),
                secret: false,
            },
            CustomField {
                name: "Token".into(),
                value: "synthetic-private-token".into(),
                secret: true,
            },
        ];
    }
    vault
}
fn filter() -> SearchFilter {
    SearchFilter {
        query: Some("person-1".into()),
        ..Default::default()
    }
}

#[test]
#[ignore = "opt-in performance workload; run npm run bench"]
fn performance_benchmarks() {
    let config = Config::read();
    for &size in &config.sizes {
        let vault = fixture(size);
        config.measure(
            "core",
            "serialize_full",
            size,
            || (),
            |_| persistence::encode_document(black_box(&vault.data), None).unwrap(),
        );
        let id = ItemId::from_public(size.div_ceil(2)).unwrap();
        let mut staged = VaultData {
            items: BTreeMap::from([(id, vault.data.items[&id].clone())]),
            vault_id: vault.data.vault_id,
            next_item_id: vault.data.next_item_id,
            revision: 1,
        };
        staged.items.get_mut(&id).unwrap().entry.name = "Synthetic changed record".into();
        let selected = HashSet::from([id]);
        let encoded =
            persistence::encode_document(&vault.data, Some((&staged, &selected))).unwrap();
        assert_eq!(
            persistence::decode_document(&encoded).unwrap().items[&id]
                .entry
                .name,
            "Synthetic changed record"
        );
        config.measure(
            "core",
            "serialize_one_item_overlay",
            size,
            || (),
            |_| {
                persistence::encode_document(black_box(&vault.data), Some((&staged, &selected)))
                    .unwrap()
            },
        );
        let query = filter();
        config.measure(
            "core",
            "search_cold",
            size,
            || vault.clone(),
            |cold| cold.management_list(black_box(query.clone())).unwrap(),
        );
        let expected = vault.management_list(query.clone()).unwrap().total;
        assert!(expected > 0);
        config.measure(
            "core",
            "search_warm",
            size,
            || (),
            |_| vault.management_list(black_box(query.clone())).unwrap(),
        );
        config.measure(
            "core",
            "search_notes",
            size,
            || (),
            |_| {
                vault
                    .management_list(SearchFilter {
                        notes: Some("private note 9".into()),
                        ..Default::default()
                    })
                    .unwrap()
            },
        );
        let document = PortableExport {
            format: PORTABLE_FORMAT.into(),
            version: PORTABLE_VERSION,
            exported_at: "2026-01-01T00:00:00Z".into(),
            items: vault
                .active_items()
                .map(|item| PortableItem {
                    id: item.entry.id,
                    name: item.entry.name.clone(),
                    username: item.entry.username.clone(),
                    password: item.entry.password.clone(),
                    url: item.entry.url.clone(),
                    notes: item.entry.notes.clone(),
                    created: item.entry.created.clone(),
                    modified: item.entry.modified.clone(),
                    kind: item.metadata.kind,
                    additional_urls: item.metadata.additional_urls.clone(),
                    custom_fields: item.metadata.custom_fields.clone(),
                    password_changed: None,
                    password_history: vec![],
                    totp: None,
                    duo: None,
                })
                .collect(),
        };
        let json = Zeroizing::new(serde_json::to_string(&document).unwrap());
        assert_eq!(
            import::import_json(&json, "synthetic.json").unwrap().len(),
            size
        );
        config.measure(
            "core",
            "import_portable",
            size,
            || (),
            |_| import::import_json(black_box(&json), "synthetic.json").unwrap(),
        );
    }
}
