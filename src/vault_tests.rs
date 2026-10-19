use super::import::{import_csv, import_json};
use super::totp::{normalize_totp_configuration, parse_totp_configuration};
use super::*;
use proptest::prelude::*;
const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn entry(id: usize, name: &str, password: &str) -> VaultEntry {
    VaultEntry {
        id,
        name: name.into(),
        username: Some("alice".into()),
        password: password.into(),
        url: Some("https://example.com".into()),
        created: "2020-01-01T00:00:00Z".into(),
        modified: "2020-01-01T00:00:00Z".into(),
        ..Default::default()
    }
}
fn memory() -> Vault {
    Vault::from_entries(
        vec![
            entry(1, "first", "secret"),
            entry(2, "second", "other-secret"),
        ],
        None,
    )
}
fn key(byte: u8) -> PasswordType {
    PasswordType::Session {
        encryption_key: [byte; 32],
        salt: [7; 16],
        kdf: 1,
        memory_kib: 8192,
        iterations: 1,
        parallelism: 1,
    }
}
fn credentials() -> VaultCredentials {
    VaultCredentials {
        locked: false,
        keypass: Some(key(42)),
    }
}
fn persisted() -> (tempfile::TempDir, Vault, VaultCredentials) {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = memory();
    vault.metadata.filename = "test.enc".into();
    vault.store = VaultStore::File {
        directory: dir.path().to_owned(),
        filename: "test.enc".into(),
    };
    let mut credentials = credentials();
    write_vault(&vault, &mut credentials).unwrap();
    (dir, vault, credentials)
}
fn update(id: usize, password: &str) -> TypedUpdate {
    TypedUpdate {
        entry: EntryUpdate {
            target: Target::Id(id),
            update: EntryChanges::default(),
            password: Some(password.into()),
        },
        kind: None,
        add_url: vec![],
        remove_url: vec![],
        clear_urls: false,
        set_fields: vec![],
        remove_fields: vec![],
        clear_fields: false,
    }
}
fn hotp(counter: u64) -> String {
    format!("otpauth://hotp/Test?secret={SECRET}&counter={counter}")
}
fn reopen(vault: &Vault) -> Vault {
    let VaultStore::File {
        directory,
        filename,
    } = &vault.store
    else {
        panic!("persistent fixture")
    };
    persistence::lookup_vault_in(directory, &mut key(42), Some(filename))
        .unwrap()
        .unwrap()
        .1
}

#[test]
fn missing_credentials_never_report_a_successful_persistent_write() {
    let (_dir, mut vault, _) = persisted();
    let before = vault.clone();
    assert!(matches!(
        vault.update_typed_entry_with_limit(update(1, "new"), &mut VaultCredentials::default(), 10),
        Err(VaultError::Locked)
    ));
    assert_eq!(vault, before);
    assert_eq!(reopen(&vault).data, before.data);
    let mut detached = Vault::default();
    assert!(write_vault(&detached, &mut credentials()).is_err());
    assert!(
        detached
            .add_entry(
                PasswordEntry {
                    name: "test".into(),
                    username: None,
                    password: "secret".into(),
                    url: None,
                    notes: None,
                    copy: false
                },
                &mut credentials()
            )
            .is_err()
    );
    assert!(detached.data.items.is_empty());
}
#[test]
fn explicit_memory_store_supports_pure_mutation_without_credentials() {
    let mut vault = Vault::memory();
    assert!(
        vault
            .add_entry(
                PasswordEntry {
                    name: "test".into(),
                    username: None,
                    password: "secret".into(),
                    url: None,
                    notes: None,
                    copy: false
                },
                &mut VaultCredentials::default()
            )
            .unwrap()
    );
    assert_eq!(vault.get_secret(&Target::Id(1)).unwrap().as_str(), "secret");
}
#[test]
fn stage_and_commit_keep_live_state_consistent_before_and_after_replacement() {
    let (dir, mut vault, mut credentials) = persisted();
    let old = fs::read(dir.path().join("test.enc")).unwrap();
    let before = vault.clone();
    let failed = persistence::with_write_fault(1, || {
        vault.update_typed_entry_with_limit(update(1, "after"), &mut credentials, 10)
    })
    .unwrap_err();
    assert!(!failed.committed());
    assert_eq!(vault, before);
    assert_eq!(fs::read(dir.path().join("test.enc")).unwrap(), old);
    let failed = persistence::with_write_fault(2, || {
        vault.update_typed_entry_with_limit(update(1, "after"), &mut credentials, 10)
    })
    .unwrap_err();
    assert!(failed.committed());
    assert_eq!(vault.get_secret(&Target::Id(1)).unwrap().as_str(), "after");
    assert_eq!(reopen(&vault).data, vault.data);
    assert_eq!(vault.item_revision(1), Some(2));
    assert_eq!(vault.vault_revision(), 1);
    write_vault(&vault, &mut credentials).unwrap();
    assert_eq!(reopen(&vault).data, vault.data);
}
#[test]
fn staging_panic_never_changes_the_live_aggregate() {
    let mut vault = memory();
    let before = vault.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), _> = vault.transaction(
            TransactionScope::Entry(1),
            &mut VaultCredentials::default(),
            |v| {
                v.item_mut(1).unwrap().entry.password = "changed".into();
                panic!("injected mutation panic")
            },
        );
    }));
    assert!(result.is_err());
    assert_eq!(vault, before);
}
#[test]
fn revisions_change_only_for_touched_items_and_real_changes() {
    let mut vault = memory();
    let mut key = VaultCredentials::default();
    assert!(
        !vault
            .update_typed_entry_with_limit(update(1, "secret"), &mut key, 10)
            .unwrap()
    );
    assert_eq!(vault.vault_revision(), 0);
    assert_eq!(vault.revision(1), Some(1));
    vault
        .update_typed_entry_with_limit(update(1, "new"), &mut key, 10)
        .unwrap();
    assert_eq!(vault.revision(1), Some(2));
    assert_eq!(vault.revision(2), Some(1));
    assert!(vault.check_revision(1, 1).is_err());
    assert!(vault.check_revision(1, 2).is_ok());
    assert_eq!(
        vault.target_revision(&Target::Name("first".into())),
        Some(2)
    );
}
#[test]
fn missing_targets_do_not_consume_ids_change_history_or_accept_private_notes() {
    let mut vault = memory();
    let before = vault.clone();
    let mut change = update(99, "discarded-secret");
    change.entry.update.notes = Some("discarded-notes".into());
    assert!(
        !vault
            .update_typed_entry_with_limit(change, &mut VaultCredentials::default(), 10)
            .unwrap()
    );
    assert!(
        !vault
            .delete_entry(Target::Id(99), &mut VaultCredentials::default())
            .unwrap()
    );
    assert!(vault.get_secret(&Target::Id(99)).is_err());
    assert_eq!(vault, before);
}
#[test]
fn complete_item_survives_trash_and_restore_and_is_wholly_purged() {
    let mut vault = memory();
    let mut key = VaultCredentials::default();
    vault.set_totp(Target::Id(1), &hotp(3), &mut key).unwrap();
    vault.set_test_metadata(
        1,
        ItemKind::PaymentCard,
        vec!["https://account.example.com".into()],
        vec![CustomField {
            name: "pin".into(),
            value: "private-pin".into(),
            secret: true,
        }],
    );
    vault
        .update_typed_entry_with_limit(update(1, "new-secret"), &mut key, 10)
        .unwrap();
    let before = vault.item(1).unwrap().clone();
    vault.delete_entry(Target::Id(1), &mut key).unwrap();
    assert!(vault.get_secret(&Target::Id(1)).is_err());
    assert_eq!(vault.view_trash()[0].entry.entry.id, 1);
    assert!(vault.browser_login("https://example.com", 1).is_none());
    assert!(vault.restore_trashed(1, &mut key).unwrap());
    let after = vault.item(1).unwrap();
    assert_eq!(after.history, before.history);
    assert_eq!(after.authenticator, before.authenticator);
    assert_eq!(after.metadata, before.metadata);
    vault.delete_entry(Target::Id(1), &mut key).unwrap();
    assert!(vault.purge_trash(Some(1), &mut key).unwrap());
    assert!(vault.item(1).is_none());
    assert!(vault.item(2).is_some());
}
#[test]
fn trash_selection_uses_stable_ids_after_other_items_are_purged() {
    let mut vault = memory();
    let mut key = VaultCredentials::default();
    for id in [1, 2] {
        vault.delete_entry(Target::Id(id), &mut key).unwrap();
    }
    vault.purge_trash(Some(1), &mut key).unwrap();
    assert!(vault.restore_trashed(2, &mut key).unwrap());
    assert_eq!(
        vault.get_secret(&Target::Id(2)).unwrap().as_str(),
        "other-secret"
    );
}
#[test]
fn stable_ids_are_never_reused_after_purge() {
    let mut vault = memory();
    let mut key = VaultCredentials::default();
    vault.delete_entry(Target::Id(2), &mut key).unwrap();
    vault.purge_trash(None, &mut key).unwrap();
    vault
        .add_entry(
            PasswordEntry {
                name: "third".into(),
                username: None,
                password: "secret".into(),
                url: None,
                notes: None,
                copy: false,
            },
            &mut key,
        )
        .unwrap();
    assert!(vault.item(2).is_none());
    assert!(vault.item(3).is_some());
}
#[test]
fn history_limits_and_restore_preserve_exact_secret_bytes() {
    for limit in [0, 1, 3] {
        let mut vault = memory();
        let mut key = VaultCredentials::default();
        for password in ["one", "two", " \nexact\t "] {
            vault
                .update_typed_entry_with_limit(update(1, password), &mut key, limit)
                .unwrap();
        }
        assert_eq!(vault.item(1).unwrap().history.len(), limit);
        assert_eq!(
            vault.get_secret(&Target::Id(1)).unwrap().as_str(),
            " \nexact\t "
        );
        if limit > 0 {
            assert!(vault.restore_password(Target::Id(1), 1, &mut key).unwrap());
            assert_eq!(vault.get_secret(&Target::Id(1)).unwrap().as_str(), "two");
        } else {
            assert!(vault.restore_password(Target::Id(1), 1, &mut key).is_err());
        }
    }
}
#[test]
fn summaries_and_search_never_include_secret_fields_or_passwords() {
    let mut vault = memory();
    vault.set_test_metadata(
        1,
        ItemKind::Login,
        vec!["https://accounts.example.com".into()],
        vec![CustomField {
            name: "token".into(),
            value: "secret-token".into(),
            secret: true,
        }],
    );
    vault.item_mut(1).unwrap().entry.notes = Some("private note".into());
    let encoded =
        serde_json::to_string(&vault.management_list(SearchFilter::default()).unwrap()).unwrap();
    for secret in ["secret-token", "private note", "other-secret"] {
        assert!(!encoded.contains(secret));
    }
    let detail = vault.management_item(1, false).unwrap();
    assert!(detail.password.is_none());
    assert!(detail.fields[0].value.is_none());
    assert_eq!(
        vault.management_item(1, true).unwrap().password.unwrap(),
        "secret"
    );
    assert!(
        vault
            .search(SearchFilter {
                query: Some("secret-token".into()),
                ..Default::default()
            })
            .is_err()
    );
    assert_eq!(
        vault
            .search(SearchFilter {
                query: Some("accounts.example.com".into()),
                ..Default::default()
            })
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        vault
            .get_custom_field(&Target::Id(1), "TOKEN")
            .unwrap()
            .as_str(),
        "secret-token"
    );
}
#[test]
fn list_filters_type_authenticator_age_and_sorting_from_complete_items() {
    let mut vault = memory();
    vault.set_test_metadata(2, ItemKind::Identity, vec![], vec![]);
    vault.set_test_totp(1, SECRET);
    let views = vault
        .view_entries(ListOptions {
            kind: Some(ItemKind::Login),
            has_totp: Some(true),
            stale_days: Some(365),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].entry.id, 1);
    let ordered = vault
        .view_entries(ListOptions {
            sort: SortField::Id,
            descending: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(ordered[0].entry.id, 2);
}
#[test]
fn trash_retention_handles_canonical_dates_and_extreme_thresholds() {
    let mut vault = memory();
    let mut key = VaultCredentials::default();
    for id in [1, 2] {
        vault.delete_entry(Target::Id(id), &mut key).unwrap();
    }
    vault.item_mut(1).unwrap().lifecycle = Lifecycle::Trashed {
        deleted_at: "2020-01-01T00:00:00Z".into(),
    };
    assert_eq!(vault.purge_expired_trash(u64::MAX, &mut key).unwrap(), 0);
    assert_eq!(vault.purge_expired_trash(365, &mut key).unwrap(), 1);
    assert!(vault.item(1).is_none());
    assert!(vault.item(2).is_some());
}
#[test]
fn hotp_matches_rfc_4226_and_advances_exactly_one_counter() {
    let mut vault = memory();
    let mut key = VaultCredentials::default();
    vault.set_totp(Target::Id(1), &hotp(0), &mut key).unwrap();
    for (counter, code) in [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ]
    .into_iter()
    .enumerate()
    {
        let result = vault.current_otp(Target::Id(1), &mut key).unwrap();
        assert_eq!(result.code.as_str(), code);
        assert_eq!(result.counter, Some(counter as u64));
        assert!(result.expires_in.is_none());
    }
    assert!(vault.current_totp(Target::Id(1)).is_err());
}
#[test]
fn hotp_counter_tracks_commit_even_when_result_is_durability_error() {
    let (_dir, mut vault, mut key) = persisted();
    vault.set_totp(Target::Id(1), &hotp(0), &mut key).unwrap();
    for (fault, expected) in [(1, 0), (2, 1)] {
        let error =
            persistence::with_write_fault(fault, || vault.current_otp(Target::Id(1), &mut key))
                .err()
                .unwrap();
        assert_eq!(error.committed(), fault == 2);
        let config = &vault
            .item(1)
            .unwrap()
            .authenticator
            .as_ref()
            .unwrap()
            .configuration;
        assert!(config.ends_with(&format!("counter={expected}")));
        assert_eq!(reopen(&vault).data, vault.data);
    }
    assert_eq!(
        vault
            .current_otp(Target::Id(1), &mut key)
            .unwrap()
            .code
            .as_str(),
        "287082"
    );
}
#[test]
fn hotp_supports_u64_counters_and_refuses_overflow_without_returning_a_code() {
    let mut vault = memory();
    let mut key = VaultCredentials::default();
    vault
        .set_totp(Target::Id(1), &hotp(u64::MAX - 1), &mut key)
        .unwrap();
    assert_eq!(
        vault.current_otp(Target::Id(1), &mut key).unwrap().counter,
        Some(u64::MAX - 1)
    );
    let before = vault.clone();
    assert!(vault.current_otp(Target::Id(1), &mut key).is_err());
    assert_eq!(vault, before);
}
#[test]
fn invalid_authenticator_inputs_never_modify_the_item() {
    let mut vault = memory();
    let before = vault.clone();
    for value in [
        "",
        "bad seed",
        "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=-1",
        "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=0&counter=1",
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&period=0",
    ] {
        assert!(
            vault
                .set_totp(Target::Id(1), value, &mut VaultCredentials::default())
                .is_err(),
            "{value}"
        );
        assert_eq!(vault, before);
    }
}
#[test]
fn portable_round_trip_remaps_ids_and_keeps_typed_item_metadata_history_and_hotp() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("export.json");
    let mut source = memory();
    let mut key = VaultCredentials::default();
    source.set_test_metadata(
        1,
        ItemKind::Identity,
        vec!["https://accounts.example.com".into()],
        vec![CustomField {
            name: "pin".into(),
            value: "1234".into(),
            secret: true,
        }],
    );
    source.set_totp(Target::Id(1), &hotp(7), &mut key).unwrap();
    source
        .update_typed_entry_with_limit(update(1, "changed"), &mut key, 10)
        .unwrap();
    source.export(path.display().to_string(), false).unwrap();
    let mut destination = Vault::from_entries(vec![entry(42, "existing", "existing-secret")], None);
    let report = destination
        .import_with_options(
            path.display().to_string(),
            ConflictPolicy::Skip,
            false,
            10,
            &mut key,
        )
        .unwrap();
    assert_eq!(report.added, 2);
    let imported = destination.item(43).unwrap();
    assert_eq!(imported.entry.name, "first");
    assert_eq!(imported.metadata, source.item(1).unwrap().metadata);
    assert_eq!(imported.history, source.item(1).unwrap().history);
    assert_eq!(
        imported.authenticator,
        source.item(1).unwrap().authenticator
    );
}
#[test]
fn import_preview_conflicts_and_same_batch_replacements_share_a_plan() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("input.json");
    fs::write(&path,r#"[{"name":"third","username":"x","password":"one"},{"name":"third","username":"x","password":"two"}]"#).unwrap();
    let mut vault = memory();
    let before = vault.clone();
    let mut key = VaultCredentials::default();
    let preview = vault
        .import_with_options(
            path.display().to_string(),
            ConflictPolicy::Replace,
            true,
            10,
            &mut key,
        )
        .unwrap();
    assert_eq!(vault, before);
    let report = vault
        .import_with_options(
            path.display().to_string(),
            ConflictPolicy::Replace,
            false,
            10,
            &mut key,
        )
        .unwrap();
    assert_eq!(
        (report.added, report.replaced),
        (preview.added, preview.replaced)
    );
    assert_eq!((report.added, report.replaced), (1, 1));
    assert_eq!(vault.item(3).unwrap().entry.password, "two");
}
#[test]
fn invalid_import_and_validation_errors_leave_live_state_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bad.json");
    fs::write(
        &path,
        r#"[{"name":"valid","password":"one"},{"password":"missing-name"}]"#,
    )
    .unwrap();
    let mut vault = memory();
    let before = vault.clone();
    assert!(
        vault
            .import_with_options(
                path.display().to_string(),
                ConflictPolicy::Skip,
                false,
                10,
                &mut VaultCredentials::default()
            )
            .is_err()
    );
    assert_eq!(vault, before);
}
#[test]
fn json_and_csv_exports_refuse_clobber_and_round_trip_exact_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let mut vault = memory();
    vault.item_mut(1).unwrap().entry.password = " \nexact\t ".into();
    vault.item_mut(1).unwrap().entry.notes = Some("multiline\nnotes".into());
    for format in ["json", "csv"] {
        let path = directory.path().join(format!("export.{format}"));
        vault.export(path.display().to_string(), false).unwrap();
        assert!(vault.export(path.display().to_string(), false).is_err());
        if format == "json" {
            let json: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(json["items"][0]["password"], " \nexact\t ");
        }
        let mut target = Vault::memory();
        target
            .import_with_options(
                path.display().to_string(),
                ConflictPolicy::Skip,
                false,
                10,
                &mut VaultCredentials::default(),
            )
            .unwrap();
        assert_eq!(
            target.item(1).unwrap().entry.password,
            vault.item(1).unwrap().entry.password,
            "{format}"
        );
        assert_eq!(
            target.item(1).unwrap().entry.notes,
            vault.item(1).unwrap().entry.notes,
            "{format}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600,
                "{format}"
            );
        }
    }
}
#[test]
fn browser_login_selection_and_typed_autofill_are_separate_and_secret_scoped() {
    let mut vault = memory();
    vault.set_test_metadata(2, ItemKind::PaymentCard, vec![], vec![]);
    assert_eq!(vault.browser_logins("https://example.com").len(), 1);
    assert!(vault.browser_login("https://example.com", 2).is_none());
    assert!(vault.browser_login("https://other.example", 1).is_none());
    assert_eq!(
        vault
            .browser_login("https://example.com", 1)
            .unwrap()
            .password,
        "secret"
    );
    assert_eq!(vault.browser_autofill().len(), 1);
    assert!(vault.browser_autofill_item(1).is_none());
    assert_eq!(
        vault.browser_autofill_item(2).unwrap().primary_secret,
        "other-secret"
    );
}
#[test]
fn validated_timestamp_and_nonzero_fixed_width_identity_reject_invalid_documents() {
    assert!(serde_json::from_str::<Timestamp>("\"yesterday\"").is_err());
    assert!(serde_json::from_str::<ItemId>("0").is_err());
    assert!(serde_json::from_str::<ItemId>(&u64::MAX.to_string()).is_err());
    let id: ItemId = serde_json::from_str(&MAX_ITEM_ID.to_string()).unwrap();
    assert_eq!(u64::from(id), MAX_ITEM_ID);
    assert_eq!(
        Timestamp::parse("2020-01-01T01:00:00+01:00").unwrap(),
        Timestamp::parse("2020-01-01T00:00:00Z").unwrap()
    );
}
#[test]
fn native_document_has_independent_schema_and_no_runtime_keys_or_paths() {
    let mut vault = memory();
    vault.metadata.filename = "runtime-only.enc".into();
    vault.metadata.duo_session = Some([37; 32]);
    let bytes = persistence::encode_document(&vault.data, None).unwrap();
    let json: serde_json::Value = rmp_serde::from_slice(&bytes).unwrap();
    assert_eq!(json["schema_version"], 2);
    assert!(json.get("vault_id").is_some());
    for key in ["filename", "duo_session", "review_key", "keypass"] {
        assert!(!format!("{json:?}").contains(key));
    }
    assert_eq!(persistence::decode_document(&bytes).unwrap(), vault.data);
}

proptest! {
    #[test]
    fn arbitrary_import_documents_never_panic(contents in ".{0,4096}") {let _=import_json(&contents,"fuzz.json");let _=import_csv(&contents,"fuzz.csv");}
    #[test]
    fn arbitrary_url_inputs_never_panic(value in ".{0,2048}") {let _=hostname(&value);let _=hosts_match(&value,&value);let _=memory().browser_logins(&value);}
}
#[test]
fn browser_credentials_are_bound_to_normalized_origins() {
    for (saved, requested, expected) in [
        ("other.com", "example.com", false),
        ("https://notexample.com/login", "example.com", false),
        ("HTTPS://Example.COM:443/login", "example.com", true),
        ("https://example.com/login", "http://example.com", false),
        ("https://example.com/login", "https://example.com", true),
        ("example.com", "http://example.com", false),
        ("http://example.com", "https://example.com", false),
        ("example.com", "login.example.com", false),
        ("mail.example.com", "example.com", false),
        ("*.example.com", "login.example.com", true),
        ("*.example.com", "mail.example.com", true),
        ("*.example.com", "example.com", false),
        ("*.github.io", "attacker.github.io", false),
        (
            "https://example.com:8443/login",
            "https://example.com:9443",
            false,
        ),
        (
            "https://example.com:8443/login",
            "https://example.com",
            false,
        ),
        (
            "https://example.com:8443/login",
            "https://example.com:8443",
            true,
        ),
        ("https://example.com:443/login", "https://EXAMPLE.com", true),
        ("example.com", "https://example.com:9443", false),
        ("http://example.com:80", "https://example.com", false),
        ("http://example.com:80", "http://example.com", true),
        ("https://[::1]:8443", "https://[::1]:9443", false),
        ("https://[::1]:8443", "https://[::1]:8443", true),
        ("https://éxample.com", "https://xn--xample-9ua.com", true),
        (
            "https://*.example.com:8443",
            "https://login.example.com:8443",
            true,
        ),
        (
            "https://*.example.com:8443",
            "https://login.example.com:9443",
            false,
        ),
        ("*.github.io", "https://attacker.github.io", false),
        (
            r"https://trusted.example\@attacker.example/login",
            "https://attacker.example",
            false,
        ),
        (
            r"https://trusted.example\@attacker.example/login",
            "https://trusted.example",
            false,
        ),
        (
            "https://user@attacker.example",
            "https://attacker.example",
            false,
        ),
        (
            "https://trusted.example\t@attacker.example",
            "https://attacker.example",
            false,
        ),
        (
            "https://trusted.example\n@attacker.example",
            "https://attacker.example",
            false,
        ),
        ("ftp://example.com", "https://example.com", false),
        ("https://example.com:70000", "https://example.com", false),
        ("https://example.com", "https://*.example.com", false),
    ] {
        let vault = Vault::from_entries(
            vec![VaultEntry {
                id: 2,
                password: "synthetic-secret".into(),
                url: Some(saved.into()),
                ..Default::default()
            }],
            None,
        );
        assert_eq!(
            hosts_match(saved, requested),
            expected,
            "{saved:?} -> {requested:?}"
        );
        assert_eq!(
            vault.browser_login(requested, 2).is_some(),
            expected,
            "selection: {saved:?} -> {requested:?}"
        );
        assert_eq!(
            vault.browser_logins(requested).len(),
            usize::from(expected),
            "summaries: {saved:?} -> {requested:?}"
        );
    }
}
#[test]
fn totp_matches_rfc_6238_sha1_vectors() {
    let raw = "GEZD GNBV-GY3TQOJQ GEZDGNBVGY3TQOJQ";
    let (normalized, bits) = normalize_totp_configuration(raw).unwrap();
    assert_eq!(normalized, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert_eq!(bits, 160);
    let totp = parse_totp_configuration(&normalized).unwrap();
    assert_eq!(totp.generate(59).to_string(), "287082");

    let uri = "otpauth://totp/RFC?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30";
    let totp = parse_totp_configuration(uri).unwrap();
    assert_eq!(totp.generate(59).to_string(), "94287082");
}

#[test]
fn totp_accepts_github_compatible_80_bit_secrets() {
    let github_secret = "GEZDGNBVGY3TQOJQ";
    let (normalized, bits) = normalize_totp_configuration(github_secret).unwrap();
    assert_eq!(bits, 80);
    let raw_totp = parse_totp_configuration(&normalized).unwrap();

    let uri = format!(
        "otpauth://totp/GitHub:test?secret={github_secret}&issuer=GitHub&algorithm=SHA1&digits=6&period=30"
    );
    let (normalized_uri, uri_bits) = normalize_totp_configuration(&uri).unwrap();
    assert_eq!(uri_bits, 80);
    let uri_totp = parse_totp_configuration(&normalized_uri).unwrap();
    assert_eq!(raw_totp.generate(59), uri_totp.generate(59));

    assert!(normalize_totp_configuration("GEZDGNBVGY3TQ").is_err());
}

#[test]
fn login_imports_preserve_fields_and_credential_bytes() {
    for (case, username, password) in [
        ("ordinary", "alice", "secret"),
        ("padded password", "alice", " padded-secret \t"),
        ("whitespace password", "alice", " \t "),
        ("empty password", "alice", ""),
        ("padded username", " alice ", "synthetic-secret"),
        ("tabbed username", "\taccount\t", "synthetic-secret"),
        ("whitespace username", " \t ", "synthetic-secret"),
    ] {
        let mut writer = csv::Writer::from_writer(Vec::new());
        writer
            .write_record(["name", "url", "username", "password", "note"])
            .unwrap();
        writer
            .write_record([
                "Example",
                "https://example.com/login",
                username,
                password,
                "personal",
            ])
            .unwrap();
        let csv = String::from_utf8(writer.into_inner().unwrap()).unwrap();
        for (format, document) in [
            ("chrome.csv", csv),
            (
                "bitwarden.json",
                json!({ "items": [{
                "type": 1, "name": "Example", "notes": "personal",
                "login": { "username": username, "password": password,
                    "uris": [{ "uri": "https://example.com/login" }] }
            }] })
                .to_string(),
            ),
            (
                "flat.json",
                json!([{
                    "name": "Example", "notes": "personal", "username": username,
                    "password": password, "url": "https://example.com/login"
                }])
                .to_string(),
            ),
            (
                "login-alias.json",
                json!([{
                    "name": "Example", "notes": "personal", "login": username,
                    "password": password, "url": "https://example.com/login"
                }])
                .to_string(),
            ),
        ] {
            let imported = if format.ends_with(".csv") {
                import_csv(&document, format)
            } else {
                import_json(&document, format)
            }
            .unwrap_or_else(|error| panic!("{format}, {case}: {error}"));
            assert_eq!(imported.len(), 1, "{format}, {case}");
            let entry = &imported[0].entry;
            assert_eq!(entry.name, "Example", "{format}, {case}");
            assert_eq!(
                entry.username.as_deref(),
                Some(username),
                "{format}, {case}"
            );
            assert_eq!(entry.password, password, "{format}, {case}");
            assert_eq!(
                entry.notes.as_ref().map(|s| s.as_str()),
                Some("personal"),
                "{format}, {case}"
            );
            assert_eq!(
                entry.url.as_deref(),
                Some("https://example.com/login"),
                "{format}, {case}"
            );
        }
    }
    assert!(import_csv("name,username\nExample,alice\n", "missing.csv").is_err());
    for (case, document) in [
        ("missing", r#"[{"name":"Example"}]"#),
        ("null", r#"[{"name":"Example","password":null}]"#),
    ] {
        assert!(
            import_json(document, "invalid.json").is_err(),
            "{case} password"
        );
    }
}

#[test]
fn malformed_external_dates_report_loss_while_portable_and_native_dates_are_strict() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("external.json");
    fs::write(
        &input,
        r#"[{"name":"test","password":"secret","created":"yesterday","modified":"unknown"}]"#,
    )
    .unwrap();
    let mut imported = Vault::memory();
    let report = imported
        .import_with_options(
            input.display().to_string(),
            ConflictPolicy::Skip,
            false,
            10,
            &mut VaultCredentials::default(),
        )
        .unwrap();
    assert_eq!(report.loss_count, 2);
    assert!(!report.losses.join(" ").contains("secret"));
    assert!(Timestamp::parse(&imported.item(1).unwrap().entry.created).is_ok());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("portable.json");
    memory().export(path.display().to_string(), false).unwrap();
    let mut document: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    document["items"][0]["created"] = "yesterday".into();
    assert!(import_json(&document.to_string(), "portable.json").is_err());
}
#[test]
fn identity_and_revision_exhaustion_leave_live_state_unchanged() {
    let mut vault = memory();
    vault.data.next_item_id = MAX_ITEM_ID + 1;
    let before = vault.clone();
    assert!(
        vault
            .add_entry(
                PasswordEntry {
                    name: "new".into(),
                    username: None,
                    password: "secret".into(),
                    url: None,
                    notes: None,
                    copy: false
                },
                &mut VaultCredentials::default()
            )
            .is_err()
    );
    assert_eq!(vault, before);
    vault.data.revision = MAX_ITEM_ID;
    let before = vault.clone();
    assert!(
        vault
            .update_typed_entry_with_limit(update(1, "new"), &mut VaultCredentials::default(), 10)
            .is_err()
    );
    assert_eq!(vault, before);
    vault.data.revision = 0;
    vault.item_mut(1).unwrap().revision = MAX_ITEM_ID;
    let before = vault.clone();
    assert!(
        vault
            .update_typed_entry_with_limit(update(1, "new"), &mut VaultCredentials::default(), 10)
            .is_err()
    );
    assert_eq!(vault, before);
}
#[test]
fn typed_totp_has_correct_lifetime_without_mutating_any_revision() {
    let mut vault = memory();
    let mut key = VaultCredentials::default();
    for period in [30, 60] {
        vault
            .set_totp(
                Target::Id(1),
                &format!("otpauth://totp/Test?secret={SECRET}&period={period}"),
                &mut key,
            )
            .unwrap();
        let before = vault.clone();
        for (timestamp, code, ttl) in [
            (0, "755224", period),
            (period - 1, "755224", 1),
            (period, "287082", period),
            (period + 10, "287082", period - 10),
            (period * 2, "359152", period),
        ] {
            assert_eq!(
                vault.totp_at(&Target::Id(1), timestamp).unwrap(),
                (code.into(), ttl)
            );
        }
        assert_eq!(vault, before);
    }
}
#[test]
fn oversize_import_is_rejected_before_parsing_or_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("oversize.json");
    let file = fs::File::create(&path).unwrap();
    file.set_len(MAX_IMPORT_BYTES + 1).unwrap();
    let mut vault = memory();
    let before = vault.clone();
    assert!(
        vault
            .import_with_options(
                path.display().to_string(),
                ConflictPolicy::Skip,
                false,
                10,
                &mut VaultCredentials::default()
            )
            .is_err()
    );
    assert_eq!(vault, before);
}
