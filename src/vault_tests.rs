#![allow(unused_must_use)]
use super::audit::password_hash;
use super::browser::{url_match_json, url_scheme};
use super::import::{import_csv, import_json};
use super::totp::{normalize_totp_configuration, parse_totp_configuration};
use super::*;
use crate::encryption::gen_master_key;
use crate::file::init_test_data_dir;
use chrono::FixedOffset;
use proptest::prelude::*;
use std::{fs, thread};

const HISTORY_LIMIT: usize = 10;

#[test]
fn browser_login_summaries_are_secret_free_and_selection_is_site_scoped() {
    let mut vault = Vault {
        entries: vec![
            VaultEntry {
                id: 1,
                name: "Personal".into(),
                password: "first-secret".into(),
                url: Some("https://example.com".into()),
                ..VaultEntry::default()
            },
            VaultEntry {
                id: 2,
                name: "Other site".into(),
                password: "other-secret".into(),
                url: Some("https://other.example".into()),
                ..VaultEntry::default()
            },
            VaultEntry {
                id: 3,
                name: "Card".into(),
                password: "card-secret".into(),
                url: Some("https://example.com".into()),
                ..VaultEntry::default()
            },
        ],
        metadata: VaultMetadata::default(),
        recovery: RecoveryData::default(),
    };
    vault.recovery.entry_metadata.push(EntryMetadata {
        entry_id: 3,
        kind: ItemKind::PaymentCard,
        ..EntryMetadata::default()
    });
    vault.recovery.totp.push(TotpRecord {
        entry_id: 1,
        configuration: "totp-secret".into(),
    });
    let summaries = vault.browser_logins_json("https://example.com");
    assert!(!summaries.contains("secret"));
    assert!(!summaries.contains("password"));
    let summaries: serde_json::Value = serde_json::from_str(&summaries).unwrap();
    assert_eq!(summaries.as_array().unwrap().len(), 1);
    assert_eq!(summaries[0]["has_totp"], true);
    let selected = vault.browser_login_json("https://example.com", 1).unwrap();
    assert!(selected.contains("first-secret"));
    assert!(!selected.contains("other-secret"));
    assert!(!selected.contains("totp-secret"));
    assert!(vault.browser_login_json("https://example.com", 2).is_none());
    assert!(vault.browser_login_json("https://example.com", 3).is_none());
    assert!(
        vault
            .browser_login_json("https://example.com", 99)
            .is_none()
    );
    assert_eq!(vault.browser_logins_json("https://unrelated.example"), "[]");
}

fn time_close(time: String) -> bool {
    let thing =
        chrono::DateTime::<FixedOffset>::parse_from_str(&time, "%Y-%m-%d %H:%M:%S%.f %:z").unwrap();
    let diff = chrono::Local::now().signed_duration_since(thing);
    diff.num_seconds() < 1
}

proptest! {
    #[test]
    fn arbitrary_import_documents_never_panic(contents in ".{0,4096}") {
        let _ = import_json(&contents, "fuzz.json");
        let _ = import_csv(&contents, "fuzz.csv");
    }

    #[test]
    fn arbitrary_url_inputs_never_panic(value in ".{0,2048}") {
        let _ = hostname(&value);
        let _ = url_scheme(&value);
        let _ = url_match_json(&[], &[], &[], &value);
    }
}

#[test]
fn misspelled_entries_field_is_rejected() {
    #[derive(Serialize)]
    struct InvalidVault {
        enteries: Vec<VaultEntry>,
        metadata: VaultMetadata,
    }

    let invalid = InvalidVault {
        enteries: vec![VaultEntry {
            id: 1,
            name: "example".to_string(),
            password: "secret".to_string(),
            ..VaultEntry::default()
        }],
        metadata: VaultMetadata {
            filename: "invalid.enc".to_string(),
        },
    };
    let encoded = rmp_serde::to_vec(&invalid).unwrap();
    assert!(rmp_serde::from_slice::<Vault>(&encoded).is_err());
}

#[test]
fn test_url_match_json_escapes_special_chars() {
    let entries = vec![VaultEntry {
        id: 1,
        name: String::from("site\"with\"quote"),
        username: Some(String::from("bob")),
        password: String::from("pa\"ss\\wrd"),
        url: Some(String::from("example.com")),
        notes: None,
        created: String::from("2026-01-01"),
        modified: String::from("2026-01-01"),
    }];
    let totp = vec![TotpRecord {
        entry_id: 1,
        configuration: "secret-never-exported".into(),
    }];
    let json = url_match_json(&entries, &totp, &[], "example.com").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed[0]["password"], "pa\"ss\\wrd");
    assert_eq!(parsed[0]["name"], "site\"with\"quote");
    assert_eq!(parsed[0]["username"], "bob");
    assert_eq!(parsed[0]["id"], 1);
    assert_eq!(parsed[0]["has_totp"], true);
    assert!(!json.contains("secret-never-exported"));
}
#[test]
fn test_url_match_json_no_match_returns_none() {
    let entries = vec![VaultEntry {
        id: 1,
        name: String::from("x"),
        username: None,
        password: String::from("p"),
        url: Some(String::from("other.com")),
        notes: None,
        created: String::from("2026-01-01"),
        modified: String::from("2026-01-01"),
    }];
    assert!(url_match_json(&entries, &[], &[], "example.com").is_none());
}

#[test]
fn browser_autofill_returns_only_cards_and_identities() {
    let mut vault = recovery_test_vault(vec![
        recovery_test_entry(1, "login", "login-user", "login-password"),
        recovery_test_entry(2, "Personal Visa", "Alice Example", "4111111111111111"),
        recovery_test_entry(3, "Home identity", "alice@example.com", ""),
    ]);
    vault.recovery.entry_metadata = vec![
        EntryMetadata {
            entry_id: 2,
            kind: ItemKind::PaymentCard,
            custom_fields: vec![CustomField {
                name: "expiration month".into(),
                value: "09".into(),
                secret: false,
            }],
            ..EntryMetadata::default()
        },
        EntryMetadata {
            entry_id: 3,
            kind: ItemKind::Identity,
            custom_fields: vec![CustomField {
                name: "city".into(),
                value: "Boise".into(),
                secret: false,
            }],
            ..EntryMetadata::default()
        },
    ];

    let parsed: serde_json::Value = serde_json::from_str(&vault.browser_autofill_json()).unwrap();
    let items = parsed.as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["kind"], "payment-card");
    assert!(items[0].get("primary_secret").is_none());
    assert!(items[0].get("custom_fields").is_none());
    assert_eq!(items[1]["kind"], "identity");
    assert!(!vault.browser_autofill_json().contains("login-password"));

    let card: serde_json::Value =
        serde_json::from_str(&vault.browser_autofill_item_json(2).unwrap()).unwrap();
    assert_eq!(card["primary_secret"], "4111111111111111");
    assert_eq!(card["custom_fields"][0]["value"], "09");
    assert!(vault.browser_autofill_item_json(1).is_none());
}

#[test]
fn test_url_match_json_rejects_substring_lookalike() {
    let entries = vec![VaultEntry {
        id: 1,
        name: String::from("lookalike"),
        username: Some(String::from("alice")),
        password: String::from("secret"),
        url: Some(String::from("https://notexample.com/login")),
        notes: None,
        created: String::from("2026-01-01"),
        modified: String::from("2026-01-01"),
    }];
    assert!(url_match_json(&entries, &[], &[], "example.com").is_none());
}

#[test]
fn test_hostname_ignores_scheme_path_port_and_case() {
    assert!(hosts_match("HTTPS://Example.COM:443/login", "example.com"));
}
#[test]
fn https_credentials_are_not_returned_to_http_pages() {
    assert!(!hosts_match(
        "https://example.com/login",
        "http://example.com"
    ));
    assert!(hosts_match(
        "https://example.com/login",
        "https://example.com"
    ));
    assert!(!hosts_match("example.com", "http://example.com"));
    assert!(hosts_match("http://example.com", "https://example.com"));
}
#[test]
fn test_domain_matching_is_exact_by_default() {
    assert!(!hosts_match("example.com", "login.example.com"));
    assert!(!hosts_match("mail.example.com", "example.com"));
}
#[test]
fn test_explicit_wildcard_matches_only_subdomains() {
    assert!(hosts_match("*.example.com", "login.example.com"));
    assert!(!hosts_match("*.example.com", "example.com"));
    assert!(!hosts_match("*.github.io", "attacker.github.io"));
}
#[test]
fn test_url_match_json_partial_match() {
    let entries = vec![VaultEntry {
        id: 2,
        name: String::from("x"),
        username: None,
        password: String::from("p"),
        url: Some(String::from("*.example.com")),
        notes: None,
        created: String::from("2026-01-01"),
        modified: String::from("2026-01-01"),
    }];
    let json = url_match_json(&entries, &[], &[], "mail.example.com").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed[0]["id"], 2);
    assert_eq!(parsed[0]["has_totp"], false);
}
#[test]
fn test_delete_entry_returns_false_when_not_found() {
    let mut vlt = Vault {
        entries: vec![VaultEntry {
            id: 1,
            name: String::from("test"),
            username: None,
            password: String::from("p"),
            url: None,
            notes: None,
            created: String::from("2026-01-01"),
            modified: String::from("2026-01-01"),
        }],
        metadata: VaultMetadata {
            filename: "test.enc".into(),
        },
        recovery: RecoveryData::default(),
    };
    let mut si = ServerInfo {
        locked: true,
        keypass: None,
    };
    let original = vlt.clone();
    for target in [Target::Name("nope".into()), Target::Id(0), Target::Id(100)] {
        assert!(
            !vlt.delete_entry(target.clone(), &mut si).unwrap(),
            "{target:?}"
        );
        assert_eq!(vlt, original, "{target:?}");
    }
    assert!(
        vlt.delete_entry(Target::Name("test".into()), &mut si)
            .unwrap()
    );
}
#[test]
fn test_update_entry_returns_false_when_not_found() {
    let mut vlt = Vault {
        entries: vec![VaultEntry {
            id: 1,
            name: String::from("test"),
            username: None,
            password: String::from("p"),
            url: None,
            notes: None,
            created: String::from("2026-01-01"),
            modified: String::from("2026-01-01"),
        }],
        metadata: VaultMetadata {
            filename: "test.enc".into(),
        },
        recovery: RecoveryData::default(),
    };
    let mut si = ServerInfo {
        locked: true,
        keypass: None,
    };
    let original = vlt.clone();
    for target in [Target::Name("nope".into()), Target::Id(0), Target::Id(100)] {
        let upd = EntryUpdate {
            target: target.clone(),
            update: UpdateArgs {
                name: Some("x".into()),
                username: None,
                password: false,
                generate_password: false,
                url: None,
                notes: None,
            },
            password: None,
        };
        assert!(
            !vlt.update_entry_with_limit(upd, &mut si, HISTORY_LIMIT)
                .unwrap(),
            "{target:?}"
        );
        assert_eq!(vlt, original, "{target:?}");
    }
}
#[test]
fn test_add_entry() {
    for info in [
        PasswordEntry {
            name: "test".into(),
            username: Some("test".into()),
            password: "test123".into(),
            url: None,
            notes: None,
            copy: false,
        },
        PasswordEntry {
            name: "full_entry".into(),
            username: Some("admin".into()),
            password: "secret123".into(),
            url: Some("https://example.com".into()),
            notes: Some("important account".into()),
            copy: false,
        },
        PasswordEntry {
            name: "minimal".into(),
            username: None,
            password: "pass".into(),
            url: None,
            notes: None,
            copy: false,
        },
    ] {
        let mut vault = recovery_test_vault(Vec::new());
        assert!(
            vault
                .add_entry(info.clone(), &mut ServerInfo::default())
                .unwrap()
        );
        let expected = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: info.name,
                username: info.username,
                password: info.password,
                url: info.url,
                notes: info.notes,
                created: vault.entries[0].created.clone(),
                modified: vault.entries[0].modified.clone(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData {
                next_entry_id: 2,
                ..RecoveryData::default()
            },
        };
        assert_eq!(vault, expected);
        assert!(time_close(vault.entries[0].created.clone()));
        assert!(time_close(vault.entries[0].modified.clone()));
    }
}
#[test]
fn test_delete_id() {
    let mut vlt = Vault {
        entries: vec![VaultEntry {
            id: 1,
            name: String::from("test"),
            username: Some(String::from("test")),
            password: String::from("test123"),
            url: None,
            notes: None,
            created: chrono::Local::now().to_string(),
            modified: chrono::Local::now().to_string(),
        }],
        metadata: VaultMetadata {
            filename: "test.enc".into(),
        },
        recovery: RecoveryData::default(),
    };
    vlt.delete_entry(
        Target::Id(1),
        &mut ServerInfo {
            locked: true,
            keypass: None,
        },
    );
    assert!(vlt.entries.is_empty());
    assert_eq!(vlt.recovery.trash.len(), 1);
    assert_eq!(vlt.recovery.trash[0].entry.name, "test");
}
#[test]
fn test_delete_name() {
    let mut vlt = Vault {
        entries: vec![VaultEntry {
            id: 1,
            name: String::from("test"),
            username: Some(String::from("test")),
            password: String::from("test123"),
            url: None,
            notes: None,
            created: chrono::Local::now().to_string(),
            modified: chrono::Local::now().to_string(),
        }],
        metadata: VaultMetadata {
            filename: "test.enc".into(),
        },
        recovery: RecoveryData::default(),
    };
    vlt.delete_entry(
        Target::Name("test".into()),
        &mut ServerInfo {
            locked: true,
            keypass: None,
        },
    );
    assert!(vlt.entries.is_empty());
    assert_eq!(vlt.recovery.trash.len(), 1);
    assert_eq!(vlt.recovery.trash[0].entry.name, "test");
}
#[test]
fn test_update_id() {
    let mut vlt = Vault {
        entries: vec![VaultEntry {
            id: 1,
            name: String::from("test"),
            username: Some(String::from("test")),
            password: String::from("test123"),
            url: None,
            notes: None,
            created: chrono::Local::now().to_string(),
            modified: chrono::Local::now().to_string(),
        }],
        metadata: VaultMetadata {
            filename: "test.enc".into(),
        },
        recovery: RecoveryData::default(),
    };
    vlt.update_entry_with_limit(
        EntryUpdate {
            target: Target::Id(1),
            update: UpdateArgs {
                name: Some(String::from("test2")),
                username: Some(String::from("test2")),
                password: false,
                generate_password: false,
                url: None,
                notes: None,
            },
            password: None,
        },
        &mut ServerInfo {
            locked: true,
            keypass: None,
        },
        HISTORY_LIMIT,
    );
    let expected = Vault {
        entries: vec![VaultEntry {
            id: 1,
            name: String::from("test2"),
            username: Some(String::from("test2")),
            password: String::from("test123"),
            url: None,
            notes: None,
            created: vlt.entries[0].created.clone(),
            modified: vlt.entries[0].modified.clone(),
        }],
        metadata: VaultMetadata {
            filename: "test.enc".into(),
        },
        recovery: RecoveryData::default(),
    };
    assert_eq!(vlt, expected);
    assert!(time_close(vlt.entries[0].modified.clone()))
}
#[test]
fn test_update_name() {
    let mut vlt = Vault {
        entries: vec![VaultEntry {
            id: 1,
            name: String::from("test"),
            username: Some(String::from("test")),
            password: String::from("test123"),
            url: None,
            notes: None,
            created: chrono::Local::now().to_string(),
            modified: chrono::Local::now().to_string(),
        }],
        metadata: VaultMetadata {
            filename: "test.enc".into(),
        },
        recovery: RecoveryData::default(),
    };
    vlt.update_entry_with_limit(
        EntryUpdate {
            target: Target::Name(String::from("test")),
            update: UpdateArgs {
                name: Some(String::from("test2")),
                username: Some(String::from("test2")),
                password: false,
                generate_password: false,
                url: None,
                notes: None,
            },
            password: None,
        },
        &mut ServerInfo {
            locked: true,
            keypass: None,
        },
        HISTORY_LIMIT,
    );
    let expected = Vault {
        entries: vec![VaultEntry {
            id: 1,
            name: String::from("test2"),
            username: Some(String::from("test2")),
            password: String::from("test123"),
            url: None,
            notes: None,
            created: vlt.entries[0].created.clone(),
            modified: vlt.entries[0].modified.clone(),
        }],
        metadata: VaultMetadata {
            filename: "test.enc".into(),
        },
        recovery: RecoveryData::default(),
    };
    assert_eq!(vlt, expected);
    assert!(time_close(vlt.entries[0].modified.clone()))
}
#[test]
fn test_export_import() {
    let mut vault = recovery_test_vault(vec![
        recovery_test_entry(1, "Login", "alice", " padded-secret "),
        recovery_test_entry(2, "Identity", "alice@example.com", ""),
    ]);
    vault.recovery.entry_metadata.push(EntryMetadata {
        entry_id: 2,
        kind: ItemKind::Identity,
        ..EntryMetadata::default()
    });
    vault.recovery.next_entry_id = 3;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("export.csv").display().to_string();
    vault.export(path.clone(), false).unwrap();
    let mut imported = recovery_test_vault(Vec::new());
    let mut server_info = ServerInfo::default();
    let preview = imported
        .import_with_options(
            path.clone(),
            ConflictPolicy::Skip,
            true,
            HISTORY_LIMIT,
            &mut server_info,
        )
        .unwrap();
    assert_eq!(preview.added, 2);
    assert!(imported.entries.is_empty());
    imported
        .import_with_options(
            path,
            ConflictPolicy::Skip,
            false,
            HISTORY_LIMIT,
            &mut server_info,
        )
        .unwrap();
    assert_eq!(imported.entries.len(), 2);
    assert_eq!(imported.entries[0].password, " padded-secret ");
    assert_eq!(imported.entries[1].password, "");
    // CSV intentionally omits typed metadata, but preserves every entry field.
    vault.recovery.entry_metadata.clear();
    assert_eq!(vault, imported);
}

#[test]
fn test_failed_import_does_not_partially_modify_vault() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "id,name,username,password,url,notes,created,modified").unwrap();
    writeln!(file, "2,valid,user,password,,,created,modified").unwrap();
    // Empty passwords are valid; a row without either a name or URL is not.
    writeln!(file, "3,,user,,,,created,modified").unwrap();

    let mut vault = Vault::default();
    assert!(
        vault
            .import_with_options(
                file.path().display().to_string(),
                ConflictPolicy::Skip,
                false,
                HISTORY_LIMIT,
                &mut ServerInfo::default(),
            )
            .is_err()
    );
    assert!(vault.entries.is_empty());
}

#[test]
fn test_imports_chrome_style_csv() {
    for password in ["secret", " padded-secret \t", " \t ", ""] {
        let mut writer = csv::Writer::from_writer(Vec::new());
        writer
            .write_record(["name", "url", "username", "password", "note"])
            .unwrap();
        writer
            .write_record([
                "Example",
                "https://example.com",
                "alice",
                password,
                "personal",
            ])
            .unwrap();
        let csv = String::from_utf8(writer.into_inner().unwrap()).unwrap();
        let imported = import_csv(&csv, "chrome.csv").unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].entry.name, "Example");
        assert_eq!(imported[0].entry.password, password);
        assert_eq!(imported[0].entry.username.as_deref(), Some("alice"));
        assert_eq!(imported[0].entry.notes.as_deref(), Some("personal"));
    }
    assert!(import_csv("name,username\nExample,alice\n", "missing.csv").is_err());
}

#[test]
fn test_imports_bitwarden_json() {
    for password in ["secret", " padded-secret \t", " \t ", ""] {
        for document in [
            json!({ "items": [{
                "type": 1,
                "name": "Example",
                "notes": "work",
                "login": {
                    "username": "alice",
                    "password": password,
                    "uris": [{ "uri": "https://example.com/login" }]
                }
            }] }),
            json!([{
                "name": "Example",
                "notes": "work",
                "username": "alice",
                "password": password,
                "url": "https://example.com/login"
            }]),
        ] {
            let entries = import_json(&document.to_string(), "logins.json").unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].entry.name, "Example");
            assert_eq!(entries[0].entry.username.as_deref(), Some("alice"));
            assert_eq!(entries[0].entry.notes.as_deref(), Some("work"));
            assert_eq!(
                entries[0].entry.url.as_deref(),
                Some("https://example.com/login")
            );
            assert_eq!(entries[0].entry.password, password);
        }
    }
    assert!(import_json(r#"[{"name":"Example"}]"#, "missing.json").is_err());
    assert!(import_json(r#"[{"name":"Example","password":null}]"#, "null.json").is_err());
}

#[test]
fn test_json_export_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("export.json");
    let vault = Vault {
        entries: vec![VaultEntry {
            id: 1,
            name: "Example".into(),
            username: Some("alice".into()),
            password: "secret".into(),
            url: Some("example.com".into()),
            notes: None,
            created: "created".into(),
            modified: "modified".into(),
        }],
        metadata: VaultMetadata::default(),
        recovery: RecoveryData {
            password_history: vec![PasswordRevision {
                entry_id: 1,
                password: "previous-secret".into(),
                changed: "2025-01-01T00:00:00Z".into(),
            }],
            totp: vec![TotpRecord {
                entry_id: 1,
                configuration: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            }],
            entry_metadata: vec![EntryMetadata {
                entry_id: 1,
                kind: ItemKind::ApiSecret,
                additional_urls: vec!["api.example.com".into()],
                password_changed: Some("2026-01-01T00:00:00Z".into()),
                custom_fields: vec![CustomField {
                    name: "environment".into(),
                    value: "production".into(),
                    secret: false,
                }],
            }],
            ..RecoveryData::default()
        },
    };
    vault.export(path.display().to_string(), false).unwrap();
    let exported: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(exported["format"], PORTABLE_FORMAT);
    assert_eq!(exported["version"], PORTABLE_VERSION);
    let mut imported = Vault::default();
    imported
        .import_with_options(
            path.display().to_string(),
            ConflictPolicy::Skip,
            false,
            HISTORY_LIMIT,
            &mut ServerInfo::default(),
        )
        .unwrap();
    assert_eq!(imported.entries, vault.entries);
    assert_eq!(
        imported.recovery.entry_metadata,
        vault.recovery.entry_metadata
    );
    assert_eq!(
        imported.recovery.password_history,
        vault.recovery.password_history
    );
    assert_eq!(imported.recovery.totp, vault.recovery.totp);
}

#[test]
fn test_import_assigns_local_stable_ids() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "id,name,username,password,url,notes,created,modified").unwrap();
    writeln!(file, "99,first,user,password,,,created,modified").unwrap();

    let mut vault = Vault::default();
    vault
        .import_with_options(
            file.path().display().to_string(),
            ConflictPolicy::Skip,
            false,
            HISTORY_LIMIT,
            &mut ServerInfo::default(),
        )
        .unwrap();
    assert_eq!(vault.entries[0].id, 1);
}

#[test]
fn portable_import_remaps_ids_for_associated_records() {
    let file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    let portable = serde_json::json!({
        "format": PORTABLE_FORMAT,
        "version": PORTABLE_VERSION,
        "exported_at": "2026-01-01T00:00:00Z",
        "items": [{
            "id": 999,
            "name": "Imported API",
            "username": "alice",
            "password": "current-secret",
            "url": "https://api.example.com",
            "notes": null,
            "created": "2025-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "type": "api-secret",
            "additional_urls": ["https://backup.example.com"],
            "custom_fields": [{"name": "env", "value": "prod", "secret": false}],
            "password_changed": "2026-01-01T00:00:00Z",
            "password_history": [{"password": "old-secret", "changed": "2025-06-01T00:00:00Z"}],
            "totp": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        }]
    });
    fs::write(file.path(), serde_json::to_vec(&portable).unwrap()).unwrap();

    let mut vault = recovery_test_vault(vec![recovery_test_entry(
        10,
        "Existing",
        "bob",
        "existing-secret",
    )]);
    vault
        .import_with_options(
            file.path().display().to_string(),
            ConflictPolicy::Skip,
            false,
            HISTORY_LIMIT,
            &mut ServerInfo::default(),
        )
        .unwrap();

    assert_eq!(vault.entries[1].id, 11);
    assert_eq!(vault.recovery.entry_metadata[0].entry_id, 11);
    assert_eq!(vault.recovery.password_history[0].entry_id, 11);
    assert_eq!(vault.recovery.totp[0].entry_id, 11);
}

#[test]
fn test_import_new_persists_vault_to_disk() {
    init_test_data_dir();
    let pass = PasswordType::Password("import_fix_test_pass!".to_string());
    let mut server_info = ServerInfo {
        locked: true,
        keypass: Some(pass.clone()),
    };
    let mut vlt: Option<Vault> = None;
    create_vault(&mut vlt, &mut server_info, false).unwrap();

    let mut tf = NamedTempFile::new().unwrap();
    {
        use std::io::Write;
        writeln!(tf, "id,name,username,password,url,notes,created,modified").unwrap();
        writeln!(
            tf,
            "1,example.com,bob,secret,,,2026-01-01 00:00:00,2026-01-01 00:00:00"
        )
        .unwrap();
        writeln!(
            tf,
            "2,test.org,alice,pw456,,,2026-01-02 00:00:00,2026-01-02 00:00:00"
        )
        .unwrap();
    }
    vlt.as_mut()
        .unwrap()
        .import_with_options(
            tf.path().to_str().unwrap().to_string(),
            ConflictPolicy::Skip,
            false,
            HISTORY_LIMIT,
            &mut server_info,
        )
        .unwrap();

    vlt.lock_vault(&mut server_info);

    let vlt1 = unlock_vault(&mut ServerInfo {
        locked: true,
        keypass: Some(pass),
    })
    .unwrap();
    assert_eq!(vlt1.entries.len(), 2);
    assert_eq!(vlt1.entries[0].name, "example.com");
    assert_eq!(vlt1.entries[1].name, "test.org");

    let fname = vlt1.metadata.filename.clone();
    let _ = fs::remove_file(data_dir().join(fname));
}
#[test]
fn test_lock_unlock_key() {
    init_test_data_dir();
    let key_directory = tempfile::tempdir().unwrap();
    let temp = key_directory.path().join("test_lock_unlock_key.pem");
    let key_path = temp.to_string_lossy().into_owned();
    gen_master_key(&mut PasswordType::Key(key_path.clone()), true);
    let filename = random_vault_filename();
    let vlt = Vault {
        entries: vec![VaultEntry {
            id: 1,
            name: String::from("test"),
            username: Some(String::from("test")),
            password: String::from("test123"),
            url: None,
            notes: None,
            created: chrono::Local::now().to_string(),
            modified: chrono::Local::now().to_string(),
        }],
        metadata: VaultMetadata {
            filename: filename.clone(),
        },
        recovery: RecoveryData::default(),
    };
    let pass = PasswordType::Key(key_path.clone());
    let pass1 = PasswordType::Key(key_path);
    let mut info = ServerInfo {
        locked: false,
        keypass: Some(pass),
    };
    write_vault(&vlt, &mut info).unwrap();
    vlt.lock_vault(&mut info).unwrap();
    let vlt1 = unlock_vault(&mut ServerInfo {
        locked: true,
        keypass: Some(pass1),
    })
    .unwrap();
    let data_path = data_dir();
    let file_path = data_path.join(&filename);
    fs::remove_file(temp).unwrap();
    fs::remove_file(file_path).unwrap();
    assert_eq!(vlt.entries, vlt1.entries);
    assert_eq!(vlt.metadata, vlt1.metadata);
    assert_eq!(vlt1.recovery.next_entry_id, 2);
}
#[test]
fn test_lock_unlock_password() {
    init_test_data_dir();
    let filename = random_vault_filename();
    let vlt = Vault {
        entries: vec![VaultEntry {
            id: 1,
            name: String::from("test"),
            username: Some(String::from("test")),
            password: String::from("test123"),
            url: None,
            notes: None,
            created: chrono::Local::now().to_string(),
            modified: chrono::Local::now().to_string(),
        }],
        metadata: VaultMetadata {
            filename: filename.clone(),
        },
        recovery: RecoveryData::default(),
    };
    let pass = PasswordType::Password("test_password1234!".to_string());
    let pass1 = PasswordType::Password("test_password1234!".to_string());
    let mut info = ServerInfo {
        locked: false,
        keypass: Some(pass),
    };
    write_vault(&vlt, &mut info).unwrap();
    vlt.lock_vault(&mut info).unwrap();
    let vlt1 = unlock_vault(&mut ServerInfo {
        locked: true,
        keypass: Some(pass1),
    })
    .unwrap();
    let data_path = data_dir();
    let file_path = data_path.join(&filename);
    fs::remove_file(file_path).unwrap();
    assert_eq!(vlt.entries, vlt1.entries);
    assert_eq!(vlt.metadata, vlt1.metadata);
    assert_eq!(vlt1.recovery.next_entry_id, 2);
}

#[test]
fn test_create_vault_key() {
    init_test_data_dir();
    for locked in [false, true] {
        let key_directory = tempfile::tempdir().unwrap();
        let key_path = key_directory.path().join("create-vault.key");
        let credential = PasswordType::Key(key_path.to_string_lossy().into_owned());
        let mut vault = None;
        let mut server_info = ServerInfo {
            locked: true,
            keypass: Some(credential.clone()),
        };
        create_vault(&mut vault, &mut server_info, locked).unwrap();
        let (filename, mut stored) = find_vault(&mut credential.clone()).unwrap();
        stored.zeroize();
        if locked {
            assert!(vault.is_none());
        } else {
            assert_eq!(
                vault,
                Some(Vault {
                    entries: Vec::new(),
                    metadata: VaultMetadata {
                        filename: filename.clone()
                    },
                    recovery: RecoveryData::default(),
                })
            );
        }
        fs::remove_file(data_dir().join(filename)).unwrap();
        fs::remove_file(key_path).unwrap();
    }
}

#[test]
fn delete_key_vault_applies_the_requested_key_retention_policy() {
    init_test_data_dir();
    for keep_key in [false, true] {
        let key_directory = tempfile::tempdir().unwrap();
        let key_path = key_directory
            .path()
            .join("delete-vault.key")
            .to_string_lossy()
            .into_owned();
        let mut vault = None;
        let mut server_info = ServerInfo {
            locked: true,
            keypass: Some(PasswordType::Key(key_path.clone())),
        };
        create_vault(&mut vault, &mut server_info, true).unwrap();
        let (filename, mut stored) = find_vault(&mut PasswordType::Key(key_path.clone())).unwrap();
        stored.zeroize();
        delete_vault(PasswordType::Key(key_path.clone()), keep_key).unwrap();
        assert!(!data_dir().join(filename).exists(), "keep_key={keep_key}");
        assert_eq!(
            Path::new(&key_path).is_file(),
            keep_key,
            "keep_key={keep_key}"
        );
    }
}

#[test]
fn test_create_vault_password() {
    init_test_data_dir();
    for locked in [false, true] {
        let credential = PasswordType::Password(
            if locked {
                "Cedar-Lantern-Quartz-4821!"
            } else {
                "Cedar-Lantern-Quartz-9274!"
            }
            .into(),
        );
        let mut vault = None;
        let mut server_info = ServerInfo {
            locked: true,
            keypass: Some(credential.clone()),
        };
        create_vault(&mut vault, &mut server_info, locked).unwrap();
        let (filename, mut stored) = find_vault(&mut credential.clone()).unwrap();
        stored.zeroize();
        if locked {
            assert!(vault.is_none());
        } else {
            assert_eq!(
                vault,
                Some(Vault {
                    entries: Vec::new(),
                    metadata: VaultMetadata {
                        filename: filename.clone()
                    },
                    recovery: RecoveryData::default(),
                })
            );
        }
        fs::remove_file(data_dir().join(filename)).unwrap();
    }
}

#[test]
fn new_vault_rekey_and_backup_passwords_enforce_the_minimum() {
    init_test_data_dir();
    let mut vault = None;
    let mut server_info = ServerInfo {
        locked: true,
        keypass: Some(PasswordType::Password("short".into())),
    };
    assert!(create_vault(&mut vault, &mut server_info, false).is_err());
    assert!(vault.is_none());

    let mut detached = Vault::default();
    assert!(
        detached
            .rekey(
                &mut ServerInfo::default(),
                PasswordType::Password("short".into())
            )
            .is_err()
    );

    let output_dir = tempfile::tempdir().unwrap();
    let path = output_dir.path().join("weak-password.pmbackup");
    let mut short = PasswordType::Password("short".into());
    assert!(
        detached
            .encrypted_backup(path.display().to_string(), &mut short, false)
            .is_err()
    );
    assert!(!path.exists());
}

#[test]
fn test_rekey_replaces_vault_and_new_password_unlocks() {
    init_test_data_dir();
    let unique = format!("{:016x}", rand::random::<u64>());
    let mut server_info = ServerInfo {
        locked: false,
        keypass: Some(PasswordType::Password(format!("old-{unique}"))),
    };
    let mut vault = None;
    create_vault(&mut vault, &mut server_info, false).unwrap();
    let old_path = data_dir().join(&vault.as_ref().unwrap().metadata.filename);
    let new_password = PasswordType::Password(format!("new-{unique}"));
    vault
        .as_mut()
        .unwrap()
        .rekey(&mut server_info, new_password.clone())
        .unwrap();
    let new_path = data_dir().join(&vault.as_ref().unwrap().metadata.filename);
    assert_eq!(old_path, new_path);
    assert!(new_path.exists());
    let mut unlock_info = ServerInfo {
        locked: true,
        keypass: Some(new_password),
    };
    assert!(unlock_vault(&mut unlock_info).is_some());
    fs::remove_file(new_path).unwrap();
}
#[test]
fn test_add_duplicate_entry_name() {
    let mut vlt = Vault {
        entries: vec![],
        metadata: VaultMetadata {
            filename: "test.enc".into(),
        },
        recovery: RecoveryData::default(),
    };
    let mut server_info = ServerInfo {
        locked: true,
        keypass: None,
    };
    assert!(
        vlt.add_entry(
            PasswordEntry {
                name: String::from("test"),
                username: Some(String::from("user1")),
                password: String::from("pass1"),
                url: None,
                notes: None,
                copy: false,
            },
            &mut server_info,
        )
        .unwrap()
    );
    let initial_len = vlt.entries.len();

    // Same name, different username -> allowed (multiple accounts per site)
    assert!(
        vlt.add_entry(
            PasswordEntry {
                name: String::from("test"),
                username: Some(String::from("user2")),
                password: String::from("pass2"),
                url: None,
                notes: None,
                copy: false,
            },
            &mut server_info,
        )
        .unwrap()
    );
    assert_eq!(vlt.entries.len(), initial_len + 1);

    // Same name AND same username -> still blocked
    assert!(
        !vlt.add_entry(
            PasswordEntry {
                name: String::from("test"),
                username: Some(String::from("user1")),
                password: String::from("pass3"),
                url: None,
                notes: None,
                copy: false,
            },
            &mut server_info,
        )
        .unwrap()
    );
    assert_eq!(vlt.entries.len(), initial_len + 1);
}
#[test]
fn test_add_multiple_entries_ids_sequential() {
    let mut vlt = Vault {
        entries: vec![],
        metadata: VaultMetadata {
            filename: "test.enc".into(),
        },
        recovery: RecoveryData::default(),
    };
    for i in 0..5 {
        vlt.add_entry(
            PasswordEntry {
                name: format!("entry{}", i),
                username: Some(format!("user{}", i)),
                password: format!("pass{}", i),
                url: None,
                notes: None,
                copy: false,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
    }
    for (i, entry) in vlt.entries.iter().enumerate() {
        assert_eq!(entry.id, i + 1);
    }
}
#[test]
fn test_delete_entry_preserves_other_ids() {
    let mut vlt = Vault {
        entries: vec![],
        metadata: VaultMetadata {
            filename: "test.enc".into(),
        },
        recovery: RecoveryData::default(),
    };
    for i in 0..5 {
        vlt.add_entry(
            PasswordEntry {
                name: format!("entry{}", i),
                username: Some(format!("user{}", i)),
                password: format!("pass{}", i),
                url: None,
                notes: None,
                copy: false,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
    }
    vlt.delete_entry(
        Target::Id(2),
        &mut ServerInfo {
            locked: true,
            keypass: None,
        },
    );
    assert_eq!(
        vlt.entries.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        vec![1, 3, 4, 5]
    );
}

#[test]
fn test_delete_name_with_only_first_match() {
    let mut vlt = Vault {
        entries: vec![
            VaultEntry {
                id: 1,
                name: String::from("dup"),
                username: Some(String::from("user1")),
                password: String::from("pass1"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            },
            VaultEntry {
                id: 2,
                name: String::from("dup"),
                username: Some(String::from("user2")),
                password: String::from("pass2"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            },
        ],
        metadata: VaultMetadata {
            filename: "test.enc".into(),
        },
        recovery: RecoveryData::default(),
    };
    vlt.delete_entry(
        Target::Name("dup".into()),
        &mut ServerInfo {
            locked: true,
            keypass: None,
        },
    );
    assert_eq!(vlt.entries.len(), 1);
    assert_eq!(vlt.entries[0].id, 2);
    assert_eq!(vlt.entries[0].username, Some(String::from("user2")));
}

#[test]
fn test_update_individual_and_all_fields() {
    for field in ["password", "url", "notes", "all"] {
        let all = field == "all";
        let mut initial = recovery_test_entry(
            1,
            if all { "original" } else { "test" },
            if all { "old_user" } else { "test" },
            if all {
                "old_pass"
            } else if field == "password" {
                "oldpass"
            } else {
                "test123"
            },
        );
        initial.url = all.then(|| "http://old.com".into());
        initial.notes = all.then(|| "old notes".into());
        initial.created = chrono::Local::now().to_string();
        initial.modified = initial.created.clone();
        let mut vault = recovery_test_vault(vec![initial.clone()]);
        let update = UpdateArgs {
            name: all.then(|| "new_name".into()),
            username: all.then(|| "new_user".into()),
            password: all || field == "password",
            generate_password: false,
            url: (all || field == "url").then(|| {
                if all {
                    "https://new.com"
                } else {
                    "https://example.com"
                }
                .into()
            }),
            notes: (all || field == "notes")
                .then(|| if all { "new notes" } else { "important notes" }.into()),
        };
        let password = update
            .password
            .then(|| if all { "new_pass" } else { "newpass" }.into());
        assert!(
            vault
                .update_entry_with_limit(
                    EntryUpdate {
                        target: Target::Id(1),
                        update,
                        password
                    },
                    &mut ServerInfo::default(),
                    HISTORY_LIMIT
                )
                .unwrap(),
            "{field}"
        );
        let entry = &vault.entries[0];
        assert_eq!(entry.name, if all { "new_name" } else { "test" }, "{field}");
        assert_eq!(
            entry.username.as_deref(),
            Some(if all { "new_user" } else { "test" }),
            "{field}"
        );
        assert_eq!(
            entry.password,
            if all {
                "new_pass"
            } else if field == "password" {
                "newpass"
            } else {
                "test123"
            },
            "{field}"
        );
        assert_eq!(
            entry.url.as_deref(),
            if all {
                Some("https://new.com")
            } else if field == "url" {
                Some("https://example.com")
            } else {
                None
            },
            "{field}"
        );
        assert_eq!(
            entry.notes.as_deref(),
            if all {
                Some("new notes")
            } else if field == "notes" {
                Some("important notes")
            } else {
                None
            },
            "{field}"
        );
        assert_eq!(entry.created, initial.created, "{field}");
    }
}

#[test]
fn test_update_no_changes() {
    let mut vlt = Vault {
        entries: vec![VaultEntry {
            id: 1,
            name: String::from("test"),
            username: Some(String::from("test")),
            password: String::from("test123"),
            url: None,
            notes: None,
            created: chrono::Local::now().to_string(),
            modified: chrono::Local::now().to_string(),
        }],
        metadata: VaultMetadata {
            filename: "test.enc".into(),
        },
        recovery: RecoveryData::default(),
    };
    let original_modified = vlt.entries[0].modified.clone();
    thread::sleep(std::time::Duration::from_millis(10));
    vlt.update_entry_with_limit(
        EntryUpdate {
            target: Target::Id(1),
            update: UpdateArgs {
                name: None,
                username: None,
                password: false,
                generate_password: false,
                url: None,
                notes: None,
            },
            password: None,
        },
        &mut ServerInfo {
            locked: true,
            keypass: None,
        },
        HISTORY_LIMIT,
    );
    assert_eq!(vlt.entries[0].modified, original_modified);
}

fn recovery_test_vault(entries: Vec<VaultEntry>) -> Vault {
    Vault {
        entries,
        metadata: VaultMetadata {
            filename: "test.enc".into(),
        },
        recovery: RecoveryData::default(),
    }
}

fn recovery_test_entry(id: usize, name: &str, username: &str, password: &str) -> VaultEntry {
    VaultEntry {
        id,
        name: name.into(),
        username: Some(username.into()),
        password: password.into(),
        url: Some("example.com".into()),
        notes: None,
        created: "created".into(),
        modified: "modified".into(),
    }
}

#[test]
fn password_updates_create_restorable_history() {
    let mut vault = recovery_test_vault(vec![recovery_test_entry(1, "site", "alice", "old")]);
    let mut server_info = ServerInfo::default();
    vault
        .update_entry_with_limit(
            EntryUpdate {
                target: Target::Id(1),
                update: UpdateArgs {
                    name: None,
                    username: None,
                    password: true,
                    generate_password: false,
                    url: None,
                    notes: None,
                },
                password: Some("new".into()),
            },
            &mut server_info,
            HISTORY_LIMIT,
        )
        .unwrap();
    assert_eq!(vault.recovery.password_history[0].password, "old");
    vault
        .restore_password(Target::Id(1), 1, &mut server_info)
        .unwrap();
    assert_eq!(vault.entries[0].password, "old");
    assert_eq!(vault.recovery.password_history[0].password, "new");
}

#[test]
fn delete_restore_and_purge_use_encrypted_trash_state() {
    let mut vault = recovery_test_vault(vec![recovery_test_entry(1, "site", "alice", "pass")]);
    let mut server_info = ServerInfo::default();
    assert!(vault.delete_entry(Target::Id(1), &mut server_info).unwrap());
    assert!(vault.entries.is_empty());
    assert_eq!(vault.recovery.trash.len(), 1);
    assert!(vault.restore_trashed(1, &mut server_info).unwrap());
    assert_eq!(vault.entries[0].name, "site");
    assert!(vault.recovery.trash.is_empty());
    vault.delete_entry(Target::Id(1), &mut server_info).unwrap();
    assert!(vault.purge_trash(None, &mut server_info).unwrap());
    assert!(vault.recovery.trash.is_empty());
}

#[test]
fn password_history_is_bounded() {
    let mut vault = recovery_test_vault(vec![recovery_test_entry(1, "site", "alice", "p0")]);
    for index in 1..=15 {
        let old = std::mem::replace(&mut vault.entries[0].password, format!("p{index}"));
        vault.push_password_history_with_limit(1, old, HISTORY_LIMIT);
    }
    assert_eq!(vault.recovery.password_history.len(), HISTORY_LIMIT);
    assert_eq!(vault.recovery.password_history[0].password, "p5");
}

#[test]
fn stable_ids_survive_delete_add_and_restore() {
    let mut vault = recovery_test_vault(vec![
        recovery_test_entry(4, "first", "alice", "one"),
        recovery_test_entry(9, "second", "bob", "two"),
    ]);
    let mut server_info = ServerInfo::default();

    assert!(vault.delete_entry(Target::Id(4), &mut server_info).unwrap());
    assert_eq!(vault.entries[0].id, 9);
    vault
        .add_entry(
            PasswordEntry {
                name: "third".into(),
                username: Some("carol".into()),
                password: "three".into(),
                url: None,
                notes: None,
                copy: false,
            },
            &mut server_info,
        )
        .unwrap();
    assert_eq!(vault.entries[1].id, 10);

    assert!(vault.restore_trashed(1, &mut server_info).unwrap());
    assert_eq!(vault.entries[2].id, 4);
    assert_eq!(vault.recovery.next_entry_id, 11);

    vault
        .delete_entry(Target::Id(10), &mut server_info)
        .unwrap();
    vault.purge_trash(None, &mut server_info).unwrap();
    vault
        .add_entry(
            PasswordEntry {
                name: "fourth".into(),
                username: Some("dana".into()),
                password: "four".into(),
                url: None,
                notes: None,
                copy: false,
            },
            &mut server_info,
        )
        .unwrap();
    assert_eq!(vault.entries.last().unwrap().id, 11);
}

#[test]
fn search_is_case_insensitive_combines_filters_and_excludes_passwords() {
    let mut first = recovery_test_entry(3, "GitHub", "Alice", "hidden-token");
    first.url = Some("https://github.com/login".into());
    first.notes = Some("Personal account".into());
    let mut second = recovery_test_entry(8, "GitLab", "alice-work", "different-secret");
    second.url = Some("https://gitlab.example".into());
    second.notes = Some("Work account".into());
    let vault = recovery_test_vault(vec![first, second]);

    let query_results = vault.search_entries(&SearchFilter {
        query: Some("ALICE".into()),
        ..SearchFilter::default()
    });
    assert_eq!(query_results.len(), 2);

    let filtered = vault.search_entries(&SearchFilter {
        name: Some("git".into()),
        url: Some("github.com".into()),
        notes: Some("personal".into()),
        ..SearchFilter::default()
    });
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].id, 3);

    let password_results = vault.search_entries(&SearchFilter {
        query: Some("hidden-token".into()),
        ..SearchFilter::default()
    });
    assert!(password_results.is_empty());
}

#[test]
fn additional_urls_are_searchable_and_used_only_for_login_autofill() {
    let login = recovery_test_entry(3, "Example", "alice", "strong-enough-secret");
    let note = recovery_test_entry(4, "Private note", "", "not-for-the-browser");
    let metadata = vec![
        EntryMetadata {
            entry_id: 3,
            kind: ItemKind::Login,
            additional_urls: vec!["https://accounts.example.net/login".into()],
            password_changed: None,
            custom_fields: Vec::new(),
        },
        EntryMetadata {
            entry_id: 4,
            kind: ItemKind::SecureNote,
            additional_urls: vec!["https://notes.example.net".into()],
            password_changed: None,
            custom_fields: Vec::new(),
        },
    ];
    let mut vault = recovery_test_vault(vec![login.clone(), note.clone()]);
    vault.recovery.entry_metadata = metadata.clone();

    let matches = vault.search_entries(&SearchFilter {
        url: Some("accounts.example.net".into()),
        ..SearchFilter::default()
    });
    assert_eq!(
        matches.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        [3]
    );
    assert!(url_match_json(&[login], &[], &metadata, "accounts.example.net").is_some());
    assert!(url_match_json(&[note], &[], &metadata, "notes.example.net").is_none());
}

#[test]
fn typed_add_and_update_persist_item_metadata_by_stable_id() {
    let mut vault = recovery_test_vault(Vec::new());
    let mut server_info = ServerInfo::default();
    assert!(
        vault
            .add_typed_entry(
                TypedEntry {
                    entry: PasswordEntry {
                        name: "Router".into(),
                        username: Some("WPA3".into()),
                        password: "network-secret".into(),
                        url: Some("https://router.example".into()),
                        notes: None,
                        copy: false,
                    },
                    kind: ItemKind::Wifi,
                    additional_urls: vec![
                        "https://backup-router.example".into(),
                        "https://backup-router.example".into(),
                    ],
                    custom_fields: vec![
                        CustomField {
                            name: "location".into(),
                            value: "upstairs".into(),
                            secret: false,
                        },
                        CustomField {
                            name: "admin-pin".into(),
                            value: "8192".into(),
                            secret: true,
                        },
                    ],
                },
                &mut server_info,
            )
            .unwrap()
    );
    let entry_id = vault.entries[0].id;
    assert_eq!(vault.item_kind(entry_id), ItemKind::Wifi);
    assert_eq!(vault.custom_fields(entry_id).len(), 2);
    assert_eq!(
        vault
            .search_entries(&SearchFilter {
                query: Some("upstairs".into()),
                ..SearchFilter::default()
            })
            .len(),
        1
    );
    assert!(
        vault
            .search_entries(&SearchFilter {
                query: Some("8192".into()),
                ..SearchFilter::default()
            })
            .is_empty()
    );
    assert_eq!(
        vault.all_urls(&vault.entries[0]).collect::<Vec<_>>(),
        ["https://router.example", "https://backup-router.example"]
    );

    assert!(
        vault
            .update_typed_entry_with_limit(
                TypedUpdate {
                    entry: EntryUpdate {
                        target: Target::Id(entry_id),
                        update: UpdateArgs {
                            name: None,
                            username: None,
                            password: false,
                            generate_password: false,
                            url: None,
                            notes: None,
                        },
                        password: None,
                    },
                    kind: Some(ItemKind::Login),
                    add_url: vec!["https://new.example".into()],
                    remove_url: vec!["https://router.example".into()],
                    clear_urls: false,
                    set_fields: vec![CustomField {
                        name: "location".into(),
                        value: "downstairs".into(),
                        secret: false,
                    }],
                    remove_fields: vec!["admin-pin".into()],
                    clear_fields: false,
                },
                &mut server_info,
                HISTORY_LIMIT,
            )
            .unwrap()
    );
    assert_eq!(vault.item_kind(entry_id), ItemKind::Login);
    assert_eq!(
        vault.custom_fields(entry_id),
        [CustomField {
            name: "location".into(),
            value: "downstairs".into(),
            secret: false,
        }]
    );
    assert_eq!(
        vault.all_urls(&vault.entries[0]).collect::<Vec<_>>(),
        ["https://backup-router.example", "https://new.example"]
    );
}

#[test]
fn import_preview_and_conflict_policies_are_deterministic() {
    let mut existing = recovery_test_entry(7, "Example", "alice", "old-password");
    existing.url = Some("https://example.com".into());
    let mut vault = recovery_test_vault(vec![existing]);
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "name,username,password,url").unwrap();
    writeln!(file, "Example,alice,new-password,https://example.com").unwrap();
    let path = file.path().display().to_string();
    let mut server_info = ServerInfo::default();

    let before = vault.clone();
    let preview = vault
        .import_with_options(
            path.clone(),
            ConflictPolicy::Replace,
            true,
            1,
            &mut server_info,
        )
        .unwrap();
    assert_eq!(preview.total, 1);
    assert_eq!(preview.replaced, 1);
    assert_eq!(vault, before);

    let replaced = vault
        .import_with_options(
            path.clone(),
            ConflictPolicy::Replace,
            false,
            1,
            &mut server_info,
        )
        .unwrap();
    assert_eq!(replaced.replaced, 1);
    assert_eq!(vault.entries[0].id, 7);
    assert_eq!(vault.entries[0].password, "new-password");
    assert_eq!(vault.recovery.password_history.len(), 1);

    let kept = vault
        .import_with_options(path, ConflictPolicy::KeepBoth, false, 1, &mut server_info)
        .unwrap();
    assert_eq!(kept.renamed, 1);
    assert_eq!(vault.entries.len(), 2);
    assert_eq!(vault.entries[1].name, "Example (imported)");
}

#[test]
fn replacement_imports_refresh_password_age_only_when_the_secret_changes() {
    let directory = tempfile::tempdir().unwrap();
    for portable in [false, true] {
        for limit in [0, HISTORY_LIMIT] {
            let mut entry = recovery_test_entry(7, "Example", "alice", "old-password");
            entry.created = "2000-01-01T00:00:00Z".into();
            let mut vault = recovery_test_vault(vec![entry.clone()]);
            vault.recovery.entry_metadata.push(EntryMetadata {
                entry_id: 7,
                password_changed: Some("2001-01-01T00:00:00Z".into()),
                ..EntryMetadata::default()
            });
            assert!(vault.password_is_stale(&vault.entries[0], 365));
            let path = directory.path().join(if portable {
                "replace.json"
            } else {
                "replace.csv"
            });
            if portable {
                entry.password = "new-password".into();
                let mut source = recovery_test_vault(vec![entry]);
                source.recovery.entry_metadata.push(EntryMetadata {
                    entry_id: 7,
                    password_changed: Some("2002-01-01T00:00:00Z".into()),
                    ..EntryMetadata::default()
                });
                source.export(path.display().to_string(), true).unwrap();
            } else {
                fs::write(
                    &path,
                    "name,username,password,url\nExample,alice,new-password,example.com\n",
                )
                .unwrap();
            }
            let mut server_info = ServerInfo::default();
            vault
                .import_with_options(
                    path.display().to_string(),
                    ConflictPolicy::Replace,
                    false,
                    limit,
                    &mut server_info,
                )
                .unwrap();
            assert_eq!(vault.entries[0].id, 7);
            assert_eq!(vault.entries[0].created, "2000-01-01T00:00:00Z");
            assert_eq!(vault.entries[0].password, "new-password");
            assert!(!vault.password_is_stale(&vault.entries[0], 365));
            assert_eq!(
                vault.recovery.password_history.len(),
                usize::from(limit > 0)
            );
            if !portable {
                let changed = vault.password_changed(&vault.entries[0]).to_string();
                vault
                    .import_with_options(
                        path.display().to_string(),
                        ConflictPolicy::Replace,
                        false,
                        limit,
                        &mut server_info,
                    )
                    .unwrap();
                assert_eq!(vault.password_changed(&vault.entries[0]), changed);
                assert_eq!(
                    vault.recovery.password_history.len(),
                    usize::from(limit > 0)
                );
            }
        }
    }
}

#[test]
fn date_sorting_uses_instants_across_formats_offsets_and_unknown_dates() {
    let timestamps = [
        (1, "2025-01-01T00:00:00-07:00"),
        (2, "2025-01-01T01:00:00+00:00"),
        (3, "2025-01-01 02:00:00 +00:00"),
        (4, "unknown"),
    ];
    let mut vault = recovery_test_vault(
        timestamps
            .iter()
            .map(|(id, timestamp)| {
                let mut entry = recovery_test_entry(*id, "Example", "alice", "secret");
                entry.created = timestamp.to_string();
                entry.modified = timestamp.to_string();
                entry
            })
            .collect(),
    );
    // Password-age sorting must use its own metadata, rather than creation time.
    vault.recovery.entry_metadata = timestamps
        .iter()
        .map(|(id, timestamp)| EntryMetadata {
            entry_id: 5 - id,
            password_changed: Some(timestamp.to_string()),
            ..EntryMetadata::default()
        })
        .collect();
    for sort in [
        SortField::Created,
        SortField::Modified,
        SortField::PasswordAge,
    ] {
        for descending in [false, true] {
            let mut expected = if sort == SortField::PasswordAge {
                vec![1, 3, 2, 4]
            } else {
                vec![4, 2, 3, 1]
            };
            if descending {
                expected.reverse();
            }
            let sorted = vault
                .view_entries(ListOptions {
                    sort,
                    descending,
                    ..ListOptions::default()
                })
                .unwrap();
            assert_eq!(
                sorted.iter().map(|view| view.entry.id).collect::<Vec<_>>(),
                expected
            );
        }
    }
}

#[test]
fn oversized_import_files_are_rejected_before_their_contents_are_read() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("oversized.json");
    let file = fs::File::create(&path).unwrap();
    file.set_len(MAX_IMPORT_BYTES + 1).unwrap();

    let error = Vault::default()
        .import_with_options(
            path.display().to_string(),
            ConflictPolicy::Skip,
            true,
            1,
            &mut ServerInfo::default(),
        )
        .unwrap_err();

    assert!(error.to_string().contains("128 MiB limit"), "{error}");
}

#[test]
fn imports_with_too_many_items_are_rejected_before_vault_changes() {
    let mut file = NamedTempFile::new().unwrap();
    {
        let mut writer = std::io::BufWriter::new(file.as_file_mut());
        writeln!(writer, "name,username,password,url").unwrap();
        for index in 0..=MAX_IMPORT_ITEMS {
            writeln!(writer, "item-{index},user,password,").unwrap();
        }
        writer.flush().unwrap();
    }
    let mut vault = recovery_test_vault(vec![recovery_test_entry(
        1,
        "existing",
        "alice",
        "unchanged",
    )]);
    let before = vault.clone();

    let error = vault
        .import_with_options(
            file.path().display().to_string(),
            ConflictPolicy::Skip,
            false,
            1,
            &mut ServerInfo::default(),
        )
        .unwrap_err();

    assert!(error.to_string().contains("100000 item limit"), "{error}");
    assert_eq!(vault, before);
}

#[test]
fn indexed_import_conflicts_track_entries_added_in_the_same_batch() {
    let mut existing = recovery_test_entry(7, "Example", "alice", "old-password");
    existing.url = Some("https://example.com".into());
    let mut vault = recovery_test_vault(vec![existing]);
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "name,username,password,url").unwrap();
    writeln!(file, "Example,alice,first,https://example.com").unwrap();
    writeln!(file, "Example,alice,second,https://example.com").unwrap();

    let report = vault
        .import_with_options(
            file.path().display().to_string(),
            ConflictPolicy::KeepBoth,
            false,
            1,
            &mut ServerInfo::default(),
        )
        .unwrap();

    assert_eq!(report.renamed, 2);
    assert_eq!(vault.entries[1].name, "Example (imported)");
    assert_eq!(vault.entries[2].name, "Example (imported 2)");
}

#[test]
fn recovery_limits_bound_history_and_expire_old_trash() {
    let mut vault = recovery_test_vault(Vec::new());
    vault.push_password_history_with_limit(1, "one".into(), 2);
    vault.push_password_history_with_limit(1, "two".into(), 2);
    vault.push_password_history_with_limit(1, "three".into(), 2);
    assert_eq!(vault.recovery.password_history.len(), 2);
    vault.push_password_history_with_limit(1, "discarded".into(), 0);
    assert_eq!(vault.recovery.password_history.len(), 2);

    let old = TrashedEntry {
        entry: recovery_test_entry(11, "old", "alice", "secret"),
        history: Vec::new(),
        deleted: (chrono::Local::now() - chrono::Duration::days(60)).to_string(),
    };
    let recent = TrashedEntry {
        entry: recovery_test_entry(12, "recent", "bob", "secret"),
        history: Vec::new(),
        deleted: chrono::Local::now().to_string(),
    };
    vault.recovery.trash = vec![old, recent];
    vault.recovery.entry_metadata.push(EntryMetadata {
        entry_id: 11,
        ..EntryMetadata::default()
    });
    vault.recovery.totp.push(TotpRecord {
        entry_id: 11,
        configuration: "secret".into(),
    });
    let purged = vault
        .purge_expired_trash(30, &mut ServerInfo::default())
        .unwrap();
    assert_eq!(purged, 1);
    assert_eq!(vault.recovery.trash[0].entry.id, 12);
    assert!(vault.recovery.entry_metadata.is_empty());
    assert!(vault.recovery.totp.is_empty());
}

#[test]
fn list_options_filter_item_type_totp_and_weakness_and_sort_results() {
    let mut alpha = recovery_test_entry(8, "Alpha", "alice", "A-very-long-unique-password-42!");
    alpha.created = "2024-01-01".into();
    let mut beta = recovery_test_entry(2, "beta", "bob", "password");
    beta.created = "2023-01-01".into();
    let mut vault = recovery_test_vault(vec![alpha, beta]);
    vault.recovery.entry_metadata = vec![EntryMetadata {
        entry_id: 2,
        kind: ItemKind::Wifi,
        additional_urls: Vec::new(),
        password_changed: Some("2025-01-01T00:00:00Z".into()),
        custom_fields: Vec::new(),
    }];
    vault.recovery.totp.push(TotpRecord {
        entry_id: 8,
        configuration: "secret".into(),
    });

    let typed = vault.apply_list_options(
        vault.entries.iter().collect(),
        &ListOptions {
            kind: Some(ItemKind::Wifi),
            ..ListOptions::default()
        },
    );
    assert_eq!(typed.iter().map(|entry| entry.id).collect::<Vec<_>>(), [2]);

    let with_totp = vault.apply_list_options(
        vault.entries.iter().collect(),
        &ListOptions {
            has_totp: Some(true),
            ..ListOptions::default()
        },
    );
    assert_eq!(
        with_totp.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        [8]
    );

    let weak = vault.apply_list_options(
        vault.entries.iter().collect(),
        &ListOptions {
            weak: true,
            ..ListOptions::default()
        },
    );
    assert_eq!(weak.iter().map(|entry| entry.id).collect::<Vec<_>>(), [2]);

    let stale = vault.apply_list_options(
        vault.entries.iter().collect(),
        &ListOptions {
            stale_days: Some(365),
            ..ListOptions::default()
        },
    );
    assert_eq!(stale.iter().map(|entry| entry.id).collect::<Vec<_>>(), [2]);

    let sorted = vault.apply_list_options(
        vault.entries.iter().collect(),
        &ListOptions {
            sort: SortField::Name,
            descending: true,
            ..ListOptions::default()
        },
    );
    assert_eq!(
        sorted.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        [2, 8]
    );
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
fn totp_follows_trash_restore_and_is_erased_on_purge() {
    let mut vault =
        recovery_test_vault(vec![recovery_test_entry(7, "service", "alice", "password")]);
    let mut server_info = ServerInfo::default();
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    assert_eq!(
        vault
            .set_totp(Target::Id(7), secret, &mut server_info)
            .unwrap(),
        Some(160)
    );
    assert_eq!(vault.totp_at(&Target::Id(7), 59).unwrap().0, "287082");

    vault.delete_entry(Target::Id(7), &mut server_info).unwrap();
    assert!(vault.totp_at(&Target::Id(7), 59).is_err());
    assert_eq!(vault.recovery.totp[0].entry_id, 7);
    vault.restore_trashed(1, &mut server_info).unwrap();
    assert_eq!(vault.totp_at(&Target::Id(7), 59).unwrap().0, "287082");

    vault.delete_entry(Target::Id(7), &mut server_info).unwrap();
    vault.purge_trash(None, &mut server_info).unwrap();
    assert!(vault.recovery.totp.is_empty());
}

#[test]
fn totp_rejects_invalid_configuration_and_can_be_removed() {
    let mut vault =
        recovery_test_vault(vec![recovery_test_entry(1, "service", "alice", "password")]);
    let mut server_info = ServerInfo::default();
    assert!(
        vault
            .set_totp(Target::Id(1), "not base32!", &mut server_info)
            .is_err()
    );
    assert!(vault.recovery.totp.is_empty());

    vault
        .set_totp(
            Target::Id(1),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            &mut server_info,
        )
        .unwrap();
    assert!(vault.remove_totp(Target::Id(1), &mut server_info).unwrap());
    assert!(vault.recovery.totp.is_empty());
    assert!(!vault.remove_totp(Target::Id(1), &mut server_info).unwrap());
}

#[test]
fn incomplete_recovery_data_is_rejected() {
    #[derive(Serialize)]
    struct IncompleteRecoveryData {
        password_history: Vec<PasswordRevision>,
        trash: Vec<TrashedEntry>,
        next_entry_id: usize,
    }

    let encoded = rmp_serde::to_vec(&IncompleteRecoveryData {
        password_history: Vec::new(),
        trash: Vec::new(),
        next_entry_id: 12,
    })
    .unwrap();
    assert!(rmp_serde::from_slice::<RecoveryData>(&encoded).is_err());
}

#[test]
fn totp_secrets_are_redacted_and_only_in_full_fidelity_json_exports() {
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let mut vault =
        recovery_test_vault(vec![recovery_test_entry(1, "service", "alice", "password")]);
    vault
        .set_totp(Target::Id(1), secret, &mut ServerInfo::default())
        .unwrap();
    assert!(!format!("{:?}", vault.recovery.totp[0]).contains(secret));

    let directory = tempfile::tempdir().unwrap();
    let json_path = directory.path().join("export.json");
    vault
        .export(json_path.display().to_string(), false)
        .unwrap();
    assert!(fs::read_to_string(json_path).unwrap().contains(secret));

    let csv_path = directory.path().join("export.csv");
    vault.export(csv_path.display().to_string(), false).unwrap();
    assert!(!fs::read_to_string(csv_path).unwrap().contains(secret));
}

#[cfg(unix)]
#[test]
fn plaintext_exports_are_created_with_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let vault = recovery_test_vault(vec![recovery_test_entry(
        1,
        "service",
        "alice",
        "exported-secret",
    )]);
    for extension in ["json", "csv"] {
        let path = directory.path().join(format!("export.{extension}"));
        vault.export(path.display().to_string(), false).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn plaintext_exports_do_not_replace_existing_files_without_force() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("export.json");
    fs::write(&path, "keep this file").unwrap();
    let vault = recovery_test_vault(vec![recovery_test_entry(
        1,
        "service",
        "alice",
        "exported-secret",
    )]);

    let error = vault.export(path.display().to_string(), false).unwrap_err();
    assert!(error.to_string().contains("already exists"), "{error}");
    assert_eq!(fs::read_to_string(&path).unwrap(), "keep this file");

    vault.export(path.display().to_string(), true).unwrap();
    let exported = fs::read_to_string(path).unwrap();
    assert!(exported.contains("exported-secret"));
}

#[test]
fn encrypted_backup_round_trip_preserves_complete_vault_state() {
    init_test_data_dir();
    let directory = tempfile::tempdir().unwrap();
    let backup_path = directory.path().join("complete.pmbackup");
    let totp_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let mut vault = recovery_test_vault(vec![recovery_test_entry(
        1,
        "active-service",
        "alice",
        "active-password",
    )]);
    vault.recovery.next_entry_id = 3;
    vault.recovery.password_history.push(PasswordRevision {
        entry_id: 1,
        password: "previous-password".into(),
        changed: "yesterday".into(),
    });
    vault.recovery.trash.push(TrashedEntry {
        entry: recovery_test_entry(2, "deleted-service", "bob", "deleted-password"),
        history: vec![PasswordRevision {
            entry_id: 2,
            password: "deleted-previous".into(),
            changed: "last-week".into(),
        }],
        deleted: "today".into(),
    });
    vault.recovery.totp.extend([
        TotpRecord {
            entry_id: 1,
            configuration: totp_secret.into(),
        },
        TotpRecord {
            entry_id: 2,
            configuration: totp_secret.into(),
        },
    ]);

    let password = format!("backup-{:016x}", rand::random::<u64>());
    let mut backup_key = PasswordType::Password(password.clone());
    vault
        .encrypted_backup(backup_path.display().to_string(), &mut backup_key, false)
        .unwrap();
    let encrypted = fs::read(&backup_path).unwrap();
    assert!(encrypted.starts_with(BACKUP_MAGIC));
    assert!(
        !encrypted
            .windows(totp_secret.len())
            .any(|part| part == totp_secret.as_bytes())
    );
    assert!(
        vault
            .encrypted_backup(backup_path.display().to_string(), &mut backup_key, false)
            .is_err()
    );
    assert_eq!(fs::read(&backup_path).unwrap(), encrypted);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&backup_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let mut wrong_key = PasswordType::Password("wrong-backup-password".into());
    assert!(
        restore_encrypted_backup(backup_path.to_str().unwrap(), &mut wrong_key, false).is_err()
    );

    let filename =
        restore_encrypted_backup(backup_path.to_str().unwrap(), &mut backup_key, false).unwrap();
    let mut restored_info = ServerInfo {
        locked: true,
        keypass: Some(PasswordType::Password(password)),
    };
    let restored = unlock_vault(&mut restored_info).unwrap();
    assert_eq!(restored.entries, vault.entries);
    assert_eq!(restored.recovery, vault.recovery);
    assert_eq!(restored.metadata.filename, filename);

    assert!(
        restore_encrypted_backup(backup_path.to_str().unwrap(), &mut backup_key, false)
            .unwrap_err()
            .to_string()
            .contains("--force")
    );
    assert_eq!(
        restore_encrypted_backup(backup_path.to_str().unwrap(), &mut backup_key, true).unwrap(),
        filename
    );
    fs::remove_file(data_dir().join(filename)).unwrap();
}

#[test]
fn encrypted_backup_rejects_tampering_and_invalid_vault_state() {
    init_test_data_dir();
    let directory = tempfile::tempdir().unwrap();
    let tampered_path = directory.path().join("tampered.pmbackup");
    let invalid_path = directory.path().join("invalid.pmbackup");
    let password = format!("adversarial-backup-{:016x}", rand::random::<u64>());
    let mut key = PasswordType::Password(password);

    let vault = recovery_test_vault(vec![recovery_test_entry(1, "service", "alice", "password")]);
    vault
        .encrypted_backup(tampered_path.display().to_string(), &mut key, false)
        .unwrap();
    let mut tampered = fs::read(&tampered_path).unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    fs::write(&tampered_path, tampered).unwrap();
    assert!(
        restore_encrypted_backup(tampered_path.to_str().unwrap(), &mut key, false)
            .unwrap_err()
            .to_string()
            .contains("corrupted")
    );

    let mut invalid =
        recovery_test_vault(vec![recovery_test_entry(1, "active", "alice", "password")]);
    invalid.recovery.trash.push(TrashedEntry {
        entry: recovery_test_entry(1, "deleted", "bob", "password"),
        history: Vec::new(),
        deleted: "today".into(),
    });
    let envelope = BackupEnvelopeRef {
        version: BACKUP_VERSION,
        created: chrono::Utc::now().to_rfc3339(),
        vault: &invalid,
    };
    let plaintext = rmp_serde::to_vec(&envelope).unwrap();
    let encrypted = try_encrypt_file(&mut key, &plaintext).unwrap();
    let mut contents = BACKUP_MAGIC.to_vec();
    contents.push(BACKUP_VERSION);
    contents.extend_from_slice(&encrypted);
    fs::write(&invalid_path, contents).unwrap();

    assert!(find_vault(&mut key).is_none());
    assert!(
        restore_encrypted_backup(invalid_path.to_str().unwrap(), &mut key, false)
            .unwrap_err()
            .to_string()
            .contains("duplicate entry IDs")
    );
    assert!(find_vault(&mut key).is_none());
}

#[test]
fn production_kdf_covers_vault_unlock_rekey_backup_restore_and_tamper_workflows() {
    with_test_kdf_parameters(PRODUCTION_KDF_PARAMETERS, || {
        init_test_data_dir();
        let directory = tempfile::tempdir().unwrap();
        let unique = format!("production-workflow-{:016x}", rand::random::<u64>());
        let old_password = format!("old-{unique}");
        let new_password = format!("new-{unique}");

        let mut server_info = ServerInfo {
            locked: false,
            keypass: Some(PasswordType::Password(old_password.clone())),
        };
        let mut vault = None;
        create_vault(&mut vault, &mut server_info, false).unwrap();
        let original_filename = vault.as_ref().unwrap().metadata.filename.clone();
        let encrypted_vault = fs::read(data_dir().join(&original_filename)).unwrap();
        assert_eq!(
            u32::from_be_bytes(encrypted_vault[10..14].try_into().unwrap()),
            PRODUCTION_KDF_PARAMETERS.memory_kib
        );
        assert_eq!(
            u32::from_be_bytes(encrypted_vault[14..18].try_into().unwrap()),
            PRODUCTION_KDF_PARAMETERS.iterations
        );
        assert_eq!(
            u32::from_be_bytes(encrypted_vault[18..22].try_into().unwrap()),
            PRODUCTION_KDF_PARAMETERS.parallelism
        );

        vault.as_ref().unwrap().lock_vault(&mut server_info);
        let mut old_unlock = ServerInfo {
            locked: true,
            keypass: Some(PasswordType::Password(old_password)),
        };
        let mut unlocked = unlock_vault(&mut old_unlock).unwrap();
        assert_eq!(unlocked.metadata.filename, original_filename);

        unlocked
            .rekey(&mut old_unlock, PasswordType::Password(new_password))
            .unwrap();
        let rekeyed_filename = unlocked.metadata.filename.clone();
        assert_eq!(original_filename, rekeyed_filename);

        let backup_path = directory.path().join("production.pmbackup");
        let tampered_path = directory.path().join("production-tampered.pmbackup");
        unlocked
            .encrypted_backup(
                backup_path.display().to_string(),
                old_unlock.keypass.as_mut().unwrap(),
                false,
            )
            .unwrap();

        let mut tampered = fs::read(&backup_path).unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        fs::write(&tampered_path, tampered).unwrap();
        let mut tamper_key = old_unlock.keypass.clone().unwrap();
        assert!(
            restore_encrypted_backup(tampered_path.to_str().unwrap(), &mut tamper_key, false)
                .unwrap_err()
                .to_string()
                .contains("corrupted")
        );

        fs::remove_file(data_dir().join(&rekeyed_filename)).unwrap();
        let mut restore_key = old_unlock.keypass.clone().unwrap();
        let restored_filename =
            restore_encrypted_backup(backup_path.to_str().unwrap(), &mut restore_key, false)
                .unwrap();
        let mut restored_unlock = ServerInfo {
            locked: true,
            keypass: Some(restore_key),
        };
        let restored = unlock_vault(&mut restored_unlock).unwrap();
        assert_eq!(restored.entries, unlocked.entries);
        assert_eq!(restored.recovery, unlocked.recovery);

        fs::remove_file(data_dir().join(restored_filename)).unwrap();
    });
}

#[test]
fn audit_reports_weak_reused_and_duplicate_logins_without_passwords() {
    let vault = recovery_test_vault(vec![
        recovery_test_entry(1, "first", "alice", "secret"),
        recovery_test_entry(2, "second", "alice", "secret"),
    ]);
    let report = vault
        .audit_snapshot(&AuditOptions::default())
        .report(None, None);
    assert!(report.contains("2 weak entries"));
    assert!(report.contains("1 reused-password groups"));
    assert!(report.contains("1 duplicate-login groups"));
    assert!(!report.contains("secret"));
}

#[test]
fn audit_reports_stale_missing_totp_and_breached_passwords() {
    let mut vault = recovery_test_vault(vec![recovery_test_entry(
        7,
        "old account",
        "alice",
        "known-breached-value",
    )]);
    vault.recovery.entry_metadata.push(EntryMetadata {
        entry_id: 7,
        password_changed: Some("2020-01-01T00:00:00Z".into()),
        ..EntryMetadata::default()
    });
    let mut breached = HashMap::new();
    breached.insert(password_hash("known-breached-value"), 42);
    let options = AuditOptions {
        stale_days: Some(365),
        check_breaches: true,
        require_totp: true,
    };
    let report = vault.audit_snapshot(&options).report(Some(&breached), None);
    assert!(report.contains("Stale password: 7. old account"));
    assert!(report.contains("Missing TOTP: 7. old account"));
    assert!(report.contains("Breached password: 7. old account (seen 42 times)"));
    assert!(report.contains("Health score: 0/100"));
    assert!(!report.contains("known-breached-value"));
}

#[test]
fn pwned_range_parser_ignores_padding_and_reconstructs_hashes() {
    let parsed = parse_pwned_range("ABCDE:0\r\n12345:9\r\n", "FFFFF");
    assert_eq!(parsed.get("FFFFF12345"), Some(&9));
    assert!(!parsed.contains_key("FFFFFABCDE"));
}

#[test]
fn import_rolls_back_when_id_allocation_fails_after_an_earlier_row() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "name,url,username,password").unwrap();
    writeln!(file, "first,https://first.example,user,first-secret").unwrap();
    writeln!(file, "second,https://second.example,user,second-secret").unwrap();
    let mut vault = Vault::default();
    vault.recovery.next_entry_id = usize::MAX - 1;
    let before = vault.clone();
    let result = vault.import_with_options(
        file.path().display().to_string(),
        ConflictPolicy::Skip,
        false,
        HISTORY_LIMIT,
        &mut ServerInfo::default(),
    );
    assert!(result.is_err());
    assert_eq!(vault, before);
}

#[test]
fn domain_reads_classify_missing_records_and_invalid_selectors() {
    let vault = Vault::default();
    assert!(matches!(
        vault.get_entry(&Target::Id(1)),
        Err(VaultError::NotFound(_))
    ));
    assert!(matches!(
        vault.get_entry(&Target::Vault {
            key: PasswordType::Password(String::new()),
            keep_key: false
        }),
        Err(VaultError::InvalidInput(_))
    ));
    assert!(matches!(
        vault.get_secret(&Target::Url("example.com".into())),
        Err(VaultError::NotFound(_))
    ));
}

#[test]
fn import_preview_matches_execution_for_conflicts_between_source_rows() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "name,url,username,password").unwrap();
    writeln!(file, "new,https://example.com,alice,first-secret").unwrap();
    writeln!(file, "new,https://example.com,alice,second-secret").unwrap();
    writeln!(file, "new,https://example.com,alice,third-secret").unwrap();
    for policy in [
        ConflictPolicy::Skip,
        ConflictPolicy::Replace,
        ConflictPolicy::KeepBoth,
    ] {
        let mut vault = Vault::default();
        let before = vault.clone();
        let path = file.path().display().to_string();
        let mut preview = vault
            .import_with_options(
                path.clone(),
                policy,
                true,
                HISTORY_LIMIT,
                &mut ServerInfo::default(),
            )
            .unwrap();
        assert_eq!(vault, before);
        let actual = vault
            .import_with_options(
                path,
                policy,
                false,
                HISTORY_LIMIT,
                &mut ServerInfo::default(),
            )
            .unwrap();
        preview.preview = false;
        assert_eq!(preview, actual);
    }
}
