use super::*;
use crate::cli::ConfigArgs;
use std::fs;

fn isolated_config() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    (directory, path)
}

#[test]
fn default_vault_selection_is_validated_and_resettable() {
    let (_directory, path) = isolated_config();
    let initial = default_test_config(true, &path);
    let updated = try_update(
        initial,
        ConfigChanges {
            default_vault: Some("selected.enc".into()),
            ..Default::default()
        },
        &path,
    )
    .unwrap();
    assert_eq!(
        read_config(&path).unlock.vault_id.as_deref(),
        Some("selected.enc")
    );
    assert!(
        try_update(
            updated.clone(),
            ConfigChanges {
                default_vault: Some("../other.enc".into()),
                ..Default::default()
            },
            &path
        )
        .is_err()
    );
    assert_eq!(read_config(&path), updated);
    let reset = try_update(
        updated,
        ConfigChanges {
            reset: true,
            ..Default::default()
        },
        &path,
    )
    .unwrap();
    assert!(reset.unlock.vault_id.is_none());
}

#[test]
fn updates_persist_all_fields_and_boundary_values() {
    for (label, length, stats, copy, password_copy, clipboard, unlock, history, retention, port) in [
        ("custom", 100, false, true, false, 12, 15, 25, 30, 8787),
        (
            "disabled timeouts",
            12,
            false,
            true,
            true,
            0,
            0,
            10,
            0,
            crate::server::DEFAULT_PORT,
        ),
        (
            "maximum values",
            u8::MAX,
            true,
            false,
            false,
            u8::MAX,
            u64::MAX,
            10,
            0,
            crate::server::DEFAULT_PORT,
        ),
    ] {
        let (_directory, config_path) = isolated_config();
        update(
            default_test_config(true, &config_path),
            ConfigArgs {
                genpass_length: Some(length),
                genpass_stats: Some(stats),
                genpass_copy: Some(copy),
                password_copy: Some(password_copy),
                clipboard_timeout: Some(clipboard),
                unlock_timeout: Some(unlock),
                password_history_limit: Some(history),
                trash_retention_days: Some(retention),
                server_port: Some(port),
                ..ConfigArgs::default()
            },
            &config_path,
        );
        assert_eq!(
            read_config(&config_path),
            Config {
                genpass: GeneratorConfig {
                    length,
                    stats,
                    copy
                },
                clipboard: ClipboardConfig { timeout: clipboard },
                unlock: UnlockConfig {
                    timeout: unlock,
                    vault_id: None
                },
                copy: CopyConfig {
                    passwords: password_copy,
                },
                recovery: RecoveryConfig {
                    password_history_limit: history,
                    trash_retention_days: retention
                },
                server: ServerConfig { port },
            },
            "{label}"
        );
    }
}

#[test]
fn test_update_single_field_preserves_unmodified_fields() {
    for (length, persist_defaults) in [(24, true), (50, false)] {
        let (_directory, config_path) = isolated_config();
        let original = default_test_config(persist_defaults, &config_path);
        let mut expected = Config::default();
        expected.genpass.length = length;
        update(
            original,
            ConfigArgs {
                genpass_length: Some(length),
                ..ConfigArgs::default()
            },
            &config_path,
        );
        assert_eq!(
            read_config(&config_path),
            expected,
            "length {length}, persisted defaults {persist_defaults}"
        );
    }
}
#[test]
fn test_default_config_values() {
    let (_directory, config_path) = isolated_config();
    let config = default_test_config(false, &config_path);
    assert_eq!(config.genpass.length, 12);
    assert!(!config.genpass.stats);
    assert!(config.genpass.copy);
    assert_eq!(config.clipboard.timeout, 15);
    assert_eq!(config.unlock.timeout, 15 * 60);
    assert!(config.copy.passwords);
    assert_eq!(config.recovery.password_history_limit, 10);
    assert_eq!(config.recovery.trash_retention_days, 0);
    assert_eq!(config.server.port, crate::server::DEFAULT_PORT);
    assert_eq!(read_config(&config_path), config);
}
#[test]
fn test_config_with_alternate_values() {
    let (_directory, config_path) = isolated_config();
    let content = r#"
[genpass]
length = 20
stats = true
copy = false

[clipboard]
timeout = 30

[unlock]
timeout = 5

[copy]
passwords = false
"#;
    fs::write(&config_path, content).unwrap();
    let conf = read_config(&config_path);
    assert_eq!(conf.genpass.length, 20);
    assert!(conf.genpass.stats);
    assert!(!conf.genpass.copy);
    assert_eq!(conf.clipboard.timeout, 30);
    assert_eq!(conf.unlock.timeout, 5);
    assert!(!conf.copy.passwords);
    assert_eq!(conf.server.port, crate::server::DEFAULT_PORT);
}

#[test]
fn successive_updates_preserve_previous_changes_and_reset_restores_defaults() {
    let (_directory, config_path) = isolated_config();
    default_test_config(true, &config_path);

    update(
        read_config(&config_path),
        ConfigArgs {
            genpass_length: Some(16),
            genpass_stats: Some(true),
            ..ConfigArgs::default()
        },
        &config_path,
    );

    update(
        read_config(&config_path),
        ConfigArgs {
            genpass_copy: Some(false),
            clipboard_timeout: Some(45),
            unlock_timeout: Some(10),
            ..ConfigArgs::default()
        },
        &config_path,
    );

    let conf = read_config(&config_path);
    assert_eq!(conf.genpass.length, 16);
    assert!(conf.genpass.stats);
    assert!(!conf.genpass.copy);
    assert_eq!(conf.clipboard.timeout, 45);
    assert_eq!(conf.unlock.timeout, 10);

    // The domain API can reset and apply overrides in one update; the CLI
    // exposes reset alone. Check both against a previously customized config.
    update(
        conf,
        ConfigArgs {
            reset: true,
            genpass_length: Some(100),
            genpass_stats: Some(true),
            genpass_copy: Some(false),
            clipboard_timeout: Some(30),
            unlock_timeout: Some(5),
            ..ConfigArgs::default()
        },
        &config_path,
    );
    let reset_with_overrides = Config {
        genpass: GeneratorConfig {
            length: 100,
            stats: true,
            copy: false,
        },
        clipboard: ClipboardConfig { timeout: 30 },
        unlock: UnlockConfig {
            timeout: 5,
            vault_id: None,
        },
        ..Config::default()
    };
    assert_eq!(read_config(&config_path), reset_with_overrides);
    update(
        read_config(&config_path),
        ConfigArgs {
            reset: true,
            ..ConfigArgs::default()
        },
        &config_path,
    );
    assert_eq!(read_config(&config_path), Config::default());
}

#[test]
fn invalid_config_is_reported_without_overwriting_the_file() {
    for (invalid, expected_error) in [
        ("[genpass]\nlength = not-a-number\n", "left unchanged"),
        (
            "[server]\nport = 0\n",
            "server.port must be between 1 and 65535",
        ),
        (
            "[genpass]\nlength = 0\n",
            "genpass.length must be between 1 and 255",
        ),
    ] {
        let (_directory, config_path) = isolated_config();
        fs::write(&config_path, invalid).unwrap();
        let error = try_read_config(&config_path).unwrap_err();
        assert!(error.contains(expected_error), "{invalid:?}: {error}");
        assert_eq!(fs::read_to_string(&config_path).unwrap(), invalid);
    }
}

#[test]
fn missing_settings_are_added_with_defaults() {
    let (_directory, config_path) = isolated_config();
    fs::write(
        &config_path,
        r#"[genpass]
length = 24

[recovery]
password_history_limit = 4
"#,
    )
    .unwrap();

    let config = try_read_config(&config_path).unwrap();

    assert_eq!(config.genpass.length, 24);
    assert_eq!(config.recovery.password_history_limit, 4);
    assert_eq!(config.recovery.trash_retention_days, 0);
    assert_eq!(config.server.port, crate::server::DEFAULT_PORT);
    let updated = fs::read_to_string(&config_path).unwrap();
    assert!(updated.contains("stats = false"));
    assert!(updated.contains("trash_retention_days = 0"));
    assert!(updated.contains(&format!("port = {}", crate::server::DEFAULT_PORT)));
}

#[test]
fn complete_config_is_not_rewritten_during_reads() {
    let (_directory, config_path) = isolated_config();
    let complete = format!(
        r#"# Keep this comment and formatting.
[genpass]
length=12
stats=false
copy=true
[clipboard]
timeout=15
[unlock]
timeout=900
[copy]
passwords=true
[recovery]
password_history_limit=10
trash_retention_days=0
[server]
port={}
"#,
        crate::server::DEFAULT_PORT
    );
    fs::write(&config_path, &complete).unwrap();

    try_read_config(&config_path).unwrap();

    assert_eq!(fs::read_to_string(&config_path).unwrap(), complete);
}
