use super::*;
use std::fs;

fn isolated_config() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    (directory, path)
}

#[test]
fn test_update_all_config_fields() {
    let (_directory, config_path) = isolated_config();
    update(
        default_test_config(true, &config_path),
        ConfigArgs {
            reset: false,
            genpass_length: Some(100),
            genpass_stats: Some(false),
            genpass_copy: Some(true),
            password_copy: None,
            clipboard_timeout: Some(12),
            unlock_timeout: Some(15),
            password_history_limit: Some(25),
            trash_retention_days: Some(30),
            server_port: Some(8787),
        },
        &config_path,
    );
    assert_eq!(
        read_config(&config_path),
        Config {
            genpass: GeneratorConfig {
                length: 100,
                stats: false,
                copy: true
            },
            clipboard: ClipboardConfig { timeout: 12 },
            unlock: UnlockConfig { timeout: 15 },
            copy: CopyConfig { passwords: true },
            recovery: RecoveryConfig {
                password_history_limit: 25,
                trash_retention_days: 30,
            },
            server: ServerConfig { port: 8787 },
        }
    );
}
#[test]
fn test_is_config_exists() {
    let (_directory, config_path) = isolated_config();
    assert!(!is_config(&config_path));
    fs::File::create(&config_path).unwrap();
    assert!(is_config(&config_path));
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
    assert_eq!(default_test_config(true, &config_path), config);
    assert_eq!(read_config(&config_path), config);
}
#[test]
fn test_reset_to_default() {
    let (_directory, config_path) = isolated_config();
    update(
        read_config(&config_path),
        ConfigArgs {
            reset: true,
            genpass_length: Some(100),
            genpass_stats: Some(true),
            genpass_copy: Some(false),
            password_copy: None,
            clipboard_timeout: Some(30),
            unlock_timeout: Some(5),
            ..ConfigArgs::default()
        },
        &config_path,
    );
    update(
        read_config(&config_path),
        ConfigArgs {
            reset: true,
            genpass_length: None,
            genpass_stats: None,
            genpass_copy: None,
            password_copy: None,
            clipboard_timeout: None,
            unlock_timeout: None,
            ..ConfigArgs::default()
        },
        &config_path,
    );
    let conf = read_config(&config_path);
    assert_eq!(conf.genpass.length, 12);
    assert!(!conf.genpass.stats);
    assert!(conf.genpass.copy);
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
fn test_multiple_updates() {
    let (_directory, config_path) = isolated_config();
    default_test_config(true, &config_path);

    update(
        read_config(&config_path),
        ConfigArgs {
            reset: false,
            genpass_length: Some(16),
            genpass_stats: Some(true),
            genpass_copy: None,
            password_copy: None,
            clipboard_timeout: None,
            unlock_timeout: None,
            ..ConfigArgs::default()
        },
        &config_path,
    );

    update(
        read_config(&config_path),
        ConfigArgs {
            reset: false,
            genpass_length: None,
            genpass_stats: None,
            genpass_copy: Some(false),
            password_copy: None,
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
}

#[test]
fn test_config_round_trip() {
    let custom = Config {
        genpass: GeneratorConfig {
            length: 32,
            stats: true,
            copy: false,
        },
        clipboard: ClipboardConfig { timeout: 60 },
        unlock: UnlockConfig { timeout: 15 },
        copy: CopyConfig { passwords: false },
        recovery: RecoveryConfig::default(),
        server: ServerConfig { port: 9876 },
    };

    for (label, original) in [("defaults", Config::default()), ("custom", custom)] {
        let (_directory, config_path) = isolated_config();
        write_file(&original, &config_path).unwrap();
        assert_eq!(read_config(&config_path), original, "{label}");
    }
}

#[test]
fn test_config_update_boundary_values() {
    for (length, clipboard_timeout, unlock_timeout, stats, copy) in [
        (12, 0, 0, false, true),
        (u8::MAX, u8::MAX, u64::MAX, true, false),
    ] {
        let (_directory, config_path) = isolated_config();
        default_test_config(true, &config_path);
        update(
            read_config(&config_path),
            ConfigArgs {
                genpass_length: Some(length),
                genpass_stats: Some(stats),
                genpass_copy: Some(copy),
                clipboard_timeout: Some(clipboard_timeout),
                unlock_timeout: Some(unlock_timeout),
                ..ConfigArgs::default()
            },
            &config_path,
        );
        let conf = read_config(&config_path);
        assert_eq!(conf.genpass.length, length);
        assert_eq!(conf.genpass.stats, stats);
        assert_eq!(conf.genpass.copy, copy);
        assert_eq!(conf.clipboard.timeout, clipboard_timeout);
        assert_eq!(conf.unlock.timeout, unlock_timeout);
    }
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
fn password_copy_default_is_configurable() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    try_update(
        Config::default(),
        ConfigArgs {
            password_copy: Some(false),
            ..ConfigArgs::default()
        },
        &config_path,
    )
    .unwrap();

    assert!(!try_read_config(&config_path).unwrap().copy.passwords);
}

#[test]
fn missing_settings_are_added_with_defaults() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
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
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
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
