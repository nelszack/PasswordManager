use super::*;
use std::fs;

fn isolated_config() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    (directory, path)
}

#[test]
fn test_config() {
    let (_directory, config_path) = isolated_config();
    test_read_write(&config_path);
    test_update(&config_path);
}
fn test_read_write(config_path: &Path) {
    let conf1 = read_config(config_path);
    default_test_config(true, config_path);
    let conf2 = read_config(config_path);
    assert_eq!(
        conf2,
        Config {
            genpass: GeneratorConfig {
                length: 12,
                stats: false,
                copy: true
            },
            clipboard: ClipboardConfig { timeout: 15 },
            unlock: UnlockConfig { timeout: 15 * 60 },
            copy: CopyConfig { passwords: true },
            recovery: RecoveryConfig::default(),
            server: ServerConfig::default(),
        }
    );
    write_file(&conf1, config_path).unwrap();
    assert_eq!(read_config(config_path), conf1)
}

fn test_update(config_path: &Path) {
    let conf1 = read_config(config_path);
    update(
        default_test_config(true, config_path),
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
        config_path,
    );
    assert_eq!(
        read_config(config_path),
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
    write_file(&conf1, config_path).unwrap();
}
#[test]
fn test_is_config_exists() {
    let (_directory, config_path) = isolated_config();
    fs::File::create(&config_path).unwrap();
    assert!(is_config(&config_path));
}
#[test]
fn test_is_config_not_exists() {
    let (_directory, config_path) = isolated_config();
    assert!(!is_config(&config_path));
}
#[test]
fn test_update_single_field() {
    let (_directory, config_path) = isolated_config();
    default_test_config(true, &config_path);
    update(
        read_config(&config_path),
        ConfigArgs {
            reset: false,
            genpass_length: Some(24),
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
    assert_eq!(conf.genpass.length, 24);
    assert!(!conf.genpass.stats);
}
#[test]
fn test_default_config_values() {
    let config = default_test_config(false, Path::new("dummy.toml"));
    assert_eq!(config.genpass.length, 12);
    assert!(!config.genpass.stats);
    assert!(config.genpass.copy);
    assert_eq!(config.clipboard.timeout, 15);
    assert_eq!(config.unlock.timeout, 15 * 60);
    assert!(config.copy.passwords);
    assert_eq!(config.recovery.password_history_limit, 10);
    assert_eq!(config.recovery.trash_retention_days, 0);
    assert_eq!(config.server.port, crate::server::DEFAULT_PORT);
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

[clpboard]
clp_timeout = 30

[unlock]
unlock_timeout = 5

[copy]
copy_pass = false
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
    let (_directory, config_path) = isolated_config();

    let original = Config {
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

    write_file(&original, &config_path).unwrap();
    let loaded = read_config(&config_path);

    assert_eq!(original, loaded);
}

#[test]
fn test_config_update_zero_timeout() {
    let (_directory, config_path) = isolated_config();
    default_test_config(true, &config_path);
    update(
        read_config(&config_path),
        ConfigArgs {
            reset: false,
            genpass_length: None,
            genpass_stats: None,
            genpass_copy: None,
            password_copy: None,
            clipboard_timeout: Some(0),
            unlock_timeout: Some(0),
            ..ConfigArgs::default()
        },
        &config_path,
    );
    let conf = read_config(&config_path);
    assert_eq!(conf.clipboard.timeout, 0);
    assert_eq!(conf.unlock.timeout, 0);
}

#[test]
fn test_config_update_max_values() {
    let (_directory, config_path) = isolated_config();
    default_test_config(true, &config_path);
    update(
        read_config(&config_path),
        ConfigArgs {
            reset: false,
            genpass_length: Some(u8::MAX),
            genpass_stats: Some(true),
            genpass_copy: Some(false),
            password_copy: None,
            clipboard_timeout: Some(u8::MAX),
            unlock_timeout: Some(u64::MAX),
            ..ConfigArgs::default()
        },
        &config_path,
    );
    let conf = read_config(&config_path);
    assert_eq!(conf.genpass.length, u8::MAX);
    assert!(conf.genpass.stats);
    assert!(!conf.genpass.copy);
    assert_eq!(conf.clipboard.timeout, u8::MAX);
    assert_eq!(conf.unlock.timeout, u64::MAX);
}

#[test]
fn test_config_preserves_unmodified_fields() {
    let (_directory, config_path) = isolated_config();
    update(
        default_test_config(false, &config_path),
        ConfigArgs {
            reset: false,
            genpass_length: Some(50),
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
    assert_eq!(conf.genpass.length, 50);
    assert!(!conf.genpass.stats);
    assert!(conf.genpass.copy);
    assert_eq!(conf.clipboard.timeout, 15);
    assert_eq!(conf.unlock.timeout, 15 * 60);
}

#[test]
fn invalid_config_is_reported_without_overwriting_the_file() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let invalid = b"[genpass]\nlength = not-a-number\n";
    fs::write(&config_path, invalid).unwrap();

    let error = try_read_config(&config_path).unwrap_err();

    assert!(error.contains("left unchanged"));
    assert_eq!(fs::read(&config_path).unwrap(), invalid);
}

#[test]
fn zero_server_port_is_rejected_without_overwriting_the_file() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let invalid = b"[server]\nport = 0\n";
    fs::write(&config_path, invalid).unwrap();

    let error = try_read_config(&config_path).unwrap_err();

    assert!(error.contains("server.port must be between 1 and 65535"));
    assert_eq!(fs::read(&config_path).unwrap(), invalid);
}

#[test]
fn zero_generator_length_is_rejected_without_overwriting_the_file() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let invalid = b"[genpass]\nlength = 0\n";
    fs::write(&config_path, invalid).unwrap();

    let error = try_read_config(&config_path).unwrap_err();

    assert!(error.contains("genpass.length must be between 1 and 255"));
    assert_eq!(fs::read(&config_path).unwrap(), invalid);
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
