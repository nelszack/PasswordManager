use crate::{
    cli::ConfigArgs,
    file::{set_private_perms, sync_parent},
};
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path};
use tempfile::NamedTempFile;

#[derive(Serialize, Deserialize, PartialEq, Debug, Default)]
#[serde(default)]
pub struct Config {
    pub genpass: GeneratorConfig,
    #[serde(alias = "clpboard")]
    pub clipboard: ClipboardConfig,
    pub unlock: UnlockConfig,
    pub copy: CopyConfig,
    #[serde(default)]
    pub recovery: RecoveryConfig,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(default)]
pub struct GeneratorConfig {
    pub length: u8,
    pub stats: bool,
    pub copy: bool,
}
#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(default)]
pub struct CopyConfig {
    #[serde(alias = "copy_pass")]
    pub passwords: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(default)]
pub struct ClipboardConfig {
    #[serde(alias = "clp_timeout")]
    pub timeout: u8,
}
#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(default)]
pub struct UnlockConfig {
    #[serde(alias = "unlock_timeout")]
    pub timeout: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct RecoveryConfig {
    pub password_history_limit: usize,
    /// Zero disables automatic trash expiration.
    pub trash_retention_days: u64,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            password_history_limit: 10,
            trash_retention_days: 0,
        }
    }
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            length: 12,
            stats: false,
            copy: true,
        }
    }
}

impl Default for CopyConfig {
    fn default() -> Self {
        Self { passwords: true }
    }
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self { timeout: 15 }
    }
}

impl Default for UnlockConfig {
    fn default() -> Self {
        Self { timeout: 15 * 60 }
    }
}

fn write_file(config: &Config, config_path: &Path) -> Result<(), String> {
    let toml_string = toml::to_string(config)
        .map_err(|error| format!("could not encode configuration: {error}"))?;
    let parent = config_path
        .parent()
        .ok_or_else(|| "configuration path has no parent directory".to_string())?;
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|error| format!("could not create configuration temp file: {error}"))?;
    set_private_perms(temporary.path())
        .map_err(|error| format!("could not protect configuration temp file: {error}"))?;
    temporary
        .write_all(toml_string.as_bytes())
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| format!("could not write configuration: {error}"))?;
    temporary
        .persist(config_path)
        .map_err(|error| format!("could not replace configuration: {}", error.error))?;
    sync_parent(config_path)
        .map_err(|error| format!("could not sync configuration directory: {error}"))?;
    Ok(())
}
fn default_config(write_to_file: bool, config_path: &Path) -> Result<Config, String> {
    let config = Config::default();
    if write_to_file {
        write_file(&config, config_path)?;
    }
    Ok(config)
}
fn is_config(config_path: &Path) -> bool {
    config_path.exists()
}
pub fn try_read_config(config_path: &Path) -> Result<Config, String> {
    if !is_config(config_path) {
        return default_config(true, config_path);
    }
    let txt = fs::read_to_string(config_path).map_err(|error| {
        format!(
            "could not read configuration at {}: {error}",
            config_path.display()
        )
    })?;
    toml::from_str(&txt).map_err(|error| {
        format!(
            "invalid configuration at {}; the file was left unchanged: {error}",
            config_path.display()
        )
    })
}

#[cfg(test)]
fn read_config(config_path: &Path) -> Config {
    try_read_config(config_path).expect("test configuration should be valid")
}

#[cfg(test)]
fn default_test_config(write_to_file: bool, config_path: &Path) -> Config {
    default_config(write_to_file, config_path).expect("test configuration should be writable")
}

pub fn try_update(
    mut config: Config,
    modify: ConfigArgs,
    config_path: &Path,
) -> Result<(), String> {
    if modify.reset {
        config = Config::default();
    }
    if let Some(i) = modify.genpass_length {
        config.genpass.length = i;
    }
    if let Some(i) = modify.genpass_stats {
        config.genpass.stats = i
    }
    if let Some(i) = modify.genpass_copy {
        config.genpass.copy = i
    }
    if let Some(i) = modify.password_copy {
        config.copy.passwords = i
    }
    if let Some(i) = modify.clipboard_timeout {
        config.clipboard.timeout = i
    }
    if let Some(i) = modify.unlock_timeout {
        config.unlock.timeout = i
    }
    if let Some(i) = modify.password_history_limit {
        config.recovery.password_history_limit = i;
    }
    if let Some(i) = modify.trash_retention_days {
        config.recovery.trash_retention_days = i;
    }
    write_file(&config, config_path)
}

#[cfg(test)]
fn update(config: Config, modify: ConfigArgs, config_path: &Path) {
    try_update(config, modify, config_path).expect("test configuration update should succeed");
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{env, fs, fs::File};

    #[test]
    fn test_config() {
        let config_path = env::temp_dir();
        let config_file = config_path.join("config.toml");
        test_read_write(&config_file);
        test_update(&config_file);
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
            }
        );
        write_file(&conf1, config_path).unwrap();
    }
    #[test]
    fn test_is_config_exists() {
        let config_path = env::temp_dir().join("test_exists.toml");
        File::create(&config_path).unwrap();
        assert!(is_config(&config_path));
        fs::remove_file(&config_path).unwrap();
    }
    #[test]
    fn test_is_config_not_exists() {
        let config_path = env::temp_dir().join("nonexistent_config.toml");
        assert!(!is_config(&config_path));
    }
    #[test]
    fn test_update_single_field() {
        let config_path = env::temp_dir().join("test_single.toml");
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
        fs::remove_file(&config_path).unwrap();
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
    }
    #[test]
    fn test_reset_to_default() {
        let config_path = env::temp_dir().join("test_reset.toml");
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
        fs::remove_file(&config_path).unwrap();
    }

    #[test]
    fn test_config_with_alternate_values() {
        let config_path = env::temp_dir().join("alternate.toml");
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
        fs::remove_file(&config_path).unwrap();
    }

    #[test]
    fn test_multiple_updates() {
        let config_path = env::temp_dir().join("multiple.toml");
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
        fs::remove_file(&config_path).unwrap();
    }

    #[test]
    fn test_config_round_trip() {
        let config_path = env::temp_dir().join("roundtrip.toml");

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
        };

        write_file(&original, &config_path).unwrap();
        let loaded = read_config(&config_path);

        assert_eq!(original, loaded);
        fs::remove_file(&config_path).unwrap();
    }

    #[test]
    fn test_config_update_zero_timeout() {
        let config_path = env::temp_dir().join("zero_timeout.toml");
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
        fs::remove_file(&config_path).unwrap();
    }

    #[test]
    fn test_config_update_max_values() {
        let config_path = env::temp_dir().join("max_values.toml");
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
        fs::remove_file(&config_path).unwrap();
    }

    #[test]
    fn test_config_preserves_unmodified_fields() {
        let config_path = env::temp_dir().join("preserve.toml");
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
        fs::remove_file(&config_path).unwrap();
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
}
