use crate::cli::ConfigArgs;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
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
pub struct GeneratorConfig {
    pub length: u8,
    pub stats: bool,
    pub copy: bool,
}
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CopyConfig {
    #[serde(alias = "copy_pass")]
    pub passwords: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ClipboardConfig {
    #[serde(alias = "clp_timeout")]
    pub timeout: u8,
}
#[derive(Serialize, Deserialize, PartialEq, Debug)]
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

impl Default for Config {
    fn default() -> Self {
        Self {
            genpass: GeneratorConfig {
                length: 12,
                stats: false,
                copy: true,
            },
            clipboard: ClipboardConfig { timeout: 15 },
            unlock: UnlockConfig { timeout: 15 * 60 },
            copy: CopyConfig { passwords: true },
            recovery: RecoveryConfig::default(),
        }
    }
}

fn write_file(config: &Config, config_path: &Path) {
    let toml_string = toml::to_string(config).unwrap();
    fs::write(config_path, &toml_string).unwrap();
}
fn default_config(write_to_file: bool, config_path: &Path) -> Config {
    let config = Config::default();
    if write_to_file {
        write_file(&config, config_path)
    }
    config
}
fn is_config(config_path: &Path) -> bool {
    config_path.exists()
}
pub fn read_config(config_path: &Path) -> Config {
    if !is_config(config_path) {
        return default_config(true, config_path);
    }
    let txt = std::fs::read_to_string(config_path).unwrap();

    match toml::from_str(&txt) {
        Ok(content) => content,
        Err(_) => {
            fix_new_config(default_config(false, config_path), &txt, config_path);
            read_config(config_path)
        }
    }
}
fn fix_new_config(config: Config, old_config_txt: &str, config_path: &Path) {
    let mut new = ConfigArgs {
        reset: false,
        genpass_copy: None,
        genpass_length: None,
        genpass_stats: None,
        clipboard_timeout: None,
        unlock_timeout: None,
        password_history_limit: None,
        trash_retention_days: None,
    };
    for section in old_config_txt.split("\n\n") {
        let mut lines = section.lines();
        let Some(header) = lines.next() else {
            continue;
        };
        let Some(trimmed) = header
            .trim()
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
        else {
            continue;
        };
        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once(" = ") else {
                continue;
            };
            match (trimmed, key.trim()) {
                ("genpass", "length") => {
                    if let Ok(v) = value.trim().parse() {
                        new.genpass_length = Some(v);
                    }
                }
                ("genpass", "stats") => {
                    if let Ok(v) = value.trim().parse() {
                        new.genpass_stats = Some(v);
                    }
                }
                ("genpass", "copy") => {
                    if let Ok(v) = value.trim().parse() {
                        new.genpass_copy = Some(v);
                    }
                }
                ("clipboard" | "clpboard", "timeout" | "clp_timeout") => {
                    if let Ok(v) = value.trim().parse() {
                        new.clipboard_timeout = Some(v);
                    }
                }
                ("unlock", "timeout" | "unlock_timeout") => {
                    if let Ok(v) = value.trim().parse() {
                        new.unlock_timeout = Some(v);
                    }
                }
                ("recovery", "password_history_limit") => {
                    if let Ok(v) = value.trim().parse() {
                        new.password_history_limit = Some(v);
                    }
                }
                ("recovery", "trash_retention_days") => {
                    if let Ok(v) = value.trim().parse() {
                        new.trash_retention_days = Some(v);
                    }
                }
                _ => {}
            }
        }
    }
    update(config, new, config_path);
}
pub fn update(mut config: Config, modify: ConfigArgs, config_path: &Path) {
    if modify.reset {
        config = default_config(false, config_path);
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
    write_file(&config, config_path);
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
        default_config(true, config_path);
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
        write_file(&conf1, config_path);
        assert_eq!(read_config(config_path), conf1)
    }

    fn test_update(config_path: &Path) {
        let conf1 = read_config(config_path);
        update(
            default_config(true, config_path),
            ConfigArgs {
                reset: false,
                genpass_length: Some(100),
                genpass_stats: Some(false),
                genpass_copy: Some(true),
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
        write_file(&conf1, config_path);
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
        default_config(true, &config_path);
        update(
            read_config(&config_path),
            ConfigArgs {
                reset: false,
                genpass_length: Some(24),
                genpass_stats: None,
                genpass_copy: None,
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
        let config = default_config(false, Path::new("dummy.toml"));
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
        default_config(true, &config_path);

        update(
            read_config(&config_path),
            ConfigArgs {
                reset: false,
                genpass_length: Some(16),
                genpass_stats: Some(true),
                genpass_copy: None,
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

        write_file(&original, &config_path);
        let loaded = read_config(&config_path);

        assert_eq!(original, loaded);
        fs::remove_file(&config_path).unwrap();
    }

    #[test]
    fn test_config_update_zero_timeout() {
        let config_path = env::temp_dir().join("zero_timeout.toml");
        default_config(true, &config_path);
        update(
            read_config(&config_path),
            ConfigArgs {
                reset: false,
                genpass_length: None,
                genpass_stats: None,
                genpass_copy: None,
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
        default_config(true, &config_path);
        update(
            read_config(&config_path),
            ConfigArgs {
                reset: false,
                genpass_length: Some(u8::MAX),
                genpass_stats: Some(true),
                genpass_copy: Some(false),
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
            default_config(false, &config_path),
            ConfigArgs {
                reset: false,
                genpass_length: Some(50),
                genpass_stats: None,
                genpass_copy: None,
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
}
