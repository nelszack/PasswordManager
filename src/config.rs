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
    #[serde(default)]
    pub server: ServerConfig,
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

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(default)]
pub struct ServerConfig {
    pub port: u16,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(default)]
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

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: crate::server::DEFAULT_PORT,
        }
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

fn has_missing_fields(current: &serde_json::Value, complete: &serde_json::Value) -> bool {
    let serde_json::Value::Object(complete) = complete else {
        return false;
    };
    let serde_json::Value::Object(current) = current else {
        return true;
    };
    complete.iter().any(|(name, complete_value)| {
        current
            .get(name)
            .is_none_or(|current_value| has_missing_fields(current_value, complete_value))
    })
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
    let config: Config = toml::from_str(&txt).map_err(|error| {
        format!(
            "invalid configuration at {}; the file was left unchanged: {error}",
            config_path.display()
        )
    })?;
    if config.genpass.length == 0 {
        return Err(format!(
            "invalid configuration at {}; genpass.length must be between 1 and 255; the file was left unchanged",
            config_path.display()
        ));
    }
    if config.server.port == 0 {
        return Err(format!(
            "invalid configuration at {}; server.port must be between 1 and 65535; the file was left unchanged",
            config_path.display()
        ));
    }
    let current: serde_json::Value = toml::from_str(&txt)
        .map_err(|error| format!("could not inspect configuration fields: {error}"))?;
    let complete = serde_json::to_value(&config)
        .map_err(|error| format!("could not inspect configuration defaults: {error}"))?;
    if has_missing_fields(&current, &complete) {
        write_file(&config, config_path)?;
    }
    Ok(config)
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
) -> Result<Config, String> {
    if modify.reset {
        config = Config::default();
    }
    if let Some(i) = modify.genpass_length {
        if i == 0 {
            return Err("generator length must be at least 1".to_string());
        }
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
    if let Some(i) = modify.server_port {
        config.server.port = i;
    }
    write_file(&config, config_path)?;
    Ok(config)
}

#[cfg(test)]
fn update(config: Config, modify: ConfigArgs, config_path: &Path) {
    let _ =
        try_update(config, modify, config_path).expect("test configuration update should succeed");
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod test;
