use password_manager::config::{Config, ConfigChanges, parse_duration};

#[derive(Clone, Copy, Debug)]
pub enum Field {
    Length,
    ClipboardTimeout,
    UnlockTimeout,
    HistoryLimit,
    TrashRetention,
    ServerPort,
    DefaultVault,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use password_manager::{
        cli::{Cli, CliCommands},
        config,
    };

    #[test]
    fn desktop_settings_match_every_cli_config_option() {
        let base = Config::default();
        let mut draft = SettingsDraft::from(&base);
        for (field, value) in [
            (Field::Length, "31"),
            (Field::ClipboardTimeout, "42"),
            (Field::UnlockTimeout, "2h"),
            (Field::HistoryLimit, "24"),
            (Field::TrashRetention, "60"),
            (Field::ServerPort, "8787"),
            (Field::DefaultVault, "selected.enc"),
        ] {
            draft.edit(field, value.into());
        }
        draft.toggle(Toggle::GeneratorStats, true);
        draft.toggle(Toggle::GeneratorCopy, false);
        draft.toggle(Toggle::PasswordCopy, false);
        let cli = Cli::try_parse_from([
            "pm",
            "config",
            "--length",
            "31",
            "--stats",
            "true",
            "--copy",
            "false",
            "--password-copy",
            "false",
            "--clipboard-timeout",
            "42",
            "--unlock-timeout",
            "2h",
            "--password-history-limit",
            "24",
            "--trash-retention-days",
            "60",
            "--server-port",
            "8787",
            "--default-vault",
            "selected.enc",
        ])
        .unwrap();
        let Some(CliCommands::Config(args)) = cli.command else {
            panic!()
        };
        let directory = tempfile::tempdir().unwrap();
        let desktop = config::try_update(
            base.clone(),
            draft.changes().unwrap(),
            &directory.path().join("desktop.toml"),
        )
        .unwrap();
        let cli = config::try_update(base, args, &directory.path().join("cli.toml")).unwrap();
        assert_eq!(desktop, cli);
    }

    #[test]
    fn invalid_settings_are_rejected_before_saving() {
        for (field, value) in [
            (Field::Length, "0"),
            (Field::Length, "256"),
            (Field::ClipboardTimeout, "256"),
            (Field::UnlockTimeout, "18446744073709551615d"),
            (Field::HistoryLimit, "-1"),
            (Field::TrashRetention, "-1"),
            (Field::ServerPort, "0"),
            (Field::ServerPort, "65536"),
            (Field::DefaultVault, "../outside.enc"),
        ] {
            let mut draft = SettingsDraft::from(&Config::default());
            draft.edit(field, value.into());
            assert!(draft.changes().is_err(), "{field:?}: {value}");
        }
    }

    #[test]
    fn automatic_vault_selection_does_not_reset_other_preferences() {
        let mut conf = Config::default();
        conf.unlock.vault_id = Some("selected.enc".into());
        conf.genpass.length = 37;
        let mut draft = SettingsDraft::from(&conf);
        draft.edit(Field::DefaultVault, String::new());
        let directory = tempfile::tempdir().unwrap();
        let updated = config::try_update(
            conf,
            draft.changes().unwrap(),
            &directory.path().join("config.toml"),
        )
        .unwrap();
        assert_eq!(updated.genpass.length, 37);
        assert!(updated.unlock.vault_id.is_none());
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Toggle {
    GeneratorStats,
    GeneratorCopy,
    PasswordCopy,
}

pub struct SettingsDraft {
    baseline: Config,
    pub length: String,
    pub stats: bool,
    pub generator_copy: bool,
    pub password_copy: bool,
    pub clipboard_timeout: String,
    pub unlock_timeout: String,
    pub history_limit: String,
    pub trash_retention: String,
    pub server_port: String,
    pub default_vault: String,
}

impl From<&Config> for SettingsDraft {
    fn from(conf: &Config) -> Self {
        Self {
            baseline: conf.clone(),
            length: conf.genpass.length.to_string(),
            stats: conf.genpass.stats,
            generator_copy: conf.genpass.copy,
            password_copy: conf.copy.passwords,
            clipboard_timeout: conf.clipboard.timeout.to_string(),
            unlock_timeout: conf.unlock.timeout.to_string(),
            history_limit: conf.recovery.password_history_limit.to_string(),
            trash_retention: conf.recovery.trash_retention_days.to_string(),
            server_port: conf.server.port.to_string(),
            default_vault: conf.unlock.vault_id.clone().unwrap_or_default(),
        }
    }
}

impl SettingsDraft {
    pub fn edit(&mut self, field: Field, value: String) {
        *match field {
            Field::Length => &mut self.length,
            Field::ClipboardTimeout => &mut self.clipboard_timeout,
            Field::UnlockTimeout => &mut self.unlock_timeout,
            Field::HistoryLimit => &mut self.history_limit,
            Field::TrashRetention => &mut self.trash_retention,
            Field::ServerPort => &mut self.server_port,
            Field::DefaultVault => &mut self.default_vault,
        } = value;
    }

    pub fn toggle(&mut self, toggle: Toggle, value: bool) {
        *match toggle {
            Toggle::GeneratorStats => &mut self.stats,
            Toggle::GeneratorCopy => &mut self.generator_copy,
            Toggle::PasswordCopy => &mut self.password_copy,
        } = value;
    }

    pub fn changes(&self) -> Result<ConfigChanges, String> {
        let length = self
            .length
            .trim()
            .parse::<u8>()
            .ok()
            .filter(|length| *length > 0)
            .ok_or("Password length must be between 1 and 255.")?;
        let clipboard = self
            .clipboard_timeout
            .trim()
            .parse::<u8>()
            .map_err(|_| "Clipboard timeout must be between 0 and 255 seconds.")?;
        let timeout = parse_duration(&self.unlock_timeout)
            .map_err(|error| format!("Lock timeout: {error}."))?;
        let history = self
            .history_limit
            .trim()
            .parse::<usize>()
            .map_err(|_| "Password history limit must be a nonnegative whole number.")?;
        let retention = self
            .trash_retention
            .trim()
            .parse::<u64>()
            .map_err(|_| "Trash retention must be a nonnegative number of days.")?;
        let port = self
            .server_port
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or("Server port must be between 1 and 65535.")?;
        let vault = self.default_vault.trim();
        if !vault.is_empty() {
            password_manager::vault::validate_vault_filename(vault)
                .map_err(|error| error.to_string())?;
        }
        let base = &self.baseline;
        // Only send edited settings. Other fields may have been changed by the
        // CLI since this form was opened; the backend rereads them before saving.
        Ok(ConfigChanges {
            reset: false,
            genpass_length: (length != base.genpass.length).then_some(length),
            genpass_stats: (self.stats != base.genpass.stats).then_some(self.stats),
            genpass_copy: (self.generator_copy != base.genpass.copy).then_some(self.generator_copy),
            password_copy: (self.password_copy != base.copy.passwords)
                .then_some(self.password_copy),
            clipboard_timeout: (clipboard != base.clipboard.timeout).then_some(clipboard),
            unlock_timeout: (timeout != base.unlock.timeout).then_some(timeout),
            password_history_limit: (history != base.recovery.password_history_limit)
                .then_some(history),
            trash_retention_days: (retention != base.recovery.trash_retention_days)
                .then_some(retention),
            server_port: (port != base.server.port).then_some(port),
            default_vault: (!vault.is_empty() && base.unlock.vault_id.as_deref() != Some(vault))
                .then(|| vault.to_owned()),
            clear_default_vault: vault.is_empty() && base.unlock.vault_id.is_some(),
        })
    }
}
