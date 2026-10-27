use password_manager::config::{Appearance, Config, ConfigChanges, parse_duration};

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
    fn appearance_edits_survive_refresh_and_save_only_the_changed_preference() {
        let base = Config::default();
        let mut draft = SettingsDraft::from(&base);
        assert!(!draft.is_dirty());
        draft.appearance = Appearance::Light;
        let mut disk = base.clone();
        disk.desktop.scale = 130;
        disk.genpass.length = 31;
        draft.reload(&disk);
        assert_eq!(draft.appearance, Appearance::Light);
        assert_eq!(draft.scale, 130);
        assert_eq!(draft.length, "31");
        assert!(draft.is_dirty());
        let changes = draft.changes().unwrap();
        assert_eq!(changes.desktop_appearance, Some(Appearance::Light));
        assert_eq!(changes.desktop_scale, None);
        assert_eq!(changes.genpass_length, None);
        draft.edit(Field::Length, "0".into());
        assert!(draft.field_error(Field::Length, &draft.length).is_some());
        assert!(
            draft
                .field_error(Field::ServerPort, &draft.server_port)
                .is_none()
        );
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

    #[test]
    fn reload_adopts_unedited_fields_and_rebases_conflicting_edits() {
        let base = Config::default();
        let mut draft = SettingsDraft::from(&base);
        draft.edit(Field::Length, "31".into());
        draft.edit(Field::DefaultVault, "local.enc".into());
        draft.toggle(Toggle::GeneratorCopy, false);
        let mut disk = base.clone();
        disk.genpass.length = 42;
        disk.genpass.stats = true;
        disk.genpass.copy = false;
        disk.copy.passwords = false;
        disk.clipboard.timeout = 7;
        disk.unlock.timeout = 300;
        disk.unlock.vault_id = Some("external.enc".into());
        disk.recovery.password_history_limit = 20;
        disk.recovery.trash_retention_days = 30;
        disk.server.port = 8787;
        draft.reload(&disk);
        assert_eq!(draft.length, "31");
        assert_eq!(draft.default_vault, "local.enc");
        assert!(draft.stats);
        assert!(!draft.generator_copy);
        assert!(!draft.password_copy);
        assert_eq!(draft.clipboard_timeout, "7");
        assert_eq!(draft.unlock_timeout, "300");
        assert_eq!(draft.history_limit, "20");
        assert_eq!(draft.trash_retention, "30");
        assert_eq!(draft.server_port, "8787");
        let changes = draft.changes().unwrap();
        assert_eq!(changes.genpass_length, Some(31));
        assert_eq!(changes.default_vault.as_deref(), Some("local.enc"));
        assert_eq!(changes.genpass_stats, None);
        assert_eq!(changes.genpass_copy, None);
        assert_eq!(changes.password_copy, None);
        assert_eq!(changes.clipboard_timeout, None);
        assert_eq!(changes.unlock_timeout, None);
        assert_eq!(changes.password_history_limit, None);
        assert_eq!(changes.trash_retention_days, None);
        assert_eq!(changes.server_port, None);
        // Once the user accepts the new baseline, later external edits follow.
        draft.edit(Field::Length, "42".into());
        disk.genpass.length = 50;
        draft.reload(&disk);
        assert_eq!(draft.length, "50");
    }

    #[test]
    fn reload_preserves_invalid_input_and_explicit_default_vault_clear() {
        let mut base = Config::default();
        base.unlock.vault_id = Some("old.enc".into());
        let mut draft = SettingsDraft::from(&base);
        draft.edit(Field::ServerPort, "unfinished".into());
        draft.edit(Field::UnlockTimeout, "2h".into());
        draft.edit(Field::DefaultVault, String::new());
        let mut disk = base.clone();
        disk.server.port = 8787;
        disk.unlock.timeout = 30;
        disk.unlock.vault_id = Some("new.enc".into());
        draft.reload(&disk);
        draft.reload(&disk);
        assert_eq!(draft.server_port, "unfinished");
        assert_eq!(draft.unlock_timeout, "2h");
        assert!(draft.default_vault.is_empty());
        assert!(draft.changes().is_err());
        draft.edit(Field::ServerPort, "8787".into());
        let changes = draft.changes().unwrap();
        assert!(changes.clear_default_vault);
        assert_eq!(changes.unlock_timeout, Some(7200));
        assert_eq!(changes.server_port, None);
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
    pub appearance: Appearance,
    pub scale: u16,
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
            appearance: conf.desktop.appearance,
            scale: conf.desktop.scale,
        }
    }
}

impl SettingsDraft {
    /// Rebase the form onto the latest disk configuration. Only fields that
    /// still match the old baseline follow disk changes; even invalid local
    /// input is retained so a refresh cannot discard work in progress.
    pub fn reload(&mut self, conf: &Config) {
        let previous = Self::from(&self.baseline);
        let next = Self::from(conf);
        macro_rules! merge {
            ($($field:ident),+ $(,)?) => {
                $(if self.$field == previous.$field {
                    self.$field = next.$field;
                })+
            };
        }
        merge!(
            length,
            stats,
            generator_copy,
            password_copy,
            clipboard_timeout,
            unlock_timeout,
            history_limit,
            trash_retention,
            server_port,
            default_vault,
            appearance,
            scale,
        );
        self.baseline = conf.clone();
    }

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
            desktop_appearance: (self.appearance != base.desktop.appearance)
                .then_some(self.appearance),
            desktop_scale: (self.scale != base.desktop.scale).then_some(self.scale),
        })
    }

    pub fn is_dirty(&self) -> bool {
        let previous = Self::from(&self.baseline);
        self.length != previous.length
            || self.stats != previous.stats
            || self.generator_copy != previous.generator_copy
            || self.password_copy != previous.password_copy
            || self.clipboard_timeout != previous.clipboard_timeout
            || self.unlock_timeout != previous.unlock_timeout
            || self.history_limit != previous.history_limit
            || self.trash_retention != previous.trash_retention
            || self.server_port != previous.server_port
            || self.default_vault != previous.default_vault
            || self.appearance != previous.appearance
            || self.scale != previous.scale
    }

    /// Validate one edited field against valid defaults so the inline error
    /// uses exactly the same rules and wording as saving the complete form.
    pub fn field_error(&self, field: Field, value: &str) -> Option<String> {
        let mut isolated = Self::from(&Config::default());
        isolated.edit(field, value.into());
        isolated.changes().err()
    }
}
