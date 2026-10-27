use super::*;

fn parse_connection_port(value: &str) -> Result<u16, &'static str> {
    value
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or("Connection port must be between 1 and 65535.")
}

impl App {
    pub(super) fn refresh_vaults(&mut self) -> Task<Message> {
        self.launch(Job::DiscoverVaults, backend::discover_vaults)
    }

    pub(super) fn reload_settings(&mut self) -> Task<Message> {
        self.launch(Job::ReloadSettings, backend::reload_settings)
    }

    pub(super) fn apply_vaults(&mut self, vaults: Vec<String>) {
        if self.select_created_vault {
            self.vault = vaults
                .iter()
                .find(|vault| !self.vaults.contains(vault))
                .cloned()
                .or_else(|| self.vault.clone());
            self.select_created_vault = false;
        }
        self.vaults = vaults;
        // Discovery must not disturb an active session or a valid selection.
        if self.session.is_none()
            && self
                .vault
                .as_ref()
                .is_none_or(|selected| !self.vaults.contains(selected))
        {
            self.vault = self
                .conf
                .unlock
                .vault_id
                .as_ref()
                .filter(|default| self.vaults.contains(default))
                .cloned()
                .or_else(|| self.vaults.first().cloned());
        }
    }

    pub(super) fn apply_configuration(&mut self, conf: Config) {
        let recovery_changed = self.running && conf.recovery != self.conf.recovery;
        self.settings.reload(&conf);

        // Adopt operation defaults without replacing an in-progress unlock or
        // generator choice. Other operations read self.conf when dispatched.
        if self.session.is_none()
            && self.master.is_empty()
            && self.confirmation.is_empty()
            && self.key_path.is_empty()
        {
            if self.unlock_timeout == self.conf.unlock.timeout.to_string() {
                self.unlock_timeout = conf.unlock.timeout.to_string();
            }
            if self.vault == self.conf.unlock.vault_id {
                self.vault = conf.unlock.vault_id.clone();
            }
        }
        if self.generator_length == self.conf.genpass.length.to_string() {
            self.generator_length = conf.genpass.length.to_string();
        }
        self.generated_stats = if self.generator.stats_enabled(&conf) && !self.generated.is_empty()
        {
            password_manager::password::password_strength_output(self.generated.expose())
        } else {
            String::new()
        };
        // A configured-port change is a preference, not permission to replace
        // the active connection or start a server on a different port.
        self.conf = conf;
        self.confirm_reset_settings = false;
        self.notice = if recovery_changed {
            "Settings reloaded. Restart the server to apply recovery settings."
        } else {
            "Settings reloaded."
        }
        .into();
    }

    /// Invalidate the old endpoint's UI state, retaining its journal on disk.
    /// That journal is recovered when the user explicitly reconnects to it.
    pub(super) fn reset_connection(&mut self, port: u16) {
        self.serial += 1;
        self.stop_tool_watches();
        self.clear_vault();
        self.pending = None;
        self.reviewed = false;
        self.warning = None;
        self.running = false;
        self.polling = false;
        self.revealing = false;
        self.busy = false;
        self.select_created_vault = false;
        self.connect_after_discovery = false;
        self.client.port = port;
        self.connection_port = port.to_string();
        self.last_status = Instant::now();
    }

    pub(super) fn use_connection_port(&mut self) -> Task<Message> {
        let port = match parse_connection_port(&self.connection_port) {
            Ok(port) => port,
            Err(error) => {
                self.report_error(error);
                return Task::none();
            }
        };
        self.reset_connection(port);
        self.notice = format!("Connecting to port {port}…");
        let client = self.client.clone();
        self.launch(Job::Attach, move || backend::attach(&client))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui::tests::app;

    #[test]
    fn connection_ports_require_a_nonzero_u16() {
        for value in ["", "0", "65536", "-1", "abc", "12.5"] {
            assert!(parse_connection_port(value).is_err(), "{value}");
        }
        assert_eq!(parse_connection_port(" 65535 "), Ok(65535));
        assert_eq!(parse_connection_port("1"), Ok(1));
    }

    #[test]
    fn invalid_port_leaves_existing_connection_and_draft_intact() {
        let mut app = app();
        app.session = Some("old-session".into());
        app.master = "unsaved input".into();
        app.connection_port = "0".into();
        let serial = app.serial;
        let _ = app.use_connection_port();
        assert_eq!(app.client.port, 7878);
        assert_eq!(app.session.as_deref(), Some("old-session"));
        assert_eq!(app.master.expose(), "unsaved input");
        assert_eq!(app.serial, serial);
    }

    #[test]
    fn changing_connection_clears_old_session_and_journal_ui_without_saving_config() {
        let mut app = app();
        let conf = app.conf.clone();
        app.running = true;
        app.session = Some("old-session".into());
        app.pending = Some("old-operation".into());
        app.reviewed = true;
        app.warning = Some("old-warning".into());
        app.master = "secret".into();
        app.generated = "generated".into();
        app.workspace.watch_otp = true;
        app.workspace.watch_duo = true;
        app.select_created_vault = true;
        app.connect_after_discovery = true;
        app.polling = true;
        let serial = app.serial;
        // Merely construct the Task. Do not execute an actual server request.
        app.connection_port = "8787".into();
        let _ = app.use_connection_port();
        assert_eq!(app.client.port, 8787);
        assert_eq!(app.conf, conf);
        assert_eq!(app.settings.server_port, conf.server.port.to_string());
        assert!(app.serial > serial);
        assert!(app.session.is_none());
        assert!(app.pending.is_none());
        assert!(!app.reviewed);
        assert!(app.warning.is_none());
        assert!(!app.running);
        assert!(app.master.is_empty());
        assert!(app.generated.is_empty());
        assert!(!app.workspace.watch_otp);
        assert!(!app.workspace.watch_duo);
        assert!(!app.select_created_vault);
        assert!(!app.connect_after_discovery);

        let mut response = password_manager::protocol::RpcResponse::success(
            ResponsePayload::Status(password_manager::protocol::ServerStatus::new(false, None)),
        );
        response.session_id = Some("stale-session".into());
        let _ = app.update(Message::Finished(
            serial,
            Job::Status,
            Arc::new(Ok(Reply::Server {
                response: Box::new(response),
                vaults: vec!["stale.enc".into()],
                pending: vec!["old-operation".into()],
            })),
        ));
        assert!(app.session.is_none());
        assert!(app.pending.is_none());
        assert!(app.vaults.is_empty());
        assert_eq!(app.client.port, 8787);
    }

    #[test]
    fn discovery_preserves_selection_and_uses_configured_default_when_needed() {
        let mut app = app();
        app.conf.unlock.vault_id = Some("z.enc".into());
        app.apply_vaults(vec!["a.enc".into(), "z.enc".into()]);
        assert_eq!(app.vault.as_deref(), Some("z.enc"));
        app.vault = Some("a.enc".into());
        app.apply_vaults(vec!["a.enc".into(), "z.enc".into()]);
        assert_eq!(app.vault.as_deref(), Some("a.enc"));
        app.session = Some("session".into());
        app.apply_vaults(vec!["z.enc".into()]);
        assert_eq!(app.vault.as_deref(), Some("a.enc"));
        assert_eq!(app.session.as_deref(), Some("session"));
    }

    #[test]
    fn reload_updates_defaults_but_preserves_settings_and_active_operation_inputs() {
        let mut app = app();
        app.settings
            .edit(SettingsField::Length, "invalid draft".into());
        app.unlock_timeout = "7m".into();
        app.generator_length = "35".into();
        app.vault = Some("selected.enc".into());
        app.connection_port = "8787".into();
        let mut external = app.conf.clone();
        external.genpass.length = 42;
        external.copy.passwords = false;
        external.unlock.timeout = 300;
        external.unlock.vault_id = Some("external.enc".into());
        external.server.port = 9898;
        app.apply_configuration(external.clone());
        assert_eq!(app.conf, external);
        assert_eq!(app.settings.length, "invalid draft");
        assert!(!app.settings.password_copy);
        assert_eq!(app.unlock_timeout, "7m");
        assert_eq!(app.generator_length, "35");
        assert_eq!(app.vault.as_deref(), Some("selected.enc"));
        assert_eq!(app.client.port, 7878);
        assert_eq!(app.connection_port, "8787");
    }

    #[test]
    fn reload_updates_untouched_defaults_without_changing_an_active_unlock() {
        let mut app = app();
        let mut external = app.conf.clone();
        external.genpass.length = 42;
        external.unlock.timeout = 300;
        external.unlock.vault_id = Some("external.enc".into());
        app.apply_configuration(external);
        assert_eq!(app.generator_length, "42");
        assert_eq!(app.unlock_timeout, "300");
        assert_eq!(app.vault.as_deref(), Some("external.enc"));

        app.master = "typing".into();
        let mut external = app.conf.clone();
        external.unlock.timeout = 600;
        external.unlock.vault_id = Some("next.enc".into());
        app.apply_configuration(external);
        assert_eq!(app.unlock_timeout, "300");
        assert_eq!(app.vault.as_deref(), Some("external.enc"));
        assert_eq!(app.master.expose(), "typing");
    }
}
