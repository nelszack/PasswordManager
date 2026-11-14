use super::*;

pub(super) struct State {
    pub(super) client: AuthenticatedClient,
    pub(super) connection_port: String,
    pub(super) connect_after_discovery: bool,
    pub(super) running: bool,
    pub(super) session: Option<String>,
    pub(super) vaults: Vec<String>,
    pub(super) vault: Option<String>,
    pub(super) master: SecretString,
    pub(super) confirmation: SecretString,
    pub(super) key_path: SecretString,
    pub(super) unlock_timeout: String,
    pub(super) creating: bool,
    pub(super) select_created_vault: bool,
    pub(super) creation: Option<Creation>,
    pub(super) last_status: Instant,
}

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
        if self.connection.select_created_vault {
            self.connection.vault = vaults
                .iter()
                .find(|vault| !self.connection.vaults.contains(vault))
                .cloned()
                .or_else(|| self.connection.vault.clone());
            self.connection.select_created_vault = false;
        }
        self.connection.vaults = vaults;
        // Discovery must not disturb an active session or a valid selection.
        if self.connection.session.is_none()
            && self
                .connection
                .vault
                .as_ref()
                .is_none_or(|selected| !self.connection.vaults.contains(selected))
        {
            self.connection.vault = self
                .conf
                .unlock
                .vault_id
                .as_ref()
                .filter(|default| self.connection.vaults.contains(default))
                .cloned()
                .or_else(|| self.connection.vaults.first().cloned());
        }
    }

    pub(super) fn apply_configuration(&mut self, conf: Config) {
        let recovery_changed = self.connection.running && conf.recovery != self.conf.recovery;
        self.settings.reload(&conf);

        // Adopt operation defaults without replacing an in-progress unlock or
        // generator choice. Other operations read self.conf when dispatched.
        if self.connection.session.is_none()
            && self.connection.master.is_empty()
            && self.connection.confirmation.is_empty()
            && self.connection.key_path.is_empty()
        {
            if self.connection.unlock_timeout == self.conf.unlock.timeout.to_string() {
                self.connection.unlock_timeout = conf.unlock.timeout.to_string();
            }
            if self.connection.vault == self.conf.unlock.vault_id {
                self.connection.vault = conf.unlock.vault_id.clone();
            }
        }
        if self.generation.length == self.conf.genpass.length.to_string() {
            self.generation.length = conf.genpass.length.to_string();
        }
        self.generation.stats =
            if self.generation.options.stats_enabled(&conf) && !self.generation.value.is_empty() {
                password_manager::password::password_strength_output(self.generation.value.expose())
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
        self.recovery = Recovery::Clear;

        self.warning = None;
        self.connection.running = false;
        self.request_state = RequestState::Idle;
        self.connection.select_created_vault = false;
        self.connection.connect_after_discovery = false;
        self.connection.client.port = port;
        self.connection.connection_port = port.to_string();
        self.connection.last_status = Instant::now();
    }

    pub(super) fn use_connection_port(&mut self) -> Task<Message> {
        let port = match parse_connection_port(&self.connection.connection_port) {
            Ok(port) => port,
            Err(error) => {
                self.report_error(error);
                return Task::none();
            }
        };
        self.navigate(Navigate::Connect(port))
    }
}

impl App {
    pub(super) fn update_connection(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Connect => return self.connect(),
            Message::RefreshVaults => return self.refresh_vaults(),
            Message::ReloadSettings => return self.reload_settings(),
            Message::ConnectionPort(value) => self.connection.connection_port = value,
            Message::UseConnectionPort => return self.use_connection_port(),
            Message::Vault(vault) => {
                self.ui.vault_name = self.names.label(&vault, &self.connection.vaults);
                self.connection.master.zeroize();
                self.connection.key_path.zeroize();
                self.connection.vault = Some(vault);
            }
            Message::Master(password) => {
                self.ui.master_error = if self.connection.creating {
                    password_manager::encryption::validate_new_password(password.expose()).err()
                } else {
                    None
                };
                self.connection.master = password;
            }
            Message::ConfirmMaster(password) => self.connection.confirmation = password,
            Message::KeyPath(path) => self.connection.key_path = path,
            Message::UnlockTimeout(value) => self.connection.unlock_timeout = value,
            Message::BrowseKey
                if !self.connection.creating && self.connection.session.is_none() =>
            {
                self.serial += 1;
                self.request_state = RequestState::Busy;
                return file_picker::pick_key_file(self.serial);
            }
            Message::Creating(creating) => {
                self.connection.creating = creating;
                self.ui.master_error = None;
                if creating {
                    self.ui.vault_name = if self.connection.vaults.is_empty() {
                        "Personal vault".into()
                    } else {
                        format!("Vault {}", self.connection.vaults.len() + 1)
                    };
                }
                self.connection.master.zeroize();
                self.connection.confirmation.zeroize();
                self.connection.key_path.zeroize();
                self.notice.clear();
                self.ui.notice_error = false;
                return iced::widget::operation::focus("master-password");
            }
            Message::Unlock => {
                let timeout =
                    match password_manager::config::parse_duration(&self.connection.unlock_timeout)
                    {
                        Ok(timeout) => timeout,
                        Err(error) => {
                            self.report_error(format!("Lock timeout: {error}"));
                            return Task::none();
                        }
                    };
                let key = if !self.connection.key_path.is_empty() {
                    let path = match workflows::absolute(self.connection.key_path.expose()) {
                        Ok(path) => path,
                        Err(error) => {
                            self.report_error(error);
                            return Task::none();
                        }
                    };
                    PasswordType::Key(path)
                } else {
                    PasswordType::Password(
                        std::mem::take(&mut self.connection.master).expose_owned(),
                    )
                };
                self.connection.master.zeroize();
                self.connection.key_path.zeroize();
                return self.request(
                    Job::Unlock,
                    ServerCommand::Unlock(UnlockInfo {
                        key,
                        timeout,
                        vault_file: self.connection.vault.clone(),
                    }),
                    None,
                );
            }
            Message::Create if self.writes_allowed() => {
                if let Err(error) = vault_names::validate_name(&self.ui.vault_name) {
                    self.report_error(error);
                    return Task::none();
                }
                if let Err(error) = password_manager::encryption::validate_new_password(
                    self.connection.master.expose(),
                ) {
                    self.report_error(error);
                    return Task::none();
                }
                if self.connection.master != self.connection.confirmation {
                    self.report_error("The two master passwords do not match.");
                    return Task::none();
                }
                // The server applies the same password policy as the CLI.
                let key = PasswordType::Password(
                    std::mem::take(&mut self.connection.master).expose_owned(),
                );
                self.connection.creation = Some(Creation {
                    password: std::mem::take(&mut self.connection.confirmation),
                    name: self.ui.vault_name.trim().to_owned(),
                });
                return self.request(Job::Create, ServerCommand::New(key), None);
            }
            Message::Stop if self.recovery.id().is_none() => {
                self.ui.confirm_stop = false;
                self.clear_vault();
                return self.request(Job::Stop, ServerCommand::Kill, None);
            }
            _ => {}
        }
        Task::none()
    }
}

impl App {
    pub(super) fn complete_status(
        &mut self,
        job: Job,
        response: password_manager::protocol::ProtocolResponse,
        vaults: Vec<String>,
    ) -> Task<Message> {
        if let ResponsePayload::Status(status) = response.payload {
            if matches!(job, Job::Connect | Job::Attach) {
                self.notice.clear();
            }
            self.connection.running = true;
            self.warning = match (status.warning, status.cloud_warning) {
                (Some(a), Some(b)) => Some(format!("{a}; {b}")),
                (a, b) => a.or(b),
            };
            let revision_changed =
                self.vault_revision.is_some() && self.vault_revision != status.vault_revision;
            self.vault_revision = status.vault_revision;
            let next_session = if status.locked {
                None
            } else {
                response.session_id
            };
            let changed = self.connection.session != next_session;
            if changed {
                let known = self
                    .ui
                    .active_vault
                    .take()
                    .filter(|(_, session)| next_session.as_ref() == Some(session));
                self.clear_vault();
                self.ui.active_vault = known;
            }
            self.connection.session = next_session;
            if status.locked {
                if self.recovery.id().is_some() {
                    self.connection.creation = None;
                }
                if self.connection.creation.is_some() && self.connection.select_created_vault {
                    let new: Vec<_> = vaults
                        .iter()
                        .filter(|id| !self.connection.vaults.contains(id))
                        .cloned()
                        .collect();
                    if new.len() == 1 {
                        let creation = self.connection.creation.take().unwrap();
                        let id = new[0].clone();
                        self.connection.vault = Some(id.clone());
                        self.connection.vaults = vaults;
                        self.connection.select_created_vault = false;
                        let client = self.connection.client.clone();
                        let timeout = self.conf.unlock.timeout;
                        return self.launch(Job::Unlock, move || {
                            backend::open_created(
                                &client,
                                id,
                                creation.name,
                                creation.password,
                                timeout,
                            )
                        });
                    }
                    self.connection.creation = None;
                    self.notice =
                        "Your vault was created. Select the new vault and unlock it to continue."
                            .into();
                }
                if self.connection.select_created_vault {
                    self.connection.vault = vaults
                        .iter()
                        .find(|vault| !self.connection.vaults.contains(vault))
                        .cloned();
                    self.connection.select_created_vault = false;
                }
                self.connection.vaults = vaults;
                if self
                    .connection
                    .vault
                    .as_ref()
                    .is_none_or(|selected| !self.connection.vaults.contains(selected))
                {
                    self.connection.vault = self.connection.vaults.first().cloned();
                }
                if matches!(job, Job::Connect | Job::Attach) {
                    self.notice.clear();
                }
            } else {
                self.connection.vaults = vaults;
                if changed {
                    self.connection.creating = false;
                    return self.load_items();
                }
                if revision_changed {
                    if self.editor.is_some() || self.recovery.id().is_some() {
                        self.notice="The vault changed on another client or device. Your draft is preserved; reopen the item before saving if it changed.".into();
                    } else {
                        self.notice = "Vault updated from another client or device.".into();
                        if let Some(id) = self.item.as_ref().map(|item| item.id) {
                            return self.refresh_item(id, ItemIntent::View, false);
                        }
                        return self.load_items();
                    }
                }
            }
        }
        Task::none()
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
        app.connection.session = Some("old-session".into());
        app.connection.master = "unsaved input".into();
        app.connection.connection_port = "0".into();
        let serial = app.serial;
        let _ = app.use_connection_port();
        assert_eq!(app.connection.client.port, 7878);
        assert_eq!(app.connection.session.as_deref(), Some("old-session"));
        assert_eq!(app.connection.master.expose(), "unsaved input");
        assert_eq!(app.serial, serial);
    }

    #[test]
    fn changing_connection_clears_old_session_and_journal_ui_without_saving_config() {
        let mut app = app();
        let conf = app.conf.clone();
        app.connection.running = true;
        app.connection.session = Some("old-session".into());
        app.recovery =
            Recovery::AwaitingAcknowledgement(password_manager::protocol::OperationReceipt {
                operation_id: "old-operation".into(),
                state: OperationState::Unknown,
                revision: None,
            });
        app.warning = Some("old-warning".into());
        app.connection.master = "secret".into();
        app.generation.value = "generated".into();
        app.workspace.otp.watch = Some(workflows::WatchTarget {
            choice: workflows::Choice {
                id: 1,
                label: "Old item".into(),
            },
            session: "old-session".into(),
            revision: 1,
        });
        app.workspace.duo.watch = Some(workflows::WatchTarget {
            choice: workflows::Choice {
                id: 1,
                label: "Old item".into(),
            },
            session: "old-session".into(),
            revision: 1,
        });
        app.connection.select_created_vault = true;
        app.connection.connect_after_discovery = true;
        app.request_state = RequestState::Polling;
        let serial = app.serial;
        // Merely construct the Task. Do not execute an actual server request.
        app.connection.connection_port = "8787".into();
        let _ = app.use_connection_port();
        assert_eq!(app.connection.client.port, 8787);
        assert_eq!(app.conf, conf);
        assert_eq!(app.settings.server_port, conf.server.port.to_string());
        assert!(app.serial > serial);
        assert!(app.connection.session.is_none());
        assert!(app.recovery.id().is_none());
        assert!(!app.recovery.reviewed());
        assert!(app.warning.is_none());
        assert!(!app.connection.running);
        assert!(app.connection.master.is_empty());
        assert!(app.generation.value.is_empty());
        assert!(app.workspace.otp.watch.is_none());
        assert!(app.workspace.duo.watch.is_none());
        assert!(!app.connection.select_created_vault);
        assert!(!app.connection.connect_after_discovery);

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
        assert!(app.connection.session.is_none());
        assert!(app.recovery.id().is_none());
        assert!(app.connection.vaults.is_empty());
        assert_eq!(app.connection.client.port, 8787);
    }

    #[test]
    fn discovery_preserves_selection_and_uses_configured_default_when_needed() {
        let mut app = app();
        app.conf.unlock.vault_id = Some("z.enc".into());
        app.apply_vaults(vec!["a.enc".into(), "z.enc".into()]);
        assert_eq!(app.connection.vault.as_deref(), Some("z.enc"));
        app.connection.vault = Some("a.enc".into());
        app.apply_vaults(vec!["a.enc".into(), "z.enc".into()]);
        assert_eq!(app.connection.vault.as_deref(), Some("a.enc"));
        app.connection.session = Some("session".into());
        app.apply_vaults(vec!["z.enc".into()]);
        assert_eq!(app.connection.vault.as_deref(), Some("a.enc"));
        assert_eq!(app.connection.session.as_deref(), Some("session"));
    }

    #[test]
    fn reload_updates_defaults_but_preserves_settings_and_active_operation_inputs() {
        let mut app = app();
        app.settings
            .edit(SettingsField::Length, "invalid draft".into());
        app.connection.unlock_timeout = "7m".into();
        app.generation.length = "35".into();
        app.connection.vault = Some("selected.enc".into());
        app.connection.connection_port = "8787".into();
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
        assert_eq!(app.connection.unlock_timeout, "7m");
        assert_eq!(app.generation.length, "35");
        assert_eq!(app.connection.vault.as_deref(), Some("selected.enc"));
        assert_eq!(app.connection.client.port, 7878);
        assert_eq!(app.connection.connection_port, "8787");
    }

    #[test]
    fn reload_updates_untouched_defaults_without_changing_an_active_unlock() {
        let mut app = app();
        let mut external = app.conf.clone();
        external.genpass.length = 42;
        external.unlock.timeout = 300;
        external.unlock.vault_id = Some("external.enc".into());
        app.apply_configuration(external);
        assert_eq!(app.generation.length, "42");
        assert_eq!(app.connection.unlock_timeout, "300");
        assert_eq!(app.connection.vault.as_deref(), Some("external.enc"));

        app.connection.master = "typing".into();
        let mut external = app.conf.clone();
        external.unlock.timeout = 600;
        external.unlock.vault_id = Some("next.enc".into());
        app.apply_configuration(external);
        assert_eq!(app.connection.unlock_timeout, "300");
        assert_eq!(app.connection.vault.as_deref(), Some("external.enc"));
        assert_eq!(app.connection.master.expose(), "typing");
    }
}
