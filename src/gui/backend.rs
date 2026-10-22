use password_manager::{
    client::AuthenticatedClient,
    config::{self, Config, ConfigChanges},
    file::{config_dir, data_dir, set_private_dir_perms, set_private_perms, sync_parent},
    protocol::{OperationState, ProtocolResponse, RequestEnvelope, ResponsePayload},
    secret::SecretString,
    server, vault,
};

#[derive(Clone, Debug)]
pub enum Reply {
    Server {
        response: Box<ProtocolResponse>,
        vaults: Vec<String>,
        pending: Vec<String>,
    },
    Settings {
        conf: Config,
        restart_required: bool,
    },
    Copied,
    Acknowledged,
    KeyFile(Option<SecretString>),
}

#[derive(Clone, Debug)]
pub struct Failure {
    pub message: String,
    pub uncertain_operation: Option<String>,
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            message,
            uncertain_operation: None,
        }
    }
}

pub fn connect(client: &AuthenticatedClient) -> Result<Reply, Failure> {
    server::start(client.port)?;
    request(
        client,
        RequestEnvelope::new(password_manager::types::ServerCommand::Status),
    )
}

pub fn request(client: &AuthenticatedClient, envelope: RequestEnvelope) -> Result<Reply, Failure> {
    let operation_id = envelope.operation_id.clone();
    let journal = Journal::new(client.port);
    if let Some(id) = &operation_id {
        journal.begin(id)?;
    }
    let response = match client.request_envelope_tracked(envelope) {
        Ok(response) => response,
        Err(error) => {
            if !error.sent
                && let Some(id) = &operation_id
            {
                journal.finish(id)?;
            }
            return Err(Failure {
                message: error.message,
                uncertain_operation: error.sent.then_some(operation_id).flatten(),
            });
        }
    };
    if let Some(id) = &operation_id
        && response.operation.as_ref().is_none_or(|receipt| {
            matches!(
                receipt.state,
                OperationState::Committed | OperationState::Failed
            )
        })
    {
        journal.finish(id).map_err(|error| Failure {
            message: error.message,
            uncertain_operation: Some(id.clone()),
        })?;
    }
    if let ResponsePayload::Operation(receipt) = &response.payload
        && matches!(
            receipt.state,
            OperationState::Committed | OperationState::Failed
        )
    {
        journal.finish(&receipt.operation_id)?;
    }
    let vaults = if matches!(&response.payload, ResponsePayload::Status(_)) {
        // Vault discovery is local and never decrypts a vault.
        vault::list_vaults().map_err(|error| Failure::from(error.to_string()))?
    } else {
        vec![]
    };
    Ok(Reply::Server {
        response: Box::new(response),
        vaults,
        pending: journal.pending()?,
    })
}

pub fn acknowledge(client: &AuthenticatedClient, id: &str) -> Result<Reply, Failure> {
    Journal::new(client.port).finish(id)?;
    Ok(Reply::Acknowledged)
}

// Only operation IDs go to disk. A lost reply must remain reviewable after the
// window closes, and restarting the GUI must never implicitly retry a change.
struct Journal {
    directory: std::path::PathBuf,
    port: u16,
}

impl Journal {
    fn new(port: u16) -> Self {
        Self {
            directory: data_dir().join("desktop-operations"),
            port,
        }
    }
    fn path(&self, id: &str) -> Result<std::path::PathBuf, Failure> {
        if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Failure::from(
                "Invalid desktop operation identifier.".to_owned(),
            ));
        }
        Ok(self.directory.join(format!("{}-{id}.pending", self.port)))
    }
    fn begin(&self, id: &str) -> Result<(), Failure> {
        let path = self.path(id)?;
        let result = (|| -> std::io::Result<()> {
            std::fs::create_dir_all(&self.directory)?;
            set_private_dir_perms(&self.directory)?;
            let file = tempfile::NamedTempFile::new_in(&self.directory)?;
            set_private_perms(file.path())?;
            file.as_file().sync_all()?;
            file.persist(&path).map_err(|error| error.error)?;
            sync_parent(&path)
        })();
        result.map_err(|error| {
            Failure::from(format!(
                "Could not record the operation before sending it: {error}"
            ))
        })
    }
    fn finish(&self, id: &str) -> Result<(), Failure> {
        let path = self.path(id)?;
        match std::fs::remove_file(&path) {
            Ok(()) => sync_parent(&path).map_err(|error| Failure::from(error.to_string())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Failure::from(format!(
                "Could not clear the desktop operation record: {error}"
            ))),
        }
    }
    fn pending(&self) -> Result<Vec<String>, Failure> {
        let entries = match std::fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(error) => return Err(Failure::from(error.to_string())),
        };
        let prefix = format!("{}-", self.port);
        let mut ids = vec![];
        for entry in entries {
            let name = entry
                .map_err(|error| Failure::from(error.to_string()))?
                .file_name();
            if let Some(id) = name
                .to_str()
                .and_then(|name| name.strip_prefix(&prefix))
                .and_then(|name| name.strip_suffix(".pending"))
                && self.path(id).is_ok()
            {
                ids.push(id.to_owned());
            }
        }
        ids.sort();
        Ok(ids)
    }
}

pub fn save_settings(changes: ConfigChanges) -> Result<Reply, Failure> {
    let path = config_dir().join("config.toml");
    save_settings_at(changes, &path, server::is_running)
}

fn save_settings_at(
    changes: ConfigChanges,
    path: &std::path::Path,
    is_running: impl FnOnce(u16) -> bool,
) -> Result<Reply, Failure> {
    let current = config::try_read_config(path)?;
    let running = is_running(current.server.port);
    let requested_port = if changes.reset {
        server::DEFAULT_PORT
    } else {
        changes.server_port.unwrap_or(current.server.port)
    };
    if running && requested_port != current.server.port {
        return Err(Failure::from(
            "Stop the running server before changing its configured port.".to_owned(),
        ));
    }
    let previous_recovery = current.recovery.clone();
    let conf = config::try_update(current, changes, path)?;
    let restart_required = running && conf.recovery != previous_recovery;
    Ok(Reply::Settings {
        conf,
        restart_required,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saving_settings_preserves_unedited_cli_changes_and_reports_restarts() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.toml");
        let mut draft = super::super::settings::SettingsDraft::from(&Config::default());
        draft.edit(super::super::settings::Field::HistoryLimit, "25".into());
        config::try_update(
            Config::default(),
            ConfigChanges {
                genpass_length: Some(42),
                genpass_stats: Some(true),
                ..Default::default()
            },
            &path,
        )
        .unwrap();
        let Reply::Settings {
            conf,
            restart_required,
        } = save_settings_at(draft.changes().unwrap(), &path, |_| true).unwrap()
        else {
            panic!()
        };
        assert_eq!(conf.genpass.length, 42);
        assert!(conf.genpass.stats);
        assert_eq!(conf.recovery.password_history_limit, 25);
        assert!(restart_required);
        assert_eq!(config::try_read_config(&path).unwrap(), conf);
    }

    #[test]
    fn port_changes_and_resets_require_stopping_the_configured_server() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.toml");
        let initial = config::try_update(
            Config::default(),
            ConfigChanges {
                server_port: Some(8787),
                ..Default::default()
            },
            &path,
        )
        .unwrap();
        for changes in [
            ConfigChanges {
                server_port: Some(8888),
                ..Default::default()
            },
            ConfigChanges {
                reset: true,
                ..Default::default()
            },
        ] {
            assert!(
                save_settings_at(changes, &path, |port| {
                    assert_eq!(port, 8787);
                    true
                })
                .is_err()
            );
            assert_eq!(config::try_read_config(&path).unwrap(), initial);
        }
        let Reply::Settings {
            conf,
            restart_required,
        } = save_settings_at(
            ConfigChanges {
                reset: true,
                ..Default::default()
            },
            &path,
            |_| false,
        )
        .unwrap()
        else {
            panic!()
        };
        assert_eq!(conf, Config::default());
        assert!(!restart_required);
    }

    #[test]
    fn journal_survives_reopening_and_is_scoped_to_the_server_port() {
        let root = tempfile::tempdir().unwrap();
        let journal = Journal {
            directory: root.path().join("operations"),
            port: 7878,
        };
        let id = "a".repeat(32);
        journal.begin(&id).unwrap();
        let reopened = Journal {
            directory: journal.directory.clone(),
            port: 7878,
        };
        assert_eq!(reopened.pending().unwrap(), vec![id.clone()]);
        assert!(
            Journal {
                directory: journal.directory.clone(),
                port: 8787
            }
            .pending()
            .unwrap()
            .is_empty()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(journal.path(&id).unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(journal.begin("../../outside").is_err());
        journal.finish(&id).unwrap();
        assert!(reopened.pending().unwrap().is_empty());
    }
}
