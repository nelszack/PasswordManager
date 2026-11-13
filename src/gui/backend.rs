use password_manager::{
    client::AuthenticatedClient,
    config::{self, Config, ConfigChanges},
    file::{config_dir, data_dir, set_private_dir_perms, set_private_perms, sync_parent},
    protocol::{OperationState, ProtocolResponse, RequestEnvelope, ResponsePayload},
    secret::SecretString,
    server,
};

#[derive(Clone, Debug)]
pub enum Reply {
    Vaults {
        vaults: Vec<String>,
        names: super::vault_names::Names,
    },
    Created {
        reply: Box<Reply>,
        names: super::vault_names::Names,
    },
    Names(super::vault_names::Names),
    WebsiteOpened,
    Configuration(Config),
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
    PickedFile(super::workflows::Field, Option<SecretString>),
    Local(String),
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
    attach(client)
}

/// Probe an existing server without starting one or changing its configuration.
pub fn attach(client: &AuthenticatedClient) -> Result<Reply, Failure> {
    request(
        client,
        RequestEnvelope::new(password_manager::types::ServerCommand::Status),
    )
}

/// Discovery is local and works independently of the server's status.
pub fn discover_vaults() -> Result<Reply, Failure> {
    Ok(Reply::Vaults {
        vaults: cached_vaults_at(&data_dir(), true)?,
        names: super::vault_names::Names::read(&config_dir().join("vault-names.json"))
            .map_err(Failure::from)?,
    })
}

type ListingCache = std::sync::Mutex<super::discovery::DirectoryCache<Vec<String>>>;
static VAULTS: std::sync::LazyLock<ListingCache> = std::sync::LazyLock::new(ListingCache::default);
static PENDING: std::sync::LazyLock<ListingCache> = std::sync::LazyLock::new(ListingCache::default);
fn cached_vaults_at(directory: &std::path::Path, force: bool) -> Result<Vec<String>, Failure> {
    VAULTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .read(directory, 0, force, || discover_vaults_at(directory))
}

fn discover_vaults_at(directory: &std::path::Path) -> Result<Vec<String>, Failure> {
    match password_manager::file::list_vault_files(directory) {
        Ok(names) => Ok(names),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(error) => Err(Failure::from(format!("Could not list vaults: {error}"))),
    }
}

pub fn reload_settings() -> Result<Reply, Failure> {
    reload_settings_at(&config_dir().join("config.toml"))
}

fn reload_settings_at(path: &std::path::Path) -> Result<Reply, Failure> {
    // try_read_config creates missing files and backfills defaults. A desktop
    // refresh must be read-only, including for absent and partial config files.
    let conf: Config = match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).map_err(|error| {
            Failure::from(format!(
                "Could not reload settings at {}: {error}",
                path.display()
            ))
        })?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Config::default(),
        Err(error) => return Err(Failure::from(format!("Could not reload settings: {error}"))),
    };
    super::settings::SettingsDraft::from(&conf)
        .changes()
        .map_err(Failure::from)?;
    if let Some(vault) = &conf.unlock.vault_id {
        password_manager::vault::validate_vault_filename(vault)
            .map_err(|error| Failure::from(error.to_string()))?;
    }
    Ok(Reply::Configuration(conf))
}

pub fn save_vault_name(id: &str, label: &str) -> Result<Reply, Failure> {
    super::vault_names::Names::save(&config_dir().join("vault-names.json"), id, label)
        .map(Reply::Names)
        .map_err(Failure::from)
}

pub fn open_created(
    client: &AuthenticatedClient,
    id: String,
    name: String,
    password: SecretString,
    timeout: u64,
) -> Result<Reply, Failure> {
    let names = super::vault_names::Names::save(&config_dir().join("vault-names.json"), &id, &name)
        .map_err(|message| {
            Failure::from(format!(
                "Your vault was created but is still locked. {message}"
            ))
        })?;
    let reply = request(
        client,
        RequestEnvelope::new(password_manager::types::ServerCommand::Unlock(
            password_manager::types::UnlockInfo {
                key: password_manager::types::PasswordType::Password(password.expose_owned()),
                timeout,
                vault_file: Some(id),
            },
        )),
    )
    .map_err(|mut failure| {
        failure.message = format!(
            "Your vault was created. Unlock it to continue. {}",
            failure.message
        );
        failure
    })?;
    Ok(Reply::Created {
        reply: Box::new(reply),
        names,
    })
}

pub fn request(client: &AuthenticatedClient, envelope: RequestEnvelope) -> Result<Reply, Failure> {
    // Invalidate even after a lost reply: creation/deletion may have committed.
    struct InvalidateVaults(bool);
    impl Drop for InvalidateVaults {
        fn drop(&mut self) {
            if self.0 {
                VAULTS
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .invalidate();
            }
        }
    }
    let _invalidate = InvalidateVaults(envelope.command.is_mutation());
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
        cached_vaults_at(&data_dir(), false)?
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
        PENDING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .invalidate();
        result.map_err(|error| {
            Failure::from(format!(
                "Could not record the operation before sending it: {error}"
            ))
        })
    }
    fn finish(&self, id: &str) -> Result<(), Failure> {
        let path = self.path(id)?;
        let result = match std::fs::remove_file(&path) {
            Ok(()) => sync_parent(&path).map_err(|error| Failure::from(error.to_string())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Failure::from(format!(
                "Could not clear the desktop operation record: {error}"
            ))),
        };
        PENDING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .invalidate();
        result
    }
    fn pending(&self) -> Result<Vec<String>, Failure> {
        PENDING.lock().unwrap_or_else(|e| e.into_inner()).read(
            &self.directory,
            self.port,
            false,
            || self.scan_pending(),
        )
    }
    fn scan_pending(&self) -> Result<Vec<String>, Failure> {
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
    fn offline_discovery_lists_sorted_vault_files_without_opening_them() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("z.enc"), b"not a decryptable vault").unwrap();
        std::fs::write(root.path().join("a.enc"), b"").unwrap();
        std::fs::write(root.path().join("other.toml"), b"").unwrap();
        std::fs::create_dir(root.path().join("directory.enc")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.path().join("a.enc"), root.path().join("link.enc"))
            .unwrap();
        assert_eq!(
            discover_vaults_at(root.path()).unwrap(),
            vec!["a.enc", "z.enc"]
        );
        assert!(
            discover_vaults_at(&root.path().join("missing"))
                .unwrap()
                .is_empty()
        );
        assert!(!root.path().join("missing").exists());
        assert!(discover_vaults_at(&root.path().join("a.enc")).is_err());
    }

    #[test]
    fn configuration_reload_is_read_only_for_missing_and_partial_files() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("missing-directory").join("config.toml");
        let Reply::Configuration(conf) = reload_settings_at(&path).unwrap() else {
            panic!()
        };
        assert_eq!(conf, Config::default());
        assert!(!path.parent().unwrap().exists());
        let path = root.path().join("config.toml");
        let partial = "# preserve this comment\n[genpass]\nlength = 42\n";
        std::fs::write(&path, partial).unwrap();
        let Reply::Configuration(conf) = reload_settings_at(&path).unwrap() else {
            panic!()
        };
        assert_eq!(conf.genpass.length, 42);
        assert_eq!(conf.server, Config::default().server);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), partial);
    }

    #[test]
    fn configuration_reload_rejects_invalid_settings_without_rewriting_disk() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.toml");
        for invalid in [
            "not toml",
            "[genpass]\nlength = 0\n",
            "[server]\nport = 0\n",
            "[unlock]\nvault_id = '../outside.enc'\n",
            "[unlock]\nvault_id = ''\n",
        ] {
            std::fs::write(&path, invalid).unwrap();
            assert!(reload_settings_at(&path).is_err(), "{invalid}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), invalid);
        }
    }

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

/// Generate from the same Clap metadata as the CLI; never truncate an existing file.
pub fn save_completions(
    shell: clap_complete::Shell,
    path: &std::path::Path,
) -> Result<Reply, Failure> {
    use clap::CommandFactory;
    use std::io::Write;
    let mut bytes = Vec::new();
    clap_complete::generate(
        shell,
        &mut password_manager::cli::Cli::command(),
        "pm",
        &mut bytes,
    );
    let parent = path
        .parent()
        .ok_or_else(|| Failure::from("Choose a destination file.".to_owned()))?;
    let mut file =
        tempfile::NamedTempFile::new_in(parent).map_err(|e| Failure::from(e.to_string()))?;
    file.write_all(&bytes)
        .and_then(|()| file.as_file().sync_all())
        .map_err(|e| Failure::from(e.to_string()))?;
    file.persist_noclobber(path)
        .map_err(|e| Failure::from(e.to_string()))?;
    sync_parent(path).map_err(|e| Failure::from(e.to_string()))?;
    Ok(Reply::Local(format!(
        "Completions saved to {}",
        path.display()
    )))
}

#[cfg(test)]
mod completion_tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn desktop_completion_files_match_cli_and_preserve_existing_destinations() {
        let directory = tempfile::tempdir().unwrap();
        for shell in [
            clap_complete::Shell::Bash,
            clap_complete::Shell::Elvish,
            clap_complete::Shell::Fish,
            clap_complete::Shell::PowerShell,
            clap_complete::Shell::Zsh,
        ] {
            let path = directory.path().join(shell.to_string());
            let mut expected = Vec::new();
            clap_complete::generate(
                shell,
                &mut password_manager::cli::Cli::command(),
                "pm",
                &mut expected,
            );
            save_completions(shell, &path).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), expected);
            std::fs::write(&path, "keep this file").unwrap();
            assert!(save_completions(shell, &path).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), b"keep this file");
        }
    }
}
