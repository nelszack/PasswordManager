//! `pm vaults` and `pm new`: vault identity by device-local name.
use super::output::Output;
use password_manager::{
    client::{AuthenticatedClient, terminal_metadata},
    config::Config,
    file::resolve_new_key_path,
    types::{PasswordType, ServerCommand, UnlockInfo},
    vault::list_vaults,
    vault_names::{self, Names},
};

fn vaults(console: &Output) -> Vec<String> {
    list_vaults().unwrap_or_else(|error| console.exit_error(&error.to_string(), 1))
}

pub(super) fn list_or_rename(
    conf: &Config,
    rename: Option<&str>,
    name: Option<&str>,
    console: &Output,
) {
    let files = vaults(console);
    let mut names = Names::load();
    if let (Some(wanted), Some(label)) = (rename, name) {
        let id = names
            .resolve(wanted, &files)
            .unwrap_or_else(|error| console.exit_error(&error, 2));
        names = Names::save(&vault_names::path(), &id, label)
            .unwrap_or_else(|error| console.exit_error(&error, 2));
    }
    let rows: Vec<_> = files
        .iter()
        .enumerate()
        .map(|(index, id)| {
            (
                id.clone(),
                names.label_at(id, index, files.len()),
                conf.unlock.vault_id.as_deref() == Some(id.as_str()),
            )
        })
        .collect();
    let width = rows
        .iter()
        .map(|(_, label, _)| label.chars().count())
        .max()
        .unwrap_or(0);
    let text = if rows.is_empty() {
        "No vaults yet. Create one with `pm new --name NAME`.".to_owned()
    } else {
        let mut text: String = rows
            .iter()
            .map(|(id, label, default)| {
                format!(
                    "{:<width$}  {}{}\n",
                    terminal_metadata(label).as_str(),
                    id,
                    if *default { "  (default)" } else { "" }
                )
            })
            .collect();
        text += "\nOpen one with `pm unlock --vault NAME`; rename with `pm vaults --rename FILE \
                 --name NAME`.";
        text
    };
    console.print_data(
        serde_json::json!(
            rows.iter()
                .map(|(id, label, default)| serde_json::json!({
                    "file": id,
                    "name": label,
                    "default": default,
                }))
                .collect::<Vec<_>>()
        ),
        &text,
    );
}

/// Create a vault, name it on this device, and open it unless `--locked`.
pub(super) fn create(
    client: &AuthenticatedClient,
    conf: &Config,
    name: Option<String>,
    key_path: Option<String>,
    locked: bool,
    console: &Output,
) {
    if let Some(name) = &name
        && let Err(error) = vault_names::validate_name(name)
    {
        console.exit_error(error, 2);
    }
    let credential =
        match key_path {
            Some(path) => PasswordType::Key(resolve_new_key_path(&path).unwrap_or_else(|error| {
                console.exit_error(&format!("invalid key path: {error}"), 2)
            })),
            None => {
                if !password_manager::prompt::from_stdin() {
                    console.print_note(
                        "There is no password reset. Choose a master password you will remember, \
                     or store it somewhere safe.",
                    );
                }
                // A rejected password is invalid input (exit 2), as documented.
                PasswordType::Password(super::remote::confirmed_password(
                    console,
                    "master password",
                    true,
                ))
            }
        };
    let before = vaults(console);
    if let Err(error) = client.request(ServerCommand::New(credential.clone())) {
        console.exit_error(&error, 1);
    }
    let after = vaults(console);
    let created = after.iter().find(|id| !before.contains(id)).cloned();
    let label = match (&created, name) {
        (Some(id), Some(name)) => match Names::save(&vault_names::path(), id, &name) {
            Ok(_) => name,
            Err(error) => {
                console.print_warning(&format!("The vault was created but not named: {error}"));
                Names::load().label(id, &after)
            }
        },
        (Some(id), None) => Names::load().label(id, &after),
        (None, name) => name.unwrap_or_else(|| "New vault".into()),
    };
    let label = terminal_metadata(&label).to_string();
    let file = created
        .as_deref()
        .map(|id| format!(" ({id})"))
        .unwrap_or_default();
    if locked || created.is_none() {
        let selector = if after.len() > 1 {
            format!(" --vault \"{label}\"")
        } else {
            String::new()
        };
        console.print_data(
            serde_json::json!({"file": created, "name": label, "unlocked": false}),
            &format!(
                "Vault \"{label}\"{file} created and left locked.\nOpen it with `pm \
                 unlock{selector}`."
            ),
        );
        return;
    }
    let unlocked = client.request(ServerCommand::Unlock(UnlockInfo {
        vault_file: created.clone(),
        key: credential,
        timeout: conf.unlock.timeout,
    }));
    match unlocked {
        Ok(_) => console.print_data(
            serde_json::json!({"file": created, "name": label, "unlocked": true}),
            &format!(
                "Vault \"{label}\"{file} created and unlocked.\nNext: add an item with `pm add \
                 --name NAME`, or import with `pm import --path FILE`.\nOnce it has items, keep \
                 a copy with `pm backup create --path FILE`."
            ),
        ),
        Err(error) => console.exit_error(
            &format!("Vault \"{label}\"{file} was created but could not be opened: {error}"),
            1,
        ),
    }
}
