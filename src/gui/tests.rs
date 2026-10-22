use super::*;
use password_manager::protocol::{OperationReceipt, RpcResponse, ServerStatus};

fn app() -> App {
    App::new(Config::default(), AuthenticatedClient::new(7878))
}

fn item() -> ItemDetail {
    ItemDetail {
        id: 1,
        revision: 3,
        name: "Example".into(),
        username: Some("alice".into()),
        kind: ItemKind::Login,
        urls: vec!["https://example.test".into()],
        notes: Some("private note".into()),
        password: Some("stored-secret".into()),
        has_secret: true,
        fields: vec![],
        has_totp: false,
        has_duo: false,
        created: String::new(),
        modified: String::new(),
    }
}

fn reply(payload: ResponsePayload, session: Option<&str>) -> Reply {
    let mut response = RpcResponse::success(payload);
    response.session_id = session.map(str::to_owned);
    Reply::Server {
        response: Box::new(response),
        vaults: vec![],
        pending: vec![],
    }
}

fn unlocked() -> App {
    let mut app = app();
    app.running = true;
    app.session = Some("a".repeat(64));
    app.item = Some(item());
    app.draft = Some(Draft::from_item(&item()));
    app.master = "master-secret".into();
    app.generated = "generated-secret".into();
    app.query = "query".into();
    app
}

#[test]
fn external_lock_clears_displayed_secrets_drafts_and_generator() {
    let mut app = unlocked();
    let _ = app.complete(
        Job::Status,
        reply(ResponsePayload::Status(ServerStatus::new(true, None)), None),
    );
    assert!(app.session.is_none());
    assert!(app.item.is_none());
    assert!(app.draft.is_none());
    assert!(app.master.is_empty());
    assert!(app.generated.is_empty());
    assert!(app.query.is_empty());
}

#[test]
fn a_new_unlock_session_invalidates_the_previous_selection() {
    let mut app = unlocked();
    let session = "b".repeat(64);
    let _ = app.complete(
        Job::Status,
        reply(
            ResponsePayload::Status(ServerStatus::new(false, None)),
            Some(&session),
        ),
    );
    assert_eq!(app.session.as_deref(), Some(session.as_str()));
    assert!(app.item.is_none());
    assert!(app.draft.is_none());
    assert!(app.generated.is_empty());
}

#[test]
fn locking_invalidates_an_in_flight_reveal_reply() {
    let mut app = unlocked();
    let old_serial = app.serial;
    let _ = app.update(Message::Lock);
    assert!(app.serial > old_serial);
    let _ = app.update(Message::Finished(
        old_serial,
        Job::Reveal,
        Arc::new(Ok(reply(
            ResponsePayload::Item(item()),
            Some(&"a".repeat(64)),
        ))),
    ));
    assert!(app.item.is_none());
    assert!(app.session.is_none());
}

#[test]
fn ordinary_status_polling_preserves_an_unlock_form() {
    let mut app = app();
    app.master = "still-typing".into();
    let _ = app.complete(
        Job::Status,
        reply(ResponsePayload::Status(ServerStatus::new(true, None)), None),
    );
    assert_eq!(app.master.expose(), "still-typing");
}

#[test]
fn passive_polling_does_not_disable_inputs_or_swallow_edits() {
    let mut app = unlocked();
    let _ = app.status();
    assert!(app.polling);
    assert!(!app.busy);
    let _ = app.update(Message::Name("Typed during a poll".into()));
    assert_eq!(app.draft.as_ref().unwrap().name, "Typed during a poll");
    assert!(app.draft.as_ref().unwrap().dirty);
}

#[test]
fn creating_an_additional_vault_selects_the_new_file() {
    let mut app = app();
    app.vaults = vec!["old.enc".into()];
    app.select_created_vault = true;
    let _ = app.complete(
        Job::Status,
        Reply::Server {
            response: Box::new(RpcResponse::success(ResponsePayload::Status(
                ServerStatus::new(true, None),
            ))),
            vaults: vec!["old.enc".into(), "new.enc".into()],
            pending: vec![],
        },
    );
    assert_eq!(app.vault.as_deref(), Some("new.enc"));
}

#[test]
fn uncertain_mutations_block_retries_and_keep_the_operation_for_review() {
    let mut app = unlocked();
    let id = "f".repeat(32);
    let _ = app.update(Message::Finished(
        app.serial,
        Job::Save,
        Arc::new(Err(Failure {
            message: "reply lost".into(),
            uncertain_operation: Some(id.clone()),
        })),
    ));
    assert_eq!(app.pending.as_deref(), Some(id.as_str()));
    assert!(!app.writes_allowed());
    assert!(app.draft.is_none());
    assert!(app.item.as_ref().unwrap().password.is_none());
    let _ = app.complete(
        Job::Reconcile,
        reply(
            ResponsePayload::Operation(OperationReceipt {
                operation_id: id.clone(),
                state: OperationState::Unknown,
                revision: None,
            }),
            None,
        ),
    );
    assert!(app.reviewed);
    assert_eq!(app.pending.as_deref(), Some(id.as_str()));
}

#[test]
fn recovered_operations_block_writes_after_reopening_the_gui() {
    let mut app = app();
    let id = "f".repeat(32);
    let _ = app.complete(
        Job::Connect,
        Reply::Server {
            response: Box::new(RpcResponse::success(ResponsePayload::Status(
                ServerStatus::new(true, None),
            ))),
            vaults: vec![],
            pending: vec![id.clone()],
        },
    );
    assert_eq!(app.pending.as_deref(), Some(id.as_str()));
    assert!(!app.writes_allowed());
}

#[test]
fn revealing_expires_and_focus_loss_hides_it_immediately() {
    let mut app = unlocked();
    app.reveal_until = Some(Instant::now() - Duration::from_secs(1));
    let _ = app.update(Message::Tick(Instant::now()));
    assert!(app.item.as_ref().unwrap().password.is_none());
    app.item = Some(item());
    app.show_generated = true;
    let _ = app.update(Message::HideSecrets);
    assert!(app.item.as_ref().unwrap().password.is_none());
    assert!(!app.show_generated);
}

#[test]
fn focus_loss_invalidates_a_reveal_that_has_not_returned_yet() {
    let mut app = unlocked();
    let _ = app.request(
        Job::Reveal,
        ServerCommand::ManagementItem {
            id: 1,
            reveal: true,
        },
        Some(3),
    );
    let serial = app.serial;
    let _ = app.update(Message::HideSecrets);
    let _ = app.update(Message::Finished(
        serial,
        Job::Reveal,
        Arc::new(Ok(reply(
            ResponsePayload::Item(item()),
            Some(&"a".repeat(64)),
        ))),
    ));
    assert!(app.item.as_ref().unwrap().password.is_none());
    assert!(!app.busy);
    assert!(app.reveal_until.is_none());
}

#[test]
fn navigation_requires_an_explicit_discard_of_unsaved_edits() {
    let mut app = unlocked();
    app.draft.as_mut().unwrap().dirty = true;
    let _ = app.update(Message::Navigate(Navigate::New));
    assert!(app.deferred.is_some());
    assert_eq!(app.draft.as_ref().unwrap().id, Some(1));
    let _ = app.update(Message::Discard);
    assert!(app.deferred.is_none());
    assert!(app.draft.as_ref().unwrap().id.is_none());
}

#[test]
fn secret_input_messages_have_redacted_debug_output() {
    for message in [
        Message::Master("sensitive-value".into()),
        Message::Password("sensitive-value".into()),
        Message::ConfirmMaster("sensitive-value".into()),
    ] {
        assert!(!format!("{message:?}").contains("sensitive-value"));
    }
}

#[test]
fn saved_settings_refresh_the_form_and_switch_a_stopped_server_connection() {
    let mut app = app();
    let mut conf = Config::default();
    conf.server.port = 8787;
    conf.genpass.length = 24;
    conf.genpass.copy = false;
    conf.genpass.stats = true;
    conf.copy.passwords = false;
    conf.clipboard.timeout = 30;
    conf.unlock.timeout = 3600;
    conf.unlock.vault_id = Some("selected.enc".into());
    conf.recovery.password_history_limit = 25;
    conf.recovery.trash_retention_days = 30;
    let _ = app.complete(
        Job::Settings,
        Reply::Settings {
            conf: conf.clone(),
            restart_required: false,
        },
    );
    assert_eq!(app.conf, conf);
    assert_eq!(app.client.port, 8787);
    assert_eq!(app.settings.server_port, "8787");
    assert_eq!(app.settings.history_limit, "25");
    assert_eq!(app.settings.trash_retention, "30");
    assert_eq!(app.vault.as_deref(), Some("selected.enc"));
    assert_eq!(app.generator_length, "24");
    assert!(!app.settings.generator_copy);
    assert!(!app.settings.password_copy);
    assert!(app.settings.stats);
}

#[test]
fn saving_settings_preserves_an_explicit_cli_port_override() {
    let mut app = app();
    app.client.port = 9999;
    let mut conf = Config::default();
    conf.server.port = 8787;
    let _ = app.complete(
        Job::Settings,
        Reply::Settings {
            conf,
            restart_required: false,
        },
    );
    assert_eq!(app.client.port, 9999);
}

#[test]
fn generator_preferences_do_not_change_unsaved_settings() {
    let mut app = app();
    let _ = app.update(Message::GeneratorLength("64".into()));
    assert_eq!(
        app.settings.length,
        Config::default().genpass.length.to_string()
    );
    let _ = app.update(Message::SettingChanged(SettingsField::Length, "32".into()));
    assert_eq!(app.generator_length, "64");
}

#[test]
fn choosing_a_key_fills_the_path_without_unlocking_and_cancel_preserves_input() {
    let mut app = app();
    app.master = "pending-password".into();
    app.key_path = "original.key".into();
    let _ = app.complete(Job::PickKey, Reply::KeyFile(None));
    assert_eq!(app.key_path.expose(), "original.key");
    assert_eq!(app.master.expose(), "pending-password");
    let _ = app.complete(Job::PickKey, Reply::KeyFile(Some("selected.key".into())));
    assert_eq!(app.key_path.expose(), "selected.key");
    assert!(app.master.is_empty());
    assert!(app.session.is_none());
    assert!(!app.busy);
}
