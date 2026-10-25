use super::*;
use password_manager::protocol::{OperationReceipt, RpcResponse, ServerStatus};

// Construct clients directly: AuthenticatedClient::new initializes the real
// application data directory, which GUI state tests must never touch.
pub(super) fn app() -> App {
    App::new(
        Config::default(),
        AuthenticatedClient {
            port: 7878,
            token_path: std::path::PathBuf::from("unused-test-token"),
            connect_timeout: Duration::from_millis(1),
            io_timeout: Duration::from_millis(1),
            max_response: 1024,
            breach_timeout: Duration::from_millis(1),
        },
    )
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
fn revealing_expires_before_watch_refresh_and_focus_loss_hides_it_immediately() {
    let mut app = account_app(true);
    let _ = app.workflow(workflows::Event::Toggle(workflows::Toggle::WatchDuo, true));
    app.polling = false;
    let now = Instant::now();
    app.last_status = now;
    app.workspace.last_watch = now - Duration::from_secs(5);
    app.item.as_mut().unwrap().password = Some("revealed secret".into());
    app.reveal_until = Some(now - Duration::from_secs(1));
    app.generated = "expired generated secret".into();
    app.generated_until = Some(now - Duration::from_secs(1));
    app.generated_stats = "old assessment".into();
    app.show_generated = true;
    let _ = app.update(Message::Tick(now));
    assert!(app.item.as_ref().unwrap().password.is_none());
    assert!(app.generated.is_empty());
    assert!(app.generated_stats.is_empty());
    assert!(app.generated_until.is_none());
    assert!(!app.show_generated);
    assert!(
        app.polling,
        "Duo watching should still refresh after expiry"
    );
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
fn saving_settings_preserves_live_connections_and_explicit_port_overrides() {
    for (running, port) in [(false, 9999), (true, 7878), (true, 9999)] {
        let mut app = app();
        app.running = running;
        app.session = running.then(|| "active-session".into());
        app.client.port = port;
        let mut conf = Config::default();
        conf.server.port = 8787;
        let _ = app.complete(
            Job::Settings,
            Reply::Settings {
                conf,
                restart_required: false,
            },
        );
        assert_eq!(app.client.port, port);
        assert_eq!(app.running, running);
        assert_eq!(app.session.as_deref(), running.then_some("active-session"));
    }
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

#[test]
fn discarding_multiline_replacement_clears_both_the_display_and_submitted_value() {
    let mut app = unlocked();
    let draft = app.draft.as_mut().unwrap();
    draft.multiline = true;
    draft.replace_password = true;
    draft.password = "synthetic replacement\nsecond line".into();
    draft.secret_editor = text_editor::Content::with_text(draft.password.expose());
    let _ = app.update(Message::ReplacePassword(false));
    let draft = app.draft.as_ref().unwrap();
    assert!(draft.password.is_empty());
    assert!(draft.secret_editor.text().is_empty());
    let ServerCommand::Update(command) = draft.command().unwrap() else {
        panic!()
    };
    assert!(command.entry.password.is_none());
    let _ = app.update(Message::ReplacePassword(true));
    let draft = app.draft.as_ref().unwrap();
    let ServerCommand::Update(command) = draft.command().unwrap() else {
        panic!()
    };
    assert_eq!(
        command.entry.password.unwrap().expose(),
        draft.secret_editor.text()
    );
}

#[test]
fn hiding_multiline_input_masks_it_without_discarding_the_replacement() {
    let mut app = unlocked();
    let replacement = "synthetic private key\nsecond line";
    let _ = app.update(Message::Password(replacement.into()));
    let _ = app.update(Message::MultilineSecret(true));
    assert!(
        app.draft
            .as_ref()
            .unwrap()
            .secret_editor
            .text()
            .contains(replacement)
    );
    let _ = app.update(Message::HideSecrets);
    // Input queued by the old visible editor cannot replace the retained
    // password after its editor buffer has been cleared.
    let _ = app.update(Message::SecretEdit(text_editor::Action::Edit(
        text_editor::Edit::Insert('x'),
    )));
    let draft = app.draft.as_ref().unwrap();
    assert!(!draft.multiline);
    assert!(draft.secret_editor.text().is_empty());
    let ServerCommand::Update(command) = draft.command().unwrap() else {
        panic!()
    };
    assert_eq!(command.entry.password.unwrap().expose(), replacement);

    let _ = app.update(Message::MultilineSecret(true));
    assert!(
        app.draft
            .as_ref()
            .unwrap()
            .secret_editor
            .text()
            .contains(replacement)
    );
    let _ = app.update(Message::MultilineSecret(false));
    assert!(app.draft.as_ref().unwrap().secret_editor.text().is_empty());
    let _ = app.generate();
    let draft = app.draft.as_ref().unwrap();
    assert!(!draft.password.is_empty());
    assert!(draft.secret_editor.text().is_empty());
}

#[test]
fn hotp_generation_refreshes_the_revision_before_the_next_item_action() {
    use password_manager::{
        protocol::AuthenticatorResponse,
        types::PasswordEntry,
        vault::{Vault, VaultCredentials},
    };
    let mut vault = Vault::memory();
    let mut key = VaultCredentials {
        locked: false,
        keypass: Some(PasswordType::Password("synthetic fixture password".into())),
    };
    vault
        .add_entry(
            PasswordEntry {
                name: "Synthetic account".into(),
                username: None,
                password: "synthetic secret".into(),
                url: None,
                notes: None,
                copy: false,
            },
            &mut key,
        )
        .unwrap();
    vault
        .set_totp(
            Target::Id(1),
            "otpauth://hotp/Synthetic?secret=JBSWY3DPEHPK3PXP&counter=0",
            &mut key,
        )
        .unwrap();
    let mut app = app();
    app.running = true;
    app.session = Some("a".repeat(64));
    app.items = vault
        .management_list(SearchFilter::default())
        .unwrap()
        .items;
    app.workspace.selected = Some(workflows::Choice {
        id: 1,
        label: "Synthetic account".into(),
    });
    for expected_counter in 0..2 {
        let prepared = app
            .workspace
            .prepare(workflows::Action::ShowOtp(false), &app)
            .unwrap();
        vault.check_revision(1, prepared.revision.unwrap()).unwrap();
        let code = vault.current_otp(Target::Id(1), &mut key).unwrap();
        assert_eq!(code.counter, Some(expected_counter));
        let payload = ResponsePayload::Authenticator(AuthenticatorResponse {
            code: code.code.as_str().into(),
            expires_in: code.expires_in,
            counter: code.counter,
            mode: "hotp".into(),
        });
        let _ = app.complete(
            Job::Workflow(workflows::Action::ShowOtp(false)),
            reply(payload, Some(&"a".repeat(64))),
        );
        assert!(
            app.busy,
            "controls must wait for the refreshed item revision"
        );
        let result = reply(
            ResponsePayload::ItemPage(vault.management_list(SearchFilter::default()).unwrap()),
            Some(&"a".repeat(64)),
        );
        let _ = app.update(Message::Finished(
            app.serial,
            Job::List,
            Arc::new(Ok(result)),
        ));
        assert!(!app.busy);
        let next = app
            .workspace
            .prepare(workflows::Action::History, &app)
            .unwrap();
        assert_eq!(next.revision, vault.item_revision(1));
    }
}

#[test]
fn generation_uses_reloaded_defaults_without_overwriting_unsaved_settings() {
    let mut app = app();
    app.tab = Tab::Generator;
    app.settings.edit(SettingsField::Length, "40".into());
    let mut conf = app.conf.clone();
    conf.genpass.copy = false;
    conf.genpass.stats = true;
    conf.genpass.length = 24;
    let _ = app.complete(Job::GenerateDefaults, Reply::Configuration(conf));
    assert_eq!(app.generated.len(), 24);
    assert!(!app.generated_stats.is_empty());
    assert!(
        !app.busy,
        "external no-copy preference must prevent auto copying"
    );
    assert_eq!(app.settings.length, "40");
}

fn editor_summary(item: &ItemDetail) -> ItemSummary {
    ItemSummary {
        id: item.id,
        revision: item.revision,
        name: item.name.clone(),
        username: item.username.clone(),
        kind: item.kind,
        urls: item.urls.clone(),
        has_totp: item.has_totp,
        has_duo: item.has_duo,
    }
}

fn editor_app() -> App {
    let mut app = unlocked();
    app.items.push(editor_summary(app.item.as_ref().unwrap()));
    app.workspace.configuration = "JBSWY3DPEHPK3PXP".into();
    app.workspace.activation = "synthetic-unused-activation".into();
    app
}

fn finish_editor_refresh(app: &mut App, mut updated: ItemDetail) {
    updated.password = None; // Management reads never reveal the primary secret.
    let _ = app.update(Message::Finished(
        app.serial,
        Job::EditorList(updated.id),
        Arc::new(Ok(reply(
            ResponsePayload::ItemPage(password_manager::vault::ItemPage {
                items: vec![editor_summary(&updated)],
                total: 1,
            }),
            Some(&"a".repeat(64)),
        ))),
    ));
    assert!(app.busy, "wait for the matching detail revision too");
    let _ = app.update(Message::Finished(
        app.serial,
        Job::EditorItem(updated.id),
        Arc::new(Ok(reply(
            ResponsePayload::Item(updated),
            Some(&"a".repeat(64)),
        ))),
    ));
    assert!(!app.busy);
}

#[test]
fn editor_authenticator_actions_bind_to_the_edited_item_instead_of_tools_selection() {
    let mut app = editor_app();
    let mut other = app.items[0].clone();
    other.id = 2;
    other.revision = 22;
    other.name = "Other item selected in Tools".into();
    app.workspace.selected = Some(workflows::Choice {
        id: other.id,
        label: other.name.clone(),
    });
    app.items.push(other);
    for action in [
        workflows::Action::SetOtp,
        workflows::Action::RemoveOtp,
        workflows::Action::EnrollDuo,
        workflows::Action::EnrollPasscodes,
        workflows::Action::RemoveDuo,
    ] {
        let prepared = app.workspace.prepare(action, &app).unwrap();
        assert_eq!(prepared.command.revision_target(), Some(&Target::Id(1)));
        assert_eq!(prepared.revision, Some(3));
        assert_eq!(prepared.session, app.session);
        assert!(prepared.confirmation.is_some());
    }
    app.items[0].revision += 1;
    assert!(
        app.workspace
            .prepare(workflows::Action::SetOtp, &app)
            .is_err(),
        "a refreshed summary must not silently rebase an old editor"
    );
    app.draft = Some(Draft::default());
    assert!(
        app.workspace
            .prepare(workflows::Action::SetOtp, &app)
            .is_err(),
        "new unsaved items must not fall back to a Tools selection"
    );
}

#[test]
fn editing_credential_fields_cancels_authenticator_confirmation_and_blocks_dirty_changes() {
    let mut app = editor_app();
    let _ = app.update(Message::Workflow(workflows::Event::Run(
        workflows::Action::SetOtp,
    )));
    assert!(app.workspace.prepared.is_some());
    let _ = app.update(Message::Name("Changed name".into()));
    assert!(app.workspace.prepared.is_none());
    assert!(
        app.workspace
            .prepare(workflows::Action::SetOtp, &app)
            .is_err()
    );
    let serial = app.serial;
    let _ = app.update(Message::Workflow(workflows::Event::Confirm));
    assert_eq!(
        app.serial, serial,
        "cancelled confirmation must not dispatch a mutation"
    );
    assert_eq!(app.draft.as_ref().unwrap().name, "Changed name");
}

#[test]
fn authenticator_mutations_keep_the_editor_open_with_fresh_status_and_revision() {
    for action in [
        workflows::Action::SetOtp,
        workflows::Action::RemoveOtp,
        workflows::Action::EnrollDuo,
        workflows::Action::EnrollPasscodes,
        workflows::Action::RemoveDuo,
    ] {
        let mut app = editor_app();
        let _ = app.complete(
            Job::Workflow(action),
            reply(
                ResponsePayload::Message("Authenticator updated".into()),
                Some(&"a".repeat(64)),
            ),
        );
        assert!(app.busy);
        assert!(
            app.draft.is_none(),
            "never edit using the previous revision during refresh"
        );
        assert!(app.workspace.activation.is_empty());
        assert!(app.workspace.configuration.is_empty());
        let mut updated = item();
        updated.revision = 4;
        updated.has_totp = action != workflows::Action::RemoveOtp;
        updated.has_duo = action == workflows::Action::EnrollDuo;
        finish_editor_refresh(&mut app, updated.clone());
        assert_eq!(app.tab, Tab::Vault);
        let draft = app.draft.as_ref().unwrap();
        assert_eq!(draft.id, Some(1));
        assert_eq!(draft.revision, Some(4));
        assert!(!draft.dirty && draft.password.is_empty());
        assert_eq!(app.item.as_ref().unwrap().has_totp, updated.has_totp);
        assert_eq!(app.item.as_ref().unwrap().has_duo, updated.has_duo);
        app.workspace.configuration = "JBSWY3DPEHPK3PXP".into();
        assert_eq!(
            app.workspace
                .prepare(workflows::Action::SetOtp, &app)
                .unwrap()
                .revision,
            Some(4)
        );
    }
}

#[test]
fn save_and_continue_editing_preserves_edits_until_saved_and_reopens_the_current_revision() {
    let mut app = editor_app();
    let _ = app.update(Message::Name("Updated credential".into()));
    let _ = app.update(Message::SaveAndEdit);
    assert!(app.busy);
    assert_eq!(app.draft.as_ref().unwrap().name, "Updated credential");
    let _ = app.update(Message::Finished(
        app.serial,
        Job::SaveEditorDefaults,
        Arc::new(Ok(Reply::Configuration(Config::default()))),
    ));
    assert!(app.busy);
    assert!(app.draft.as_ref().unwrap().dirty);
    let _ = app.update(Message::Finished(
        app.serial,
        Job::SaveEditor,
        Arc::new(Ok(reply(
            ResponsePayload::Message("Item saved".into()),
            Some(&"a".repeat(64)),
        ))),
    ));
    let mut updated = item();
    updated.name = "Updated credential".into();
    updated.revision = 4;
    finish_editor_refresh(&mut app, updated);
    let draft = app.draft.as_ref().unwrap();
    assert_eq!(draft.name, "Updated credential");
    assert_eq!(draft.revision, Some(4));
    assert!(!draft.dirty);
}

#[test]
fn locking_during_editor_refresh_prevents_the_old_editor_from_reappearing() {
    let mut app = editor_app();
    let _ = app.refresh_editor(1);
    let old_serial = app.serial;
    let _ = app.update(Message::Lock);
    let _ = app.update(Message::Finished(
        old_serial,
        Job::EditorItem(1),
        Arc::new(Ok(reply(
            ResponsePayload::Item(item()),
            Some(&"a".repeat(64)),
        ))),
    ));
    assert!(app.draft.is_none() && app.item.is_none() && app.session.is_none());
}

fn account_app(duo: bool) -> App {
    let mut app = unlocked();
    app.draft = None;
    app.item.as_mut().unwrap().has_totp = true;
    app.item.as_mut().unwrap().has_duo = duo;
    app.items = vec![editor_summary(app.item.as_ref().unwrap())];
    app.workspace.selected = Some(workflows::Choice {
        id: 1,
        label: "Example".into(),
    });
    app
}

fn pending_account_request() -> password_manager::types::DuoPushRequest {
    password_manager::types::DuoPushRequest {
        id: "synthetic-request".into(),
        application: "Synthetic app".into(),
        username: "alice".into(),
        location: "Test location".into(),
        summary: "Test login".into(),
        expires_at: (chrono::Utc::now().timestamp() + 300) as u64,
        code_digits: Some(3),
        unsupported: None,
        fingerprint: "synthetic-review".into(),
    }
}

#[test]
fn clicking_a_duo_account_fetches_once_and_never_enables_watching() {
    let mut app = account_app(true);
    let selected = app.item.take().unwrap();
    let _ = app.complete(
        Job::Item,
        reply(ResponsePayload::Item(selected), Some(&"a".repeat(64))),
    );
    assert!(app.polling && !app.busy);
    assert!(!app.workspace.watch_duo);
    assert!(app.workspace.duo_watch_target.is_none());
    let _ = app.update(Message::Finished(
        app.serial,
        Job::Workflow(workflows::Action::Requests),
        Arc::new(Ok(reply(
            ResponsePayload::DuoRequests(vec![pending_account_request()]),
            Some(&"a".repeat(64)),
        ))),
    ));
    assert_eq!(app.workspace.duo_requests_for(&app).unwrap().len(), 1);
    let serial = app.serial;
    let now = Instant::now();
    for seconds in [5, 10, 30, 120] {
        app.last_status = now + Duration::from_secs(seconds);
        let _ = app.update(Message::Tick(app.last_status));
        assert_eq!(
            app.serial, serial,
            "account navigation must not start repeated polling"
        );
        assert!(!app.workspace.watch_duo && !app.polling);
    }
    app.workspace.code = "123".into();
    let _ = app.update(Message::Workflow(workflows::Event::Run(
        workflows::Action::Respond(0, true),
    )));
    let prepared = app.workspace.prepared.as_ref().unwrap();
    assert_eq!(prepared.revision, Some(3));
    assert_eq!(prepared.command.revision_target(), Some(&Target::Id(1)));
    assert!(
        matches!(&prepared.command, ServerCommand::Duo(password_manager::types::DuoCommand::Respond { request_id, fingerprint, .. })
        if request_id == "synthetic-request" && fingerprint == "synthetic-review")
    );
}

#[test]
fn switching_accounts_rejects_late_duo_results_and_keeps_watch_off() {
    let mut app = account_app(true);
    let selected = app.item.take().unwrap();
    let _ = app.complete(
        Job::Item,
        reply(ResponsePayload::Item(selected), Some(&"a".repeat(64))),
    );
    let old_serial = app.serial;
    let mut other = item();
    other.id = 2;
    app.items.push(editor_summary(&other));
    let _ = app.update(Message::Navigate(Navigate::Select(2)));
    let serial = app.serial;
    let _ = app.update(Message::Finished(
        old_serial,
        Job::Workflow(workflows::Action::Requests),
        Arc::new(Ok(reply(
            ResponsePayload::DuoRequests(vec![pending_account_request()]),
            Some(&"a".repeat(64)),
        ))),
    ));
    let _ = app.update(Message::Finished(
        serial,
        Job::Item,
        Arc::new(Ok(reply(
            ResponsePayload::Item(other),
            Some(&"a".repeat(64)),
        ))),
    ));
    assert_eq!(app.item.as_ref().unwrap().id, 2);
    assert_eq!(app.workspace.selected.as_ref().unwrap().id, 2);
    assert!(app.workspace.duo_requests_for(&app).is_none());
    assert!(!app.workspace.watch_duo);
}

#[test]
fn returning_to_an_account_rebinds_requests_after_a_different_tools_selection() {
    let mut app = account_app(true);
    app.tab = Tab::Tools;
    app.workspace.selected = Some(workflows::Choice {
        id: 2,
        label: "Other account".into(),
    });
    let _ = app.update(Message::Tab(Tab::Vault));
    assert_eq!(app.workspace.selected.as_ref().unwrap().id, 1);
    assert_eq!(
        app.workspace
            .duo_inflight_target
            .as_ref()
            .unwrap()
            .choice
            .id,
        1
    );
    assert!(app.polling && !app.workspace.watch_duo);
}

fn account_otp(counter: Option<u64>) -> ResponsePayload {
    ResponsePayload::Authenticator(password_manager::protocol::AuthenticatorResponse {
        code: "123456".into(),
        expires_in: counter.is_none().then_some(30),
        counter,
        mode: if counter.is_some() { "hotp" } else { "totp" }.into(),
    })
}

#[test]
fn account_otp_is_bound_to_its_account_and_hides_on_focus_loss_or_navigation() {
    let mut app = account_app(false);
    let _ = app.update(Message::Workflow(workflows::Event::Run(
        workflows::Action::ShowOtp(false),
    )));
    let _ = app.update(Message::Finished(
        app.serial,
        Job::Workflow(workflows::Action::ShowOtp(false)),
        Arc::new(Ok(reply(account_otp(None), Some(&"a".repeat(64))))),
    ));
    assert!(app.workspace.otp_result_for(&app).is_some());
    app.workspace.selected.as_mut().unwrap().id = 2;
    assert!(app.workspace.otp_result_for(&app).is_none());
    app.workspace.selected.as_mut().unwrap().id = 1;
    let _ = app.update(Message::HideSecrets);
    assert!(app.workspace.otp_result_for(&app).is_none());
    let _ = app.update(Message::Workflow(workflows::Event::Run(
        workflows::Action::ShowOtp(false),
    )));
    let _ = app.update(Message::HideSecrets);
    let _ = app.update(Message::Finished(
        app.serial,
        Job::Workflow(workflows::Action::ShowOtp(false)),
        Arc::new(Ok(reply(account_otp(None), Some(&"a".repeat(64))))),
    ));
    assert!(
        app.workspace.otp_result_for(&app).is_none(),
        "late replies must remain concealed"
    );
}

#[test]
fn account_hotp_keeps_its_code_and_details_while_refreshing_for_repeated_actions() {
    let mut app = account_app(false);
    for counter in 0..2 {
        let _ = app.update(Message::Workflow(workflows::Event::Run(
            workflows::Action::ShowOtp(false),
        )));
        let _ = app.update(Message::Finished(
            app.serial,
            Job::Workflow(workflows::Action::ShowOtp(false)),
            Arc::new(Ok(reply(account_otp(Some(counter)), Some(&"a".repeat(64))))),
        ));
        assert!(app.busy && app.item.is_none());
        assert!(app.workspace.otp_result_for(&app).is_some());
        let mut refreshed = item();
        refreshed.has_totp = true;
        refreshed.revision = 4 + counter;
        let _ = app.update(Message::Finished(
            app.serial,
            Job::AccountList(1),
            Arc::new(Ok(reply(
                ResponsePayload::ItemPage(password_manager::vault::ItemPage {
                    items: vec![editor_summary(&refreshed)],
                    total: 1,
                }),
                Some(&"a".repeat(64)),
            ))),
        ));
        let _ = app.update(Message::Finished(
            app.serial,
            Job::AccountItem(1),
            Arc::new(Ok(reply(
                ResponsePayload::Item(refreshed),
                Some(&"a".repeat(64)),
            ))),
        ));
        assert!(!app.busy && app.draft.is_none());
        assert_eq!(app.item.as_ref().unwrap().id, 1);
        assert_eq!(
            app.workspace.otp_result_for(&app).unwrap().counter,
            Some(counter)
        );
        assert_eq!(
            app.workspace
                .prepare(workflows::Action::ShowOtp(false), &app)
                .unwrap()
                .revision,
            Some(4 + counter)
        );
    }
}

fn field_account() -> (App, FieldTarget) {
    let mut app = account_app(false);
    app.item.as_mut().unwrap().fields = vec![
        password_manager::vault::ItemField {
            name: "Recovery code".into(),
            secret: true,
            value: None,
        },
        password_manager::vault::ItemField {
            name: "Region".into(),
            secret: false,
            value: Some("Test region".into()),
        },
        password_manager::vault::ItemField {
            name: "Second secret".into(),
            secret: true,
            value: None,
        },
    ];
    (
        app,
        FieldTarget {
            id: 1,
            revision: 3,
            index: 0,
        },
    )
}

#[test]
fn custom_field_actions_bind_the_clicked_account_field_and_revision() {
    let (mut app, target) = field_account();
    app.workspace.selected = Some(workflows::Choice {
        id: 2,
        label: "Other tools selection".into(),
    });
    app.conf.clipboard.timeout = 9;
    app.workspace.otp_copy_timeout = "60".into();
    let (command, revision) = app.custom_field_command(target, true).unwrap();
    assert_eq!(revision, 3);
    assert!(
        matches!(command, ServerCommand::GetField { target: Target::Id(1), name, copy_timeout: Some(9) } if name == "Recovery code")
    );
    for invalid in [
        FieldTarget { id: 2, ..target },
        FieldTarget {
            revision: 4,
            ..target
        },
        FieldTarget {
            index: 99,
            ..target
        },
    ] {
        let serial = app.serial;
        let _ = app.update(Message::RevealField(invalid));
        assert_eq!(
            app.serial, serial,
            "stale field actions must not dispatch a request"
        );
        assert!(app.custom_field_command(invalid, true).is_err());
    }
}

#[test]
fn custom_field_reveal_only_shows_the_requested_secret_and_expires() {
    let (mut app, target) = field_account();
    app.item.as_mut().unwrap().fields[2].value = Some("previously shown".into());
    let _ = app.update(Message::RevealField(target));
    assert!(app.revealing && app.busy);
    assert!(app.item.as_ref().unwrap().password.is_none());
    assert!(app.item.as_ref().unwrap().fields[2].value.is_none());
    let _ = app.update(Message::Finished(
        app.serial,
        Job::Field(target),
        Arc::new(Ok(reply(
            ResponsePayload::Secret("synthetic recovery code".into()),
            Some(&"a".repeat(64)),
        ))),
    ));
    let fields = &app.item.as_ref().unwrap().fields;
    assert_eq!(
        fields[0].value.as_ref().unwrap().expose(),
        "synthetic recovery code"
    );
    assert_eq!(fields[1].value.as_ref().unwrap().expose(), "Test region");
    assert!(fields[2].value.is_none());
    let deadline = app.reveal_until.unwrap();
    assert!(deadline <= Instant::now() + Duration::from_secs(15));
    let _ = app.update(Message::Tick(deadline + Duration::from_secs(1)));
    assert!(app.item.as_ref().unwrap().fields[0].value.is_none());
    assert!(app.item.as_ref().unwrap().fields[1].value.is_some());
}

#[test]
fn custom_field_reveals_cannot_reappear_after_focus_loss_or_account_changes() {
    let (mut app, target) = field_account();
    let _ = app.update(Message::RevealField(target));
    let old_serial = app.serial;
    let _ = app.update(Message::HideSecrets);
    assert!(app.serial > old_serial);
    let _ = app.update(Message::Finished(
        old_serial,
        Job::Field(target),
        Arc::new(Ok(reply(
            ResponsePayload::Secret("late synthetic secret".into()),
            Some(&"a".repeat(64)),
        ))),
    ));
    assert!(app.item.as_ref().unwrap().fields[0].value.is_none());
    app.item.as_mut().unwrap().id = 2;
    let _ = app.complete(
        Job::Field(target),
        reply(
            ResponsePayload::Secret("wrong account secret".into()),
            Some(&"a".repeat(64)),
        ),
    );
    assert!(app.item.as_ref().unwrap().fields[0].value.is_none());
}

#[test]
fn custom_field_copy_reloads_timeout_and_never_reveals_the_value() {
    let (mut app, target) = field_account();
    app.conf.clipboard.timeout = 0;
    let _ = app.update(Message::CopyField(target));
    let serial = app.serial;
    let mut current = Config::default();
    current.clipboard.timeout = 12;
    let _ = app.update(Message::Finished(
        serial,
        Job::FieldCopyDefaults(target),
        Arc::new(Ok(Reply::Configuration(current))),
    ));
    assert!(app.busy && app.serial > serial);
    let (command, _) = app.custom_field_command(target, true).unwrap();
    assert!(matches!(
        command,
        ServerCommand::GetField {
            copy_timeout: Some(12),
            ..
        }
    ));
    let _ = app.update(Message::Finished(
        app.serial,
        Job::FieldCopy,
        Arc::new(Ok(reply(
            ResponsePayload::Message("Custom field copied to clipboard.".into()),
            Some(&"a".repeat(64)),
        ))),
    ));
    assert!(app.item.as_ref().unwrap().fields[0].value.is_none());
    let mut disabled = app.conf.clone();
    disabled.clipboard.timeout = 0;
    let serial = app.serial;
    let _ = app.complete(
        Job::FieldCopyDefaults(target),
        Reply::Configuration(disabled),
    );
    assert_eq!(
        app.serial, serial,
        "zero timeout must block the copy before sending"
    );
    assert!(app.custom_field_command(target, true).is_err());
    assert!(app.custom_field_command(target, false).is_ok());
}

#[test]
fn hiding_the_last_custom_field_restores_the_primary_reveal_action() {
    let (mut app, target) = field_account();
    let _ = app.update(Message::RevealField(target));
    let _ = app.update(Message::Finished(
        app.serial,
        Job::Field(target),
        Arc::new(Ok(reply(
            ResponsePayload::Secret("synthetic secret".into()),
            Some(&"a".repeat(64)),
        ))),
    ));
    assert!(app.reveal_until.is_some());
    let _ = app.update(Message::HideField(target));
    assert!(app.item.as_ref().unwrap().fields[0].value.is_none());
    assert!(app.reveal_until.is_none());
}

#[test]
fn review_hiding_secrets_cancels_otp_preflights_before_dispatch() {
    for (event, job) in [
        (
            workflows::Event::Toggle(workflows::Toggle::WatchOtp, true),
            Job::WatchOtpDefaults,
        ),
        (
            workflows::Event::Run(workflows::Action::ShowOtp(true)),
            Job::WorkflowDefaults(workflows::Action::ShowOtp(true)),
        ),
    ] {
        let mut app = account_app(false);
        let _ = app.update(Message::Workflow(event));
        let preflight_serial = app.serial;
        assert!(app.busy);
        let _ = app.update(Message::HideSecrets);
        let hidden_serial = app.serial;
        let _ = app.update(Message::Finished(
            preflight_serial,
            job,
            Arc::new(Ok(Reply::Configuration(app.conf.clone()))),
        ));
        assert!(!app.workspace.watch_otp);
        assert!(app.workspace.otp_watch_target.is_none());
        assert!(
            !app.busy && !app.polling,
            "a hidden preflight must not dispatch OTP work"
        );
        assert_eq!(app.serial, hidden_serial);
    }
}

fn incomplete_audit_reply(session: Option<String>) -> Reply {
    use password_manager::vault::{AuditLabel, AuditReport};
    let entry = AuditLabel {
        id: 1,
        name: "Synthetic account".into(),
        username: Some("alice".into()),
        password_changed: "2026-01-01".into(),
    };
    let report = AuditReport {
        total: 2,
        healthy: 0,
        score: 0,
        weak: vec![entry.clone()],
        reused: vec![],
        duplicates: vec![],
        stale: vec![entry.clone()],
        missing_totp: vec![],
        breached: vec![(entry.clone(), 42)],
        breach_error: Some("Synthetic breach service timeout".into()),
        unchecked: vec![entry],
    };
    let mut response = RpcResponse::new(ResponseCode::Failure, ResponsePayload::Audit(report));
    response.session_id = session;
    Reply::Server {
        response: Box::new(response),
        vaults: vec![],
        pending: vec![],
    }
}

#[test]
fn review_incomplete_breach_checks_replace_old_reports_with_partial_findings() {
    let mut app = account_app(false);
    app.workspace.result = Some(ResponsePayload::Message("Previous report".into()));
    let _ = app.complete(
        Job::Workflow(workflows::Action::Audit),
        incomplete_audit_reply(app.session.clone()),
    );
    let Some(ResponsePayload::Audit(report)) = &app.workspace.result else {
        panic!("the partial audit report must remain available");
    };
    assert_eq!(report.weak.len(), 1);
    assert_eq!(report.stale.len(), 1);
    assert_eq!(report.breached[0].1, 42);
    assert_eq!(report.unchecked.len(), 1);
    assert!(report.breach_error.is_some());
    assert!(app.notice.contains("incomplete"));
    assert!(app.notice.contains("Synthetic breach service timeout"));
    assert!(app.session.is_some());
}

#[test]
fn review_incomplete_audits_from_other_sessions_clear_previous_results() {
    for session in [Some("b".repeat(64)), None] {
        let mut app = account_app(false);
        app.workspace.result = Some(ResponsePayload::Message("Previous report".into()));
        let _ = app.complete(
            Job::Workflow(workflows::Action::Audit),
            incomplete_audit_reply(session),
        );
        assert!(app.workspace.result.is_none());
        assert!(app.item.is_none() && app.items.is_empty());
        assert!(app.session.is_none());
    }
}
