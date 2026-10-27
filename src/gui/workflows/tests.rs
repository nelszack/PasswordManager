use super::*;
use password_manager::protocol::{AuthenticatorResponse, RpcResponse};

fn app() -> App {
    let mut app = super::super::tests::app();
    app.running = true;
    app.session = Some("a".repeat(64));
    app.items.push(ItemSummary {
        id: 7,
        revision: 11,
        name: "Work".into(),
        username: Some("alice".into()),
        kind: ItemKind::Login,
        urls: vec![],
        has_totp: true,
        has_duo: true,
    });
    app.workspace.selected = Some(Choice {
        id: 7,
        label: "7 · Work".into(),
    });
    app
}

fn duo_request() -> DuoPushRequest {
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;
    DuoPushRequest {
        id: "request-1".into(),
        application: "Work VPN".into(),
        username: "alice".into(),
        location: "Boise".into(),
        summary: "New login".into(),
        expires_at,
        code_digits: Some(3),
        unsupported: None,
        fingerprint: "reviewed-fingerprint".into(),
    }
}

fn receive_duo(app: &mut App, requests: Vec<DuoPushRequest>) {
    app.workspace.duo_inflight_target = Some(WatchTarget::selected(app).unwrap());
    app.workspace
        .receive(ResponsePayload::DuoRequests(requests));
}

fn workflow_reply(app: &App, payload: ResponsePayload) -> Reply {
    let mut response = RpcResponse::success(payload);
    response.session_id = app.session.clone();
    Reply::Server {
        response: Box::new(response),
        vaults: vec![],
        pending: vec![],
    }
}

fn history_page() -> ResponsePayload {
    ResponsePayload::History(password_manager::vault::HistoryPage {
        history: vec!["yesterday".into()],
    })
}

fn load_history(app: &mut App) {
    let _ = app.workflow(Event::Run(Action::History));
    let reply = workflow_reply(app, history_page());
    let _ = app.update(super::super::Message::Finished(
        app.serial,
        Job::Workflow(Action::History),
        Arc::new(Ok(reply)),
    ));
}

fn add_other_account(app: &mut App) {
    let mut other = app.items[0].clone();
    other.id = 8;
    other.name = "Other".into();
    other.has_duo = false;
    app.items.push(other);
}

#[test]
fn queued_current_vault_actions_cannot_dispatch_without_an_unlock_session() {
    let mut app = app();
    app.session = None;
    app.vault = Some("selected.enc".into());
    app.workspace.path = absolute("synthetic-transfer.json").unwrap();
    app.workspace.password = "synthetic fixture password".into();
    app.workspace.confirmation = app.workspace.password.clone();
    for action in [
        Action::History,
        Action::Trash,
        Action::Purge(None),
        Action::Audit,
        Action::Backup,
        Action::Export,
        Action::Rekey,
        Action::Search,
        Action::Import,
        Action::PreviewImport,
    ] {
        let Err(error) = app.workspace.prepare(action, &app) else {
            panic!("{action:?} must require a reviewed unlock session");
        };
        assert_eq!(error, "Unlock a vault first.");
    }
    for action in [Action::NewVault, Action::RestoreBackup, Action::DeleteVault] {
        assert!(app.workspace.prepare(action, &app).is_ok(), "{action:?}");
    }
    app.workspace.import_new = true;
    for action in [Action::Import, Action::PreviewImport] {
        assert!(app.workspace.prepare(action, &app).is_ok(), "{action:?}");
    }
}

#[test]
fn item_actions_bind_to_the_reviewed_item_and_revision() {
    let mut app = app();
    app.workspace.configuration = "JBSWY3DPEHPK3PXP".into();
    load_history(&mut app);
    for action in [
        Action::History,
        Action::RestorePassword(1),
        Action::SetOtp,
        Action::ShowOtp(false),
        Action::ShowOtp(true),
        Action::RemoveOtp,
        Action::Requests,
        Action::RemoveDuo,
    ] {
        let prepared = app.workspace.prepare(action, &app).unwrap();
        assert_eq!(prepared.revision, Some(11));
        assert_eq!(prepared.session, app.session);
        assert!(matches!(
            prepared.command.revision_target(),
            Some(Target::Id(7))
        ));
    }
    app.items.clear();
    assert!(app.workspace.prepare(Action::SetOtp, &app).is_err());
}

#[test]
fn history_does_not_follow_an_account_selected_on_the_vault_tab() {
    let mut app = app();
    app.tab = Tab::Tools;
    add_other_account(&mut app);
    load_history(&mut app);
    assert!(app.workspace.history_for(&app).is_some());

    let _ = app.update(super::super::Message::Tab(Tab::Vault));
    let _ = app.update(super::super::Message::Navigate(Navigate::Select(8)));
    let reply = workflow_reply(
        &app,
        ResponsePayload::Item(ItemDetail {
            id: 8,
            revision: 11,
            name: "Other".into(),
            username: Some("alice".into()),
            kind: ItemKind::Login,
            urls: vec![],
            notes: None,
            password: None,
            has_secret: true,
            fields: vec![],
            has_totp: true,
            has_duo: false,
            created: String::new(),
            modified: String::new(),
        }),
    );
    let _ = app.update(super::super::Message::Finished(
        app.serial,
        Job::Item,
        Arc::new(Ok(reply)),
    ));
    let _ = app.update(super::super::Message::Tab(Tab::Tools));

    assert_eq!(app.workspace.selected.as_ref().unwrap().id, 8);
    assert_eq!(
        app.workspace
            .history_result_target
            .as_ref()
            .unwrap()
            .choice
            .id,
        7
    );
    assert!(app.workspace.history_for(&app).is_none());
    assert!(
        app.workspace
            .prepare(Action::RestorePassword(1), &app)
            .is_err()
    );
}

#[test]
fn history_reply_keeps_its_initiating_account_instead_of_the_current_selection() {
    let mut app = app();
    add_other_account(&mut app);
    let _ = app.workflow(Event::Run(Action::History));
    app.workspace.selected = Some(Choice {
        id: 8,
        label: "Other".into(),
    });
    app.workspace.receive(history_page());
    assert_eq!(
        app.workspace
            .history_result_target
            .as_ref()
            .unwrap()
            .choice
            .id,
        7
    );
    assert!(app.workspace.history_for(&app).is_none());
    assert!(
        app.workspace
            .prepare(Action::RestorePassword(1), &app)
            .is_err()
    );
    app.workspace.selected = Some(Choice {
        id: 7,
        label: "Work".into(),
    });
    assert!(app.workspace.history_for(&app).is_some());
}

#[test]
fn history_rejects_revision_session_and_availability_changes_before_or_after_reply() {
    for before_reply in [false, true] {
        for change in 0..4 {
            let mut app = app();
            let _ = app.workflow(Event::Run(Action::History));
            if !before_reply {
                app.workspace.receive(history_page());
            }
            match change {
                0 => app.items[0].revision += 1,
                1 => app.session = Some("b".repeat(64)),
                2 => app.items.clear(),
                _ => app.running = false,
            }
            if before_reply {
                app.workspace.receive(history_page());
            }
            assert!(app.workspace.history_for(&app).is_none());
            assert!(
                app.workspace
                    .prepare(Action::RestorePassword(1), &app)
                    .is_err()
            );
        }
    }
}

#[test]
fn history_confirmation_rechecks_the_reviewed_context_before_sending() {
    for change in 0..3 {
        let mut app = app();
        add_other_account(&mut app);
        load_history(&mut app);
        let prepared = app
            .workspace
            .prepare(Action::RestorePassword(1), &app)
            .unwrap();
        match change {
            0 => {
                app.workspace.selected = Some(Choice {
                    id: 8,
                    label: "Other".into(),
                })
            }
            1 => {
                app.items[0].revision += 1;
                // Even a newly loaded page cannot validate an older confirmation.
                load_history(&mut app);
                assert!(app.workspace.history_for(&app).is_some());
            }
            _ => app.session = Some("b".repeat(64)),
        }
        let serial = app.serial;
        let _ = app.execute_workflow(prepared);
        assert_eq!(
            app.serial, serial,
            "stale restoration must not send a request"
        );
        assert!(!app.busy);
    }
}

#[test]
fn failed_history_reload_cannot_relabel_an_older_page() {
    let mut app = app();
    add_other_account(&mut app);
    load_history(&mut app);
    app.workspace.selected = Some(Choice {
        id: 8,
        label: "Other".into(),
    });
    let _ = app.workflow(Event::Run(Action::History));
    assert!(app.workspace.result.is_none());
    assert!(app.workspace.history_result_target.is_none());
    assert_eq!(
        app.workspace
            .history_inflight_target
            .as_ref()
            .unwrap()
            .choice
            .id,
        8
    );

    let mut response = RpcResponse::message(ResponseCode::Failure, "synthetic history failure");
    response.session_id = app.session.clone();
    let _ = app.update(super::super::Message::Finished(
        app.serial,
        Job::Workflow(Action::History),
        Arc::new(Ok(Reply::Server {
            response: Box::new(response),
            vaults: vec![],
            pending: vec![],
        })),
    ));
    assert!(app.workspace.result.is_none());
    assert!(app.workspace.history_for(&app).is_none());
    assert!(
        app.workspace
            .prepare(Action::RestorePassword(1), &app)
            .is_err()
    );
}

#[test]
fn current_history_preserves_valid_password_restoration() {
    let mut app = app();
    load_history(&mut app);
    let prepared = app
        .workspace
        .prepare(Action::RestorePassword(1), &app)
        .unwrap();
    assert_eq!(prepared.revision, Some(11));
    assert_eq!(prepared.session, app.session);
    assert!(prepared.confirmation.as_ref().unwrap().contains("Work"));
    assert!(
        prepared
            .confirmation
            .as_ref()
            .unwrap()
            .contains("yesterday")
    );
    assert!(matches!(
        &prepared.command,
        ServerCommand::RestorePassword {
            target: Target::Id(7),
            revision: 1
        }
    ));
    assert!(
        app.workspace
            .prepare(Action::RestorePassword(0), &app)
            .is_err()
    );
    assert!(
        app.workspace
            .prepare(Action::RestorePassword(2), &app)
            .is_err()
    );
    let serial = app.serial;
    let _ = app.execute_workflow(prepared);
    assert!(app.serial > serial);
    assert!(app.busy);
}

#[test]
fn history_without_a_request_context_is_ignored_and_clearing_the_vault_drops_context() {
    let mut app = app();
    app.workspace.receive(history_page());
    assert!(app.workspace.result.is_none());
    load_history(&mut app);
    assert!(app.workspace.history_result_target.is_some());
    app.workspace.clear_vault();
    assert!(app.workspace.history_result_target.is_none());
    assert!(app.workspace.history_inflight_target.is_none());
    assert!(app.workspace.result.is_none());
}

#[test]
fn confirmation_holds_the_reviewed_command_and_cannot_cross_sessions() {
    let mut app = app();
    app.workspace.configuration = "original-secret".into();
    let prepared = app.workspace.prepare(Action::SetOtp, &app).unwrap();
    assert!(prepared.confirmation.as_ref().unwrap().contains("Work"));
    assert!(
        !prepared
            .confirmation
            .as_ref()
            .unwrap()
            .contains("original-secret")
    );
    app.session = Some("b".repeat(64));
    let _ = app.execute_workflow(prepared);
    assert!(!app.busy);
    assert!(app.notice.contains("session changed"));
}

#[test]
fn editing_inputs_cancels_the_pending_confirmation() {
    let mut app = app();
    app.workspace.configuration = "first".into();
    app.workspace.prepared = Some(app.workspace.prepare(Action::SetOtp, &app).unwrap());
    let _ = app.workflow(Event::Field(Field::Configuration, "second".into()));
    assert!(app.workspace.prepared.is_none());
    assert!(!app.busy);
}

#[test]
fn file_operations_preserve_preview_and_conflict_policy_and_require_password_confirmation() {
    let mut app = app();
    let root = tempfile::tempdir().unwrap();
    app.workspace.path = root.path().join("items.json").to_str().unwrap().into();
    app.workspace.import_new = true;
    app.workspace.policy = Policy::KeepBoth;
    let preview = app.workspace.prepare(Action::PreviewImport, &app).unwrap();
    let ServerCommand::Import(request) = &preview.command else {
        panic!()
    };
    assert!(request.preview && request.new);
    assert_eq!(request.conflicts, ConflictPolicy::KeepBoth);
    assert!(request.key_pass.is_none());
    assert!(preview.confirmation.is_none());
    assert!(app.workspace.prepare(Action::Import, &app).is_err());
    app.workspace.password = "a sufficiently strong backup password".into();
    assert!(app.workspace.prepare(Action::Backup, &app).is_err());
    app.workspace.confirmation = app.workspace.password.clone();
    assert!(
        app.workspace
            .prepare(Action::Backup, &app)
            .unwrap()
            .confirmation
            .is_some()
    );
    assert!(
        app.workspace
            .prepare(Action::Export, &app)
            .unwrap()
            .confirmation
            .as_ref()
            .unwrap()
            .contains("plaintext")
    );
    assert!(app.workspace.prepare(Action::RestoreBackup, &app).is_err());
    app.session = None;
    assert!(app.workspace.prepare(Action::RestoreBackup, &app).is_ok());
}

#[test]
fn uncertain_operations_block_new_mutations_but_allow_review_reads() {
    let mut app = app();
    app.pending = Some("f".repeat(32));
    assert!(app.workspace.prepare(Action::ShowOtp(false), &app).is_err());
    assert!(app.workspace.prepare(Action::History, &app).is_ok());
    assert!(app.workspace.prepare(Action::Audit, &app).is_ok());
}

#[test]
fn purge_and_restore_require_a_reviewed_trash_entry() {
    let mut app = app();
    assert!(app.workspace.prepare(Action::Purge(None), &app).is_err());
    app.workspace.result = Some(ResponsePayload::Trash(password_manager::vault::TrashPage {
        trash: vec![password_manager::vault::TrashSummary {
            id: 9,
            name: "Deleted".into(),
            kind: ItemKind::Login,
            username: None,
            deleted: "today".into(),
            has_totp: false,
        }],
    }));
    let prepared = app.workspace.prepare(Action::Purge(Some(9)), &app).unwrap();
    assert!(prepared.confirmation.as_ref().unwrap().contains("Deleted"));
    assert!(
        app.workspace
            .prepare(Action::RestoreTrash(9), &app)
            .unwrap()
            .confirmation
            .is_none()
    );
    assert!(
        app.workspace
            .prepare(Action::RestoreTrash(10), &app)
            .is_err()
    );
}

#[test]
fn duo_decisions_capture_the_reviewed_fingerprint_and_verified_code() {
    let mut app = app();
    receive_duo(&mut app, vec![duo_request()]);
    assert!(
        app.workspace
            .prepare(Action::Respond(0, true), &app)
            .is_err()
    );
    app.workspace.code = "123".into();
    let prepared = app
        .workspace
        .prepare(Action::Respond(0, true), &app)
        .unwrap();
    assert!(prepared.confirmation.as_ref().unwrap().contains("Boise"));
    let ServerCommand::Duo(DuoCommand::Respond {
        request_id,
        fingerprint,
        code,
        approve,
        ..
    }) = &prepared.command
    else {
        panic!()
    };
    assert_eq!(request_id, "request-1");
    assert_eq!(fingerprint, "reviewed-fingerprint");
    assert_eq!(code.expose(), "123");
    assert!(approve);
    if let Some(requests) = &mut app.workspace.duo_requests {
        requests[0].expires_at = 0;
    }
    assert!(
        app.workspace
            .prepare(Action::Respond(0, true), &app)
            .is_err()
    );
}

#[test]
fn focus_loss_discards_late_secret_results_without_losing_mutation_receipts() {
    let mut app = app();
    app.workspace.request_epoch = app.workspace.secret_epoch;
    app.workspace.hide_secrets();
    app.workspace
        .receive(ResponsePayload::Secret("late secret".into()));
    assert!(app.workspace.result.is_none());
    app.workspace
        .receive(ResponsePayload::Authenticator(AuthenticatorResponse {
            code: "123456".into(),
            expires_in: Some(30),
            counter: None,
            mode: "totp".into(),
        }));
    assert!(app.workspace.result.is_none());
    app.workspace
        .receive(ResponsePayload::Message("counter saved".into()));
    assert!(matches!(
        app.workspace.result,
        Some(ResponsePayload::Message(_))
    ));
}

#[test]
fn external_lock_clears_tools_credentials_results_and_confirmation() {
    let mut app = app();
    app.workspace.password = "password".into();
    app.workspace.configuration = "otp seed".into();
    app.workspace.code = "123".into();
    app.workspace.watch_duo = true;
    receive_duo(&mut app, vec![duo_request()]);
    app.workspace.prepared = Some(app.workspace.prepare(Action::SetOtp, &app).unwrap());
    let response = RpcResponse::success(ResponsePayload::Status(
        password_manager::protocol::ServerStatus::new(true, None),
    ));
    let _ = app.complete(
        Job::Status,
        Reply::Server {
            response: Box::new(response),
            vaults: vec![],
            pending: vec![],
        },
    );
    assert!(app.workspace.password.is_empty());
    assert!(app.workspace.configuration.is_empty());
    assert!(app.workspace.code.is_empty());
    assert!(!app.workspace.watch_duo);
    assert!(app.workspace.duo_requests.is_none());
    assert!(app.workspace.prepared.is_none());
    assert!(app.workspace.result.is_none());
}

#[test]
fn advanced_search_keeps_all_cli_filters_and_never_requests_secrets() {
    let mut app = app();
    app.workspace.notes = "note text".into();
    app.workspace.query = "search text".into();
    app.workspace.kind = Some(ItemKind::ApiSecret);
    app.workspace.has_otp = Some(false);
    app.workspace.weak = true;
    app.workspace.stale_days = "30".into();
    app.workspace.sort = SortField::Modified;
    app.workspace.descending = true;
    let prepared = app.workspace.prepare(Action::Search, &app).unwrap();
    let ServerCommand::ManagementList(filter) = &prepared.command else {
        panic!()
    };
    assert_eq!(filter.notes.as_ref().unwrap().expose(), "note text");
    assert_eq!(filter.query.as_deref(), Some("search text"));
    assert_eq!(filter.list.kind, Some(ItemKind::ApiSecret));
    assert_eq!(filter.list.has_totp, Some(false));
    assert!(filter.list.weak && filter.list.descending);
    assert_eq!(filter.list.stale_days, Some(30));
    assert_eq!(filter.list.sort, SortField::Modified);
}

#[test]
fn passive_watch_does_not_extend_unlock_or_starve_status_checks() {
    let mut app = app();
    let prepared = app.workspace.prepare(Action::WatchOtp, &app).unwrap();
    assert!(!prepared.command.extends_unlock());
    assert!(!prepared.command.is_mutation());
    let now = Instant::now();
    app.tab = Tab::Tools;
    app.workspace.watch_otp = true;
    app.workspace.otp_watch_target = Some(WatchTarget::selected(&app).unwrap());
    app.workspace.last_watch = now - Duration::from_secs(1);
    app.last_status = now - Duration::from_secs(2);
    let _ = app.update(super::super::Message::Tick(now));
    assert!(app.polling);
    assert!(!app.busy);
}

#[test]
fn passive_watch_preserves_inputs_and_watch_target_when_selection_changes() {
    let mut app = app();
    app.workspace.code = "123".into();
    app.workspace.password = "pending backup password".into();
    app.workspace.watch_duo = true;
    app.workspace.duo_watch_target = Some(WatchTarget::selected(&app).unwrap());
    let prepared = app.workspace.prepare(Action::Requests, &app).unwrap();
    let _ = app.execute_workflow(prepared);
    assert!(app.polling);
    assert!(!app.busy);
    assert_eq!(app.workspace.code.expose(), "123");
    assert_eq!(app.workspace.password.expose(), "pending backup password");
    let serial = app.serial;
    let _ = app.workflow(Event::Select(Choice {
        id: 8,
        label: "Other".into(),
    }));
    assert!(app.serial > serial);
    assert!(!app.polling);
    assert!(app.workspace.watch_duo);
    assert_eq!(
        app.workspace.duo_watch_target.as_ref().unwrap().choice.id,
        7
    );
    assert!(app.workspace.duo_requests_for(&app).is_none());
}

#[test]
fn current_vault_import_keeps_its_report_selection_and_unlock_session() {
    let mut app = app();
    let report = password_manager::vault::ImportReport {
        total: 2,
        skipped: 2,
        ..Default::default()
    };
    let mut response = RpcResponse::success(ResponsePayload::ImportReport(report.clone()));
    response.session_id = app.session.clone();
    let session = app.session.clone();
    let _ = app.complete(
        Job::Workflow(Action::Import),
        Reply::Server {
            response: Box::new(response),
            vaults: vec![],
            pending: vec![],
        },
    );
    assert_eq!(app.session, session);
    assert!(
        matches!(&app.workspace.result, Some(ResponsePayload::ImportReport(saved)) if saved == &report)
    );
    assert_eq!(app.workspace.selected.as_ref().unwrap().id, 7);
}

#[test]
fn confirmation_cannot_discard_edits_started_on_another_tab() {
    let mut app = app();
    app.workspace.configuration = "synthetic seed".into();
    let prepared = app.workspace.prepare(Action::SetOtp, &app).unwrap();
    app.draft = Some(Draft {
        name: "Unsaved item".into(),
        dirty: true,
        ..Default::default()
    });
    let _ = app.execute_workflow(prepared);
    assert!(!app.busy);
    assert!(app.draft.as_ref().unwrap().dirty);
    assert!(app.notice.contains("Save or discard"));
}

#[test]
fn opening_tools_does_not_enable_duo_watching_or_fetch_requests() {
    let mut app = app();
    let _ = app.update(super::super::Message::OpenItemTools(7));
    assert!(!app.workspace.watch_duo);
    assert!(app.workspace.duo_watch_target.is_none());
    assert!(!app.polling && !app.busy);
}

#[test]
fn duo_requests_and_secret_results_do_not_replace_each_other() {
    let mut app = app();
    app.workspace
        .receive(ResponsePayload::Secret("temporary reveal".into()));
    let deadline = app.workspace.result_until;
    receive_duo(&mut app, vec![duo_request()]);
    assert_eq!(app.workspace.result_until, deadline);
    assert!(matches!(
        app.workspace.result,
        Some(ResponsePayload::Secret(_))
    ));
    app.workspace
        .receive(ResponsePayload::Message("other operation finished".into()));
    assert_eq!(app.workspace.duo_requests.as_ref().unwrap().len(), 1);
    assert!(
        app.workspace
            .prepare(Action::Respond(0, false), &app)
            .is_ok()
    );
    app.workspace.hide_secrets();
    assert_eq!(app.workspace.duo_requests.as_ref().unwrap().len(), 1);
}

#[test]
fn duo_polling_pauses_during_review_and_refreshes_after_a_decision() {
    let mut app = app();
    app.tab = Tab::Tools;
    app.workspace.section = Section::Security;
    app.workspace.watch_duo = true;
    receive_duo(&mut app, vec![duo_request()]);
    let _ = app.workflow(Event::Run(Action::Respond(0, false)));
    assert!(app.workspace.prepared.is_some());
    let now = Instant::now();
    app.workspace.last_watch = now - Duration::from_secs(5);
    app.last_status = now;
    let _ = app.update(super::super::Message::Tick(now));
    assert!(!app.polling && !app.busy);
    let _ = app.workflow(Event::Confirm);
    assert!(app.busy && !app.polling);
    let reply = workflow_reply(&app, ResponsePayload::Message("Denied".into()));
    let _ = app.update(super::super::Message::Finished(
        app.serial,
        Job::Workflow(Action::Respond(0, false)),
        Arc::new(Ok(reply)),
    ));
    assert!(app.polling && !app.busy);
    assert!(app.workspace.duo_requests.is_none());
    assert!(app.workspace.prepared.is_none());
}

#[test]
fn duo_selection_and_section_changes_preserve_watch_but_hide_other_items_requests() {
    let mut app = app();
    app.workspace.section = Section::Security;
    let _ = app.workflow(Event::Toggle(Toggle::WatchDuo, true));
    let bound = app.workspace.duo_watch_target.clone().unwrap();
    app.polling = false;
    receive_duo(&mut app, vec![duo_request()]);
    let _ = app.workflow(Event::Section(Section::Recovery));
    assert!(app.workspace.watch_duo);
    assert_eq!(app.workspace.duo_watch_target, Some(bound.clone()));
    let _ = app.workflow(Event::Select(Choice {
        id: 8,
        label: "Other".into(),
    }));
    assert!(app.workspace.watch_duo);
    assert_eq!(app.workspace.duo_watch_target, Some(bound));
    assert!(app.workspace.duo_requests_for(&app).is_none());
    assert!(
        app.workspace
            .prepare(Action::Respond(0, false), &app)
            .is_err()
    );
}

fn totp(code: &str) -> ResponsePayload {
    ResponsePayload::Authenticator(AuthenticatorResponse {
        code: code.into(),
        expires_in: Some(30),
        counter: None,
        mode: "totp".into(),
    })
}

#[test]
fn otp_timeout_override_is_validated_and_scoped_to_codes() {
    let mut app = app();
    app.conf.clipboard.timeout = 9;
    for (input, expected) in [("", Some(9)), (" 255 ", Some(255))] {
        app.workspace.otp_copy_timeout = input.into();
        let prepared = app.workspace.prepare(Action::ShowOtp(true), &app).unwrap();
        assert!(
            matches!(prepared.command, ServerCommand::Totp(TotpCommand::Show { copy_timeout, .. }) if copy_timeout == expected)
        );
        let passive = app.workspace.prepare(Action::WatchOtp, &app).unwrap();
        assert!(matches!(
            passive.command,
            ServerCommand::Totp(TotpCommand::Watch {
                copy_timeout: None,
                ..
            })
        ));
        assert!(!passive.command.extends_unlock());
    }
    for input in ["0", "-1", "256", "1.5", "seconds"] {
        app.workspace.otp_copy_timeout = input.into();
        assert!(app.workspace.prepare(Action::ShowOtp(true), &app).is_err());
        assert!(app.workspace.prepare(Action::ShowOtp(false), &app).is_ok());
    }
}

#[test]
fn watch_copies_first_and_each_changed_code_once_without_extending_unlock() {
    let mut app = app();
    app.workspace.copy_watched_otp = true;
    app.workspace.otp_copy_timeout = "22".into();
    let _ = app.workflow(Event::Toggle(Toggle::WatchOtp, true));
    assert!(app.polling && !app.busy);
    let passive = app.workspace.prepare(Action::WatchOtp, &app).unwrap();
    assert!(matches!(
        passive.command,
        ServerCommand::Totp(TotpCommand::Watch {
            copy_timeout: None,
            ..
        })
    ));
    app.polling = false;
    let _ = app.complete_otp_watch(Action::WatchOtp, totp("123456"));
    assert!(
        app.busy && !app.polling,
        "a clipboard mutation must retain its completion"
    );
    let copied = app.workspace.prepare(Action::CopyWatchedOtp, &app).unwrap();
    assert!(matches!(
        copied.command,
        ServerCommand::Totp(TotpCommand::Watch {
            copy_timeout: Some(22),
            ..
        })
    ));
    assert!(!copied.command.extends_unlock());
    assert!(copied.command.is_mutation());
    app.busy = false;
    let _ = app.complete_otp_watch(Action::CopyWatchedOtp, totp("123456"));
    let serial = app.serial;
    let _ = app.complete_otp_watch(Action::WatchOtp, totp("123456"));
    assert_eq!(
        app.serial, serial,
        "unchanged codes must never request another copy"
    );
    let _ = app.complete_otp_watch(Action::WatchOtp, totp("654321"));
    assert!(app.serial > serial);
    assert!(app.busy && !app.polling);
}

#[test]
fn otp_copy_refetch_at_a_code_boundary_becomes_the_previous_code() {
    let mut app = app();
    app.workspace.copy_watched_otp = true;
    app.workspace.otp_copy_timeout = "10".into();
    let _ = app.workflow(Event::Toggle(Toggle::WatchOtp, true));
    app.polling = false;
    let _ = app.complete_otp_watch(Action::WatchOtp, totp("123456"));
    app.busy = false;
    let _ = app.complete_otp_watch(Action::CopyWatchedOtp, totp("654321"));
    let serial = app.serial;
    let _ = app.complete_otp_watch(Action::WatchOtp, totp("654321"));
    assert_eq!(app.serial, serial);
    assert_eq!(app.workspace.previous_otp.expose(), "654321");
}

#[test]
fn watch_copy_cannot_start_with_zero_timeout_or_continue_after_focus_loss() {
    let mut app = app();
    app.workspace.copy_watched_otp = true;
    app.workspace.otp_copy_timeout = "0".into();
    let _ = app.workflow(Event::Toggle(Toggle::WatchOtp, true));
    assert!(!app.workspace.watch_otp && !app.busy && !app.polling);
    app.workspace.otp_copy_timeout = "10".into();
    let _ = app.workflow(Event::Toggle(Toggle::WatchOtp, true));
    app.polling = false;
    app.workspace.hide_secrets();
    let serial = app.serial;
    let _ = app.complete_otp_watch(Action::WatchOtp, totp("123456"));
    assert_eq!(app.serial, serial);
    assert!(app.workspace.result.is_none());
    assert!(app.workspace.previous_otp.is_empty());
}

#[test]
fn duo_replacement_confirmation_applies_only_to_push_enrollment() {
    let mut app = app();
    app.workspace.activation = "synthetic activation".into();
    app.workspace.replace_duo = true;
    let push = app.workspace.prepare(Action::EnrollDuo, &app).unwrap();
    assert!(push.confirmation.as_ref().unwrap().contains("replacing"));
    assert!(matches!(
        push.command,
        ServerCommand::Duo(DuoCommand::Enroll { replace: true, .. })
    ));
    let passcodes = app
        .workspace
        .prepare(Action::EnrollPasscodes, &app)
        .unwrap();
    assert!(!passcodes.confirmation.as_ref().unwrap().contains("replac"));
    assert!(matches!(
        passcodes.command,
        ServerCommand::Totp(TotpCommand::Duo { .. })
    ));
}

#[test]
fn duo_watch_interval_is_bounded_and_invalid_start_is_rejected() {
    let mut app = app();
    for valid in ["3", " 5 ", "60"] {
        app.workspace.duo_interval = valid.into();
        assert!(app.workspace.duo_interval_seconds().is_ok());
    }
    for invalid in ["", "0", "2", "61", "-5", "3.5", "five"] {
        app.workspace.duo_interval = invalid.into();
        let _ = app.workflow(Event::Toggle(Toggle::WatchDuo, true));
        assert!(!app.workspace.watch_duo);
        assert!(app.workspace.duo_watch_target.is_none());
        assert!(!app.polling && !app.busy);
    }
}

#[test]
fn background_watch_uses_bound_target_and_pauses_for_confirmation() {
    let mut app = app();
    let _ = app.workflow(Event::Toggle(Toggle::WatchDuo, true));
    app.polling = false;
    app.workspace.duo_interval = "12".into();
    let now = Instant::now();
    app.workspace.selected = Some(Choice {
        id: 8,
        label: "Other".into(),
    });
    app.tab = Tab::Vault;
    app.workspace.section = Section::Files;
    app.workspace.last_watch = now - Duration::from_secs(11);
    let serial = app.serial;
    let _ = app.poll_tool_watches(now);
    assert_eq!(app.serial, serial);
    app.workspace.last_watch = now - Duration::from_secs(12);
    let _ = app.poll_tool_watches(now);
    assert!(app.polling && !app.busy);
    assert_eq!(
        app.workspace
            .duo_inflight_target
            .as_ref()
            .unwrap()
            .choice
            .id,
        7
    );
    app.polling = false;
    let _ = app.complete_duo_requests(ResponsePayload::DuoRequests(vec![duo_request()]));
    assert!(app.workspace.duo_requests_for(&app).is_none());
    app.workspace.selected = Some(Choice {
        id: 7,
        label: "Work".into(),
    });
    assert!(app.workspace.duo_requests_for(&app).is_some());
    app.workspace.prepared = Some(
        app.workspace
            .prepare(Action::Respond(0, false), &app)
            .unwrap(),
    );
    app.workspace.last_watch = now - Duration::from_secs(12);
    let serial = app.serial;
    let _ = app.poll_tool_watches(now);
    assert_eq!(app.serial, serial);
    assert!(!app.polling && !app.busy);
}

#[test]
fn duo_cache_and_polling_reject_item_revision_and_session_changes() {
    let mut app = app();
    let _ = app.workflow(Event::Toggle(Toggle::WatchDuo, true));
    app.polling = false;
    receive_duo(&mut app, vec![duo_request()]);
    app.items[0].revision += 1;
    assert!(app.workspace.duo_requests_for(&app).is_none());
    assert!(
        app.workspace
            .prepare(Action::Respond(0, false), &app)
            .is_err()
    );
    let _ = app.poll_tool_watches(Instant::now());
    assert!(!app.workspace.watch_duo);
    assert!(app.workspace.duo_requests.is_none());
    let _ = app.workflow(Event::Toggle(Toggle::WatchDuo, true));
    app.polling = false;
    app.session = Some("b".repeat(64));
    let _ = app.complete_duo_requests(ResponsePayload::DuoRequests(vec![duo_request()]));
    assert!(app.workspace.duo_requests.is_none());
}

#[test]
fn duo_response_cache_binds_to_inflight_item_and_never_current_selection() {
    let mut app = app();
    let _ = app.workflow(Event::Run(Action::Requests));
    app.busy = false;
    app.workspace.selected = Some(Choice {
        id: 8,
        label: "Other".into(),
    });
    let _ = app.complete_duo_requests(ResponsePayload::DuoRequests(vec![duo_request()]));
    assert_eq!(
        app.workspace.duo_request_target.as_ref().unwrap().choice.id,
        7
    );
    assert!(app.workspace.duo_requests_for(&app).is_none());
    app.workspace.selected = Some(Choice {
        id: 7,
        label: "Work".into(),
    });
    assert_eq!(app.workspace.duo_requests_for(&app).unwrap().len(), 1);
}

#[test]
fn duo_notifications_deduplicate_fingerprints_and_ignore_expired_requests() {
    let mut state = State::default();
    let mut request = duo_request();
    assert!(state.observe_duo(&[request.clone()]));
    assert!(!state.observe_duo(&[request.clone()]));
    request.fingerprint = "changed-review-details".into();
    assert!(state.observe_duo(&[request.clone()]));
    assert!(!state.observe_duo(&[]));
    assert!(state.observe_duo(&[request.clone()]));
    request.expires_at = 0;
    assert!(!state.observe_duo(&[request]));
}

#[test]
fn trash_and_audit_use_readable_labels_and_preserve_finding_details() {
    let entry = password_manager::vault::TrashSummary {
        id: 9,
        name: "Deleted".into(),
        kind: ItemKind::ApiSecret,
        username: None,
        deleted: "2026-10-15T12:00:00.123456789+00:00".into(),
        has_totp: false,
    };
    let label = view::trash_label(&entry);
    assert!(label.contains("API secret"));
    assert!(label.contains("Oct ") && label.contains("2026"));
    assert!(!label.starts_with("9 ·"));
    assert!(!label.contains("123456789") && !label.contains("+00:00"));
    let label = password_manager::vault::AuditLabel {
        id: 7,
        name: "Work".into(),
        username: Some("alice".into()),
        password_changed: "2025-10-01 12:30".into(),
    };
    let rendered = view::report(&ResponsePayload::Audit(
        password_manager::vault::AuditReport {
            total: 1,
            healthy: 0,
            score: 0,
            weak: vec![label.clone()],
            stale: vec![label],
            reused: vec![],
            duplicates: vec![],
            missing_totp: vec![],
            breached: vec![],
            breach_error: None,
            unchecked: vec![],
        },
    ));
    assert!(rendered.contains("username: alice"));
    assert!(rendered.contains("last changed 2025-10-01 12:30"));
}

#[test]
fn automatic_copy_reloads_defaults_and_honors_external_disable() {
    let mut app = app();
    app.workspace.copy_watched_otp = true;
    let _ = app.workflow(Event::Toggle(Toggle::WatchOtp, true));
    app.polling = false;
    let _ = app.complete_otp_watch(Action::WatchOtp, totp("123456"));
    assert!(app.busy && !app.polling);
    let serial = app.serial;
    let mut conf = app.conf.clone();
    conf.clipboard.timeout = 0;
    let _ = app.update(super::super::Message::Finished(
        serial,
        Job::WatchCopyDefaults,
        Arc::new(Ok(Reply::Configuration(conf))),
    ));
    assert_eq!(
        app.serial, serial,
        "a disabled copy must never launch a mutation"
    );
    assert!(!app.busy && !app.polling);
    assert!(app.workspace.watch_otp);
    assert!(!app.workspace.copy_watched_otp);
    assert!(app.notice.contains("timeout is zero"));
}

#[test]
fn automatic_copy_uses_reloaded_timeout_and_cannot_survive_focus_loss() {
    let mut app = app();
    app.workspace.copy_watched_otp = true;
    let _ = app.workflow(Event::Toggle(Toggle::WatchOtp, true));
    app.polling = false;
    let _ = app.complete_otp_watch(Action::WatchOtp, totp("123456"));
    let mut conf = app.conf.clone();
    conf.clipboard.timeout = 44;
    let _ = app.update(super::super::Message::Finished(
        app.serial,
        Job::WatchCopyDefaults,
        Arc::new(Ok(Reply::Configuration(conf.clone()))),
    ));
    assert!(app.busy && !app.polling);
    let prepared = app.workspace.prepare(Action::CopyWatchedOtp, &app).unwrap();
    assert!(matches!(
        prepared.command,
        ServerCommand::Totp(TotpCommand::Watch {
            copy_timeout: Some(44),
            ..
        })
    ));
    // Complete that mutation, observe another code, then leave the window during
    // its defaults preflight. The read may finish; the next copy must not start.
    app.busy = false;
    let _ = app.complete_otp_watch(Action::CopyWatchedOtp, totp("123456"));
    let _ = app.complete_otp_watch(Action::WatchOtp, totp("654321"));
    let serial = app.serial;
    let _ = app.update(super::super::Message::HideSecrets);
    let _ = app.update(super::super::Message::Finished(
        serial,
        Job::WatchCopyDefaults,
        Arc::new(Ok(Reply::Configuration(conf))),
    ));
    assert_eq!(app.serial, serial);
    assert!(!app.busy && !app.polling && !app.workspace.watch_otp);
    assert!(app.workspace.result.is_none());
}

#[test]
fn duo_revision_conflict_stops_background_watch_and_discards_requests() {
    let mut app = app();
    let _ = app.workflow(Event::Toggle(Toggle::WatchDuo, true));
    receive_duo(&mut app, vec![duo_request()]);
    let mut response = RpcResponse::message(ResponseCode::Conflict, "item revision changed");
    response.session_id = app.session.clone();
    let _ = app.update(super::super::Message::Finished(
        app.serial,
        Job::Workflow(Action::Requests),
        Arc::new(Ok(Reply::Server {
            response: Box::new(response),
            vaults: vec![],
            pending: vec![],
        })),
    ));
    assert!(!app.workspace.watch_duo);
    assert!(app.workspace.duo_watch_target.is_none());
    assert!(app.workspace.duo_requests.is_none());
    assert!(app.workspace.duo_request_target.is_none());
    assert!(app.workspace.prepared.is_none());
}

#[test]
fn zero_timeout_copy_actions_cannot_fall_back_to_revealing_or_consuming_codes() {
    let mut app = app();
    app.conf.clipboard.timeout = 0;
    assert!(app.workspace.prepare(Action::ShowOtp(true), &app).is_err());
    assert!(app.workspace.prepare(Action::ShowOtp(false), &app).is_ok());
    app.workspace.otp_copy_timeout = "20".into();
    assert!(app.workspace.prepare(Action::ShowOtp(true), &app).is_ok());
}

#[test]
fn pending_duo_request_stays_reviewable_across_refresh_ticks_and_status_checks() {
    let mut app = app();
    let _ = app.workflow(Event::Toggle(Toggle::WatchDuo, true));
    let reply = workflow_reply(&app, ResponsePayload::DuoRequests(vec![duo_request()]));
    let _ = app.update(super::super::Message::Finished(
        app.serial,
        Job::Workflow(Action::Requests),
        Arc::new(Ok(reply)),
    ));
    app.workspace.code = "123".into();
    let serial = app.serial;
    let now = Instant::now();
    app.workspace.last_watch = now - Duration::from_secs(60);
    for seconds in [5, 10, 20, 60, 120] {
        let tick = now + Duration::from_secs(seconds);
        app.last_status = tick;
        let _ = app.update(super::super::Message::Tick(tick));
        assert_eq!(
            app.serial, serial,
            "automatic fetch must not replace a request under review"
        );
        assert!(!app.busy && !app.polling);
        assert_eq!(
            app.workspace.duo_requests_for(&app).unwrap()[0].id,
            "request-1"
        );
        assert_eq!(app.workspace.code.expose(), "123");
    }
    // Pausing Duo refresh must not pause detection of vault locks or switches.
    app.last_status = now - Duration::from_secs(2);
    let _ = app.update(super::super::Message::Tick(now));
    assert!(app.polling && !app.busy);
    let reply = workflow_reply(
        &app,
        ResponsePayload::Status(password_manager::protocol::ServerStatus::new(false, None)),
    );
    let _ = app.update(super::super::Message::Finished(
        app.serial,
        Job::Status,
        Arc::new(Ok(reply)),
    ));
    let reviewed = app
        .workspace
        .prepare(Action::Respond(0, true), &app)
        .unwrap();
    assert!(matches!(reviewed.command,
        ServerCommand::Duo(DuoCommand::Respond { ref request_id, ref fingerprint, .. })
            if request_id == "request-1" && fingerprint == "reviewed-fingerprint"
    ));
}

#[test]
fn manual_duo_refresh_still_replaces_a_paused_review_and_resumes_monitoring() {
    let mut app = app();
    let _ = app.workflow(Event::Toggle(Toggle::WatchDuo, true));
    app.polling = false;
    receive_duo(&mut app, vec![duo_request()]);
    assert!(app.workspace.duo_review_pending(&app));
    let _ = app.workflow(Event::Run(Action::Requests));
    assert!(app.polling && !app.busy);
    let reply = workflow_reply(&app, ResponsePayload::DuoRequests(vec![]));
    let _ = app.update(super::super::Message::Finished(
        app.serial,
        Job::Workflow(Action::Requests),
        Arc::new(Ok(reply)),
    ));
    assert!(!app.workspace.duo_review_pending(&app));
    assert!(app.workspace.duo_requests_for(&app).unwrap().is_empty());
    let now = Instant::now();
    app.last_status = now;
    app.workspace.last_watch = now - Duration::from_secs(5);
    let _ = app.update(super::super::Message::Tick(now));
    assert!(app.polling && !app.busy);
}

#[test]
fn expired_duo_request_resumes_fetching_without_extending_its_deadline() {
    let mut app = app();
    let _ = app.workflow(Event::Toggle(Toggle::WatchDuo, true));
    app.polling = false;
    let mut expired = duo_request();
    expired.expires_at = 0;
    receive_duo(&mut app, vec![expired]);
    assert!(!app.workspace.duo_review_pending(&app));
    assert!(
        app.workspace
            .prepare(Action::Respond(0, false), &app)
            .is_err()
    );
    let now = Instant::now();
    app.last_status = now;
    app.workspace.last_watch = now - Duration::from_secs(5);
    let _ = app.update(super::super::Message::Tick(now));
    assert!(app.polling && !app.busy);
    assert_eq!(
        app.workspace.duo_requests.as_ref().unwrap()[0].expires_at,
        0
    );
}

#[test]
fn otp_watch_results_bind_to_the_prepared_account_even_if_selection_changes() {
    let mut app = app();
    let _ = app.workflow(Event::Toggle(Toggle::WatchOtp, true));
    app.polling = false;
    let mut other = app.items[0].clone();
    other.id = 8;
    app.items.push(other);
    app.workspace.selected = Some(Choice {
        id: 8,
        label: "Other account".into(),
    });
    let now = Instant::now();
    app.workspace.last_watch = now - Duration::from_secs(2);
    let _ = app.poll_tool_watches(now);
    assert_eq!(
        app.workspace
            .otp_inflight_target
            .as_ref()
            .unwrap()
            .choice
            .id,
        7
    );
    app.polling = false;
    let _ = app.complete_otp_watch(Action::WatchOtp, totp("123456"));
    assert_eq!(
        app.workspace.otp_result_target.as_ref().unwrap().choice.id,
        7
    );
    assert!(app.workspace.otp_result_for(&app).is_none());
}

#[test]
fn tools_results_and_options_are_separate_without_discarding_a_reviewed_result() {
    let mut app = app();
    app.workspace.section = Section::Audit;
    app.workspace
        .receive(ResponsePayload::Message("Audit done".into()));
    assert!(app.workspace.show_results);
    let _ = app.workflow(Event::ShowResults(false));
    assert!(!app.workspace.show_results);
    assert!(app.workspace.result.is_some());
    let _ = app.workflow(Event::ShowResults(true));
    assert!(app.workspace.show_results);
    let _ = app.workflow(Event::Section(Section::Trash));
    assert!(!app.workspace.show_results);
    assert!(app.workspace.result.is_none());
}

#[test]
fn direct_file_tool_selection_opens_the_requested_task_and_clears_old_credentials() {
    let mut app = app();
    app.workspace.password = "temporary password".into();
    let _ = app.workflow(Event::FileOperation(FileOperation::Import));
    assert_eq!(app.workspace.section, Section::Files);
    assert_eq!(app.workspace.file_operation, FileOperation::Import);
    assert!(app.workspace.password.is_empty());
}

#[test]
fn onboarding_import_targets_a_new_vault_when_no_vault_is_unlocked() {
    let mut app = app();
    app.session = None;
    let _ = app.workflow(Event::FileOperation(FileOperation::Import));
    assert!(app.workspace.import_new);
    assert_eq!(app.workspace.section, Section::Files);
}

#[test]
fn empty_health_assessment_has_no_numeric_score() {
    let mut assessment = password_manager::vault::AuditReport {
        total: 0,
        healthy: 0,
        score: 100,
        weak: vec![],
        stale: vec![],
        reused: vec![],
        duplicates: vec![],
        missing_totp: vec![],
        breached: vec![],
        unchecked: vec![],
        breach_error: None,
    };
    let rendered = view::report(&ResponsePayload::Audit(assessment.clone()));
    assert!(rendered.contains("No login items to assess"));
    assert!(!rendered.contains("100") && !rendered.contains("0 of 0"));
    assessment.total = 2;
    assessment.healthy = 1;
    assessment.score = 50;
    let rendered = view::report(&ResponsePayload::Audit(assessment));
    assert!(rendered.contains("50/100"));
    assert!(rendered.contains("1 of 2"));
}
