use super::*;

impl App {
    pub(in crate::gui) fn complete_workflow(
        &mut self,
        action: Action,
        payload: ResponsePayload,
        session_id: Option<String>,
        audit_warning: Option<String>,
        incremental: bool,
    ) -> Task<Message> {
        if let Some((id, _)) = self.ui.undo_trash.as_ref() {
            let resolved = match action {
                workflows::Action::RestoreTrash(target)
                | workflows::Action::Purge(Some(target)) => target == *id,
                workflows::Action::Purge(None) => true,
                workflows::Action::Trash => {
                    matches!(&payload, ResponsePayload::Trash(page) if !page.trash.iter().any(|entry| entry.id == *id))
                }
                _ => false,
            };
            if resolved {
                self.ui.undo_trash = None;
            }
        }
        if action == workflows::Action::Requests {
            return self.complete_duo_requests(payload);
        }
        if matches!(
            action,
            workflows::Action::WatchOtp | workflows::Action::CopyWatchedOtp
        ) {
            return self.complete_otp_watch(action, payload);
        }
        if matches!(action, workflows::Action::Respond(..)) {
            self.notice = if let ResponsePayload::Message(message) = &payload {
                message.clone()
            } else {
                "Duo response recorded.".into()
            };
            self.workspace.clear_duo_requests();
            self.workspace.receive(payload);
            return self.workflow(workflows::Event::Run(workflows::Action::Requests));
        }
        if matches!(
            action,
            workflows::Action::EnrollDuo | workflows::Action::RemoveDuo
        ) {
            self.workspace.reset_duo();
        }
        let first_result = self.workspace.result.is_none();
        self.notice = if let Some(warning) = audit_warning {
            format!("Audit completed with incomplete breach checks: {warning}")
        } else if let ResponsePayload::Message(message) = &payload {
            message.clone()
        } else {
            if self.tab == Tab::Vault {
                ""
            } else {
                match action {
                    workflows::Action::Audit => "Vault health check complete.",
                    workflows::Action::History => "Password history loaded.",
                    workflows::Action::Trash => "Deleted items loaded.",
                    workflows::Action::Search => "Search complete.",
                    workflows::Action::PreviewImport => "Import preview ready.",
                    _ => "Operation complete.",
                }
            }
            .into()
        };
        if action.changes_vault() {
            let changes_selection = matches!(
                action,
                workflows::Action::NewVault
                    | workflows::Action::RestoreBackup
                    | workflows::Action::DeleteVault
            ) || action == workflows::Action::Import
                && self.workspace.files.import_new;
            if !changes_selection {
                if self.connection.session != session_id {
                    self.clear_vault();
                    self.connection.session = session_id.clone();
                }
                self.item = None;
                self.editor = Editor::Closed;
                self.workspace.receive(payload);
                let refresh = if incremental {
                    Task::none()
                } else if self.connection.session.is_some() {
                    self.load_items()
                } else {
                    self.status()
                };
                return Task::batch([refresh, workflows::show_result()]);
            }
            let restored = if let ResponsePayload::Vault(reference) = &payload {
                Some(reference.vault_file.clone())
            } else {
                None
            };
            self.clear_vault();
            if let Some(filename) = restored {
                self.connection.vault = Some(filename);
            }
            if matches!(action, workflows::Action::NewVault)
                || action == workflows::Action::Import && self.workspace.files.import_new
            {
                self.connection.select_created_vault = true;
            }
            self.workspace.receive(payload);
            return Task::batch([self.status(), workflows::show_result()]);
        }
        let consumed_hotp = matches!(
            &payload,
            ResponsePayload::Authenticator(code) if code.counter.is_some()
        );
        let refresh = consumed_hotp
            || matches!(
                action,
                workflows::Action::RestorePassword(_)
                    | workflows::Action::RestoreTrash(_)
                    | workflows::Action::SetOtp
                    | workflows::Action::RemoveOtp
                    | workflows::Action::EnrollDuo
                    | workflows::Action::EnrollPasscodes
                    | workflows::Action::RemoveDuo
            );
        self.workspace.receive(payload);
        if refresh {
            if self.tab == Tab::Vault
                && action.edits_authenticator()
                && let Some(id) = self.editor.as_ref().and_then(|draft| draft.id)
            {
                if self
                    .workspace
                    .duo
                    .watch
                    .as_ref()
                    .is_some_and(|target| target.choice.id == id)
                {
                    self.workspace.reset_duo();
                }
                return self.refresh_item(id, ItemIntent::Edit, incremental);
            }
            if consumed_hotp
                && self.tab == Tab::Vault
                && self.editor.is_none()
                && let Some(id) = self.item.as_ref().map(|item| item.id)
            {
                if self
                    .workspace
                    .duo
                    .watch
                    .as_ref()
                    .is_some_and(|target| target.choice.id == id)
                {
                    self.workspace.reset_duo();
                }
                return self.refresh_item(id, ItemIntent::View, incremental);
            }
            self.item = None;
            self.editor = Editor::Closed;
            let refresh = if incremental {
                Task::none()
            } else {
                self.load_items()
            };
            return Task::batch([refresh, workflows::show_result()]);
        }
        if matches!(action, workflows::Action::ShowOtp(_)) && self.tab == Tab::Vault {
            return Task::none();
        }
        if first_result
            || !(self.workspace.otp.watch.is_some() || self.workspace.duo.watch.is_some())
        {
            return workflows::show_result();
        }
        Task::none()
    }
}
