use super::*;

pub(super) struct State {
    pub(super) token: SecretString,
    pub(super) vaults: Vec<String>,
    pub(super) vault: Option<String>,
    pub(super) review: Option<password_manager::cloud::ConflictReview>,
    pub(super) choices: Vec<password_manager::cloud::Choice>,
}

impl App {
    pub(super) fn update_cloud(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Cloud(action) => {
                let job = if matches!(action, password_manager::cloud::Action::List) {
                    Job::CloudList
                } else if matches!(action, password_manager::cloud::Action::Conflicts) {
                    self.cloud.review = None;
                    self.cloud.choices.clear();
                    Job::CloudConflicts
                } else {
                    self.cloud.review = None;
                    self.cloud.choices.clear();
                    Job::Cloud
                };
                return self.request(job, ServerCommand::Cloud(action), None);
            }
            Message::CloudChoice(id, field, side) => {
                if !self.busy() {
                    self.cloud
                        .choices
                        .retain(|c| c.id != id || c.field != field);
                    self.cloud
                        .choices
                        .push(password_manager::cloud::Choice { id, field, side });
                }
            }
            Message::CloudChooseAll(side) => {
                if !self.busy()
                    && let Some(review) = &self.cloud.review
                {
                    self.cloud.choices = review
                        .items
                        .iter()
                        .flat_map(|item| {
                            item.fields
                                .iter()
                                .map(move |field| password_manager::cloud::Choice {
                                    id: item.id,
                                    field: field.field.clone(),
                                    side,
                                })
                        })
                        .collect();
                }
            }
            Message::ResolveCloud => {
                if !self.writes_allowed() || self.editor.as_ref().is_some_and(|d| d.dirty) {
                    self.notice =
                        "Save or discard pending item edits before resolving sync conflicts."
                            .into();
                    return Task::none();
                }
                if let Some(review) = self.cloud.review.take() {
                    let resolution = password_manager::cloud::Resolution {
                        token: review.token,
                        choices: std::mem::take(&mut self.cloud.choices),
                    };
                    self.hide_secrets();
                    self.workspace.clear_vault();
                    return self.request(
                        Job::CloudResolve,
                        ServerCommand::Cloud(password_manager::cloud::Action::Resolve(resolution)),
                        None,
                    );
                }
            }
            Message::CloudToken(token) => self.cloud.token = token,
            Message::CloudVault(id) => self.cloud.vault = Some(id),
            Message::SaveCloudToken => {
                let token = std::mem::take(&mut self.cloud.token);
                return self.launch(Job::Local, move || {
                    password_manager::cloud::install_token(token.expose())
                        .map_err(Failure::from)?;
                    Ok(Reply::Local("Device credential saved".into()))
                });
            }
            _ => {}
        }
        Task::none()
    }
}

impl App {
    pub(super) fn complete_cloud(&mut self, job: Job, payload: ResponsePayload) -> Task<Message> {
        match (job, payload) {
            (Job::CloudList, ResponsePayload::Message(message)) => {
                match serde_json::from_str::<Vec<password_manager::cloud::RemoteVault>>(&message) {
                    Ok(vaults) => {
                        self.cloud.vaults = vaults.into_iter().map(|v| v.id).collect();
                        self.cloud.vault = self.cloud.vaults.first().cloned();
                        self.notice =
                            format!("{} cloud vault(s) available", self.cloud.vaults.len());
                    }
                    Err(e) => self.notice = format!("Invalid vault list: {e}"),
                }
            }
            (Job::CloudConflicts, ResponsePayload::Message(message)) => {
                match serde_json::from_str::<password_manager::cloud::ConflictReview>(&message) {
                    Ok(review) => {
                        self.notice = if review.items.is_empty() {
                            "No item differences. Apply the resolution to reconcile the snapshots."
                        } else {
                            "Choose which values to keep, then apply the resolution."
                        }
                        .into();
                        self.cloud.choices.clear();
                        self.cloud.review = Some(review);
                    }
                    Err(e) => self.notice = format!("Invalid conflict review: {e}"),
                }
            }
            (Job::CloudResolve, ResponsePayload::Message(message)) => {
                self.notice = message;
                self.workspace.clear_vault();
                self.item = None;
                self.editor = Editor::Closed;
                self.ui.undo_trash = None;
                self.ui.saved_item = None;
                return self.load_items();
            }
            (Job::Cloud, ResponsePayload::Message(message)) => {
                self.notice = message;
                return self.refresh_vaults();
            }

            _ => {
                self.notice =
                    "The server returned an unexpected response. Refresh the vault.".into()
            }
        }
        Task::none()
    }
}
