//! The vault tab: browsing, opening, revealing, copying, and deleting items.
//! Editing lives in `editor.rs`; this module owns item selection and replies.
use super::*;

impl App {
    pub(super) fn update_items(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::FilterKind(kind) => {
                self.ui.kind = kind;
                self.ui.item_page = 0;
            }
            Message::ItemPage(page) => {
                self.ui.item_page = page;
                self.ui.page_input.clear();
            }
            Message::PageInput(value) => self.ui.page_input = value,
            Message::SortItems(reverse) => {
                self.ui.reverse_items = reverse;
                self.ui.item_page = 0;
                self.ui.page_input.clear();
            }
            Message::JumpItemPage => {
                let pages = self
                    .matching_items()
                    .len()
                    .div_ceil(presentation::PAGE_SIZE)
                    .max(1);
                if let Ok(page) = self.ui.page_input.parse::<usize>()
                    && page > 0
                    && page <= pages
                {
                    self.ui.item_page = page - 1;
                    self.ui.page_input.clear();
                } else {
                    self.report_error(format!("Enter a page number from 1 to {pages}."));
                }
            }

            Message::Search(query) => {
                self.query = query;
                self.ui.item_page = 0;
            }
            Message::Navigate(destination) if self.connection.session.is_some() => {
                if matches!(destination, Navigate::New) && !self.writes_allowed() {
                    return Task::none();
                }
                self.tab = Tab::Vault;
                return self.navigate(destination);
            }
            Message::UndoDelete if self.writes_allowed() && self.editor.is_none() => {
                if let Some((id, session)) = self.ui.undo_trash.take()
                    && self.connection.session.as_ref() == Some(&session)
                {
                    return self.request(
                        Job::Workflow(workflows::Action::RestoreTrash(id)),
                        ServerCommand::RestoreTrash(id),
                        None,
                    );
                }
            }
            Message::CopyUsername
                if self.writes_allowed()
                    && self.connection.session.is_some()
                    && self.editor.is_none() =>
            {
                return self.reload_then(Then::FetchUsername);
            }
            Message::OpenWebsite(index)
                if self.connection.session.is_some() && self.editor.is_none() =>
            {
                if let Some(url) = self
                    .item
                    .as_ref()
                    .and_then(|item| item.urls.get(index))
                    .cloned()
                {
                    return self.launch(Job::OpenWebsite, move || {
                        website::open(&url).map_err(Failure::from)?;
                        Ok(Reply::WebsiteOpened)
                    });
                }
            }
            Message::RevealField(target) => match self.custom_field_command(target, false) {
                Ok((command, revision)) => {
                    self.hide_secrets();
                    return self.request(Job::Field(target), command, Some(revision));
                }
                Err(error) => self.report_error(error),
            },
            Message::HideField(target) => {
                if let Some(field) = self
                    .item
                    .as_mut()
                    .filter(|item| item.id == target.id && item.revision == target.revision)
                    .and_then(|item| item.fields.get_mut(target.index))
                    && field.secret
                {
                    field.value = None;
                }
                if self.item.as_ref().is_some_and(|item| {
                    item.password.is_none()
                        && item
                            .fields
                            .iter()
                            .all(|field| !field.secret || field.value.is_none())
                }) {
                    self.reveal_until = None;
                }
            }
            Message::CopyField(target) if self.writes_allowed() => {
                return self.reload_then(Then::CopyField(target));
            }
            Message::Reveal => {
                if self.reveal_until.is_some() {
                    self.hide_secrets();
                } else if let Some(item) = &self.item {
                    return self.request(
                        Job::Reveal,
                        ServerCommand::ManagementItem {
                            id: item.id,
                            reveal: true,
                        },
                        Some(item.revision),
                    );
                }
            }
            Message::Copy if self.writes_allowed() => {
                return self.reload_then(Then::CopyItem);
            }
            Message::Delete => {
                self.delete_confirm = true;
                return Task::batch([
                    iced::widget::operation::snap_to(
                        "account-details",
                        iced::widget::operation::RelativeOffset::START,
                    ),
                    iced::widget::operation::focus("cancel-delete"),
                ]);
            }
            Message::CancelDelete => self.delete_confirm = false,
            Message::ConfirmDelete if self.writes_allowed() => {
                if let Some(item) = &self.item {
                    return self.request(
                        Job::Delete,
                        ServerCommand::Delete(Target::Id(item.id)),
                        Some(item.revision),
                    );
                }
            }
            Message::ReviewConflict if self.editor.conflicted() => {
                if let Some(id) = self.editor.as_ref().and_then(|draft| draft.id) {
                    return self.request(
                        Job::ConflictReview,
                        ServerCommand::ManagementItem { id, reveal: false },
                        None,
                    );
                }
            }
            Message::ReapplyConflict if self.editor.conflicted() => {
                if let Some(original) = &self.item
                    && let Some(latest) = self.editor.reapply(original)
                {
                    self.item = Some(latest);
                    self.notice = "Your edits are reapplied to the reviewed version. Review the \
                                   draft, then Save item."
                        .into();
                    self.ui.notice_error = false;
                }
            }
            _ => {}
        }
        Task::none()
    }

    /// Applies a server reply to an item request.
    pub(super) fn complete_item(
        &mut self,
        job: Job,
        payload: ResponsePayload,
        incremental: bool,
        changed_id: Option<usize>,
    ) -> Task<Message> {
        match (job, payload) {
            (Job::UsernameValue, ResponsePayload::Item(item)) => {
                if self.item.as_ref().is_some_and(|current| {
                    current.id == item.id && current.revision == item.revision
                }) && let Some(username) = item.username.filter(|value| !value.is_empty())
                {
                    let timeout = self.conf.clipboard.timeout;
                    let username = SecretString::from(username);
                    return self.launch(Job::UsernameCopied, move || {
                        password_manager::clipboard::copy_with_timeout(username.expose(), timeout)
                            .map_err(Failure::from)?;
                        Ok(Reply::Copied)
                    });
                }
            }
            (Job::ConflictReview, ResponsePayload::Item(mut item)) => {
                if self.editor.as_ref().and_then(|draft| draft.id) == Some(item.id) {
                    item.password = None;
                    for field in &mut item.fields {
                        if field.secret {
                            field.value = None;
                        }
                    }
                    self.editor.review(item);
                }
            }
            (Job::List, ResponsePayload::ItemPage(page)) => self.replace_items(page.items),
            (Job::SavedList, ResponsePayload::ItemPage(page)) => {
                let selected = self.ui.saved_item.take().and_then(|saved| {
                    let mut matches = page.items.iter().filter(|item| {
                        !saved.previous_ids.contains(&item.id)
                            && item.name == saved.name
                            && item.kind == saved.kind
                    });
                    let id = matches.next()?.id;
                    matches.next().is_none().then_some(id)
                });
                self.replace_items(page.items);
                if let Some(id) = selected {
                    let item = self.items.iter().find(|item| item.id == id).unwrap();
                    return self.open_item(id, ItemIntent::View, Some(item.revision));
                }
                self.notice = "Item saved. Select it from your items to continue.".into();
            }
            (Job::RefreshItem(id, intent), ResponsePayload::ItemPage(page)) => {
                self.replace_items(page.items);
                if let Some(item) = self.items.iter().find(|item| item.id == id) {
                    return self.open_item(id, intent, Some(item.revision));
                }
                self.workspace.hide_secrets();
                self.notice = "This item is no longer available. Refresh the vault.".into();
            }
            (Job::OpenItem(id, ItemIntent::Edit), ResponsePayload::Item(item)) if item.id == id => {
                self.editor = Editor::new(Draft::from_item(&item));
                self.item = Some(item);
                return iced::widget::operation::snap_to_end("credential-editor");
            }
            (Job::Item | Job::OpenItem(_, ItemIntent::View), ResponsePayload::Item(item)) => {
                if let Job::OpenItem(id, ItemIntent::View) = job
                    && item.id != id
                {
                    self.workspace.hide_secrets();
                    self.notice =
                        "The server returned a different account. Refresh the vault.".into();
                    return Task::none();
                }
                self.workspace.selected = Some(workflows::Choice {
                    id: item.id,
                    label: format!("{} · {}", item.id, item.name),
                });
                self.item = Some(item);
                return self.fetch_selected_duo();
            }
            (Job::Field(target), ResponsePayload::Secret(value)) => {
                if let Some(field) = self
                    .item
                    .as_mut()
                    .filter(|item| item.id == target.id && item.revision == target.revision)
                    .and_then(|item| item.fields.get_mut(target.index))
                    && field.secret
                {
                    field.value = Some(value);
                    self.reveal_until = Some(Instant::now() + Duration::from_secs(15));
                    self.notice.clear();
                }
            }
            (Job::FieldCopy, ResponsePayload::Message(message)) => self.notice = message,
            (Job::Reveal, ResponsePayload::Item(item)) => {
                self.item = Some(item);
                self.reveal_until = Some(Instant::now() + Duration::from_secs(15));
            }
            (Job::SaveEditor, _) => {
                if let Some(id) = self.editor.as_ref().and_then(|draft| draft.id) {
                    self.notice = "Item saved. You can configure its authenticators below.".into();
                    return self.refresh_item(id, ItemIntent::Edit, incremental);
                }
            }
            (Job::Save, _) => {
                self.ui.editor_show_secret = false;
                let id = self.editor.as_ref().and_then(|draft| draft.id);
                self.ui.saved_item = self.editor.as_ref().filter(|_| id.is_none()).map(|draft| {
                    presentation::SavedItem {
                        name: draft.name.clone(),
                        kind: draft.kind,
                        previous_ids: self.items.iter().map(|item| item.id).collect(),
                    }
                });
                self.workspace.prepared = None;
                self.workspace.clear_inputs();
                self.editor = Editor::Closed;
                self.item = None;
                self.delete_confirm = false;
                self.notice = "Item saved.".into();
                if incremental {
                    self.ui.saved_item = None;
                }
                if let Some(id) = id.or(incremental.then_some(changed_id).flatten()) {
                    return self.refresh_item(id, ItemIntent::View, incremental);
                }
                return self.load_items_for(Job::SavedList);
            }
            (Job::Delete, _) => {
                if let (Some(item), Some(session)) = (&self.item, &self.connection.session) {
                    self.ui.undo_trash = Some((item.id, session.clone()));
                }
                self.workspace.prepared = None;
                self.workspace.clear_inputs();
                self.editor = Editor::Closed;
                self.item = None;
                self.delete_confirm = false;
                self.notice = "Item moved to encrypted trash. You can restore it from Tools → \
                               Deleted items."
                    .into();
                return if incremental {
                    Task::none()
                } else {
                    self.load_items()
                };
            }
            (Job::Copy, _) => self.notice = "Secret copied with timed clipboard cleanup.".into(),
            _ => {
                self.notice =
                    "The server returned an unexpected response. Refresh the vault.".into()
            }
        }
        Task::none()
    }

    pub(super) fn load_items(&mut self) -> Task<Message> {
        self.load_items_for(Job::List)
    }

    pub(super) fn load_items_for(&mut self, job: Job) -> Task<Message> {
        self.request(
            job,
            ServerCommand::List(SearchFilter {
                list: ListOptions {
                    sort: SortField::Name,
                    ..Default::default()
                },
                ..Default::default()
            }),
            None,
        )
    }

    pub(super) fn open_item(
        &mut self,
        id: usize,
        intent: ItemIntent,
        revision: Option<u64>,
    ) -> Task<Message> {
        self.request(
            Job::OpenItem(id, intent),
            ServerCommand::ManagementItem { id, reveal: false },
            revision,
        )
    }

    pub(super) fn refresh_item(
        &mut self,
        id: usize,
        intent: ItemIntent,
        incremental: bool,
    ) -> Task<Message> {
        if intent == ItemIntent::Edit {
            self.hide_secrets();
            self.editor = Editor::Closed;
            self.workspace.prepared = None;
            self.workspace.clear_inputs();
        }
        self.item = None;
        if incremental {
            self.open_item(id, intent, None)
        } else {
            self.load_items_for(Job::RefreshItem(id, intent))
        }
    }

    pub(super) fn navigate(&mut self, destination: Navigate) -> Task<Message> {
        if self.editor.as_ref().is_some_and(|draft| draft.dirty) {
            self.editor.defer(destination);
            return iced::widget::operation::focus("keep-editing");
        }
        self.hide_secrets();
        self.cancel_passive_read();
        self.notice.clear();
        self.ui.undo_trash = None;
        self.delete_confirm = false;
        self.workspace.prepared = None;
        self.workspace.clear_inputs();
        self.editor = Editor::Closed;

        self.item = None;
        match destination {
            Navigate::Select(id) => {
                let revision = self
                    .items
                    .iter()
                    .find(|item| item.id == id)
                    .map(|item| item.revision);
                self.request(
                    Job::Item,
                    ServerCommand::ManagementItem { id, reveal: false },
                    revision,
                )
            }
            Navigate::New => {
                self.ui.editor_advanced = false;
                self.ui.editor_authenticators = false;
                self.editor = Editor::new(Draft::default());
                iced::widget::operation::focus("item-name")
            }
            Navigate::Close => Task::none(),
            Navigate::Refresh => self.load_items(),
            Navigate::Connect(port) => {
                self.reset_connection(port);
                self.notice = format!("Connecting to port {port}…");
                let client = self.connection.client.clone();
                self.launch(Job::Attach, move || backend::attach(&client))
            }
        }
    }
}
