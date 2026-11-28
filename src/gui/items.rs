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
            Message::FilterTag(tag) => {
                self.ui.tag = tag;
                self.ui.item_page = 0;
            }
            Message::FilterFavorites(value) => {
                self.ui.favorites_only = value;
                self.ui.item_page = 0;
            }
            Message::ToggleSelecting => {
                self.ui.selecting = !self.ui.selecting;
                self.ui.selected.clear();
                self.ui.bulk_confirm = false;
            }
            Message::SelectItem(id) if self.ui.selecting => {
                if !self.ui.selected.remove(&id) {
                    self.ui.selected.insert(id);
                }
                self.ui.bulk_confirm = false;
            }
            Message::SelectAllShown if self.ui.selecting => {
                // The same rows the list shows, including its reverse (Z–A) order.
                let shown: Vec<usize> = {
                    let matching = self.matching_items();
                    let count = matching.len();
                    let window = presentation::Page::items(self.ui.item_page, count);
                    window
                        .range
                        .map(|offset| {
                            let index = if self.ui.reverse_items {
                                count - 1 - offset
                            } else {
                                offset
                            };
                            self.items[matching[index]].id
                        })
                        .collect()
                };
                self.ui.selected.extend(shown);
            }
            Message::BulkTag(tag) => self.ui.bulk_tag = tag,
            Message::BulkStart(op) if self.writes_allowed() && !self.ui.selected.is_empty() => {
                if op == BulkOp::Trash && !self.ui.bulk_confirm {
                    self.ui.bulk_confirm = true;
                    return iced::widget::operation::focus("bulk-confirm");
                }
                return self.start_bulk(op);
            }
            Message::BulkConfirm if self.ui.bulk_confirm => {
                self.ui.bulk_confirm = false;
                return self.start_bulk(BulkOp::Trash);
            }
            Message::BulkCancel => self.ui.bulk_confirm = false,
            Message::ClearFilters => {
                self.query.clear();
                self.ui.kind = None;
                self.ui.tag = None;
                self.ui.favorites_only = false;
                self.ui.item_page = 0;
            }
            Message::SelectAdjacent(next)
                if self.tab == Tab::Vault
                    && self.editor.is_none()
                    && self.connection.session.is_some() =>
            {
                if let Some(id) = self.adjacent_item(next) {
                    return self.navigate(Navigate::Select(id));
                }
            }
            Message::AddAttachment if self.writes_allowed() && self.editor.is_none() => {
                if let Some(item) = &self.item {
                    let id = item.id;
                    self.serial += 1;
                    self.request_state = RequestState::Busy;
                    return file_picker::pick_attachment(self.serial, id, None);
                }
            }
            Message::SaveAttachment(index) if self.editor.is_none() => {
                if let Some(item) = &self.item
                    && let Some(attachment) = item.attachments.get(index)
                {
                    let (id, name) = (item.id, attachment.name.clone());
                    self.serial += 1;
                    self.request_state = RequestState::Busy;
                    return file_picker::pick_attachment(self.serial, id, Some((index, name)));
                }
            }
            Message::RemoveAttachment(index) if self.writes_allowed() => {
                self.remove_attachment = self
                    .item
                    .as_ref()
                    .and_then(|item| item.attachments.get(index))
                    .map(|a| a.name.clone());
            }
            Message::CancelRemoveAttachment => self.remove_attachment = None,
            Message::ConfirmRemoveAttachment if self.writes_allowed() => {
                if let (Some(name), Some(item)) = (self.remove_attachment.take(), &self.item) {
                    let (id, revision) = (item.id, item.revision);
                    return self.request(
                        Job::Attachment(id),
                        ServerCommand::Attachment(AttachmentCommand::Remove {
                            target: Target::Id(id),
                            name,
                        }),
                        Some(revision),
                    );
                }
            }
            Message::ToggleFavorite if self.writes_allowed() && self.editor.is_none() => {
                if let Some(item) = &self.item {
                    let mut change = TypedUpdate::from(EntryUpdate {
                        target: Target::Id(item.id),
                        update: EntryChanges::default(),
                        password: None,
                    });
                    change.favorite = Some(!item.favorite);
                    let (id, revision) = (item.id, item.revision);
                    return self.request(
                        Job::Favorite(id),
                        ServerCommand::Update(change),
                        Some(revision),
                    );
                }
            }
            Message::ItemPage(page) => {
                self.ui.item_page = page;
            }
            Message::SortItems(reverse) => {
                self.ui.reverse_items = reverse;
                self.ui.item_page = 0;
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
            (Job::List, ResponsePayload::ItemPage(page)) => {
                self.replace_items(page.items);
                // An item asked for while locked (`pm gui --open`, or the extension's
                // "Open in desktop app") opens once the unlocked list arrives.
                if let Some(id) = self.ui.open_after_unlock.take() {
                    if self.items.iter().any(|item| item.id == id) {
                        return self.navigate(Navigate::Select(id));
                    }
                    self.notice = "That item is not in this vault.".into();
                }
            }
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
                    label: item.name.clone(),
                });
                // Time-based codes show live, with a countdown, as soon as the item opens.
                let live_code = item.otp_mode == Some(password_manager::types::OtpMode::Totp)
                    && !item.has_duo
                    && self.writes_allowed()
                    && self.workspace.otp.watch.is_none();
                self.item = Some(item);
                if live_code {
                    return self.update(Message::Workflow(workflows::Event::Toggle(
                        workflows::Toggle::WatchOtp,
                        true,
                    )));
                }
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
            (Job::Attachment(id), ResponsePayload::Message(message)) => {
                self.notice = message;
                return self.refresh_item(id, ItemIntent::View, incremental);
            }
            (Job::Attachment(id), _) => {
                return self.refresh_item(id, ItemIntent::View, incremental);
            }
            (Job::Favorite(id), _) => {
                return self.refresh_item(id, ItemIntent::View, incremental);
            }
            (Job::Bulk, _) => return self.next_bulk(),
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
                self.remove_attachment = None;
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
                self.remove_attachment = None;
                self.notice = "Item moved to encrypted trash. You can restore it from Tools → \
                               Deleted items."
                    .into();
                return if incremental {
                    Task::none()
                } else {
                    self.load_items()
                };
            }
            (Job::Copy, _) => {
                let label = self.item.as_ref().map_or_else(
                    || "Password".to_owned(),
                    |item| model::secret_label(item.kind),
                );
                self.notice = format!(
                    "{label} copied. The clipboard clears in {} seconds.",
                    self.conf.clipboard.timeout
                );
            }
            _ => {
                self.notice =
                    "The server returned an unexpected response. Refresh the vault.".into()
            }
        }
        Task::none()
    }

    /// The item after (or before) the selection in list order, moving the page
    /// along; the first or last item when nothing is selected.
    pub(super) fn adjacent_item(&mut self, next: bool) -> Option<usize> {
        let (position, id) = {
            let matching = self.matching_items();
            let len = matching.len();
            // List position `p` shows matching[p], or matching[len - 1 - p] reversed.
            let flip = |p: usize| {
                if self.ui.reverse_items {
                    len - 1 - p
                } else {
                    p
                }
            };
            let current = self.item.as_ref().and_then(|item| {
                matching
                    .iter()
                    .position(|&index| self.items[index].id == item.id)
                    .map(flip)
            });
            let position = match (current, next) {
                (Some(position), true) => (position + 1).min(len.checked_sub(1)?),
                (Some(position), false) => position.saturating_sub(1),
                (None, true) => 0,
                (None, false) => len.checked_sub(1)?,
            };
            if current == Some(position) {
                return None;
            }
            let id = (position < len).then(|| self.items[matching[flip(position)]].id);
            (position, id)
        };
        self.ui.item_page = position / presentation::ITEM_PAGE_SIZE;
        id
    }

    /// Queue the selected items for one bulk change, in list order.
    fn start_bulk(&mut self, op: BulkOp) -> Task<Message> {
        let queue: std::collections::VecDeque<(usize, u64)> = self
            .items
            .iter()
            .filter(|item| self.ui.selected.contains(&item.id))
            .map(|item| (item.id, item.revision))
            .collect();
        let op = match op {
            BulkOp::Tag(_) => {
                let tag = self.ui.bulk_tag.trim().to_owned();
                if tag.is_empty() {
                    self.report_error("Type a tag to add, then choose Add tag.");
                    return Task::none();
                }
                BulkOp::Tag(tag)
            }
            op => op,
        };
        self.ui.bulk = Some(Bulk {
            op,
            total: queue.len(),
            queue,
        });
        self.next_bulk()
    }

    /// Send the next bulk change, or report the finished batch.
    fn next_bulk(&mut self) -> Task<Message> {
        let Some(bulk) = self.ui.bulk.as_mut() else {
            return Task::none();
        };
        let Some((id, revision)) = bulk.queue.pop_front() else {
            let bulk = self.ui.bulk.take().expect("checked above");
            let items = if bulk.total == 1 { "item" } else { "items" };
            self.notice = match bulk.op {
                BulkOp::Favorite(true) => format!("Added {} {items} to favorites.", bulk.total),
                BulkOp::Favorite(false) => {
                    format!("Removed {} {items} from favorites.", bulk.total)
                }
                BulkOp::Tag(tag) => format!("Tagged {} {items} “{tag}”.", bulk.total),
                BulkOp::Trash => format!(
                    "Moved {} {items} to encrypted trash. Restore them from Tools → Deleted items.",
                    bulk.total
                ),
            };
            self.ui.selected.clear();
            self.ui.selecting = false;
            self.ui.bulk_tag.clear();
            return self.load_items();
        };
        let command = match &bulk.op {
            BulkOp::Trash => ServerCommand::Delete(Target::Id(id)),
            op => {
                let mut change = TypedUpdate::from(EntryUpdate {
                    target: Target::Id(id),
                    update: EntryChanges::default(),
                    password: None,
                });
                match op {
                    BulkOp::Favorite(value) => change.favorite = Some(*value),
                    BulkOp::Tag(tag) => change.add_tags = vec![tag.clone()],
                    BulkOp::Trash => unreachable!("handled above"),
                }
                ServerCommand::Update(change)
            }
        };
        self.request(Job::Bulk, command, Some(revision))
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

    /// Attach the chosen file, or save an attachment to the chosen path. The
    /// item must still be the one open when the chooser was shown.
    pub(super) fn attachment_picked(
        &mut self,
        id: usize,
        save: Option<usize>,
        path: String,
    ) -> Task<Message> {
        let Some(item) = self.item.as_ref().filter(|item| item.id == id) else {
            return Task::none();
        };
        let revision = item.revision;
        let command = match save {
            None => AttachmentCommand::Add {
                target: Target::Id(id),
                path,
                name: None,
            },
            Some(index) => match item.attachments.get(index) {
                // The system dialog already confirmed any replacement.
                Some(attachment) => AttachmentCommand::Save {
                    target: Target::Id(id),
                    name: attachment.name.clone(),
                    path,
                    force: true,
                },
                None => return Task::none(),
            },
        };
        self.request(
            Job::Attachment(id),
            ServerCommand::Attachment(command),
            Some(revision),
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
        self.remove_attachment = None;
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
