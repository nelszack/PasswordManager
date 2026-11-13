use super::*;

impl App {
    pub(super) fn update_editor(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Edit if self.editor.is_none() && self.writes_allowed() => {
                self.ui.undo_trash = None;
                self.notice.clear();
                if let Some(item) = &self.item {
                    self.ui.editor_advanced = item.fields.iter().any(|field| {
                        !model::profile(item.kind)
                            .suggested
                            .iter()
                            .any(|(name, _)| field.name.eq_ignore_ascii_case(name))
                    });
                    self.editor = Editor::new(Draft::from_item(item));
                    self.workspace.prepared = None;
                    self.workspace.clear_inputs();
                    self.hide_secrets();
                    self.ui.editor_authenticators = false;
                    return iced::widget::operation::focus("item-name");
                }
            }
            Message::Name(value) => {
                if let Some(draft) = self.editor.as_mut() {
                    draft.name = value;
                    draft.dirty = true;
                }
            }
            Message::TemplateValue(name, secret, value) => {
                if let Some(draft) = self.editor.as_mut() {
                    if let Some(field) = draft
                        .fields
                        .iter_mut()
                        .find(|field| !field.removed && field.name.eq_ignore_ascii_case(name))
                    {
                        field.value = value;
                        field.value_edited = true;
                        field.changed = true;
                        field.secret |= secret;
                    } else if !value.is_empty() {
                        draft.fields.push(model::FieldDraft {
                            name: name.into(),
                            value,
                            secret,
                            changed: true,
                            value_edited: true,
                            ..Default::default()
                        });
                    }
                    draft.dirty = true;
                }
            }
            Message::AddField => {
                if let Some(draft) = self.editor.as_mut() {
                    draft.fields.push(model::FieldDraft::default());
                    draft.dirty = true;
                    return iced::widget::operation::focus(format!(
                        "custom-field-{}",
                        draft.fields.len() - 1
                    ));
                }
            }
            Message::FieldName(index, value) => {
                if let Some(draft) = self.editor.as_mut()
                    && let Some(field) = draft.fields.get_mut(index)
                {
                    field.name = value;
                    field.changed = true;
                    draft.dirty = true;
                }
            }
            Message::FieldValue(index, value) => {
                if let Some(draft) = self.editor.as_mut()
                    && let Some(field) = draft.fields.get_mut(index)
                {
                    field.value = value;
                    field.changed = true;
                    field.value_edited = true;
                    draft.dirty = true;
                }
            }
            Message::FieldSecret(index, value) => {
                if let Some(draft) = self.editor.as_mut()
                    && let Some(field) = draft.fields.get_mut(index)
                {
                    field.secret = value;
                    field.changed = true;
                    draft.dirty = true;
                }
            }
            Message::RemoveField(index) => {
                if let Some(draft) = self.editor.as_mut()
                    && let Some(field) = draft.fields.get_mut(index)
                {
                    field.removed = true;
                    field.value.zeroize();
                    draft.dirty = true;
                    if model::profile(draft.kind)
                        .suggested
                        .iter()
                        .any(|(name, _)| field.name.eq_ignore_ascii_case(name))
                    {
                        return iced::widget::operation::focus(format!("template-{}", field.name));
                    }
                    return iced::widget::operation::focus("item-name");
                }
            }
            Message::ShowEditorSecret(value) if self.editor.is_some() => {
                self.ui.editor_show_secret = value;
            }
            Message::MultilineSecret(value) => {
                self.ui.editor_show_secret = false;
                if let Some(draft) = self.editor.as_mut() {
                    draft.multiline = value;
                    draft.secret_editor = if value {
                        text_editor::Content::with_text(draft.password.expose())
                    } else {
                        text_editor::Content::new()
                    };
                }
            }
            Message::SecretEdit(action) => {
                if let Some(draft) = self.editor.as_mut()
                    && draft.multiline
                    && (draft.id.is_none() || draft.replace_password)
                {
                    let editing = action.is_edit();
                    draft.secret_editor.perform(action);
                    if editing {
                        draft.password = draft.secret_editor.text().into();
                        draft.dirty = true;
                    }
                }
            }
            Message::Username(value) => {
                if let Some(draft) = self.editor.as_mut() {
                    draft.username = value;
                    draft.dirty = true;
                }
            }
            Message::Kind(value) => {
                if let Some(draft) = self.editor.as_mut() {
                    draft.kind = value;
                    draft.dirty = true;
                    self.ui.editor_advanced = draft.fields.iter().any(|field| {
                        !field.removed
                            && !model::profile(value)
                                .suggested
                                .iter()
                                .any(|(name, _)| field.name.eq_ignore_ascii_case(name))
                    });
                }
            }
            Message::Password(value) => {
                if let Some(draft) = self.editor.as_mut() {
                    draft.password = value;
                    draft.replace_password = true;
                    draft.dirty = true;
                }
            }
            Message::CopyPolicy(policy) => {
                if let Some(draft) = self.editor.as_mut() {
                    draft.copy_policy = policy;
                }
            }
            Message::ReplacePassword(value) => {
                self.ui.editor_show_secret = false;
                if let Some(draft) = self.editor.as_mut() {
                    draft.replace_password = value;
                    if !value {
                        draft.password.zeroize();
                        draft.secret_editor = text_editor::Content::new();
                    }
                    draft.dirty = true;
                }
            }
            Message::Url(index, value) => {
                if let Some(draft) = self.editor.as_mut()
                    && let Some(url) = draft.urls.get_mut(index)
                {
                    *url = value;
                    draft.dirty = true;
                }
            }
            Message::AddUrl => {
                if let Some(draft) = self.editor.as_mut() {
                    draft.urls.push(String::new());
                    draft.dirty = true;
                    return iced::widget::operation::focus(format!(
                        "website-{}",
                        draft.urls.len() - 1
                    ));
                }
            }
            Message::RemoveUrl(index) => {
                if let Some(draft) = self.editor.as_mut()
                    && index < draft.urls.len()
                {
                    draft.urls.remove(index);
                    draft.dirty = true;
                    return iced::widget::operation::focus(if draft.urls.is_empty() {
                        "item-name".into()
                    } else {
                        format!("website-{}", index.min(draft.urls.len() - 1))
                    });
                }
            }
            Message::Notes(action) => {
                if let Some(draft) = self.editor.as_mut() {
                    if action.is_edit() {
                        draft.notes_changed = true;
                        draft.dirty = true;
                    }
                    draft.notes.perform(action);
                }
            }
            _ => {}
        }
        Task::none()
    }
}

impl App {
    pub(super) fn custom_field_command(
        &self,
        target: FieldTarget,
        copy: bool,
    ) -> Result<(ServerCommand, u64), String> {
        let item = self
            .item
            .as_ref()
            .filter(|item| item.id == target.id && item.revision == target.revision)
            .ok_or("The selected account changed. Select the field again.")?;
        let field = item
            .fields
            .get(target.index)
            .ok_or("This field is no longer available. Refresh the account.")?;
        if copy && self.conf.clipboard.timeout == 0 {
            return Err("Copying is disabled because the clipboard timeout is zero.".into());
        }
        Ok((
            ServerCommand::GetField {
                target: Target::Id(item.id),
                name: field.name.clone(),
                copy_timeout: copy.then_some(self.conf.clipboard.timeout),
            },
            item.revision,
        ))
    }

    pub(super) fn fetch_username(&mut self) -> Task<Message> {
        if self.conf.clipboard.timeout == 0 {
            self.report_error(
                "Copying is disabled. Set a clipboard timeout in Settings → Security.",
            );
            return Task::none();
        }
        if let Some(item) = &self.item {
            return self.request(
                Job::UsernameValue,
                ServerCommand::ManagementItem {
                    id: item.id,
                    reveal: false,
                },
                Some(item.revision),
            );
        }
        Task::none()
    }

    pub(super) fn copy_item(&mut self) -> Task<Message> {
        if self.conf.clipboard.timeout == 0 {
            self.notice = "Copying is disabled because the clipboard timeout is zero.".into();
            return Task::none();
        }
        if let Some(item) = &self.item {
            return self.request(
                Job::Copy,
                ServerCommand::ManagementCopy {
                    id: item.id,
                    timeout: self.conf.clipboard.timeout,
                },
                Some(item.revision),
            );
        }
        Task::none()
    }

    pub(super) fn save_item(&mut self, job: Job) -> Task<Message> {
        if self.editor.conflicted() {
            self.report_error("Review and reapply your edits to the latest item before saving.");
            return Task::none();
        }
        if let Some(draft) = self.editor.as_ref() {
            match draft.command() {
                Ok(mut command) => {
                    draft.apply_copy_policy(&mut command, &self.conf);
                    return self.request(job, command, draft.revision);
                }
                Err(error) => self.report_error(error),
            }
        }
        Task::none()
    }
}
