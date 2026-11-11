//! State owned by one desktop workflow, independent of presentation flags.
use super::{Draft, ItemDetail, Navigate, SecretString};
use password_manager::protocol::OperationReceipt;
use std::time::{Duration, Instant};

#[derive(Default)]
pub(super) enum Recovery {
    #[default]
    Clear,
    AwaitingOutcome(String),
    AwaitingAcknowledgement(OperationReceipt),
}
impl Recovery {
    pub fn id(&self) -> Option<&String> {
        match self {
            Self::Clear => None,
            Self::AwaitingOutcome(id) => Some(id),
            Self::AwaitingAcknowledgement(receipt) => Some(&receipt.operation_id),
        }
    }
    pub fn reviewed(&self) -> bool {
        matches!(self, Self::AwaitingAcknowledgement(_))
    }
}

#[derive(Default)]
enum Conflict {
    #[default]
    None,
    NeedsReview,
    Reviewed(Box<ItemDetail>),
}
#[derive(Default)]
pub(super) enum Editor {
    #[default]
    Closed,
    Editing(Box<Editing>),
}
pub(super) struct Editing {
    draft: Draft,
    conflict: Conflict,
    deferred: Option<Navigate>,
}
impl Editor {
    pub fn new(draft: Draft) -> Self {
        Self::Editing(Box::new(Editing {
            draft,
            conflict: Conflict::None,
            deferred: None,
        }))
    }
    pub fn as_ref(&self) -> Option<&Draft> {
        match self {
            Self::Closed => None,
            Self::Editing(editing) => Some(&editing.draft),
        }
    }
    pub fn as_mut(&mut self) -> Option<&mut Draft> {
        match self {
            Self::Closed => None,
            Self::Editing(editing) => Some(&mut editing.draft),
        }
    }
    pub fn is_some(&self) -> bool {
        self.as_ref().is_some()
    }
    pub fn is_none(&self) -> bool {
        self.as_ref().is_none()
    }
    pub fn get_or_insert_with(&mut self, create: impl FnOnce() -> Draft) -> &mut Draft {
        if self.is_none() {
            *self = Self::new(create());
        }
        self.as_mut().expect("editor is open")
    }
    pub fn defer(&mut self, destination: Navigate) {
        if let Self::Editing(editing) = self {
            editing.deferred = Some(destination);
        }
    }
    pub fn deferred(&self) -> Option<&Navigate> {
        match self {
            Self::Closed => None,
            Self::Editing(editing) => editing.deferred.as_ref(),
        }
    }
    pub fn take_deferred(&mut self) -> Option<Navigate> {
        match self {
            Self::Closed => None,
            Self::Editing(editing) => editing.deferred.take(),
        }
    }
    pub fn conflicted(&self) -> bool {
        matches!(self, Self::Editing(editing) if !matches!(editing.conflict, Conflict::None))
    }
    pub fn require_review(&mut self) {
        if let Self::Editing(editing) = self {
            editing.conflict = Conflict::NeedsReview;
        }
    }
    pub fn review(&mut self, latest: ItemDetail) {
        if let Self::Editing(editing) = self {
            editing.conflict = Conflict::Reviewed(Box::new(latest));
        }
    }
    pub fn latest(&self) -> Option<&ItemDetail> {
        match self {
            Self::Editing(editing) => match &editing.conflict {
                Conflict::Reviewed(latest) => Some(latest),
                _ => None,
            },
            Self::Closed => None,
        }
    }
    pub fn reapply(&mut self, original: &ItemDetail) -> Option<ItemDetail> {
        let latest = self.latest()?;
        let draft = self.as_ref()?;
        if draft.id != Some(latest.id) || original.id != latest.id {
            return None;
        }
        let draft = draft.rebase(original, latest);
        let Self::Editing(editing) = self else {
            return None;
        };
        let Conflict::Reviewed(latest) = std::mem::take(&mut editing.conflict) else {
            return None;
        };
        editing.draft = draft;
        Some(*latest)
    }
}

#[derive(Default)]
pub(super) enum GeneratedSecret {
    #[default]
    Empty,
    Ready {
        value: SecretString,
        until: Instant,
        visible: bool,
    },
}
impl GeneratedSecret {
    pub fn new(value: SecretString) -> Self {
        Self::Ready {
            value,
            until: Instant::now() + Duration::from_secs(60),
            visible: false,
        }
    }
    pub fn expose(&self) -> &str {
        match self {
            Self::Empty => "",
            Self::Ready { value, .. } => value.expose(),
        }
    }
    pub fn secret(&self) -> SecretString {
        self.expose().into()
    }
    pub fn is_empty(&self) -> bool {
        self.expose().is_empty()
    }
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.expose().len()
    }
    pub fn deadline(&self) -> Option<Instant> {
        match self {
            Self::Empty => None,
            Self::Ready { until, .. } => Some(*until),
        }
    }
    pub fn visible(&self) -> bool {
        matches!(self, Self::Ready { visible: true, .. })
    }
    pub fn set_visible(&mut self, show: bool) {
        if let Self::Ready { visible, .. } = self {
            *visible = show;
        }
    }
    pub fn clear(&mut self) {
        *self = Self::Empty;
    }
    pub fn expire(&mut self, now: Instant) -> bool {
        if self.deadline().is_some_and(|until| now >= until) {
            self.clear();
            true
        } else {
            false
        }
    }
    #[cfg(test)]
    pub fn set_deadline(&mut self, deadline: Instant) {
        if let Self::Ready { until, .. } = self {
            *until = deadline;
        }
    }
}
impl From<&str> for GeneratedSecret {
    fn from(value: &str) -> Self {
        Self::new(value.into())
    }
}
impl From<String> for GeneratedSecret {
    fn from(value: String) -> Self {
        Self::new(value.into())
    }
}
