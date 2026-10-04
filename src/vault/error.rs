use std::fmt;

/// Domain failures carry a stable category independently of their display text.
#[derive(Debug, PartialEq, Eq)]
pub enum VaultError {
    Locked,
    NotFound(String),
    InvalidInput(String),
    Conflict(String),
    Persistence(String),
    /// The replacement is visible, but directory sync failed. Do not roll back.
    Durability(String),
    Validation(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked => f.write_str("vault is locked"),
            Self::NotFound(message)
            | Self::InvalidInput(message)
            | Self::Conflict(message)
            | Self::Persistence(message)
            | Self::Durability(message)
            | Self::Validation(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for VaultError {}
impl From<String> for VaultError {
    fn from(message: String) -> Self {
        Self::Validation(message)
    }
}
impl From<&str> for VaultError {
    fn from(message: &str) -> Self {
        Self::Validation(message.into())
    }
}

impl VaultError {
    pub fn committed(&self) -> bool {
        matches!(self, Self::Durability(_))
    }

    pub(super) fn context(self, context: impl fmt::Display) -> Self {
        let message = format!("{context}: {self}");
        match self {
            Self::Locked => Self::Locked,
            Self::NotFound(_) => Self::NotFound(message),
            Self::InvalidInput(_) => Self::InvalidInput(message),
            Self::Conflict(_) => Self::Conflict(message),
            Self::Persistence(_) => Self::Persistence(message),
            Self::Durability(_) => Self::Durability(message),
            Self::Validation(_) => Self::Validation(message),
        }
    }
}
