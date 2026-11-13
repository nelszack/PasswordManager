use serde::{Deserialize, Serialize};
/// Local application commands; never accepted from the browser native host.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Status,
    Conflicts,
    Resolve(Resolution),
    Check,
    Now,
    Enable,
    Disable,
    List,
    Pull(String),
    PullCopy(String),
}

/// Review contains labels and redacted comparisons, never credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictReview {
    pub token: String,
    pub items: Vec<ConflictItem>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictItem {
    pub id: u64,
    pub local: String,
    pub remote: String,
    pub fields: Vec<ConflictField>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictField {
    pub field: String,
    pub local: String,
    pub remote: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Local,
    Remote,
}
impl std::fmt::Display for Side {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Local => "Local",
            Self::Remote => "Cloud",
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Choice {
    pub id: u64,
    pub field: String,
    pub side: Side,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resolution {
    pub token: String,
    pub choices: Vec<Choice>,
}
