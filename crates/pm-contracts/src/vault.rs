use crate::{
    secret::SecretString,
    types::{CustomField, ItemKind},
};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemSummary {
    pub id: usize,
    pub revision: u64,
    pub name: String,
    pub username: Option<String>,
    pub kind: ItemKind,
    pub urls: Vec<String>,
    pub has_totp: bool,
    pub has_duo: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemPage {
    pub items: Vec<ItemSummary>,
    pub total: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryPage {
    pub history: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrashSummary {
    pub id: usize,
    pub name: String,
    pub kind: ItemKind,
    pub username: Option<String>,
    pub deleted: String,
    pub has_totp: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrashPage {
    pub trash: Vec<TrashSummary>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemField {
    pub name: String,
    pub secret: bool,
    pub value: Option<SecretString>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemDetail {
    pub id: usize,
    pub revision: u64,
    pub name: String,
    pub username: Option<String>,
    pub kind: ItemKind,
    pub urls: Vec<String>,
    pub notes: Option<SecretString>,
    pub password: Option<SecretString>,
    pub has_secret: bool,
    pub fields: Vec<ItemField>,
    pub has_totp: bool,
    pub has_duo: bool,
    pub created: String,
    pub modified: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserLogin {
    pub id: usize,
    pub revision: u64,
    pub name: String,
    pub username: Option<String>,
    pub password: SecretString,
    pub has_totp: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutofillItem {
    pub id: usize,
    pub revision: u64,
    pub name: String,
    pub kind: ItemKind,
    pub username: Option<String>,
    pub primary_secret: SecretString,
    pub custom_fields: Vec<CustomField>,
}
/// Public audit findings contain labels and counts, never password hashes or secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLabel {
    pub id: usize,
    pub name: String,
    pub username: Option<String>,
    pub password_changed: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub total: usize,
    pub healthy: usize,
    pub score: usize,
    pub weak: Vec<AuditLabel>,
    pub reused: Vec<Vec<AuditLabel>>,
    pub duplicates: Vec<Vec<AuditLabel>>,
    pub stale: Vec<AuditLabel>,
    pub missing_totp: Vec<AuditLabel>,
    pub breached: Vec<(AuditLabel, u64)>,
    pub breach_error: Option<String>,
    pub unchecked: Vec<AuditLabel>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub total: usize,
    pub added: usize,
    pub replaced: usize,
    pub skipped: usize,
    pub renamed: usize,
    pub preview: bool,
    pub unsupported: usize,
    pub loss_count: usize,
    /// Bounded, secret-free descriptions indexed by source row/item.
    pub losses: Vec<String>,
}
