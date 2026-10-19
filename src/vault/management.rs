use super::*;
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
impl Vault {
    pub(super) fn summary(&self, item: &Item) -> ItemSummary {
        ItemSummary {
            id: item.entry.id,
            revision: item.revision,
            name: item.entry.name.clone(),
            username: item.entry.username.clone(),
            kind: item.metadata.kind,
            urls: self.all_urls(&item.entry).map(str::to_owned).collect(),
            has_totp: item.authenticator.is_some(),
            has_duo: item.duo.is_some(),
        }
    }
    pub fn management_list(&self, filter: SearchFilter) -> Result<ItemPage, VaultError> {
        let entries = self.apply_list_options(self.search_entries(&filter), &filter.list);
        let total = entries.len();
        let items = entries
            .into_iter()
            .map(|e| self.summary(self.item(e.id).unwrap()))
            .collect();
        Ok(ItemPage { items, total })
    }
    pub fn management_item(&self, id: usize, reveal: bool) -> Result<ItemDetail, VaultError> {
        let item = self
            .item(id)
            .filter(|i| i.active())
            .ok_or_else(|| VaultError::NotFound("item not found".into()))?;
        let e = &item.entry;
        Ok(ItemDetail {
            id,
            revision: item.revision,
            name: e.name.clone(),
            username: e.username.clone(),
            kind: item.metadata.kind,
            urls: self.all_urls(e).map(str::to_owned).collect(),
            notes: e.notes.clone(),
            password: reveal.then(|| e.password.clone()),
            has_secret: !e.password.is_empty(),
            fields: item
                .metadata
                .custom_fields
                .iter()
                .map(|f| ItemField {
                    name: f.name.clone(),
                    secret: f.secret,
                    value: (!f.secret || reveal).then(|| f.value.clone()),
                })
                .collect(),
            has_totp: item.authenticator.is_some(),
            has_duo: item.duo.is_some(),
            created: e.created.to_string(),
            modified: e.modified.to_string(),
        })
    }
    pub fn target_detail(&self, target: &Target, reveal: bool) -> Result<ItemDetail, VaultError> {
        let id = self
            .entry_id(target)
            .ok_or_else(|| VaultError::NotFound("item not found".into()))?;
        self.management_item(id, reveal)
    }
}
