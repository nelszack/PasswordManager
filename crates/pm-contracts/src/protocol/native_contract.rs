//! One operation policy feeds the native host and generated browser contract.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeAction {
    #[default]
    Status,
    Lock,
    OpenDesktop,
    DuoRequests,
    DuoRespond,
    GetAutofillItems,
    GetLoginItems,
    GetDuoItems,
    GetLoginItem,
    GetAutofillItem,
    GetTotp,
    SaveCredentials,
    UpdateCredentials,
    OperationStatus,
    GetPasskeys,
    CreatePasskey,
    GetPasskeyAssertion,
    VerifyPasskeyUser,
    CopyLoginValue,
    CopyGenerated,
    SearchItems,
    CopyItem,
    CheckSavedLogin,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePolicy {
    pub mutates: bool,
    pub lane: &'static str,
    pub timeout_ms: u64,
    pub allowed_senders: &'static [&'static str],
    pub required_fields: &'static [&'static str],
    pub optional_fields: &'static [&'static str],
    pub result_shape: &'static str,
}
impl NativeAction {
    pub const ALL: [Self; 23] = [
        Self::Status,
        Self::Lock,
        Self::OpenDesktop,
        Self::DuoRequests,
        Self::DuoRespond,
        Self::GetAutofillItems,
        Self::GetLoginItems,
        Self::GetDuoItems,
        Self::GetLoginItem,
        Self::GetAutofillItem,
        Self::GetTotp,
        Self::SaveCredentials,
        Self::UpdateCredentials,
        Self::OperationStatus,
        Self::GetPasskeys,
        Self::CreatePasskey,
        Self::GetPasskeyAssertion,
        Self::VerifyPasskeyUser,
        Self::CopyLoginValue,
        Self::CopyGenerated,
        Self::SearchItems,
        Self::CopyItem,
        Self::CheckSavedLogin,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Lock => "lock",
            Self::OpenDesktop => "openDesktop",
            Self::DuoRequests => "duoRequests",
            Self::DuoRespond => "duoRespond",
            Self::GetAutofillItems => "getAutofillItems",
            Self::GetLoginItems => "getLoginItems",
            Self::GetDuoItems => "getDuoItems",
            Self::GetLoginItem => "getLoginItem",
            Self::GetAutofillItem => "getAutofillItem",
            Self::GetTotp => "getTotp",
            Self::SaveCredentials => "saveCredentials",
            Self::UpdateCredentials => "updateCredentials",
            Self::OperationStatus => "operationStatus",
            Self::GetPasskeys => "getPasskeys",
            Self::CreatePasskey => "createPasskey",
            Self::GetPasskeyAssertion => "getPasskeyAssertion",
            Self::VerifyPasskeyUser => "verifyPasskeyUser",
            Self::CopyLoginValue => "copyLoginValue",
            Self::CopyGenerated => "copyGenerated",
            Self::SearchItems => "searchItems",
            Self::CopyItem => "copyItem",
            Self::CheckSavedLogin => "checkSavedLogin",
        }
    }
    pub fn policy(self) -> NativePolicy {
        let mutates = matches!(
            self,
            Self::Lock
                | Self::DuoRespond
                | Self::GetTotp
                | Self::SaveCredentials
                | Self::UpdateCredentials
                | Self::CreatePasskey
        );
        let lane = match self {
            Self::Status | Self::Lock | Self::OpenDesktop | Self::OperationStatus => "control",
            Self::DuoRequests | Self::DuoRespond | Self::GetDuoItems => "duo",
            // Waits for the person in the desktop app; never blocks other lanes.
            Self::VerifyPasskeyUser => "approval",
            _ => "work",
        };
        let allowed_senders: &[&str] = match self {
            Self::Lock | Self::OpenDesktop => &["popup", "background"],
            Self::OperationStatus => &["popup", "prompt", "background"],
            _ => &["background"],
        };
        let (required_fields, optional_fields, result_shape): (&[&str], &[&str], &str) = match self
        {
            Self::Status => (&[], &[], "status"),
            Self::Lock => (&[], &[], "message"),
            // With an item ID, the desktop app opens showing that item.
            Self::OpenDesktop => (&[], &["entryId"], "message"),
            Self::DuoRequests => (&["entryId", "expectedSession"], &[], "duoArray"),
            Self::DuoRespond => (
                &[
                    "entryId",
                    "requestId",
                    "fingerprint",
                    "approve",
                    "expectedSession",
                ],
                &["verificationCode"],
                "message",
            ),
            Self::GetAutofillItems => (&[], &[], "summaryArray"),
            Self::GetLoginItems | Self::GetDuoItems => (&["domain"], &[], "summaryArray"),
            Self::GetLoginItem => (
                &["domain", "entryId", "expectedRevision", "expectedSession"],
                &[],
                "login",
            ),
            Self::GetAutofillItem => (
                &["entryId", "expectedRevision", "expectedSession"],
                &[],
                "autofill",
            ),
            Self::GetTotp => (
                &["domain", "entryId", "expectedRevision", "expectedSession"],
                &[],
                "authenticator",
            ),
            Self::SaveCredentials => (
                &["domain", "password", "name", "expectedSession"],
                &["username"],
                "message",
            ),
            Self::UpdateCredentials => (
                &[
                    "domain",
                    "entryId",
                    "password",
                    "expectedRevision",
                    "expectedSession",
                ],
                &["username"],
                "message",
            ),
            Self::OperationStatus => (&["operationId"], &[], "receipt"),
            Self::GetPasskeys => (&["domain", "passkeyRequest"], &[], "passkeyArray"),
            // `verificationToken` comes from verifyPasskeyUser after the
            // person confirmed in the desktop app.
            Self::CreatePasskey => (
                &["domain", "passkeyRequest", "expectedSession"],
                &["verificationToken"],
                "passkeyCredential",
            ),
            Self::GetPasskeyAssertion => (
                &[
                    "domain",
                    "entryId",
                    "passkeyRequest",
                    "expectedRevision",
                    "expectedSession",
                ],
                &["verificationToken"],
                "passkeyCredential",
            ),
            Self::VerifyPasskeyUser => (&["domain", "expectedSession"], &[], "message"),
            // The desktop service copies with timed clearing; the value never
            // reaches the browser.
            Self::CopyLoginValue => (
                &[
                    "domain",
                    "entryId",
                    "field",
                    "expectedRevision",
                    "expectedSession",
                ],
                &[],
                "message",
            ),
            Self::CopyGenerated => (&["password"], &[], "message"),
            // Metadata only (names, usernames, addresses); the popup searches
            // the whole vault without receiving any secret.
            Self::SearchItems => (&["query"], &[], "itemPage"),
            Self::CopyItem => (
                &["entryId", "field", "expectedRevision", "expectedSession"],
                &[],
                "message",
            ),
            // Whether a captured sign-in is already saved; the service compares
            // and returns matching summaries, never a secret.
            Self::CheckSavedLogin => (&["domain", "password"], &["username"], "summaryArray"),
        };
        NativePolicy {
            mutates,
            lane,
            allowed_senders,
            required_fields,
            optional_fields,
            result_shape,
            timeout_ms: match self {
                Self::DuoRequests | Self::DuoRespond => 65_000,
                // The service waits up to 90 seconds for the person.
                Self::VerifyPasskeyUser => 100_000,
                _ => 15_000,
            },
        }
    }
}
impl zeroize::Zeroize for NativeAction {
    fn zeroize(&mut self) {
        *self = Self::Status;
    }
}
impl PartialEq<&str> for NativeAction {
    fn eq(&self, s: &&str) -> bool {
        self.as_str() == *s
    }
}

pub fn browser_contract() -> String {
    let operations: std::collections::BTreeMap<_, _> = NativeAction::ALL
        .into_iter()
        .map(|a| (a.as_str(), a.policy()))
        .collect();
    use crate::types::ItemKind;
    let profiles: std::collections::BTreeMap<String, serde_json::Value> = [
        ItemKind::Login,
        ItemKind::SecureNote,
        ItemKind::PaymentCard,
        ItemKind::Identity,
        ItemKind::Wifi,
        ItemKind::SoftwareLicense,
        ItemKind::SshKey,
        ItemKind::ApiSecret,
    ]
    .into_iter()
    .map(|kind| {
        let profile = crate::item_profile::profile(kind);
        let owner = profile.owner.split(" (").next().unwrap_or(profile.owner);
        (
            kind.to_string(),
            serde_json::json!({
                "title": profile.title,
                "owner": owner,
                "secret": profile.secret_name(),
            }),
        )
    })
    .collect();
    include_str!("native_contract.template.js")
        .replace("__PROTOCOL_VERSION__", &super::PROTOCOL_VERSION.to_string())
        .replace(
            "__ITEM_PROFILES__",
            &serde_json::to_string_pretty(&profiles).expect("profiles serialize"),
        )
        .replace(
            "__OPERATIONS__",
            &serde_json::to_string_pretty(&operations).expect("policies serialize"),
        )
}
/// Declarations and runtime validation are generated from the same action policy.
pub fn browser_declarations() -> String {
    let mut requests = String::new();
    let mut results = String::new();
    for action in NativeAction::ALL {
        let policy = action.policy();
        requests.push_str(&format!("    {}: {{", action.as_str()));
        if policy.mutates {
            requests.push_str(" operationId: string;");
        }
        for field in policy.required_fields {
            requests.push_str(&format!(" {field}: {};", typescript_field(field)));
        }
        for field in policy.optional_fields {
            requests.push_str(&format!(" {field}?: {};", typescript_field(field)));
        }
        requests.push_str(" };\n");
        let result = match policy.result_shape {
            "message" => "string",
            "status" => "ServerStatus",
            "summaryArray" => "ItemSummary[]",
            "login" => "BrowserLogin",
            "autofill" => "AutofillItem",
            "authenticator" => "Authenticator",
            "duoArray" => "DuoRequest[]",
            "receipt" => "OperationReceipt",
            "passkeyArray" => "PasskeyChoice[]",
            "passkeyCredential" => "PasskeyCredentialJSON",
            "itemPage" => "ItemPage",
            _ => unreachable!(),
        };
        results.push_str(&format!(
            "    {}: {}{};\n",
            action.as_str(),
            result,
            if policy.mutates {
                " | OperationReceipt"
            } else {
                ""
            }
        ));
    }
    include_str!("native_contract.template.d.ts")
        .replace("__PROTOCOL_VERSION__", &super::PROTOCOL_VERSION.to_string())
        .replace("__REQUESTS__", &requests)
        .replace("__RESULTS__", &results)
}
fn typescript_field(field: &str) -> &'static str {
    match field {
        "entryId" | "expectedRevision" => "number",
        "approve" => "boolean",
        _ => "string",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn checked_in_browser_types_match_rust_policy() {
        assert_eq!(
            super::browser_declarations(),
            include_str!("../../../../extension/command_contract.d.ts")
        );
    }
    #[test]
    fn checked_in_browser_contract_matches_rust_policy() {
        assert_eq!(
            super::browser_contract(),
            include_str!("../../../../extension/command_contract.js"),
            "Regenerate extension/command_contract.js using generate-command-contract"
        );
    }
}
