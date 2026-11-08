//! One operation policy feeds the native host and generated browser contract.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeAction {
    #[default]
    Status,
    Lock,
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
    pub const ALL: [Self; 13] = [
        Self::Status,
        Self::Lock,
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
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Lock => "lock",
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
        );
        let lane = match self {
            Self::Status | Self::Lock | Self::OperationStatus => "control",
            Self::DuoRequests | Self::DuoRespond | Self::GetDuoItems => "duo",
            _ => "work",
        };
        let allowed_senders: &[&str] = match self {
            Self::Lock => &["popup", "background"],
            Self::OperationStatus => &["popup", "prompt", "background"],
            _ => &["background"],
        };
        let (required_fields, optional_fields, result_shape): (&[&str], &[&str], &str) = match self
        {
            Self::Status => (&[], &[], "status"),
            Self::Lock => (&[], &[], "message"),
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
        };
        NativePolicy {
            mutates,
            lane,
            allowed_senders,
            required_fields,
            optional_fields,
            result_shape,
            timeout_ms: if matches!(self, Self::DuoRequests | Self::DuoRespond) {
                65_000
            } else {
                15_000
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
    include_str!("native_contract.template.js")
        .replace("__PROTOCOL_VERSION__", &super::PROTOCOL_VERSION.to_string())
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
            include_str!("../../extension/command_contract.d.ts")
        );
    }
    #[test]
    fn checked_in_browser_contract_matches_rust_policy() {
        assert_eq!(
            super::browser_contract(),
            include_str!("../../extension/command_contract.js"),
            "Regenerate extension/command_contract.js using generate-command-contract"
        );
    }
}
