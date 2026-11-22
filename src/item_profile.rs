//! Per-type editor guidance shared by the desktop editor and the mobile app:
//! display title, labels for the owner and primary secret, and the custom
//! fields suggested for a new item. Card and identity autofill read these
//! field names, so every client should offer the same ones.
use crate::types::ItemKind;
use serde_json::{Value, json};

pub const KINDS: [ItemKind; 8] = [
    ItemKind::Login,
    ItemKind::SecureNote,
    ItemKind::PaymentCard,
    ItemKind::Identity,
    ItemKind::Wifi,
    ItemKind::SoftwareLicense,
    ItemKind::SshKey,
    ItemKind::ApiSecret,
];

pub struct Profile {
    pub title: &'static str,
    pub owner: &'static str,
    pub secret: &'static str,
    pub name_hint: &'static str,
    pub guidance: &'static str,
    pub suggested: &'static [(&'static str, bool)],
}
pub fn profile(kind: ItemKind) -> Profile {
    match kind {
        ItemKind::Login => Profile {
            title: "Login",
            owner: "Username or email",
            secret: "Password",
            name_hint: "e.g. Personal email",
            guidance: "Save sign-in details and the websites where they work.",
            suggested: &[],
        },
        ItemKind::SecureNote => Profile {
            title: "Secure note",
            owner: "Owner (optional)",
            secret: "Private content",
            name_hint: "e.g. Recovery instructions",
            guidance: "Store private content. Choose the multiline editor for longer text.",
            suggested: &[],
        },
        ItemKind::PaymentCard => Profile {
            title: "Payment card",
            owner: "Cardholder",
            secret: "Card number",
            name_hint: "e.g. Everyday card",
            guidance: "Keep your card number, cardholder, and optional expiry and security code \
                       together.",
            suggested: &[
                ("Expiry", false),
                ("Security code", true),
                ("Billing address", false),
            ],
        },
        ItemKind::Identity => Profile {
            title: "Identity",
            owner: "Full name",
            secret: "Identity number (optional)",
            name_hint: "e.g. Personal identity",
            guidance: "Store identity and contact details. Add the fields you need below.",
            suggested: &[
                ("Email", false),
                ("Phone", false),
                ("Address", false),
                ("Date of birth", true),
            ],
        },
        ItemKind::Wifi => Profile {
            title: "Wi-Fi",
            owner: "Network name (SSID)",
            secret: "Wi-Fi password",
            name_hint: "e.g. Home Wi-Fi",
            guidance: "Save the network name and the password used to join it.",
            suggested: &[("Security", false), ("Router address", false)],
        },
        ItemKind::SoftwareLicense => Profile {
            title: "Software license",
            owner: "Licensed to",
            secret: "License key",
            name_hint: "e.g. Photo editor license",
            guidance: "Keep the license key with the product, version, and renewal details.",
            suggested: &[("Software", false), ("Version", false), ("Expires", false)],
        },
        ItemKind::SshKey => Profile {
            title: "SSH key",
            owner: "User or host",
            secret: "Private key",
            name_hint: "e.g. Production SSH key",
            guidance: "Store the private key with its connection details. Use the multiline \
                       editor to paste a key. Set SSH agent to on or confirm to use it with ssh.",
            suggested: &[
                ("Hostname", false),
                ("Port", false),
                ("Public key", false),
                ("Passphrase", true),
                ("SSH agent", false),
            ],
        },
        ItemKind::ApiSecret => Profile {
            title: "API secret",
            owner: "Account or service",
            secret: "API key or token",
            name_hint: "e.g. Development API token",
            guidance: "Store the token issued by your service, plus its environment and expiry.",
            suggested: &[
                ("Endpoint", false),
                ("Environment", false),
                ("Expires", false),
            ],
        },
    }
}

/// Every profile as JSON for the mobile app, in [`KINDS`] order.
pub fn profiles_json() -> Value {
    Value::Array(
        KINDS
            .iter()
            .map(|&kind| {
                let profile = profile(kind);
                json!({
                    "kind": kind,
                    "title": profile.title,
                    "owner": profile.owner,
                    "secret": profile.secret,
                    "name_hint": profile.name_hint,
                    "guidance": profile.guidance,
                    "suggested": profile
                        .suggested
                        .iter()
                        .map(|(name, secret)| json!({"name": name, "secret": secret}))
                        .collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_profiles_cover_every_kind_with_serialized_names() {
        let profiles = profiles_json();
        let profiles = profiles.as_array().unwrap();
        assert_eq!(profiles.len(), KINDS.len());
        assert_eq!(profiles[2]["kind"], "payment-card");
        assert_eq!(profiles[2]["secret"], "Card number");
        let ssh = profiles.iter().find(|p| p["kind"] == "ssh-key").unwrap();
        assert!(
            ssh["suggested"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field["name"] == "SSH agent" && field["secret"] == false)
        );
    }
}
