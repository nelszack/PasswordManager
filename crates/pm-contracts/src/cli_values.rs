use crate::types::{ItemKind, SortField};
use clap::ValueEnum;
// CLI presentation traits live in this adapter, outside domain definitions.
macro_rules! cli_values {
    ($ty:ty, $($variant:path => ($name:literal, $help:literal)),+ $(,)?) => {
        impl ValueEnum for $ty {
            fn value_variants<'a>() -> &'a [Self] { &[$($variant),+] }
            fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
                Some(match self { $($variant => clap::builder::PossibleValue::new($name).help($help)),+ })
            }
        }
    };
}
cli_values!(ItemKind,
    ItemKind::Login => ("login", "Website or application credentials"),
    ItemKind::SecureNote => ("secure-note", "Free-form confidential text"),
    ItemKind::PaymentCard => ("payment-card", "Payment-card details"),
    ItemKind::Identity => ("identity", "Personal identity or contact information"),
    ItemKind::Wifi => ("wifi", "Wireless network credentials"),
    ItemKind::SoftwareLicense => ("software-license", "Software product key and license details"),
    ItemKind::SshKey => ("ssh-key", "SSH private key or connection details"),
    ItemKind::ApiSecret => ("api-secret", "API token, client secret, or service credential"),
);
cli_values!(SortField,
    SortField::Id => ("id", "Stable numeric entry ID"),
    SortField::Name => ("name", "Item name, compared case-insensitively"),
    SortField::Created => ("created", "Creation time"),
    SortField::Modified => ("modified", "Last modification time"),
    SortField::PasswordAge => ("password-age", "Age of the current password"),
);
cli_values!(crate::types::ConflictPolicy,
    crate::types::ConflictPolicy::Skip => ("skip", "Keep the existing item"),
    crate::types::ConflictPolicy::Replace => ("replace", "Replace the existing item"),
    crate::types::ConflictPolicy::KeepBoth => ("keep-both", "Import a separate item with a distinct name"),
);
cli_values!(crate::types::OtpMode,
    crate::types::OtpMode::Hotp => ("hotp", "Counter-based code"),
    crate::types::OtpMode::Totp => ("totp", "Time-based code"),
);
