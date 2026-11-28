//! Payment-card and identity autofill for platforms that describe form fields
//! with text (Android autofill hints, HTML `autocomplete` tokens, view IDs, and
//! labels). Field roles use HTML `autocomplete` names; the rules mirror the
//! browser extension's (`content_autofill.js`, `content_fields.js`).
use super::*;

const CARD_ROLES: &[&str] = &[
    "cc-name",
    "cc-given-name",
    "cc-additional-name",
    "cc-family-name",
    "cc-number",
    "cc-exp",
    "cc-exp-month",
    "cc-exp-year",
    "cc-csc",
    "cc-type",
];
/// Name and address fields establish identity context for email/phone fields.
const IDENTITY_CONTEXT_ROLES: &[&str] = &[
    "name",
    "given-name",
    "additional-name",
    "family-name",
    "honorific-prefix",
    "honorific-suffix",
    "organization",
    "street-address",
    "address-line1",
    "address-line2",
    "address-line3",
    "address-level1",
    "address-level2",
    "address-level3",
    "address-level4",
    "country",
    "country-name",
    "postal-code",
];
const CONTACT_ROLES: &[&str] = &["nickname", "email", "tel"];
const LOGIN_TOKENS: &[&str] = &[
    "username",
    "current-password",
    "new-password",
    "one-time-code",
];

/// Android `View.AUTOFILL_HINT_*` and androidx `HintConstants` values, lowercased.
const ANDROID_HINTS: &[(&str, &str)] = &[
    ("creditcardnumber", "cc-number"),
    ("creditcardexpirationdate", "cc-exp"),
    ("creditcardexpirationmonth", "cc-exp-month"),
    ("creditcardexpirationyear", "cc-exp-year"),
    ("creditcardsecuritycode", "cc-csc"),
    ("personname", "name"),
    ("persongivenname", "given-name"),
    ("personmiddlename", "additional-name"),
    ("personfamilyname", "family-name"),
    ("personnameprefix", "honorific-prefix"),
    ("personnamesuffix", "honorific-suffix"),
    ("emailaddress", "email"),
    ("phone", "tel"),
    ("phonenumber", "tel"),
    ("phonenational", "tel"),
    ("postaladdress", "street-address"),
    ("streetaddress", "address-line1"),
    ("extendedaddress", "address-line2"),
    ("addresslocality", "address-level2"),
    ("addressregion", "address-level1"),
    ("addresscountry", "country"),
    ("postalcode", "postal-code"),
];

fn alphanumeric(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Whether `words` appear in order in a normalized description.
fn ordered(description: &str, words: &[&str]) -> bool {
    let mut rest = description;
    words.iter().all(|word| match rest.find(word) {
        Some(index) => {
            rest = &rest[index + word.len()..];
            true
        }
        None => false,
    })
}

fn infer_card(d: &str) -> Option<&'static str> {
    if ["cvc", "cvv", "cardsecurity", "securitycode"]
        .iter()
        .any(|w| d.contains(w))
    {
        Some("cc-csc")
    } else if ordered(d, &["expir", "month"]) || d.contains("expmonth") || d.contains("ccmonth") {
        Some("cc-exp-month")
    } else if ordered(d, &["expir", "year"]) || d.contains("expyear") || d.contains("ccyear") {
        Some("cc-exp-year")
    } else if ["expir", "cardexp", "ccexp"].iter().any(|w| d.contains(w)) {
        Some("cc-exp")
    } else if ["cardholder", "nameoncard", "ccname"]
        .iter()
        .any(|w| d.contains(w))
    {
        Some("cc-name")
    } else if ["cardnumber", "ccnumber", "creditcard"]
        .iter()
        .any(|w| d.contains(w))
    {
        Some("cc-number")
    } else {
        None
    }
}

fn infer_identity(d: &str) -> Option<&'static str> {
    let has = |w: &str| d.contains(w);
    Some(if has("postal") || has("zip") {
        "postal-code"
    } else if has("addressline3") || has("address3") {
        "address-line3"
    } else if has("addressline2") || has("address2") || has("apartment") || has("suite") {
        "address-line2"
    } else if has("street") || has("addressline1") || has("address1") {
        "address-line1"
    } else if has("city") || has("town") {
        "address-level2"
    } else if has("county") || has("district") {
        "address-level3"
    } else if has("state") || has("province") || has("region") {
        "address-level1"
    } else if has("countryname") {
        "country-name"
    } else if has("country") {
        "country"
    } else if (has("first") || has("given")) && has("name") {
        "given-name"
    } else if (has("middle") || has("additional")) && has("name") {
        "additional-name"
    } else if has("last") || has("family") || has("surname") {
        "family-name"
    } else if has("fullname") || has("contactname") {
        "name"
    } else if has("company") || has("organization") {
        "organization"
    } else if has("phone") || has("mobile") || has("telephone") {
        "tel"
    } else if has("email") {
        "email"
    } else {
        return None;
    })
}

/// One field's role and the kind of item that fills it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct FieldRole {
    pub kind: ItemKind,
    pub role: &'static str,
}

fn role_of(description: &str) -> Option<FieldRole> {
    let tokens: Vec<String> = description
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect();
    // Explicit roles override guesses from names and labels.
    for token in &tokens {
        if LOGIN_TOKENS.contains(&token.as_str()) {
            return None;
        }
        let token = token.as_str();
        if let Some(role) = CARD_ROLES.iter().find(|r| **r == token) {
            return Some(FieldRole {
                kind: ItemKind::PaymentCard,
                role,
            });
        }
        if let Some(role) = IDENTITY_CONTEXT_ROLES
            .iter()
            .chain(CONTACT_ROLES)
            .find(|r| **r == token)
        {
            return Some(FieldRole {
                kind: ItemKind::Identity,
                role,
            });
        }
        let hint = alphanumeric(token);
        if let Some((_, role)) = ANDROID_HINTS.iter().find(|(known, _)| *known == hint) {
            let kind = if role.starts_with("cc-") {
                ItemKind::PaymentCard
            } else {
                ItemKind::Identity
            };
            return Some(FieldRole { kind, role });
        }
    }
    let normalized = alphanumeric(description);
    if let Some(role) = infer_card(&normalized) {
        return Some(FieldRole {
            kind: ItemKind::PaymentCard,
            role,
        });
    }
    infer_identity(&normalized).map(|role| FieldRole {
        kind: ItemKind::Identity,
        role,
    })
}

/// Roles for each described field. Email and phone fields count as identity
/// fields only beside a name or address field, as they are common on login and
/// search forms.
pub(crate) fn classify(descriptions: &[String]) -> Vec<Option<FieldRole>> {
    let mut roles: Vec<_> = descriptions.iter().map(|d| role_of(d)).collect();
    let context = roles
        .iter()
        .flatten()
        .any(|r| IDENTITY_CONTEXT_ROLES.contains(&r.role));
    if !context {
        for role in &mut roles {
            if role.is_some_and(|r| CONTACT_ROLES.contains(&r.role)) {
                *role = None;
            }
        }
    }
    roles
}

fn aliases(role: &str) -> &'static [&'static str] {
    match role {
        "cc-name" => &["cardholder", "cardholder name", "name on card", "cc name"],
        "cc-given-name" => &["cardholder first name", "cc given name"],
        "cc-additional-name" => &["cardholder middle name", "cc additional name"],
        "cc-family-name" => &["cardholder last name", "cc family name"],
        "cc-exp" => &[
            "expiration",
            "expiry",
            "expiration date",
            "expiry date",
            "cc exp",
        ],
        "cc-exp-month" => &[
            "expiration month",
            "expiry month",
            "exp month",
            "cc exp month",
        ],
        "cc-exp-year" => &["expiration year", "expiry year", "exp year", "cc exp year"],
        "cc-csc" => &["cvv", "cvc", "csc", "security code", "card security code"],
        "cc-type" => &["card type", "network", "brand"],
        "name" => &["name", "full name", "legal name"],
        "given-name" => &["first name", "given name"],
        "additional-name" => &["middle name", "additional name"],
        "family-name" => &["last name", "family name", "surname"],
        "honorific-prefix" => &["title", "prefix", "honorific prefix"],
        "honorific-suffix" => &["suffix", "honorific suffix"],
        "nickname" => &["nickname", "preferred name"],
        "email" => &["email", "email address"],
        "tel" => &["phone", "telephone", "mobile", "phone number"],
        "organization" => &["organization", "company", "business"],
        "street-address" => &["street address", "full address", "address"],
        "address-line1" => &["address line 1", "address1", "street"],
        "address-line2" => &["address line 2", "address2", "apartment", "suite", "unit"],
        "address-line3" => &["address line 3", "address3"],
        "address-level1" => &["state", "province", "region"],
        "address-level2" => &["city", "town"],
        "address-level3" => &["district", "county"],
        "address-level4" => &["suburb", "neighborhood"],
        "country" => &["country code", "country"],
        "country-name" => &["country name", "country"],
        "postal-code" => &["postal code", "zip", "zip code"],
        _ => &[],
    }
}

/// `MM/YY`, `MM/YYYY`, `MM-YY`, or `MMYY` split into month and year.
fn split_expiry(value: &str) -> Option<(String, String)> {
    let digits: Vec<&str> = value
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .collect();
    let (month, year) = match digits.as_slice() {
        [month, year] => ((*month).to_owned(), (*year).to_owned()),
        [compact] if compact.len() == 4 => (compact[..2].to_owned(), compact[2..].to_owned()),
        _ => return None,
    };
    let number: u8 = month.parse().ok()?;
    ((1..=12).contains(&number) && matches!(year.len(), 2 | 4))
        .then(|| (format!("{number:02}"), year))
}

impl Item {
    fn typed_field(&self, role: &str) -> Option<&SecretString> {
        let accepted: Vec<String> = aliases(role).iter().map(|a| alphanumeric(a)).collect();
        self.metadata
            .custom_fields
            .iter()
            .filter(|f| !item_rules::is_reserved_field(&f.name))
            .find(|f| accepted.contains(&alphanumeric(&f.name)))
            .map(|f| &f.value)
            .filter(|value| !value.is_empty())
    }

    fn typed_value(&self, role: &str) -> Option<String> {
        if role == "cc-number" {
            return (!self.entry.password.is_empty())
                .then(|| self.entry.password.expose().to_owned());
        }
        if let Some(value) = self.typed_field(role) {
            return Some(value.expose().to_owned());
        }
        let username = || self.entry.username.clone().filter(|u| !u.is_empty());
        match role {
            "cc-name" | "name" => username(),
            "email" if self.metadata.kind == ItemKind::PaymentCard => username(),
            "cc-exp-month" | "cc-exp-year" => {
                let (month, year) = split_expiry(self.typed_field("cc-exp")?.expose())?;
                Some(if role == "cc-exp-month" { month } else { year })
            }
            "given-name" | "family-name" => {
                let full = self
                    .typed_field("name")
                    .map(|v| v.expose().to_owned())
                    .or_else(username)?;
                let words: Vec<&str> = full.split_whitespace().collect();
                (words.len() >= 2).then(|| {
                    if role == "given-name" {
                        words[0].to_owned()
                    } else {
                        words[words.len() - 1].to_owned()
                    }
                })
            }
            _ => None,
        }
    }
}

impl Vault {
    /// Values for the requested roles from one card or identity. Only roles the
    /// item can fill are returned; unknown roles are ignored.
    pub(crate) fn typed_fill_values(
        &self,
        id: usize,
        kind: ItemKind,
        roles: &[String],
    ) -> Result<BTreeMap<String, SecretString>, VaultError> {
        let item = self
            .item(id)
            .filter(|item| item.active() && item.metadata.kind == kind)
            .filter(|_| matches!(kind, ItemKind::PaymentCard | ItemKind::Identity))
            .ok_or_else(|| VaultError::NotFound("card or identity not found".into()))?;
        Ok(roles
            .iter()
            .filter_map(|role| Some((role.clone(), item.typed_value(role)?.into())))
            .collect())
    }

    /// Cards or identities a person can choose from; no secret values.
    pub(crate) fn typed_fill_choices(&self, kind: ItemKind) -> Vec<ItemSummary> {
        self.active_items()
            .filter(|item| item.metadata.kind == kind)
            .filter(|_| matches!(kind, ItemKind::PaymentCard | ItemKind::Identity))
            .map(|item| self.summary(item))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles(fields: &[&str]) -> Vec<Option<&'static str>> {
        classify(&fields.iter().map(|f| (*f).to_owned()).collect::<Vec<_>>())
            .into_iter()
            .map(|r| r.map(|r| r.role))
            .collect()
    }

    #[test]
    fn fields_are_classified_from_hints_tokens_and_labels() {
        assert_eq!(
            roles(&[
                "creditCardNumber",
                "cc-exp",
                "cardholder_name",
                "card_cvv",
                "expiry month",
                "input exp_year",
                "username",
                "searchbox",
            ]),
            [
                Some("cc-number"),
                Some("cc-exp"),
                Some("cc-name"),
                Some("cc-csc"),
                Some("cc-exp-month"),
                Some("cc-exp-year"),
                None,
                None,
            ]
        );
        assert_eq!(
            roles(&[
                "personGivenName",
                "family_name",
                "postalCode",
                "emailAddress",
                "phone"
            ]),
            [
                Some("given-name"),
                Some("family-name"),
                Some("postal-code"),
                Some("email"),
                Some("tel"),
            ]
        );
        // Without a name or address field, email and phone stay unclassified.
        assert_eq!(roles(&["emailAddress", "tel"]), [None, None]);
        // An explicit login token wins over a guess from its label.
        assert_eq!(roles(&["username email"]), [None]);
        let card = classify(&["cc-number".into()])[0].unwrap();
        assert_eq!(card.kind, ItemKind::PaymentCard);
    }

    #[test]
    fn values_come_from_items_with_derived_expiry_and_names() {
        let mut vault = Vault::memory();
        let mut key = VaultCredentials::default();
        let field = |name: &str, value: &str| CustomField {
            name: name.into(),
            value: value.into(),
            secret: false,
        };
        for (name, kind, username, secret, fields) in [
            (
                "Visa",
                ItemKind::PaymentCard,
                "Alex Q Example",
                "4111111111111111",
                vec![field("Expiry", "9/2030"), field("Security code", "123")],
            ),
            (
                "Home",
                ItemKind::Identity,
                "Alex Example",
                "",
                vec![field("Email", "alex@example.com"), field("ZIP", "12345")],
            ),
        ] {
            vault
                .add_typed_entry(
                    TypedEntry {
                        entry: PasswordEntry {
                            name: name.into(),
                            username: Some(username.into()),
                            password: secret.into(),
                            url: None,
                            notes: None,
                            copy: false,
                        },
                        kind,
                        additional_urls: vec![],
                        custom_fields: fields,
                        tags: vec![],
                        favorite: false,
                    },
                    &mut key,
                )
                .unwrap();
        }
        let request = |id, kind, roles: &[&str]| {
            vault
                .typed_fill_values(
                    id,
                    kind,
                    &roles.iter().map(|r| (*r).to_owned()).collect::<Vec<_>>(),
                )
                .map(|values| {
                    values
                        .into_iter()
                        .map(|(role, value)| (role, value.expose_owned()))
                        .collect::<Vec<_>>()
                })
        };
        assert_eq!(
            request(
                1,
                ItemKind::PaymentCard,
                &[
                    "cc-number",
                    "cc-name",
                    "cc-exp-month",
                    "cc-exp-year",
                    "cc-csc",
                    "cc-type"
                ]
            )
            .unwrap(),
            [
                ("cc-csc".into(), "123".into()),
                ("cc-exp-month".into(), "09".into()),
                ("cc-exp-year".into(), "2030".into()),
                ("cc-name".into(), "Alex Q Example".into()),
                ("cc-number".into(), "4111111111111111".into()),
            ]
        );
        assert_eq!(
            request(
                2,
                ItemKind::Identity,
                &["given-name", "family-name", "email", "postal-code", "tel"]
            )
            .unwrap(),
            [
                ("email".into(), "alex@example.com".into()),
                ("family-name".into(), "Example".into()),
                ("given-name".into(), "Alex".into()),
                ("postal-code".into(), "12345".into()),
            ]
        );
        // The requested kind must match, and logins are never offered.
        assert!(request(1, ItemKind::Identity, &["name"]).is_err());
        assert!(request(99, ItemKind::PaymentCard, &["cc-number"]).is_err());
        assert_eq!(vault.typed_fill_choices(ItemKind::PaymentCard).len(), 1);
        assert!(vault.typed_fill_choices(ItemKind::Login).is_empty());
        for (value, expected) in [
            ("09/30", Some(("09", "30"))),
            ("1-2031", Some(("01", "2031"))),
            ("0928", Some(("09", "28"))),
            ("13/30", None),
            ("soon", None),
        ] {
            assert_eq!(
                split_expiry(value),
                expected.map(|(m, y)| (m.to_owned(), y.to_owned())),
                "{value}"
            );
        }
    }
}
