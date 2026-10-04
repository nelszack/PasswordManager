use crate::terminal::metadata;
use crate::{
    types::ItemKind,
    vault::{EntryView, TrashView},
};
use zeroize::Zeroizing;

fn kind(view: &EntryView<'_>) -> ItemKind {
    view.metadata
        .map_or(ItemKind::Login, |metadata| metadata.kind)
}

#[cfg(test)]
pub(super) fn entry_details(view: &EntryView<'_>) -> Zeroizing<String> {
    entry_details_with_secrets(view, false)
}

pub(super) fn entry_details_with_secrets(
    view: &EntryView<'_>,
    reveal_secrets: bool,
) -> Zeroizing<String> {
    let fields = Zeroizing::new(
        view.metadata
            .map_or(&[][..], |metadata| metadata.custom_fields.as_slice())
            .iter()
            .map(|field| {
                if field.secret && !reveal_secrets {
                    format!("{}=<redacted>", metadata(&field.name).as_str())
                } else {
                    format!(
                        "{}={}",
                        metadata(&field.name).as_str(),
                        metadata(&field.value).as_str()
                    )
                }
            })
            .collect::<Vec<_>>(),
    );
    let fields = Zeroizing::new(fields.join("\n"));
    Zeroizing::new(format!(
        "Type: {}\nURLs: {:?}\n{:?}{}{}\n",
        kind(view),
        view.urls,
        view.entry,
        if fields.is_empty() {
            ""
        } else {
            "\nCustom fields:\n"
        },
        *fields
    ))
}

pub(super) fn entries(views: &[EntryView<'_>]) -> String {
    if views.is_empty() {
        return "No entries.".into();
    }
    views
        .iter()
        .map(|view| {
            let entry = view.entry;
            let urls = view.urls.join(", ");
            let fields = view
                .metadata
                .map_or(&[][..], |metadata| metadata.custom_fields.as_slice())
                .iter()
                .map(|field| {
                    if field.secret {
                        format!("{} [secret]", field.name)
                    } else {
                        format!("{}={}", field.name, field.value)
                    }
                })
                .collect::<Vec<_>>();
            format!(
                "{}. {} [{}] {:?} {:?} {:?} {:?}{}\n",
                entry.id,
                metadata(&entry.name).as_str(),
                kind(view),
                entry.username,
                (!urls.is_empty()).then_some(urls),
                entry.notes,
                fields,
                if view.has_totp { " [TOTP]" } else { "" }
            )
        })
        .collect()
}

pub(super) fn history(changed: &[&str]) -> String {
    if changed.is_empty() {
        return "No password history.".into();
    }
    changed
        .iter()
        .enumerate()
        .map(|(index, changed)| format!("{}. changed {}\n", index + 1, metadata(changed).as_str()))
        .collect()
}

pub(super) fn trash(items: &[TrashView<'_>]) -> String {
    if items.is_empty() {
        return "Trash is empty.".into();
    }
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            format!(
                "{}. {} [{}] {:?} deleted {}{}\n",
                index + 1,
                metadata(&item.entry.entry.name).as_str(),
                kind(&item.entry),
                item.entry.entry.username,
                metadata(item.deleted).as_str(),
                if item.entry.has_totp { " [TOTP]" } else { "" }
            )
        })
        .collect()
}

pub(crate) fn audit(findings: &crate::vault::AuditReport) -> String {
    let score = findings.score;
    let healthy = findings.healthy;
    let weak = &findings.weak;
    let reused = &findings.reused;
    let duplicates = &findings.duplicates;
    let stale = &findings.stale;
    let missing_totp = &findings.missing_totp;
    let breached_entries = &findings.breached;
    let breach_error = findings.breach_error.as_deref();
    let mut report = format!(
        "Health score: {score}/100 ({healthy}/{} login entries have no detected issues).\nAudit: {} weak entries, {} reused-password groups, {} duplicate-login groups, {} stale entries, {} missing TOTP, {} breached entries.\n",
        findings.total,
        weak.len(),
        reused.len(),
        duplicates.len(),
        stale.len(),
        missing_totp.len(),
        breached_entries.len(),
    );
    for entry in weak {
        report.push_str(&format!(
            "Weak: {}. {} {:?}\n",
            entry.id,
            metadata(&entry.name).as_str(),
            entry.username
        ));
    }
    for entries in reused {
        let labels = entries
            .iter()
            .map(|entry| format!("{}. {}", entry.id, metadata(&entry.name).as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        report.push_str(&format!("Reused password: {labels}\n"));
    }
    for entries in duplicates {
        let labels = entries
            .iter()
            .map(|entry| format!("{}. {}", entry.id, metadata(&entry.name).as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        report.push_str(&format!("Duplicate login: {labels}\n"));
    }
    for entry in stale {
        report.push_str(&format!(
            "Stale password: {}. {} (last changed {})\n",
            entry.id,
            metadata(&entry.name).as_str(),
            metadata(&entry.password_changed).as_str()
        ));
    }
    for entry in missing_totp {
        report.push_str(&format!(
            "Missing TOTP: {}. {}\n",
            entry.id,
            metadata(&entry.name).as_str()
        ));
    }
    for (entry, count) in breached_entries {
        report.push_str(&format!(
            "Breached password: {}. {} (seen {count} times)\n",
            entry.id,
            metadata(&entry.name).as_str()
        ));
    }
    if let Some(error) = breach_error {
        report.push_str(&format!("Breach check unavailable: {error}\n"));
    }
    if !findings.unchecked.is_empty() {
        report.push_str(&format!(
            "Breach checks incomplete: {} of {} login entries checked successfully.\n",
            findings.total - findings.unchecked.len(),
            findings.total
        ));
        for entry in &findings.unchecked {
            report.push_str(&format!(
                "Unchecked breach status: {}. {}\n",
                entry.id,
                metadata(&entry.name).as_str()
            ));
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        types::CustomField,
        vault::{EntryMetadata, VaultEntry},
    };

    #[test]
    fn every_metadata_view_escapes_controls_and_keeps_secret_fields_redacted() {
        let attack = "Metadata\x1b]52;c;c2VjcmV0\x07\nFake row";
        let entry = VaultEntry {
            name: attack.into(),
            ..Default::default()
        };
        let record = EntryMetadata {
            custom_fields: vec![
                CustomField {
                    name: attack.into(),
                    value: attack.into(),
                    secret: false,
                },
                CustomField {
                    name: "secret".into(),
                    value: "must-stay-redacted".into(),
                    secret: true,
                },
            ],
            ..Default::default()
        };
        let view = || EntryView {
            entry: &entry,
            metadata: Some(&record),
            has_totp: false,
            urls: vec![],
        };
        let outputs = [
            entry_details(&view()).to_string(),
            entries(&[view()]),
            history(&[attack]),
            trash(&[TrashView {
                entry: view(),
                deleted: attack,
            }]),
        ];
        for text in outputs {
            assert!(!text.contains(['\x1b', '\x07']));
            assert!(text.contains("\\nFake row"));
            assert!(!text.contains("must-stay-redacted"));
        }
    }
}
