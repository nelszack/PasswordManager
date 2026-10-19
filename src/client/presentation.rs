use crate::{protocol::ResponsePayload, terminal::metadata};

pub fn render(payload: &ResponsePayload) -> String {
    match payload {
        ResponsePayload::Message(message) => message.clone(),
        ResponsePayload::Secret(secret) => secret.expose().to_owned(),
        ResponsePayload::Status(status) => format!(
            "Status: {}\nVersion: {}{}",
            if status.locked { "Locked" } else { "Unlocked" },
            status.version,
            status
                .warning
                .as_ref()
                .map(|w| format!("\nWarning: {w}"))
                .unwrap_or_default()
        ),
        ResponsePayload::Authenticator(code) => {
            if let Some(counter) = code.counter {
                format!(
                    "HOTP: {} (counter {counter}; next counter saved)",
                    code.code.expose()
                )
            } else {
                format!(
                    "TOTP: {} ({}s remaining)",
                    code.code.expose(),
                    code.expires_in.unwrap_or_default()
                )
            }
        }
        ResponsePayload::Vault(reference) => format!(
            "Encrypted backup restored as {}. Unlock it with the backup password/key.",
            reference.vault_file
        ),
        ResponsePayload::ItemPage(page) => {
            if page.items.is_empty() {
                return "No entries.".into();
            }
            page.items
                .iter()
                .map(|item| {
                    format!(
                        "{}. {} [{}] {:?} {:?}{}\n",
                        item.id,
                        metadata(&item.name).as_str(),
                        item.kind,
                        item.username,
                        item.urls,
                        if item.has_totp { " [OTP]" } else { "" }
                    )
                })
                .collect()
        }
        ResponsePayload::Item(item) => {
            let fields = item
                .fields
                .iter()
                .map(|f| {
                    format!(
                        "{}={}",
                        metadata(&f.name).as_str(),
                        f.value
                            .as_ref()
                            .map(|v| metadata(v.expose()).to_string())
                            .unwrap_or_else(|| "<redacted>".into())
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                "Name: {}\nType: {}\nUsername: {:?}\nURLs: {:?}\nNotes: {}\nPassword: {}\nCustom fields:\n{}\n",
                metadata(&item.name).as_str(),
                item.kind,
                item.username,
                item.urls,
                item.notes
                    .as_ref()
                    .map(|v| metadata(v.expose()).to_string())
                    .unwrap_or_default(),
                item.password
                    .as_ref()
                    .map(|v| metadata(v.expose()).to_string())
                    .unwrap_or_else(|| "<redacted>".into()),
                fields
            )
        }
        ResponsePayload::Audit(report) => audit(report),
        ResponsePayload::ImportReport(report) => import_report(report),
        ResponsePayload::History(page) => {
            if page.history.is_empty() {
                return "No password history.".into();
            }
            page.history
                .iter()
                .enumerate()
                .map(|(index, changed)| {
                    format!("{}. changed {}\n", index + 1, metadata(changed).as_str())
                })
                .collect()
        }
        ResponsePayload::Trash(page) => {
            if page.trash.is_empty() {
                return "Trash is empty.".into();
            }
            page.trash
                .iter()
                .map(|item| {
                    format!(
                        "{}. {} [{}] deleted {}\n",
                        item.id,
                        metadata(&item.name).as_str(),
                        item.kind,
                        metadata(&item.deleted).as_str(),
                    )
                })
                .collect()
        }
        _ => serde_json::to_string_pretty(payload).unwrap_or_default(),
    }
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

fn import_report(report: &crate::vault::ImportReport) -> String {
    use std::fmt::Write;
    let mut output = format!(
        "Import {}: {} parsed, {} added, {} replaced, {} kept with a new name, {} skipped.",
        if report.preview {
            "preview"
        } else {
            "finished"
        },
        report.total,
        report.added,
        report.replaced,
        report.renamed,
        report.skipped
    );
    if report.unsupported > 0 || report.loss_count > 0 {
        let _ = write!(
            output,
            " {} unsupported items, {} data-loss warnings.",
            report.unsupported, report.loss_count
        );
        for loss in &report.losses {
            let _ = write!(output, "\nWarning: {}", metadata(loss).as_str());
        }
        if report.loss_count > report.losses.len() {
            let _ = write!(
                output,
                "\n{} additional warnings omitted.",
                report.loss_count - report.losses.len()
            );
        }
    }
    output
}
