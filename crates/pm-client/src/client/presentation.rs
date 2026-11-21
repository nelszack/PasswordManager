use crate::{protocol::ResponsePayload, terminal::metadata};

pub fn render(payload: &ResponsePayload) -> String {
    match payload {
        ResponsePayload::Message(message) => message.clone(),
        ResponsePayload::CloudVaults(vaults) => {
            serde_json::to_string_pretty(vaults).expect("cloud vaults serialize")
        }
        ResponsePayload::CloudConflicts(review) => {
            serde_json::to_string_pretty(review).expect("cloud conflicts serialize")
        }
        ResponsePayload::Secret(secret) => secret.expose().to_owned(),
        ResponsePayload::Status(status) => format!(
            "Status: {}\nVersion: {}{}{}{}",
            if status.locked {
                "Locked (run `pm unlock` to open your vault)"
            } else {
                "Unlocked"
            },
            status.version,
            status
                .ssh_requests
                .iter()
                .map(|request| format!(
                    "\nSSH request {}: key \"{}\" for {} (pm ssh-agent approve {})",
                    request.id,
                    metadata(&request.key).as_str(),
                    metadata(&request.host).as_str(),
                    request.id
                ))
                .collect::<String>(),
            status
                .passkey_requests
                .iter()
                .map(|request| format!(
                    "\nPasskey request {}: confirm it is you for {} (pm passkey approve {})",
                    request.id,
                    metadata(&request.site).as_str(),
                    request.id
                ))
                .collect::<String>(),
            status
                .warning
                .as_ref()
                .into_iter()
                .chain(status.cloud_warning.as_ref())
                .map(|w| format!("\nWarning: {w}"))
                .collect::<String>()
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
        ResponsePayload::Operation(receipt) => format!(
            "Operation {}: {:?}. {}",
            receipt.operation_id,
            receipt.state,
            match receipt.state {
                crate::protocol::OperationState::Committed =>
                    "The change completed; do not repeat it.",
                crate::protocol::OperationState::CommittedDurabilityUnknown =>
                    "The change committed, but storage durability is uncertain. Inspect the vault and storage before continuing.",
                crate::protocol::OperationState::Pending =>
                    "The change is still running. Check again before making another change.",
                crate::protocol::OperationState::Failed =>
                    "The change failed. Inspect the vault before trying again.",
                crate::protocol::OperationState::Unknown =>
                    "The server has no retained outcome. Inspect the vault; do not assume the change failed.",
            }
        ),
        ResponsePayload::ItemPage(page) => {
            if page.items.is_empty() {
                return "No items. Add one with `pm add --name NAME` or import with `pm import`."
                    .into();
            }
            let mut listing: String = page
                .items
                .iter()
                .map(|item| {
                    let mut block = format!(
                        "#{} {}{} ({}{})\n",
                        item.id,
                        if item.favorite { "★ " } else { "" },
                        metadata(&item.name).as_str(),
                        item.kind,
                        if item.has_totp { ", OTP" } else { "" }
                    );
                    if let Some(username) = item.username.as_deref().filter(|u| !u.is_empty()) {
                        block += &format!("   Username: {}\n", metadata(username).as_str());
                    }
                    if !item.urls.is_empty() {
                        block += &format!("   URLs: {}\n", urls(&item.urls));
                    }
                    if !item.tags.is_empty() {
                        block += &format!("   Tags: {}\n", tags(&item.tags));
                    }
                    block
                })
                .collect();
            let shown = page.items.len();
            let count = if shown == page.total {
                format!("{shown} {}", if shown == 1 { "item" } else { "items" })
            } else {
                format!("{shown} of {} items", page.total)
            };
            listing += &format!("\n{count}. Show one with `pm get NAME` or `pm get --id ID`.\n");
            listing
        }
        ResponsePayload::Item(item) => {
            let mut lines = vec![
                format!("Name:     {}", metadata(&item.name).as_str()),
                format!("Type:     {}", item.kind),
            ];
            if let Some(username) = item.username.as_deref().filter(|u| !u.is_empty()) {
                lines.push(format!("Username: {}", metadata(username).as_str()));
            }
            if !item.urls.is_empty() {
                lines.push(format!("URLs:     {}", urls(&item.urls)));
            }
            if !item.tags.is_empty() {
                lines.push(format!("Tags:     {}", tags(&item.tags)));
            }
            if item.favorite {
                lines.push("Favorite: yes".into());
            }
            if !item.attachments.is_empty() {
                lines.push("Attachments:".into());
                lines.extend(
                    item.attachments.iter().map(|a| {
                        format!("  {} ({})", metadata(&a.name).as_str(), byte_size(a.size))
                    }),
                );
            }
            lines.push(format!(
                "Password: {}",
                item.password
                    .as_ref()
                    .map(|v| metadata(v.expose()).to_string())
                    .unwrap_or_else(|| "<hidden> (use --password-only to print it)".into())
            ));
            if let Some(notes) = item.notes.as_ref().filter(|n| !n.expose().is_empty()) {
                lines.push(format!("Notes:    {}", metadata(notes.expose()).as_str()));
            }
            if !item.fields.is_empty() {
                lines.push("Custom fields:".into());
                lines.extend(item.fields.iter().map(|f| {
                    format!(
                        "  {}: {}",
                        metadata(&f.name).as_str(),
                        f.value
                            .as_ref()
                            .map(|v| metadata(v.expose()).to_string())
                            .unwrap_or_else(|| "<hidden> (use --reveal-secrets)".into())
                    )
                }));
            }
            lines.join("\n") + "\n"
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
                    format!(
                        "{}. changed {}\n",
                        index + 1,
                        metadata(&timestamp(changed)).as_str()
                    )
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
                        "#{} {} ({}) deleted {}\n",
                        item.id,
                        metadata(&item.name).as_str(),
                        item.kind,
                        metadata(&timestamp(&item.deleted)).as_str(),
                    )
                })
                .collect()
        }
        _ => serde_json::to_string_pretty(payload).unwrap_or_default(),
    }
}

pub fn audit(findings: &crate::vault::AuditReport) -> String {
    if findings.total == 0 {
        return "No login items to assess. Add or import a login before checking vault health.\n"
            .into();
    }
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
            "Weak: {}. {} ({})\n",
            entry.id,
            metadata(&entry.name).as_str(),
            optional_metadata(entry.username.as_deref())
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
            metadata(&timestamp(&entry.password_changed)).as_str()
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

fn optional_metadata(value: Option<&str>) -> String {
    value
        .filter(|v| !v.is_empty())
        .map(|v| metadata(v).to_string())
        .unwrap_or_else(|| "—".into())
}

fn byte_size(bytes: u64) -> String {
    match bytes {
        0..1024 => format!("{bytes} B"),
        1024..1_048_576 => format!("{:.1} KiB", bytes as f64 / 1024.0),
        _ => format!("{:.1} MiB", bytes as f64 / 1_048_576.0),
    }
}

fn tags(values: &[String]) -> String {
    values
        .iter()
        .map(|tag| metadata(tag).to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn urls(values: &[String]) -> String {
    if values.is_empty() {
        "—".into()
    } else {
        values
            .iter()
            .map(|v| metadata(v).to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Show RFC 3339 instants as `YYYY-MM-DD HH:MM UTC`; leave anything else unchanged.
fn timestamp(value: &str) -> String {
    let utc = value.ends_with('Z') || value.ends_with("+00:00");
    match (value.get(..10), value.get(10..11), value.get(11..16)) {
        (Some(date), Some("T"), Some(time)) if utc => format!("{date} {time} UTC"),
        _ => value.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn timestamps_are_shortened_only_when_utc() {
        assert_eq!(
            super::timestamp("2026-11-19T04:11:18.793348284+00:00"),
            "2026-11-19 04:11 UTC"
        );
        assert_eq!(
            super::timestamp("2026-11-19T04:11:18Z"),
            "2026-11-19 04:11 UTC"
        );
        assert_eq!(
            super::timestamp("2026-11-19T04:11:18+02:00"),
            "2026-11-19T04:11:18+02:00"
        );
        assert_eq!(super::timestamp("yesterday"), "yesterday");
    }
}
