use crate::{protocol::ResponsePayload, terminal::metadata};
use pm_contracts::item_profile::profile;
use pm_contracts::vault::{ItemDetail, ItemPage};

/// How one output renders text. Only text this module adds changes; item data never does.
#[derive(Clone, Copy, Debug)]
pub struct Style {
    /// Plain ASCII punctuation instead of typographic glyphs (pipes, TERM=dumb,
    /// PM_PLAIN, non-UTF-8 locales).
    pub ascii: bool,
    /// The terminal width that list columns fit into (40 to 400).
    width: usize,
    /// Show item notes in details (the CLI's `get --reveal-secrets`); hidden by
    /// default, as in the desktop and mobile apps.
    pub reveal_notes: bool,
}

impl Default for Style {
    fn default() -> Self {
        Self {
            ascii: false,
            width: 100,
            reveal_notes: false,
        }
    }
}

impl Style {
    pub fn with_width(mut self, columns: usize) -> Self {
        self.width = columns.clamp(40, 400);
        self
    }
}

fn glyph(style: Style, unicode: &'static str, ascii: &'static str) -> &'static str {
    if style.ascii { ascii } else { unicode }
}

fn dot(style: Style) -> &'static str {
    glyph(style, " · ", " - ")
}

pub fn render(style: Style, payload: &ResponsePayload) -> String {
    match payload {
        ResponsePayload::Message(message) => message.clone(),
        ResponsePayload::CloudVaults(vaults) => cloud_vaults(vaults),
        ResponsePayload::CloudConflicts(review) => cloud_conflicts(style, review),
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
        ResponsePayload::ItemPage(page) => item_page(style, page, None),
        ResponsePayload::Item(item) => item_detail(style, item),
        ResponsePayload::Audit(report) => audit(style, report),
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
                        "Revision {}  changed {}\n",
                        index + 1,
                        metadata(&timestamp(changed)).as_str()
                    )
                })
                .chain(std::iter::once(
                    "\nRestore one with `pm restore-password NAME --revision N`.\n".to_owned(),
                ))
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
                        "#{:<4} {}  ({}, deleted {})\n",
                        item.id,
                        metadata(&item.name).as_str(),
                        profile(item.kind).title,
                        metadata(&timestamp(&item.deleted)).as_str(),
                    )
                })
                .chain(std::iter::once(
                    "\nRestore one with `pm restore --id ID`; erase one with `pm purge --id ID`.\n"
                        .to_owned(),
                ))
                .collect()
        }
        _ => serde_json::to_string_pretty(payload).unwrap_or_default(),
    }
}

pub fn audit(style: Style, findings: &crate::vault::AuditReport) -> String {
    use std::fmt::Write;
    if findings.total == 0 {
        return "No login items to assess. Add or import a login before checking vault health.\n"
            .into();
    }
    fn plural(count: usize, one: &str, many: &str) -> String {
        format!("{count} {}", if count == 1 { one } else { many })
    }
    // One row per login, with ID, name and username in aligned columns across
    // the whole report, so every section reads as the same table.
    let everyone: Vec<&crate::vault::AuditLabel> = findings
        .weak
        .iter()
        .chain(findings.reused.iter().flatten())
        .chain(findings.duplicates.iter().flatten())
        .chain(findings.stale.iter())
        .chain(findings.missing_totp.iter())
        .chain(findings.breached.iter().map(|(entry, _)| entry))
        .collect();
    let id_width = everyone
        .iter()
        .map(|entry| entry.id.to_string().len() + 1)
        .max()
        .unwrap_or(2);
    let name_width = everyone
        .iter()
        .map(|entry| cells(metadata(&entry.name).as_str()))
        .max()
        .unwrap_or(0)
        .min(40);
    let label = |entry: &crate::vault::AuditLabel| -> String {
        let name = elide(style, metadata(&entry.name).as_str(), 40);
        let pad = " ".repeat(name_width.saturating_sub(cells(&name)));
        let user = entry
            .username
            .as_deref()
            .filter(|u| !u.is_empty())
            .map(|u| metadata(u).to_string())
            .unwrap_or_default();
        let id = format!("#{}", entry.id);
        format!("{id:<id_width$}  {name}{pad}  {user}")
            .trim_end()
            .to_owned()
    };
    // Each reused or duplicate group is numbered, with one member per line.
    let groups = |groups: &[Vec<crate::vault::AuditLabel>]| -> Vec<String> {
        groups
            .iter()
            .enumerate()
            .flat_map(|(index, group)| {
                std::iter::once(format!("Group {}:", index + 1))
                    .chain(group.iter().map(|entry| format!("  {}", label(entry))))
            })
            .collect()
    };
    let mut report = format!(
        "Vault health: {}/100{}{} of {} have no issues\n",
        findings.score,
        dot(style),
        findings.healthy,
        plural(findings.total, "login", "logins"),
    );
    let mut section = |title: String, lines: Vec<String>| {
        if !lines.is_empty() {
            let _ = write!(report, "\n{title}:\n");
            for line in lines {
                let _ = writeln!(report, "  {line}");
            }
        }
    };
    section(
        format!("Weak passwords ({})", findings.weak.len()),
        findings.weak.iter().map(&label).collect(),
    );
    section(
        format!(
            "Reused passwords ({})",
            plural(findings.reused.len(), "group", "groups")
        ),
        groups(&findings.reused),
    );
    section(
        format!(
            "Duplicate logins ({})",
            plural(findings.duplicates.len(), "group", "groups")
        ),
        groups(&findings.duplicates),
    );
    section(
        format!("Old passwords ({})", findings.stale.len()),
        findings
            .stale
            .iter()
            .map(|entry| {
                format!(
                    "{}  (changed {})",
                    label(entry),
                    metadata(&timestamp(&entry.password_changed)).as_str()
                )
            })
            .collect(),
    );
    section(
        format!("No one-time code set up ({})", findings.missing_totp.len()),
        findings.missing_totp.iter().map(&label).collect(),
    );
    section(
        format!("Found in known breaches ({})", findings.breached.len()),
        findings
            .breached
            .iter()
            .map(|(entry, count)| format!("{}  (seen {count} times)", label(entry)))
            .collect(),
    );
    if let Some(error) = &findings.breach_error {
        let _ = write!(
            report,
            "\nBreach check unavailable: {}\n",
            metadata(error).as_str()
        );
    }
    if !findings.unchecked.is_empty() {
        let _ = write!(
            report,
            "\nBreach checks incomplete: {} of {} checked.\n",
            findings.total - findings.unchecked.len(),
            plural(findings.total, "login", "logins")
        );
        for entry in &findings.unchecked {
            let _ = writeln!(report, "  Not checked: {}", label(entry));
        }
    }
    if findings.healthy < findings.total {
        report +=
            "\nFix one with `pm update --id ID --generate`, or open it with `pm get --id ID`.\n";
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

fn urls(style: Style, values: &[String]) -> String {
    if values.is_empty() {
        glyph(style, "—", "-").into()
    } else {
        values
            .iter()
            .map(|v| metadata(v).to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Show RFC 3339 instants in the local time zone as `YYYY-MM-DD HH:MM ZONE`;
/// leave anything that is not a timestamp unchanged.
fn timestamp(value: &str) -> String {
    timestamp_in(value, &jiff::tz::TimeZone::system())
}

fn timestamp_in(value: &str, zone: &jiff::tz::TimeZone) -> String {
    match value.parse::<jiff::Timestamp>() {
        Ok(instant) => instant
            .to_zoned(zone.clone())
            .strftime("%Y-%m-%d %H:%M %Z")
            .to_string(),
        Err(_) => value.to_owned(),
    }
}

/// Item list: one aligned line per item so long vaults stay scannable.
/// `empty` replaces the empty-vault hint when a search or filter matched nothing.
pub fn item_page(style: Style, page: &ItemPage, empty: Option<&str>) -> String {
    if page.items.is_empty() {
        return empty
            .unwrap_or(
                "This vault has no items yet. Add one with `pm add --name NAME`, or import with \
                 `pm import --path FILE`.",
            )
            .to_owned();
    }
    let names: Vec<String> = page
        .items
        .iter()
        .map(|item| {
            format!(
                "{}{}",
                if item.favorite {
                    glyph(style, "★ ", "* ")
                } else {
                    ""
                },
                metadata(&item.name).as_str()
            )
        })
        .collect();
    let id_width = page
        .items
        .iter()
        .map(|item| item.id.to_string().len())
        .max()
        .unwrap_or(1);
    // Columns fit the terminal; long values are shortened here, while `pm get`
    // and --json keep them whole.
    let width = style.width;
    let names: Vec<String> = names
        .into_iter()
        .map(|name| elide(style, &name, (width / 3).clamp(16, 60)))
        .collect();
    let name_width = names.iter().map(|name| cells(name)).max().unwrap_or(0);
    let details_width = width.saturating_sub(id_width + name_width + 5).max(20);
    let mut listing = String::new();
    for (item, name) in page.items.iter().zip(names) {
        let mut details = vec![profile(item.kind).title.to_owned()];
        if let Some(username) = item.username.as_deref().filter(|u| !u.is_empty()) {
            details.push(metadata(username).to_string());
        }
        if let Some(url) = item.urls.first() {
            details.push(metadata(url).to_string());
        }
        if item.has_totp {
            details.push("one-time code".into());
        }
        for tag in &item.tags {
            details.push(format!("#{}", metadata(tag).as_str()));
        }
        let pad = " ".repeat(name_width.saturating_sub(cells(&name)));
        listing += &format!(
            "#{:<id_width$}  {name}{pad}  {}\n",
            item.id,
            elide(style, &details.join(dot(style)), details_width)
        );
    }
    let shown = page.items.len();
    let count = if shown == page.total {
        format!("{shown} {}", if shown == 1 { "item" } else { "items" })
    } else {
        format!("{shown} of {} items", page.total)
    };
    listing + &format!("\n{count}. Show one with `pm get NAME` or `pm get --id ID`.\n")
}

fn item_detail(style: Style, item: &ItemDetail) -> String {
    let profile = profile(item.kind);
    let mut rows: Vec<(String, String)> = vec![
        ("Name".into(), metadata(&item.name).to_string()),
        ("ID".into(), item.id.to_string()),
        ("Type".into(), profile.title.into()),
    ];
    if let Some(username) = item.username.as_deref().filter(|u| !u.is_empty()) {
        rows.push((short_label(profile.owner), metadata(username).to_string()));
    }
    if !item.urls.is_empty() {
        let label = if item.urls.len() == 1 {
            "Website"
        } else {
            "Websites"
        };
        rows.push((label.into(), urls(style, &item.urls)));
    }
    if item.has_secret || item.password.is_some() {
        rows.push((
            short_label(profile.secret),
            item.password
                .as_ref()
                .map(|v| metadata(v.expose()).to_string())
                .unwrap_or_else(|| {
                    format!(
                        "{} (hidden; add --password-only to print it)",
                        glyph(style, "••••••••", "********")
                    )
                }),
        ));
    }
    if item.has_totp {
        let kind = match item.otp_mode {
            Some(pm_contracts::types::OtpMode::Hotp) => "counter-based",
            _ => "time-based",
        };
        rows.push((
            "One-time code".into(),
            format!("{kind}; run `pm totp show --id {}`", item.id),
        ));
    }
    if item.has_duo {
        rows.push((
            "Duo Push".into(),
            format!("enrolled; run `pm duo requests --id {}`", item.id),
        ));
    }
    if !item.tags.is_empty() {
        rows.push(("Tags".into(), tags(&item.tags)));
    }
    if item.favorite {
        rows.push(("Favorite".into(), "yes".into()));
    }
    if let Some(notes) = item.notes.as_ref().filter(|n| !n.expose().is_empty()) {
        let shown = style.reveal_notes;
        rows.push((
            "Notes".into(),
            if shown {
                metadata(notes.expose()).to_string()
            } else {
                "(hidden; add --reveal-secrets)".into()
            },
        ));
    }
    for field in &item.fields {
        rows.push((
            metadata(&field.name).to_string(),
            field
                .value
                .as_ref()
                .map(|v| metadata(v.expose()).to_string())
                .unwrap_or_else(|| {
                    format!(
                        "{} (hidden; add --reveal-secrets)",
                        glyph(style, "••••••••", "********")
                    )
                }),
        ));
    }
    for attachment in &item.attachments {
        rows.push((
            "Attachment".into(),
            format!(
                "{} ({})",
                metadata(&attachment.name).as_str(),
                byte_size(attachment.size)
            ),
        ));
    }
    rows.push(("Modified".into(), timestamp(&item.modified)));
    rows.push(("Created".into(), timestamp(&item.created)));
    let width = rows
        .iter()
        .map(|(label, _)| label.chars().count() + 1)
        .max()
        .unwrap_or(0)
        .min(24);
    rows.into_iter()
        .map(|(label, value)| format!("{:<width$}  {value}\n", format!("{label}:")))
        .collect()
}

/// Terminal cells a string occupies: wide East Asian characters and emoji take
/// two, combining marks none.
fn cells(value: &str) -> usize {
    value
        .chars()
        .map(|c| match c as u32 {
            0x0300..=0x036F | 0x200B..=0x200F | 0xFE00..=0xFE0F => 0,
            0x1100..=0x115F
            | 0x2E80..=0xA4CF
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE30..=0xFE4F
            | 0xFF00..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x1F300..=0x1FAFF
            | 0x20000..=0x3FFFD => 2,
            _ => 1,
        })
        .sum()
}

/// At most `limit` cells, ending in "…" ("..." in ASCII output) when shortened.
fn elide(style: Style, value: &str, limit: usize) -> String {
    if cells(value) <= limit {
        return value.to_owned();
    }
    let marker = glyph(style, "…", "...");
    let reserved = cells(marker);
    let mut out = String::new();
    let mut used = 0;
    for c in value.chars() {
        let width = cells(&c.to_string());
        if used + width + reserved > limit {
            break;
        }
        used += width;
        out.push(c);
    }
    out + marker
}

/// Drop parenthetical editor guidance: "Identity number (optional)" -> "Identity number".
fn short_label(label: &str) -> String {
    label.split(" (").next().unwrap_or(label).to_owned()
}

fn cloud_vaults(vaults: &[pm_contracts::cloud::RemoteVault]) -> String {
    if vaults.is_empty() {
        return "No vaults are on the sync server yet. Upload this one with `pm sync enable`."
            .into();
    }
    let mut text = String::new();
    for vault in vaults {
        text += &format!(
            "{}  version {}  {}\n",
            metadata(&vault.id).as_str(),
            metadata(&vault.version).as_str(),
            byte_size(vault.size)
        );
    }
    text + "\nDownload one with `pm sync pull ID`.\n"
}

fn cloud_conflicts(style: Style, review: &pm_contracts::cloud::ConflictReview) -> String {
    if review.items.is_empty() {
        return "No conflicts: this device and the cloud agree.".into();
    }
    let mut text = String::new();
    for item in &review.items {
        text += &format!(
            "Item {}: this device \"{}\"{}cloud \"{}\"\n",
            item.id,
            metadata(&item.local).as_str(),
            dot(style),
            metadata(&item.remote).as_str()
        );
        for field in &item.fields {
            text += &format!(
                "  {}: this device {}{}cloud {}\n",
                metadata(&field.field).as_str(),
                metadata(&field.local).as_str(),
                dot(style),
                metadata(&field.remote).as_str()
            );
        }
    }
    let example = review
        .items
        .first()
        .and_then(|item| item.fields.first().map(|field| (item.id, field)))
        .map(|(id, field)| format!(" --choose {id}:{}:local", metadata(&field.field).as_str()))
        .unwrap_or_default();
    text + &format!(
        "\nResolve with `pm sync resolve --review {}{example}` (one --choose per field; local \
         or remote).\n",
        metadata(&review.token).as_str()
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn timestamps_use_the_given_zone_and_leave_other_text_alone() {
        let utc = jiff::tz::TimeZone::UTC;
        assert_eq!(
            super::timestamp_in("2026-11-19T04:11:18.793348284+00:00", &utc),
            "2026-11-19 04:11 UTC"
        );
        let plus_one = jiff::tz::TimeZone::fixed(jiff::tz::offset(1));
        assert!(
            super::timestamp_in("2026-11-19T04:11:18Z", &plus_one).starts_with("2026-11-19 05:11")
        );
        assert_eq!(super::timestamp_in("yesterday", &utc), "yesterday");
    }

    #[test]
    fn empty_lists_distinguish_an_empty_vault_from_no_matches() {
        let page = pm_contracts::vault::ItemPage {
            items: vec![],
            total: 0,
        };
        assert!(super::item_page(super::Style::default(), &page, None).contains("no items yet"));
        assert_eq!(
            super::item_page(super::Style::default(), &page, Some("No items match.")),
            "No items match."
        );
    }
}
