use super::*;

pub(super) fn password_hash(password: &str) -> String {
    hex::encode_upper(Sha1::digest(password.as_bytes()))
}

pub(super) fn parse_pwned_range(body: &str, prefix: &str) -> HashMap<String, u64> {
    body.lines()
        .filter_map(|line| {
            let (suffix, count) = line.trim().split_once(':')?;
            let count = count.parse::<u64>().ok()?;
            (count > 0).then(|| (format!("{prefix}{}", suffix.to_ascii_uppercase()), count))
        })
        .collect()
}

pub(super) async fn breached_hashes<'a>(
    password_hashes: impl Iterator<Item = &'a str>,
) -> Result<HashMap<String, u64>, String> {
    let prefixes = password_hashes
        .map(|hash| hash[..5].to_string())
        .collect::<HashSet<_>>();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("password-manager/0.1 breach-audit")
        .build()
        .map_err(|error| format!("could not initialize breach checker: {error}"))?;
    const MAX_CONCURRENT_REQUESTS: usize = 8;
    let mut pending = prefixes.into_iter();
    let mut requests = tokio::task::JoinSet::new();
    for prefix in pending.by_ref().take(MAX_CONCURRENT_REQUESTS) {
        requests.spawn(fetch_breached_prefix(client.clone(), prefix));
    }

    let mut matches = HashMap::new();
    while let Some(result) = requests.join_next().await {
        matches.extend(result.map_err(|error| format!("breach-check task failed: {error}"))??);
        if let Some(prefix) = pending.next() {
            requests.spawn(fetch_breached_prefix(client.clone(), prefix));
        }
    }
    Ok(matches)
}

async fn fetch_breached_prefix(
    client: reqwest::Client,
    prefix: String,
) -> Result<HashMap<String, u64>, String> {
    const MAX_RANGE_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
    let response = client
        .get(format!("https://api.pwnedpasswords.com/range/{prefix}"))
        .header("Add-Padding", "true")
        .send()
        .await
        .map_err(|error| format!("Pwned Passwords request failed: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Pwned Passwords returned an error: {error}"))?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RANGE_RESPONSE_BYTES)
    {
        return Err("Pwned Passwords returned an oversized response".to_string());
    }
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("could not read Pwned Passwords response: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RANGE_RESPONSE_BYTES as usize {
            body.zeroize();
            return Err("Pwned Passwords returned an oversized response".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    let text = match std::str::from_utf8(&body) {
        Ok(text) => text,
        Err(error) => {
            body.zeroize();
            return Err(format!("Pwned Passwords returned invalid UTF-8: {error}"));
        }
    };
    let matches = parse_pwned_range(text, &prefix);
    body.zeroize();
    Ok(matches)
}

impl Vault {
    pub(crate) fn audit_snapshot(&self, options: &AuditOptions) -> AuditSnapshot {
        let metadata_by_id: HashMap<_, _> = self
            .recovery
            .entry_metadata
            .iter()
            .map(|record| (record.entry_id, record))
            .collect();
        let totp_ids: HashSet<_> = self
            .recovery
            .totp
            .iter()
            .map(|record| record.entry_id)
            .collect();
        let entries = self
            .entries
            .iter()
            .filter(|entry| {
                metadata_by_id
                    .get(&entry.id)
                    .is_none_or(|metadata| metadata.kind == ItemKind::Login)
            })
            .map(|entry| AuditEntrySnapshot {
                id: entry.id,
                name: entry.name.clone(),
                username: entry.username.clone(),
                password_hash: password_hash(&entry.password),
                weak: zxcvbn::zxcvbn(&entry.password, &[]).score() <= zxcvbn::Score::Two,
                stale: options
                    .stale_days
                    .is_some_and(|days| self.password_is_stale(entry, days)),
                password_changed: self.password_changed(entry).to_string(),
                missing_totp: options.require_totp && !totp_ids.contains(&entry.id),
                identity: (
                    entry
                        .url
                        .as_deref()
                        .and_then(hostname)
                        .unwrap_or_else(|| entry.name.to_ascii_lowercase()),
                    entry.username.as_deref().unwrap_or("").to_ascii_lowercase(),
                ),
            })
            .collect();
        AuditSnapshot { entries }
    }
}

impl AuditSnapshot {
    pub(super) fn report(
        &self,
        breached: Option<&HashMap<String, u64>>,
        breach_error: Option<&str>,
    ) -> String {
        let mut weak = Vec::new();
        let mut stale = Vec::new();
        let mut missing_totp = Vec::new();
        let mut breached_entries = Vec::new();
        let mut passwords: HashMap<&str, Vec<&AuditEntrySnapshot>> = HashMap::new();
        let mut identities: HashMap<&(String, String), Vec<&AuditEntrySnapshot>> = HashMap::new();
        let mut unhealthy = HashSet::new();

        for entry in &self.entries {
            if entry.weak {
                weak.push(entry);
                unhealthy.insert(entry.id);
            }
            if entry.stale {
                stale.push(entry);
                unhealthy.insert(entry.id);
            }
            if entry.missing_totp {
                missing_totp.push(entry);
                unhealthy.insert(entry.id);
            }
            if let Some(count) = breached
                .and_then(|hashes| hashes.get(&entry.password_hash))
                .copied()
            {
                breached_entries.push((entry, count));
                unhealthy.insert(entry.id);
            }
            passwords
                .entry(&entry.password_hash)
                .or_default()
                .push(entry);
            identities.entry(&entry.identity).or_default().push(entry);
        }
        let reused: Vec<_> = passwords
            .values()
            .filter(|entries| entries.len() > 1)
            .collect();
        for entries in &reused {
            unhealthy.extend(entries.iter().map(|entry| entry.id));
        }
        let duplicates: Vec<_> = identities
            .values()
            .filter(|entries| entries.len() > 1)
            .collect();
        for entries in &duplicates {
            unhealthy.extend(entries.iter().map(|entry| entry.id));
        }
        let healthy = self.entries.len().saturating_sub(unhealthy.len());
        let score = if self.entries.is_empty() {
            100
        } else {
            healthy * 100 / self.entries.len()
        };
        let mut report = format!(
            "Health score: {score}/100 ({healthy}/{} login entries have no detected issues).\nAudit: {} weak entries, {} reused-password groups, {} duplicate-login groups, {} stale entries, {} missing TOTP, {} breached entries.\n",
            self.entries.len(),
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
                entry.id, entry.name, entry.username
            ));
        }
        for entries in reused {
            let labels = entries
                .iter()
                .map(|entry| format!("{}. {}", entry.id, entry.name))
                .collect::<Vec<_>>()
                .join(", ");
            report.push_str(&format!("Reused password: {labels}\n"));
        }
        for entries in duplicates {
            let labels = entries
                .iter()
                .map(|entry| format!("{}. {}", entry.id, entry.name))
                .collect::<Vec<_>>()
                .join(", ");
            report.push_str(&format!("Duplicate login: {labels}\n"));
        }
        for entry in stale {
            report.push_str(&format!(
                "Stale password: {}. {} (last changed {})\n",
                entry.id, entry.name, entry.password_changed
            ));
        }
        for entry in missing_totp {
            report.push_str(&format!("Missing TOTP: {}. {}\n", entry.id, entry.name));
        }
        for (entry, count) in breached_entries {
            report.push_str(&format!(
                "Breached password: {}. {} (seen {count} times)\n",
                entry.id, entry.name
            ));
        }
        if let Some(error) = breach_error {
            report.push_str(&format!("Breach check unavailable: {error}\n"));
        }
        report
    }

    pub(crate) async fn audit(&self, check_breaches: bool) -> AuditOutcome {
        let breach_result = if check_breaches {
            Some(
                breached_hashes(
                    self.entries
                        .iter()
                        .map(|entry| entry.password_hash.as_str()),
                )
                .await,
            )
        } else {
            None
        };
        let (breached, error) = match breach_result.as_ref() {
            Some(Ok(matches)) => (Some(matches), None),
            Some(Err(error)) => (None, Some(error.as_str())),
            None => (None, None),
        };
        AuditOutcome {
            report: self.report(breached, error),
            incomplete: error.is_some(),
        }
    }
}
