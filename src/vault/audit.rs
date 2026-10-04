use super::*;

pub(super) fn password_hash(password: &str) -> String {
    hex::encode_upper(Sha1::digest(password.as_bytes()))
}

#[cfg(test)]
pub(super) fn parse_pwned_range(body: &str, prefix: &str) -> HashMap<String, u64> {
    parse_pwned_range_matching(body, prefix, |_| true)
}

fn parse_pwned_range_matching(
    body: &str,
    prefix: &str,
    wanted: impl Fn(&str) -> bool,
) -> HashMap<String, u64> {
    body.lines()
        .filter_map(|line| {
            let (suffix, count) = line.trim().split_once(':')?;
            let count = count.parse::<u64>().ok()?;
            if count == 0 {
                return None;
            }
            let mut hash = Zeroizing::new(format!("{prefix}{}", suffix.to_ascii_uppercase()));
            wanted(&hash).then(|| (std::mem::take(&mut *hash), count))
        })
        .collect()
}

// These hashes are password verifiers; clear additional audit-owned copies.
struct BreachTargets(HashSet<String>);
impl Drop for BreachTargets {
    fn drop(&mut self) {
        for mut hash in self.0.drain() {
            hash.zeroize();
        }
    }
}

struct BreachCheck {
    matches: HashMap<String, u64>,
    unchecked_prefixes: HashSet<String>,
    error: Option<String>,
}

async fn breached_hashes<'a>(password_hashes: impl Iterator<Item = &'a str>) -> BreachCheck {
    let mut targets = BreachTargets(HashSet::new());
    for hash in password_hashes {
        if !targets.0.contains(hash) {
            targets.0.insert(hash.to_owned());
        }
    }
    let targets = std::sync::Arc::new(targets);
    let prefixes = targets
        .0
        .iter()
        .map(|hash| hash[..5].to_string())
        .collect::<HashSet<_>>();
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("password-manager/0.1 breach-audit")
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return BreachCheck {
                matches: HashMap::new(),
                unchecked_prefixes: prefixes,
                error: Some(format!("could not initialize breach checker: {error}")),
            };
        }
    };
    // Finish before the CLI's five-minute response timeout, retaining partial results.
    check_breached_prefixes(prefixes, std::time::Duration::from_secs(240), |prefix| {
        fetch_breached_prefix(client.clone(), prefix, std::sync::Arc::clone(&targets))
    })
    .await
}

async fn check_breached_prefixes<F, Fut>(
    prefixes: HashSet<String>,
    timeout: std::time::Duration,
    fetch: F,
) -> BreachCheck
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<HashMap<String, u64>, String>> + Send + 'static,
{
    let mut check = BreachCheck {
        matches: HashMap::new(),
        unchecked_prefixes: prefixes.clone(),
        error: None,
    };
    const MAX_CONCURRENT_REQUESTS: usize = 8;
    let mut pending = prefixes.into_iter();
    let mut requests = tokio::task::JoinSet::new();
    let deadline = tokio::time::Instant::now() + timeout;
    let spawn = |requests: &mut tokio::task::JoinSet<_>, prefix: String| {
        let response = fetch(prefix.clone());
        requests.spawn(async move { (prefix, response.await) });
    };
    for prefix in pending.by_ref().take(MAX_CONCURRENT_REQUESTS) {
        spawn(&mut requests, prefix);
    }
    loop {
        let result = match tokio::time::timeout_at(deadline, requests.join_next()).await {
            Ok(Some(result)) => result,
            Ok(None) => break,
            Err(_) => {
                let message = "overall breach-check deadline exceeded";
                check.error = Some(match check.error.take() {
                    Some(error) => format!("{error}; {message}"),
                    None => message.into(),
                });
                break;
            }
        };
        match result {
            Ok((prefix, Ok(matches))) => {
                check.unchecked_prefixes.remove(&prefix);
                check.matches.extend(matches);
            }
            Ok((_, Err(error))) => {
                check.error.get_or_insert(error);
            }
            Err(error) => {
                check
                    .error
                    .get_or_insert_with(|| format!("breach-check task failed: {error}"));
            }
        }
        if let Some(prefix) = pending.next() {
            spawn(&mut requests, prefix);
        }
    }
    // Drop/abort pending requests immediately on deadline or completion.
    requests.abort_all();
    check
}

async fn fetch_breached_prefix(
    client: reqwest::Client,
    prefix: String,
    targets: std::sync::Arc<BreachTargets>,
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
    let matches = parse_pwned_range_matching(text, &prefix, |hash| targets.0.contains(hash));
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
        let now = chrono::Utc::now();
        let entries = self
            .entries
            .iter()
            .filter(|entry| {
                metadata_by_id
                    .get(&entry.id)
                    .is_none_or(|metadata| metadata.kind == ItemKind::Login)
            })
            .map(|entry| {
                let changed = self
                    .password_changed_with_metadata(entry, metadata_by_id.get(&entry.id).copied());
                AuditEntrySnapshot {
                    id: entry.id,
                    name: entry.name.clone(),
                    username: entry.username.clone(),
                    password_hash: password_hash(&entry.password),
                    weak: zxcvbn::zxcvbn(&entry.password, &[]).score() <= zxcvbn::Score::Two,
                    stale: options
                        .stale_days
                        .is_some_and(|days| password_is_stale_at(changed, days, now)),
                    password_changed: changed.to_string(),
                    missing_totp: options.require_totp && !totp_ids.contains(&entry.id),
                    identity: (
                        entry
                            .url
                            .as_deref()
                            .and_then(hostname)
                            .unwrap_or_else(|| entry.name.to_ascii_lowercase()),
                        entry.username.as_deref().unwrap_or("").to_ascii_lowercase(),
                    ),
                }
            })
            .collect();
        AuditSnapshot { entries }
    }
}

impl AuditSnapshot {
    pub(super) fn findings(
        &self,
        breached: Option<&HashMap<String, u64>>,
        breach_error: Option<&str>,
    ) -> AuditReport {
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
        AuditReport {
            total: self.entries.len(),
            healthy,
            score,
            weak: weak.into_iter().map(AuditEntrySnapshot::label).collect(),
            reused: reused
                .into_iter()
                .map(|group| group.iter().map(|entry| entry.label()).collect())
                .collect(),
            duplicates: duplicates
                .into_iter()
                .map(|group| group.iter().map(|entry| entry.label()).collect())
                .collect(),
            stale: stale.into_iter().map(AuditEntrySnapshot::label).collect(),
            missing_totp: missing_totp
                .into_iter()
                .map(AuditEntrySnapshot::label)
                .collect(),
            breached: breached_entries
                .into_iter()
                .map(|(entry, count)| (entry.label(), count))
                .collect(),
            breach_error: breach_error.map(str::to_owned),
            unchecked: vec![],
        }
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
        self.audit_outcome(breach_result.as_ref())
    }

    fn audit_outcome(&self, check: Option<&BreachCheck>) -> AuditOutcome {
        let mut report = self.findings(
            check.map(|check| &check.matches),
            check.and_then(|check| check.error.as_deref()),
        );
        if let Some(check) = check {
            let unchecked: Vec<_> = self
                .entries
                .iter()
                .filter(|entry| check.unchecked_prefixes.contains(&entry.password_hash[..5]))
                .collect();
            report.unchecked = unchecked
                .into_iter()
                .map(AuditEntrySnapshot::label)
                .collect();
        }

        AuditOutcome {
            report,
            incomplete: check
                .is_some_and(|check| check.error.is_some() || !check.unchecked_prefixes.is_empty()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    #[test]
    fn range_parser_retains_only_target_hashes_and_ignores_padding() {
        let targets = HashSet::from(["FFFFFABCDE".to_string(), "FFFFF12345".to_string()]);
        let parsed = parse_pwned_range_matching(
            "abcde:12\r\n12345:0\r\n99999:42\r\nbroken\r\nABCDE:invalid\r\n",
            "FFFFF",
            |hash| targets.contains(hash),
        );
        assert_eq!(parsed, HashMap::from([("FFFFFABCDE".into(), 12)]));
        assert!(
            parse_pwned_range_matching("99999:42", "FFFFF", |hash| targets.contains(hash))
                .is_empty()
        );
    }

    #[tokio::test]
    async fn range_checks_bound_concurrency_and_preserve_complete_or_partial_results() {
        for (total, failures, known_breaches) in [
            (0, vec![], false),
            (1, vec![], false),
            (12, vec![], true),
            (12, vec![1, 6], true),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let active = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let failed_prefixes: HashSet<String> =
                failures.into_iter().map(|id| format!("{id:05}")).collect();
            let prefixes = (0..total).map(|id| format!("{id:05}")).collect();
            let result = check_breached_prefixes(prefixes, Duration::from_secs(1), |prefix| {
                let calls = Arc::clone(&calls);
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);
                let failed = failed_prefixes.contains(&prefix);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(count, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    if failed {
                        Err("synthetic network failure".into())
                    } else if known_breaches {
                        Ok(HashMap::from([(format!("{prefix}{}", "A".repeat(35)), 42)]))
                    } else {
                        Ok(HashMap::new())
                    }
                }
            })
            .await;
            assert_eq!(calls.load(Ordering::SeqCst), total);
            assert_eq!(peak.load(Ordering::SeqCst), total.min(8));
            assert_eq!(
                result.matches.len(),
                (total - failed_prefixes.len()) * usize::from(known_breaches)
            );
            assert_eq!(result.error.is_some(), !failed_prefixes.is_empty());
            assert_eq!(result.unchecked_prefixes, failed_prefixes);
        }
    }

    #[tokio::test]
    async fn overall_deadline_retains_results_and_cancels_hanging_ranges() {
        let dropped = Arc::new(AtomicUsize::new(0));
        struct Dropped(Arc<AtomicUsize>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let start = tokio::time::Instant::now();
        let result = check_breached_prefixes(
            HashSet::from(["00000".into(), "00001".into()]),
            Duration::from_millis(30),
            |prefix| {
                let dropped = Arc::clone(&dropped);
                async move {
                    if prefix == "00000" {
                        Ok(HashMap::from([("known-hash".into(), 42)]))
                    } else {
                        let _dropped = Dropped(dropped);
                        std::future::pending().await
                    }
                }
            },
        )
        .await;
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(result.matches.get("known-hash"), Some(&42));
        assert_eq!(result.unchecked_prefixes, HashSet::from(["00001".into()]));
        assert!(result.error.unwrap().contains("deadline exceeded"));
        tokio::task::yield_now().await;
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn partial_report_marks_unchecked_entries_without_exposing_passwords() {
        let passwords = [
            "synthetic-breached-password",
            "synthetic-unchecked-password",
        ];
        let vault = Vault {
            entries: passwords
                .iter()
                .enumerate()
                .map(|(index, password)| VaultEntry {
                    id: index + 1,
                    name: format!("Account {}", index + 1),
                    password: (*password).into(),
                    ..Default::default()
                })
                .collect(),
            metadata: VaultMetadata::default(),
            recovery: RecoveryData::default(),
        };
        let snapshot = vault.audit_snapshot(&AuditOptions::default());
        let check = BreachCheck {
            matches: HashMap::from([(password_hash(passwords[0]), 42)]),
            unchecked_prefixes: HashSet::from([password_hash(passwords[1])[..5].to_owned()]),
            error: Some("synthetic network failure".into()),
        };
        let outcome = snapshot.audit_outcome(Some(&check));
        assert!(outcome.incomplete);
        assert_eq!(outcome.report.breached[0].0.id, 1);
        assert_eq!(outcome.report.unchecked[0].id, 2);
        let rendered = crate::server::presentation::audit(&outcome.report);
        assert!(rendered.contains("Breached password: 1. Account 1 (seen 42 times)"));
        assert!(rendered.contains("Unchecked breach status: 2. Account 2"));
        assert!(rendered.contains("1 of 2 login entries checked successfully"));
        for password in passwords {
            assert!(!rendered.contains(password));
        }
        assert!(!snapshot.audit(false).await.incomplete);
    }
}
