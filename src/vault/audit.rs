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
