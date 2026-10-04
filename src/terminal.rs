use zeroize::Zeroizing;

/// Render untrusted metadata as one terminal-safe value. Stored data and raw
/// secret/export APIs remain unchanged.
pub(crate) fn metadata(value: &str) -> Zeroizing<String> {
    escape(value, false)
}

/// Preserve our output's layout while neutralizing terminal control sequences.
pub(crate) fn output(value: &str) -> Zeroizing<String> {
    escape(value, true)
}

fn escape(value: &str, preserve_layout: bool) -> Zeroizing<String> {
    let mut escaped = Zeroizing::new(String::with_capacity(value.len()));
    for c in value.chars() {
        if (c.is_control() && !(preserve_layout && matches!(c, '\n' | '\t')))
            || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            escaped.extend(c.escape_default());
        } else {
            escaped.push(c);
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_values_cannot_issue_terminal_commands_or_forge_rows() {
        let attack = "Name\x1b]52;c;c2VjcmV0\x07\r\n\t\u{009b}31m\u{202e}é";
        let rendered = metadata(attack);
        assert_eq!(
            rendered.as_str(),
            "Name\\u{1b}]52;c;c2VjcmV0\\u{7}\\r\\n\\t\\u{9b}31m\\u{202e}é"
        );
        assert!(!rendered.chars().any(char::is_control));
        assert_eq!(
            output("line\n\tvalue\x1b[2J").as_str(),
            "line\n\tvalue\\u{1b}[2J"
        );
    }
}
