use crate::clipboard::copy_with_timeout;
use rand::prelude::*;
use zxcvbn::{Score, zxcvbn};

pub struct PasswordOptions<'a> {
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: Option<&'a str>,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions<'_> {
    fn default() -> Self {
        Self {
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: Some("!@#$%^&*-_=+"),
            exclude_ambiguous: false,
        }
    }
}

pub fn generate_password(len: u8) -> String {
    generate_password_with_options(len, &PasswordOptions::default())
        .expect("password length must be nonzero and the default character set must be valid")
}

pub fn generate_password_with_options(
    len: u8,
    options: &PasswordOptions<'_>,
) -> Result<String, String> {
    const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
    const DIGITS: &str = "0123456789";
    const AMBIGUOUS: &str = "Il1O0o|`'\"";
    if len == 0 {
        return Err("password length must be at least one".to_string());
    }
    if options.symbols.is_some_and(|symbols| !symbols.is_ascii()) {
        return Err("symbols must contain ASCII characters only".to_string());
    }
    let mut classes = Vec::new();
    for (enabled, characters) in [
        (options.uppercase, UPPERCASE),
        (options.lowercase, LOWERCASE),
        (options.digits, DIGITS),
        (options.symbols.is_some(), options.symbols.unwrap_or("")),
    ] {
        if enabled {
            let class: Vec<u8> = characters
                .bytes()
                .filter(|byte| !options.exclude_ambiguous || !AMBIGUOUS.as_bytes().contains(byte))
                .collect();
            if !class.is_empty() {
                classes.push(class);
            }
        }
    }
    if classes.is_empty() {
        return Err("at least one non-empty character class is required".to_string());
    }
    let charset: Vec<u8> = classes.iter().flatten().copied().collect();
    let mut rng = rand::rng();
    let mut password = Vec::with_capacity(len as usize);

    if len as usize >= classes.len() {
        for class in &classes {
            password.push(class[rng.random_range(0..class.len())]);
        }
    }

    while password.len() < len as usize {
        password.push(charset[rng.random_range(0..charset.len())]);
    }
    password.shuffle(&mut rng);
    String::from_utf8(password)
        .map_err(|_| "symbols must contain ASCII characters only".to_string())
}

pub fn generate_passphrase(words: u8, separator: &str) -> Result<String, String> {
    const LEFT: &[&str] = &[
        "amber", "ancient", "autumn", "bold", "bright", "calm", "cedar", "cinder", "clear",
        "cloud", "cobalt", "coral", "crisp", "dawn", "deep", "ember", "fable", "fair", "fern",
        "frost", "gentle", "gold", "grand", "green", "harbor", "hidden", "indigo", "iron", "ivory",
        "jade", "keen", "lively", "lunar", "maple", "merry", "misty", "noble", "north", "ocean",
        "olive", "opal", "quiet", "rapid", "red", "river", "royal", "sage", "silver", "solar",
        "solid", "spring", "stone", "swift", "tender", "tidal", "true", "velvet", "vivid", "warm",
        "wild", "winter", "wise", "young", "zenith",
    ];
    const RIGHT: &[&str] = &[
        "acorn", "badger", "beacon", "birch", "brook", "canyon", "castle", "comet", "crane",
        "creek", "dolphin", "eagle", "falcon", "field", "finch", "forest", "fox", "garden",
        "glade", "grove", "heron", "hill", "island", "lake", "lantern", "lark", "leaf", "meadow",
        "moon", "oak", "otter", "owl", "panda", "peak", "pine", "planet", "quartz", "raven",
        "reef", "ridge", "robin", "sail", "shore", "sparrow", "star", "summit", "sun", "tiger",
        "trail", "tree", "valley", "violet", "wave", "willow", "wind", "wolf", "wren", "yard",
        "zephyr", "harvest", "isle", "orchard", "prairie", "rain",
    ];
    if words == 0 {
        return Err("passphrases require at least one word".to_string());
    }
    if separator.contains(['\n', '\r']) {
        return Err("the separator cannot contain a newline".to_string());
    }
    let mut rng = rand::rng();
    Ok((0..words)
        .map(|_| {
            format!(
                "{}{}",
                LEFT[rng.random_range(0..LEFT.len())],
                RIGHT[rng.random_range(0..RIGHT.len())]
            )
        })
        .collect::<Vec<_>>()
        .join(separator))
}

pub fn generated_password_output(
    pass: String,
    stats: bool,
    copy: bool,
    copy_time: u8,
) -> (String, Option<String>) {
    let mut output = format!("Password: {pass}\n");
    if stats {
        output.push_str(&password_strength_output(&pass));
    }
    let warning = if copy {
        copy_with_timeout(&pass, copy_time).err()
    } else {
        None
    };
    (output, warning)
}

pub fn password_strength_output(pass: &str) -> String {
    let mut output = String::from("Password stats:\n");
    let estimate = zxcvbn(pass, &[]);
    let entropy = (estimate.guesses() as f64).log2();
    output.push_str(&format!("    Score (0-4): {}\n", estimate.score()));
    output.push_str(&format!("    Entropy: {entropy:.2} bits\n"));
    let rating = match estimate.score() {
        Score::Zero => "Very Weak",
        Score::One => "Weak",
        Score::Two => "Fair",
        Score::Three => "Good",
        Score::Four => "Strong",
        _ => unreachable!(),
    };
    output.push_str(&format!("    Strength: {rating}\n"));
    if let Some(feedback) = estimate.feedback() {
        if let Some(warning) = feedback.warning() {
            output.push_str(&format!("    Warning: {warning}\n"));
        }
        let mut parts = Vec::new();
        for suggestion in feedback.suggestions() {
            parts.push(suggestion.to_string());
        }
        if !parts.is_empty() {
            output.push_str(&format!("    Suggestions: {}\n", parts.join(". ")));
        }
    }
    output
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_generate_password_length() {
        for len in 1..=64u8 {
            let pass = generate_password(len);
            assert_eq!(pass.len(), len as usize);
        }
    }

    #[test]
    fn test_generate_password_charset() {
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";
        let pass = generate_password(200);
        for c in pass.chars() {
            assert!(
                CHARSET.contains(&(c as u8)),
                "Character '{}' not in charset",
                c
            );
        }
    }

    #[test]
    fn test_generate_password_uniqueness() {
        let pass1 = generate_password(32);
        let pass2 = generate_password(32);
        assert_ne!(pass1, pass2, "Generated passwords should be unique");
    }

    #[test]
    fn test_generate_password_empty_is_rejected() {
        assert!(generate_password_with_options(0, &PasswordOptions::default()).is_err());
    }

    #[test]
    fn test_generate_password_contains_uppercase() {
        let pass = generate_password(100);
        assert!(pass.chars().any(|c| c.is_uppercase()));
    }

    #[test]
    fn test_generate_password_contains_lowercase() {
        let pass = generate_password(100);
        assert!(pass.chars().any(|c| c.is_lowercase()));
    }

    #[test]
    fn test_generate_password_contains_digits() {
        let pass = generate_password(100);
        assert!(pass.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_password_contains_special() {
        let special_chars = "!@#$%^&*-_=+";
        let pass = generate_password(200);
        assert!(
            pass.chars().any(|c| special_chars.contains(c)),
            "Password should contain at least one special character"
        );
    }

    #[test]
    fn test_practical_lengths_guarantee_all_character_classes() {
        for len in [4, 12, 32, 255] {
            let pass = generate_password(len);
            assert!(pass.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pass.chars().any(|c| c.is_ascii_lowercase()));
            assert!(pass.chars().any(|c| c.is_ascii_digit()));
            assert!(pass.chars().any(|c| "!@#$%^&*-_=+".contains(c)));
        }
    }

    #[test]
    fn test_generate_password_long_length() {
        let pass = generate_password(128);
        assert_eq!(pass.len(), 128);
    }

    #[test]
    fn test_generate_password_max_u8_length() {
        let pass = generate_password(u8::MAX);
        assert_eq!(pass.len(), u8::MAX as usize);
    }

    #[test]
    fn test_generate_password_single_char() {
        let pass = generate_password(1);
        assert_eq!(pass.len(), 1);
        assert!(pass.chars().next().is_some());
    }

    #[test]
    fn test_generate_password_boundary_lengths() {
        for len in &[1u8, 2, 11, 12, 13, 64, 127, 200, 255] {
            let pass = generate_password(*len);
            assert_eq!(pass.len(), *len as usize, "Length {} failed", len);
        }
    }

    #[test]
    fn test_generate_password_all_special_chars() {
        let special_chars = "!@#$%^&*-_=+";
        let mut all_found = true;
        for special in special_chars.chars() {
            let mut found = false;
            for _ in 0..1000 {
                let pass = generate_password(100);
                if pass.contains(special) {
                    found = true;
                    break;
                }
            }
            if !found {
                all_found = false;
                break;
            }
        }
        assert!(all_found, "Not all special characters were generated");
    }

    #[test]
    fn test_generate_password_no_whitespace() {
        let pass = generate_password(255);
        assert!(
            !pass.chars().any(|c| c.is_whitespace()),
            "Password should not contain whitespace"
        );
    }

    #[test]
    fn test_generate_password_all_ascii() {
        let pass = generate_password(255);
        assert!(
            pass.is_ascii(),
            "Password should only contain ASCII characters"
        );
    }

    #[test]
    fn test_custom_character_classes_and_ambiguous_filter() {
        let password = generate_password_with_options(
            100,
            &PasswordOptions {
                uppercase: false,
                lowercase: false,
                digits: true,
                symbols: None,
                exclude_ambiguous: true,
            },
        )
        .unwrap();
        assert!(password.bytes().all(|byte| byte.is_ascii_digit()));
        assert!(!password.contains('0'));
        assert!(!password.contains('1'));
    }

    #[test]
    fn invalid_or_empty_character_sets_are_rejected() {
        let no_characters = PasswordOptions {
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: None,
            exclude_ambiguous: false,
        };
        assert!(generate_password_with_options(16, &no_characters).is_err());

        let empty_symbols = PasswordOptions {
            symbols: Some(""),
            ..no_characters
        };
        assert!(generate_password_with_options(16, &empty_symbols).is_err());

        let non_ascii_symbols = PasswordOptions {
            symbols: Some("🔐"),
            ..no_characters
        };
        assert!(generate_password_with_options(16, &non_ascii_symbols).is_err());
    }

    #[test]
    fn short_passwords_still_use_only_the_requested_characters() {
        let symbols_only = PasswordOptions {
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: Some("xy"),
            exclude_ambiguous: false,
        };
        assert!(generate_password_with_options(0, &symbols_only).is_err());
        for length in 1..=3 {
            let password = generate_password_with_options(length, &symbols_only).unwrap();
            assert_eq!(password.len(), length as usize);
            assert!(password.bytes().all(|byte| matches!(byte, b'x' | b'y')));
        }
    }

    #[test]
    fn test_passphrase_word_count_and_separator() {
        let phrase = generate_passphrase(6, ".").unwrap();
        assert_eq!(phrase.split('.').count(), 6);
        assert!(generate_passphrase(0, "-").is_err());
        assert!(generate_passphrase(2, "\n").is_err());
        assert!(generate_passphrase(2, "\r\n").is_err());
    }

    #[test]
    fn test_generate_password_reasonable_randomness() {
        let mut unique_passwords = std::collections::HashSet::new();
        for _ in 0..100 {
            let pass = generate_password(32);
            assert!(
                unique_passwords.insert(pass),
                "Generated duplicate password"
            );
        }
    }
}
