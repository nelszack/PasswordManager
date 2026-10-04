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
    generate_password_with_rng(len, options, &mut rand::rng())
}

fn generate_password_with_rng<R: Rng + ?Sized>(
    len: u8,
    options: &PasswordOptions<'_>,
    rng: &mut R,
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
    let mut password = Vec::with_capacity(len as usize);

    if len as usize >= classes.len() {
        for class in &classes {
            password.push(class[rng.random_range(0..class.len())]);
        }
    }

    while password.len() < len as usize {
        password.push(charset[rng.random_range(0..charset.len())]);
    }
    password.shuffle(rng);
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
    let pass = zeroize::Zeroizing::new(pass);
    let mut output = format!("Password: {}\n", pass.as_str());
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
#[path = "password_tests.rs"]
mod test;
