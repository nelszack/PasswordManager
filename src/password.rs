use crate::clipboard::copy_with_timeout;
use rand::{distributions::Uniform, prelude::*};
use zxcvbn::{Score, zxcvbn};

pub fn generate_password(len: u8) -> String {
    const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const DIGITS: &[u8] = b"0123456789";
    const SPECIAL: &[u8] = b"!@#$%^&*-_=+";
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";
    let mut rng = rand::rngs::OsRng;
    let mut password = Vec::with_capacity(len as usize);

    // At practical password lengths, guarantee every major character class
    // instead of merely hoping random sampling includes each one.
    if len >= 4 {
        for class in [UPPERCASE, LOWERCASE, DIGITS, SPECIAL] {
            password.push(class[rng.gen_range(0..class.len())]);
        }
    }

    let range = Uniform::from(0..CHARSET.len());
    while password.len() < len as usize {
        password.push(CHARSET[rng.sample(range)]);
    }
    password.shuffle(&mut rng);
    String::from_utf8(password).expect("password character set is ASCII")
}

pub fn generate_and_print_password(len: u8, stats: bool, copy: bool, copy_time: u8) {
    if len < 12 {
        println!("Tip: for better security, use a password length of at least 12.")
    }
    let pass = generate_password(len);
    println!("Password: {}", pass);
    if stats {
        print_password_strength(&pass);
    }
    if copy && let Err(error) = copy_with_timeout(&pass, copy_time) {
        eprintln!("Warning: {error}");
    }
}

pub fn print_password_strength(pass: &str) {
    println!("Password stats:");
    let estimate = zxcvbn(pass, &[]);
    let entropy = (estimate.guesses() as f64).log2();
    println!("    Score (0-4): {}", estimate.score());
    println!("    Entropy: {:.2} bits", entropy);
    let rating = match estimate.score() {
        Score::Zero => "Very Weak",
        Score::One => "Weak",
        Score::Two => "Fair",
        Score::Three => "Good",
        Score::Four => "Strong",
        _ => unreachable!(),
    };
    println!("    Strength: {}", rating);
    if let Some(feedback) = estimate.feedback() {
        if let Some(warning) = feedback.warning() {
            println!("    Warning: {}", warning)
        }
        let mut parts = Vec::new();
        for suggestion in feedback.suggestions() {
            parts.push(suggestion.to_string());
        }
        if !parts.is_empty() {
            println!("    Suggestions: {}", parts.join(". "));
        }
    }
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
    fn test_generate_password_empty() {
        let pass = generate_password(0);
        assert_eq!(pass.len(), 0);
        assert_eq!(pass, "");
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
