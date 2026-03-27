use crate::clpboard::cpy;
use rand::{distributions::Uniform, prelude::*};
use zxcvbn::{Score, zxcvbn};

pub fn pass_gen(len: u8) -> String {
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";
    let mut rng = rand::rngs::OsRng;
    let range = Uniform::from(0..CHARSET.len());

    let pass: String = (0..len)
        .map(|_| {
            let idx = rng.sample(range);
            CHARSET[idx] as char
        })
        .collect();
    pass
}

pub fn gen_pass(len: u8, stats: bool, copy: bool, copy_time: u8) {
    if len < 12 {
        println!("for better security the recomended password length at least 12")
    }
    let pass = pass_gen(len);
    println!("password: {}", pass);
    if stats {
        pass_str(&pass);
    }
    if copy {
        cpy(&pass, copy_time);
    }
}

pub fn pass_str(pass: &String) {
    println!("password stats:");
    let estimate = zxcvbn(&pass, &[]);
    let entropy = (estimate.guesses() as f64).log2();
    println!("    score (0-4): {}", estimate.score());
    println!("    entropy: {}", entropy);
    let rating = match estimate.score() {
        Score::Zero => "Very Weak",
        Score::One => "Weak",
        Score::Two => "Fair",
        Score::Three => "Good",
        Score::Four => "Strong",
        _ => unreachable!(),
    };
    println!("    password strength: {}", rating);
    if let Some(fdback) = estimate.feedback() {
        if let Some(warning) = fdback.warning() {
            println!("    WARNING: {}", warning.to_string())
        }
        let mut parts = Vec::new();
        for suggestions in fdback.suggestions() {
            parts.push(suggestions.to_string());
        }
        if let Some(sugestion_str) = Some(parts.join(". ")) {
            println!("    Suggestion(s): {}", sugestion_str);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pass_gen_length() {
        for len in 1..=64u8 {
            let pass = pass_gen(len);
            assert_eq!(pass.len(), len as usize);
        }
    }

    #[test]
    fn test_pass_gen_charset() {
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";
        let pass = pass_gen(200);
        for c in pass.chars() {
            assert!(
                CHARSET.contains(&(c as u8)),
                "Character '{}' not in charset",
                c
            );
        }
    }

    #[test]
    fn test_pass_gen_uniqueness() {
        let pass1 = pass_gen(32);
        let pass2 = pass_gen(32);
        assert_ne!(pass1, pass2, "Generated passwords should be unique");
    }

    #[test]
    fn test_pass_gen_empty() {
        let pass = pass_gen(0);
        assert_eq!(pass.len(), 0);
        assert_eq!(pass, "");
    }

    #[test]
    fn test_pass_gen_contains_uppercase() {
        let pass = pass_gen(100);
        assert!(pass.chars().any(|c| c.is_uppercase()));
    }

    #[test]
    fn test_pass_gen_contains_lowercase() {
        let pass = pass_gen(100);
        assert!(pass.chars().any(|c| c.is_lowercase()));
    }

    #[test]
    fn test_pass_gen_contains_digits() {
        let pass = pass_gen(100);
        assert!(pass.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_pass_gen_contains_special() {
        let special_chars = "!@#$%^&*-_=+";
        let pass = pass_gen(200);
        assert!(
            pass.chars().any(|c| special_chars.contains(c)),
            "Password should contain at least one special character"
        );
    }

    #[test]
    fn test_pass_gen_long_length() {
        let pass = pass_gen(128);
        assert_eq!(pass.len(), 128);
    }

    #[test]
    fn test_pass_gen_max_u8_length() {
        let pass = pass_gen(u8::MAX);
        assert_eq!(pass.len(), u8::MAX as usize);
    }

    #[test]
    fn test_pass_gen_single_char() {
        let pass = pass_gen(1);
        assert_eq!(pass.len(), 1);
        assert!(pass.chars().next().is_some());
    }

    #[test]
    fn test_pass_gen_boundary_lengths() {
        for len in &[1u8, 2, 11, 12, 13, 64, 127, 200, 255] {
            let pass = pass_gen(*len);
            assert_eq!(pass.len(), *len as usize, "Length {} failed", len);
        }
    }

    #[test]
    fn test_pass_gen_all_special_chars() {
        let special_chars = "!@#$%^&*-_=+";
        let mut all_found = true;
        for special in special_chars.chars() {
            let mut found = false;
            for _ in 0..1000 {
                let pass = pass_gen(100);
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
    fn test_pass_gen_no_whitespace() {
        let pass = pass_gen(255);
        assert!(
            !pass.chars().any(|c| c.is_whitespace()),
            "Password should not contain whitespace"
        );
    }

    #[test]
    fn test_pass_gen_all_ascii() {
        let pass = pass_gen(255);
        assert!(
            pass.chars().all(|c| c.is_ascii()),
            "Password should only contain ASCII characters"
        );
    }

    #[test]
    fn test_pass_gen_reasonable_randomness() {
        let mut unique_passwords = std::collections::HashSet::new();
        for _ in 0..100 {
            let pass = pass_gen(32);
            assert!(
                unique_passwords.insert(pass),
                "Generated duplicate password"
            );
        }
    }
}
