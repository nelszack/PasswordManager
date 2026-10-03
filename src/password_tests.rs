use super::*;
use rand::rngs::StdRng;

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
fn test_generate_password_empty_is_rejected() {
    assert!(generate_password_with_options(0, &PasswordOptions::default()).is_err());
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
fn test_generate_password_boundary_lengths() {
    for len in &[1u8, 2, 11, 12, 13, 64, 127, 200, 255] {
        let pass = generate_password(*len);
        assert_eq!(pass.len(), *len as usize, "Length {} failed", len);
    }
}

#[test]
fn seeded_generation_is_reproducible() {
    let mut first = StdRng::seed_from_u64(42);
    let mut second = StdRng::seed_from_u64(42);
    let options = PasswordOptions::default();
    assert_eq!(
        generate_password_with_rng(64, &options, &mut first).unwrap(),
        generate_password_with_rng(64, &options, &mut second).unwrap()
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
fn seeded_stream_advances_between_passwords() {
    let mut rng = StdRng::seed_from_u64(7);
    let options = PasswordOptions::default();
    let first = generate_password_with_rng(32, &options, &mut rng).unwrap();
    let second = generate_password_with_rng(32, &options, &mut rng).unwrap();
    assert_ne!(first, second);
}
