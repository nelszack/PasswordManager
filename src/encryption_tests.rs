use super::*;
use proptest::prelude::*;
use std::fs;

#[test]
fn new_master_passwords_require_length_and_strength() {
    assert!(validate_new_password("").is_err());
    assert!(validate_new_password("thirteen-char").is_err());
    assert!(validate_new_password("aaaaaaaaaaaaaa").is_err());
    assert!(validate_new_password("password-password-password").is_err());
    assert!(validate_new_password("Cedar-Lantern-Quartz-9274!").is_ok());
}

#[test]
fn session_rewrites_preserve_the_parameters_that_derived_the_key() {
    let original_parameters = KdfParameters {
        memory_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    };
    let newer_parameters = KdfParameters {
        memory_kib: 16 * 1024,
        iterations: 2,
        parallelism: 2,
    };
    let password = "parameter-migration-test";
    let mut session = PasswordType::Password(password.into());
    let first = with_test_kdf_parameters(original_parameters, || {
        try_encrypt_file_in_place(&mut session, b"first".to_vec()).unwrap()
    });
    assert_eq!(
        u32::from_be_bytes(first[10..14].try_into().unwrap()),
        original_parameters.memory_kib
    );

    let rewritten = with_test_kdf_parameters(newer_parameters, || {
        try_encrypt_file_in_place(&mut session, b"rewritten".to_vec()).unwrap()
    });
    assert_eq!(
        u32::from_be_bytes(rewritten[10..14].try_into().unwrap()),
        original_parameters.memory_kib
    );
    assert_eq!(
        u32::from_be_bytes(rewritten[14..18].try_into().unwrap()),
        original_parameters.iterations
    );
    assert_eq!(
        u32::from_be_bytes(rewritten[18..22].try_into().unwrap()),
        original_parameters.parallelism
    );

    let mut fresh_password = PasswordType::Password(password.into());
    assert_eq!(
        decrypt_file(&mut fresh_password, &rewritten).as_deref(),
        Some(b"rewritten".as_slice())
    );
}

proptest! {
    #[test]
    fn arbitrary_encrypted_inputs_never_panic(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        let mut session = PasswordType::Session {
            encryption_key: [0; 32],
            salt: [0; 16],
            kdf: KDF_ARGON2ID,
            memory_kib: FAST_TEST_KDF_PARAMETERS.memory_kib,
            iterations: FAST_TEST_KDF_PARAMETERS.iterations,
            parallelism: FAST_TEST_KDF_PARAMETERS.parallelism,
        };
        let _ = decrypt_file(&mut session, &bytes);
    }

    #[test]
    fn out_of_policy_kdf_headers_are_rejected_without_derivation(
        memory_kib in prop_oneof![0u32..8192, 1_048_577u32..u32::MAX],
        iterations in 0u32..=10,
        parallelism in 0u32..=16,
    ) {
        let mut header = vec![0u8; HEADER_LEN + 16];
        header[..8].copy_from_slice(VAULT_MAGIC);
        header[8] = VAULT_VERSION;
        header[9] = KDF_ARGON2ID;
        header[10..14].copy_from_slice(&memory_kib.to_be_bytes());
        header[14..18].copy_from_slice(&iterations.to_be_bytes());
        header[18..22].copy_from_slice(&parallelism.to_be_bytes());
        let mut password = PasswordType::Password("parser-test".into());
        prop_assert!(decrypt_file(&mut password, &header).is_none());
    }
}

#[test]
fn test_encrypt_decrypt_pass() {
    let plaintext = "this is a test".as_bytes();
    let mut pass = PasswordType::Password("test123".into());
    let encrypt = encrypt_file(&mut pass, plaintext);
    let decrypt = decrypt_file(&mut pass, &encrypt).unwrap();
    assert_eq!(decrypt, plaintext)
}
#[test]
fn test_encrypt_decrypt_key() {
    crate::file::init_test_data_dir();
    let directory = tempfile::tempdir().unwrap();
    let temp = directory.path().join("temp.enc");
    gen_master_key(
        &mut PasswordType::Key(temp.to_string_lossy().into_owned()),
        true,
    );
    let plaintext = "this is a test".as_bytes();
    let mut pass = PasswordType::Key(temp.to_str().unwrap().to_string());
    let encrypt = encrypt_file(&mut pass, plaintext);
    let decrypt = decrypt_file(&mut pass, &encrypt).unwrap();
    fs::remove_file(temp).unwrap();
    assert_eq!(decrypt, plaintext)
}
#[test]
fn test_encrypt_decrypt_empty_plaintext() {
    let plaintext = b"";
    let mut pass = PasswordType::Password("test123".into());
    let encrypt = encrypt_file(&mut pass, plaintext);
    let decrypt = decrypt_file(&mut pass, &encrypt).unwrap();
    assert_eq!(decrypt, plaintext);
}
#[test]
fn test_encrypt_decrypt_large_plaintext() {
    let plaintext = vec![0u8; 10000];
    let mut pass = PasswordType::Password("test123".into());
    let encrypt = encrypt_file(&mut pass, &plaintext);
    let decrypt = decrypt_file(&mut pass, &encrypt).unwrap();
    assert_eq!(decrypt, plaintext);
}
#[test]
fn test_decrypt_invalid_data_returns_none() {
    let mut pass = PasswordType::Password("test123".into());
    let result = decrypt_file(&mut pass, b"short");
    assert!(result.is_none());
}
#[test]
fn test_decrypt_wrong_password_returns_none() {
    let plaintext = "secret data".as_bytes();
    let mut pass1 = PasswordType::Password("password1".into());
    let encrypt = encrypt_file(&mut pass1, plaintext);
    let mut pass2 = PasswordType::Password("password2".into());
    let result = decrypt_file(&mut pass2, &encrypt);
    assert!(result.is_none());
}
#[test]
fn in_place_encryption_reuses_a_sufficiently_sized_buffer() {
    let expected = b"plaintext kept in the original allocation";
    let mut plaintext = Vec::with_capacity(expected.len() + HEADER_LEN + 16);
    plaintext.extend_from_slice(expected);
    let allocation = plaintext.as_ptr();
    let mut pass = PasswordType::Password("test123".into());
    let encrypted = try_encrypt_file_in_place(&mut pass, plaintext).unwrap();
    assert_eq!(encrypted.as_ptr(), allocation);
    assert_eq!(decrypt_file(&mut pass, &encrypted).unwrap(), expected);
}
#[test]
fn unversioned_encryption_format_is_rejected() {
    let mut pass = PasswordType::Password("test123".into());
    assert!(decrypt_file(&mut pass, &[0; 64]).is_none());
}
#[test]
fn independent_sessions_use_random_salts_and_one_session_reuses_its_key() {
    let plaintext = b"same plaintext";
    let mut first_session = PasswordType::Password("test123".into());
    let mut second_session = PasswordType::Password("test123".into());
    let e1 = encrypt_file(&mut first_session, plaintext);
    let e2 = encrypt_file(&mut second_session, plaintext);
    let e3 = encrypt_file(&mut first_session, plaintext);
    const SALT_OFFSET: usize = 8 + 1 + 1 + 4 + 4 + 4;
    assert_ne!(
        &e1[SALT_OFFSET..SALT_OFFSET + SALT_LEN],
        &e2[SALT_OFFSET..SALT_OFFSET + SALT_LEN]
    );
    assert_eq!(
        &e1[SALT_OFFSET..SALT_OFFSET + SALT_LEN],
        &e3[SALT_OFFSET..SALT_OFFSET + SALT_LEN]
    );
    assert_ne!(e1, e3, "every write still requires a fresh nonce");
}

#[test]
fn authenticated_header_rejects_tampering() {
    let mut pass = PasswordType::Password("test123".into());
    let encrypted = encrypt_file(&mut pass, b"sensitive vault data");
    for offset in [8, 9, 10, 22, HEADER_LEN - 1] {
        let mut tampered = encrypted.clone();
        tampered[offset] ^= 1;
        assert!(
            decrypt_file(&mut pass, &tampered).is_none(),
            "tampered header byte {offset} was accepted"
        );
    }
}

#[test]
fn authenticated_ciphertext_rejects_tampering_and_truncation() {
    let mut pass = PasswordType::Password("test123".into());
    let encrypted = encrypt_file(&mut pass, b"sensitive vault data");
    let mut tampered = encrypted.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(decrypt_file(&mut pass, &tampered).is_none());
    assert!(decrypt_file(&mut pass, &encrypted[..encrypted.len() - 1]).is_none());
}

#[test]
fn hostile_kdf_parameters_are_rejected_before_derivation() {
    let mut pass = PasswordType::Password("test123".into());
    let encrypted = encrypt_file(&mut pass, b"sensitive vault data");
    for memory_kib in [0, 1024 * 1024 + 1] {
        let mut hostile = encrypted.clone();
        hostile[10..14].copy_from_slice(&(memory_kib as u32).to_be_bytes());
        assert!(decrypt_file(&mut pass, &hostile).is_none());
    }
}
