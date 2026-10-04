#![no_main]
use password_manager::{
    encryption::{decrypt_file, try_encrypt_file_in_place, validate_vault_header},
    types::PasswordType,
};
use zeroize::Zeroizing;

fn session() -> PasswordType {
    PasswordType::Session {
        encryption_key: [42; 32],
        salt: [7; 16],
        kdf: 1,
        memory_kib: 8192,
        iterations: 1,
        parallelism: 1,
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // Always use cached synthetic keys: hostile headers must never force an
    // expensive Argon2 allocation in the fuzzer.
    let _ = validate_vault_header(data);
    let _ = decrypt_file(&mut session(), data).map(Zeroizing::new);
    let mut encrypted = try_encrypt_file_in_place(&mut session(), data.to_vec()).unwrap();
    let plaintext = Zeroizing::new(decrypt_file(&mut session(), &encrypted).unwrap());
    assert_eq!(plaintext.as_slice(), data);
    // Mutate every region over successive inputs, including authenticated KDF
    // metadata, salt, nonce, ciphertext, and authentication tag.
    let index = data.first().copied().unwrap_or(0) as usize % encrypted.len();
    encrypted[index] ^= 1;
    assert!(decrypt_file(&mut session(), &encrypted).is_none());
});
