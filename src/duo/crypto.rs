//! RSA operations use the AWS-LC backend also used by rustls. Keep the wire
//! format compatible with existing PKCS#8 PEM keys and SPKI enrollment keys.
use super::{VaultError, invalid};
use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der},
    rand::SystemRandom,
    rsa::KeySize,
    signature::{KeyPair, RSA_PKCS1_SHA512, RsaKeyPair},
};
use zeroize::Zeroizing;

pub(crate) fn new_key() -> Result<RsaKeyPair, VaultError> {
    RsaKeyPair::generate(KeySize::Rsa2048)
        .map_err(|_| invalid("could not generate Duo enrollment key"))
}
pub(crate) fn public_pem(key: &RsaKeyPair) -> Result<String, VaultError> {
    let der = AsDer::<PublicKeyX509Der>::as_der(key.public_key())
        .map_err(|_| invalid("could not encode Duo enrollment public key"))?;
    pem_rfc7468::encode_string("PUBLIC KEY", pem_rfc7468::LineEnding::LF, der.as_ref())
        .map_err(|_| invalid("could not encode Duo enrollment public key"))
}
pub(crate) fn private_pem(key: &RsaKeyPair) -> Result<Zeroizing<String>, VaultError> {
    let der = AsDer::<Pkcs8V1Der>::as_der(key)
        .map_err(|_| invalid("could not encode Duo push signing key"))?;
    pem_rfc7468::encode_string("PRIVATE KEY", pem_rfc7468::LineEnding::LF, der.as_ref())
        .map(Zeroizing::new)
        .map_err(|_| invalid("could not encode Duo push signing key"))
}
pub(crate) fn load_key(pem: &str) -> Result<RsaKeyPair, VaultError> {
    if pem.len() > 16384 {
        return Err(invalid("Duo push signing key exceeds the size limit"));
    }
    let (label, bytes) = pem_rfc7468::decode_vec(pem.as_bytes())
        .map_err(|_| invalid("invalid Duo push signing key"))?;
    let bytes = Zeroizing::new(bytes);
    if label != "PRIVATE KEY" {
        return Err(invalid("expected a PKCS#8 Duo push signing key"));
    }
    let key =
        RsaKeyPair::from_pkcs8(&bytes).map_err(|_| invalid("invalid Duo push signing key"))?;
    if !(256..=512).contains(&key.public_modulus_len()) {
        return Err(invalid("unsupported Duo push signing key size"));
    }
    Ok(key)
}
pub(crate) fn sign(pem: &str, message: &[u8]) -> Result<Vec<u8>, VaultError> {
    let key = load_key(pem)?;
    let mut signature = vec![0; key.public_modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA512,
        &SystemRandom::new(),
        message,
        &mut signature,
    )
    .map_err(|_| invalid("could not sign Duo push request"))?;
    Ok(signature)
}
