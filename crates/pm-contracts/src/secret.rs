//! Secret fields own their cleanup, including on early returns and parse errors.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    borrow::Borrow,
    fmt,
    ops::{Deref, DerefMut},
};
use zeroize::Zeroize;

#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretString(String);

impl SecretString {
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Explicitly transfer a secret to an API that requires an owned String.
    /// The recipient becomes responsible for its lifetime and cleanup.
    pub fn expose_owned(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}
impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}
impl Deref for SecretString {
    type Target = String;
    fn deref(&self) -> &String {
        &self.0
    }
}
impl DerefMut for SecretString {
    fn deref_mut(&mut self) -> &mut String {
        &mut self.0
    }
}
impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
impl Borrow<str> for SecretString {
    fn borrow(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}
impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}
impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for SecretString {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.expose())
    }
}
impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}
impl PartialEq<str> for SecretString {
    fn eq(&self, other: &str) -> bool {
        self.expose() == other
    }
}
impl PartialEq<&str> for SecretString {
    fn eq(&self, other: &&str) -> bool {
        self.expose() == *other
    }
}
impl PartialEq<String> for SecretString {
    fn eq(&self, other: &String) -> bool {
        self.expose() == other
    }
}
impl PartialEq<SecretString> for String {
    fn eq(&self, other: &SecretString) -> bool {
        self == other.expose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting_redacts_but_explicit_serialization_preserves_exact_bytes() {
        let secret = SecretString::from(" \nsynthetic\t ");
        assert!(!format!("{secret:?} {secret}").contains("synthetic"));
        let encoded = serde_json::to_string(&secret).unwrap();
        let decoded: SecretString = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.expose(), " \nsynthetic\t ");
        assert_eq!(decoded.expose_owned(), " \nsynthetic\t ");
    }

    #[test]
    fn explicit_zeroization_clears_contents() {
        let mut secret = SecretString::from("synthetic");
        secret.zeroize();
        assert!(secret.is_empty());
    }
}

/// A growable plaintext byte buffer. Growing copies into a fresh allocation
/// and wipes the old one, whereas `Vec` growth frees it without wiping.
/// It dereferences only to a slice, so callers cannot grow it unwiped.
#[derive(Default)]
pub struct SecretBuffer(zeroize::Zeroizing<Vec<u8>>);

impl SecretBuffer {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(zeroize::Zeroizing::new(Vec::with_capacity(capacity)))
    }

    /// Ensure room for `additional` more bytes without an unwiped reallocation.
    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        if self.0.capacity() - self.0.len() < additional {
            self.grow(additional);
        }
    }

    #[cold]
    #[inline(never)]
    fn grow(&mut self, additional: usize) {
        let needed = self
            .0
            .len()
            .checked_add(additional)
            .expect("secret buffer capacity overflow");
        let capacity = needed.max(self.0.capacity().saturating_mul(2)).max(64);
        let mut grown = Vec::with_capacity(capacity);
        grown.extend_from_slice(&self.0);
        // Dropping the previous Zeroizing wrapper wipes its whole allocation.
        drop(std::mem::replace(
            &mut self.0,
            zeroize::Zeroizing::new(grown),
        ));
    }

    #[inline]
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.reserve(bytes.len());
        self.0.extend_from_slice(bytes);
    }

    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    pub fn into_inner(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.0
    }
}

impl From<zeroize::Zeroizing<Vec<u8>>> for SecretBuffer {
    fn from(bytes: zeroize::Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
}

impl Deref for SecretBuffer {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        &self.0
    }
}
impl DerefMut for SecretBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl fmt::Debug for SecretBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBuffer(<redacted>)")
    }
}
impl std::io::Write for SecretBuffer {
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    #[inline]
    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod secret_buffer_tests {
    use super::SecretBuffer;
    use std::io::Write;

    #[test]
    fn growth_preserves_contents_and_reserved_capacity_is_not_reallocated() {
        let mut buffer = SecretBuffer::default();
        for chunk in 0..200u8 {
            buffer.write_all(&[chunk; 37]).unwrap();
        }
        assert_eq!(buffer.len(), 200 * 37);
        assert!(
            buffer
                .chunks(37)
                .enumerate()
                .all(|(i, c)| c.iter().all(|&b| b == i as u8))
        );

        let mut sized = SecretBuffer::with_capacity(1024);
        let before = sized.as_ptr();
        sized.extend_from_slice(&[1; 1000]);
        sized.reserve(24);
        sized.extend_from_slice(&[2; 24]);
        assert_eq!(
            sized.as_ptr(),
            before,
            "reserved capacity must be used in place"
        );
        assert_eq!(sized.capacity(), 1024);
    }
}
