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
