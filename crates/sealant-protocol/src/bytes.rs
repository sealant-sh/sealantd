//! Binary-safe payload type: arbitrary bytes carried as base64 over JSON.
//!
//! Process and terminal streams are arbitrary bytes and must never be assumed to be UTF-8. On the
//! JSON wire they are encoded as a base64 string; the original byte count is carried separately by
//! the event so truncation is unambiguous.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use schemars::JsonSchema;
use schemars::r#gen::SchemaGenerator;
use schemars::schema::Schema;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Arbitrary bytes that serialize as a base64 string in JSON.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Base64Bytes(Vec<u8>);

impl Base64Bytes {
    /// Wrap owned bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Number of raw bytes carried.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume into the owned byte vector.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    /// The base64 (standard alphabet, padded) encoding of the bytes.
    #[must_use]
    pub fn to_base64(&self) -> String {
        BASE64.encode(&self.0)
    }

    /// Decode a base64 string into bytes.
    ///
    /// # Errors
    /// Returns the underlying [`base64::DecodeError`] if `s` is not valid base64.
    pub fn from_base64(s: &str) -> Result<Self, base64::DecodeError> {
        BASE64.decode(s).map(Self)
    }
}

impl core::fmt::Debug for Base64Bytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Base64Bytes(<{} bytes>)", self.0.len())
    }
}

impl From<Vec<u8>> for Base64Bytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&[u8]> for Base64Bytes {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl Serialize for Base64Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_base64(&s).map_err(D::Error::custom)
    }
}

impl JsonSchema for Base64Bytes {
    fn schema_name() -> String {
        "Base64Bytes".to_owned()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let mut schema = <String as JsonSchema>::json_schema(generator).into_object();
        schema.format = Some("byte".to_owned());
        schema.metadata().description =
            Some("Arbitrary bytes, base64-encoded (standard alphabet, padded).".to_owned());
        schema.into()
    }

    fn is_referenceable() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_arbitrary_bytes_including_nul_and_invalid_utf8() {
        let raw = vec![0u8, 159, 146, 150, b'h', b'i', 0xff, 0xfe];
        let value = Base64Bytes::new(raw.clone());
        let json = serde_json::to_string(&value).expect("ser");
        // Encoded as a JSON string, not raw bytes.
        assert!(json.starts_with('"') && json.ends_with('"'));
        let back: Base64Bytes = serde_json::from_str(&json).expect("de");
        assert_eq!(back.as_slice(), raw.as_slice());
    }

    #[test]
    fn debug_hides_contents() {
        let value = Base64Bytes::new(vec![1, 2, 3]);
        assert_eq!(format!("{value:?}"), "Base64Bytes(<3 bytes>)");
    }
}
