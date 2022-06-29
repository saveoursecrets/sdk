//! Custom typed headers.
use axum::headers::{self, Header, HeaderName, HeaderValue};

use once_cell::sync::Lazy;

pub static X_SIGNED_MESSAGE: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_static("x-signed-message"));

pub static X_COMMIT_HASH: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_static("x-commit-hash"));

pub static X_COMMIT_PROOF: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_static("x-commit-proof"));

/// Represents the `x-signed-message` header.
#[derive(Debug)]
pub struct SignedMessage(Vec<u8>);

impl AsRef<[u8]> for SignedMessage {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Header for SignedMessage {
    fn name() -> &'static HeaderName {
        &X_SIGNED_MESSAGE
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values.next().ok_or_else(headers::Error::invalid)?;
        let value =
            base64::decode(&value).map_err(|_| headers::Error::invalid())?;
        Ok(SignedMessage(value))
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let s = base64::encode(&self.0);
        let value = HeaderValue::from_str(&s)
            .expect("failed to create signed message header");
        values.extend(std::iter::once(value));
    }
}

/// Represents the `x-commit-hash` header.
#[derive(Debug, Eq, PartialEq)]
pub struct CommitHashHeader([u8; 32]);

impl Header for CommitHashHeader {
    fn name() -> &'static HeaderName {
        &X_COMMIT_HASH
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values.next().ok_or_else(headers::Error::invalid)?;
        let value: &str =
            value.to_str().map_err(|_| headers::Error::invalid())?;

        if value.len() != 64 {
            return Err(headers::Error::invalid());
        }

        let value = hex::decode(value.as_bytes())
            .map_err(|_| headers::Error::invalid())?;

        let value: [u8; 32] = value
            .as_slice()
            .try_into()
            .map_err(|_| headers::Error::invalid())?;
        Ok(CommitHashHeader(value))
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let s = hex::encode(&self.0);
        let value = HeaderValue::from_str(&s)
            .expect("failed to create commit hash header");
        values.extend(std::iter::once(value));
    }
}

impl From<CommitHashHeader> for [u8; 32] {
    fn from(value: CommitHashHeader) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for CommitHashHeader {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Represents the `x-commit-proof` header.
#[derive(Debug, Eq, PartialEq)]
pub struct CommitProofHeader(Vec<u8>);

impl Header for CommitProofHeader {
    fn name() -> &'static HeaderName {
        &X_COMMIT_PROOF
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values.next().ok_or_else(headers::Error::invalid)?;
        let value: &str =
            value.to_str().map_err(|_| headers::Error::invalid())?;
        let value =
            base64::decode(value).map_err(|_| headers::Error::invalid())?;
        Ok(CommitProofHeader(value))
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let s = base64::encode(&self.0);
        let value = HeaderValue::from_str(&s)
            .expect("failed to create commit proof header");
        values.extend(std::iter::once(value));
    }
}

impl AsRef<[u8]> for CommitProofHeader {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
