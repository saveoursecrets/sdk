//! Custom typed headers.
use axum::headers::{self, Header, HeaderName, HeaderValue};

use sos_core::{encode, decode, commit_tree::CommitProof};

use once_cell::sync::Lazy;

pub static X_SIGNED_MESSAGE: Lazy<HeaderName> = Lazy::new(|| {
    HeaderName::from_static(sos_core::headers::X_SIGNED_MESSAGE)
});

//pub static X_COMMIT_HASH: Lazy<HeaderName> =
    //Lazy::new(|| HeaderName::from_static(sos_core::headers::X_COMMIT_HASH));

pub static X_COMMIT_PROOF: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_static(sos_core::headers::X_COMMIT_PROOF));

pub static X_LEAF_PROOF: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_static(sos_core::headers::X_LEAF_PROOF));

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

/*
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
        let value = base64::decode(value.as_bytes())
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
        let s = base64::encode(&self.0);
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
*/

/// Represents the `x-commit-proof` header.
#[derive(Debug, Eq, PartialEq)]
pub struct CommitProofHeader(CommitProof);

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
        let value: CommitProof =
            decode(&value).map_err(|_| headers::Error::invalid())?;
        Ok(CommitProofHeader(value))
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let v = encode(&self.0)
            .expect("failed to encode commit proof header");
        let s = base64::encode(&v);
        let value = HeaderValue::from_str(&s)
            .expect("failed to create commit proof header");
        values.extend(std::iter::once(value));
    }
}

impl From<CommitProofHeader> for CommitProof {
    fn from(proof: CommitProofHeader) -> Self {
        proof.0
    }
}
