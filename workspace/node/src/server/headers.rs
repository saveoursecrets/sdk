//! Custom typed headers.
use axum::headers::{self, Header, HeaderName, HeaderValue};
use sos_core::{commit_tree::CommitProof, decode, encode};
use uuid::Uuid;

use once_cell::sync::Lazy;

pub static X_SESSION: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_static(sos_core::constants::X_SESSION));

#[deprecated]
pub static X_SIGNED_MESSAGE: Lazy<HeaderName> = Lazy::new(|| {
    HeaderName::from_static(sos_core::constants::X_SIGNED_MESSAGE)
});

#[deprecated]
pub static X_COMMIT_PROOF: Lazy<HeaderName> = Lazy::new(|| {
    HeaderName::from_static(sos_core::constants::X_COMMIT_PROOF)
});

#[deprecated]
pub static X_MATCH_PROOF: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_static(sos_core::constants::X_MATCH_PROOF));

/// Represents the `x-session` header.
pub struct Session(Uuid);

impl Session {
    /// Get the identifier.
    pub fn id(&self) -> &Uuid {
        &self.0
    }
}

impl Header for Session {
    fn name() -> &'static HeaderName {
        &X_SESSION
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values.next().ok_or_else(headers::Error::invalid)?;
        let value = value.to_str().map_err(|_| headers::Error::invalid())?;
        let value =
            Uuid::parse_str(&value).map_err(|_| headers::Error::invalid())?;
        Ok(Session(value))
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let s = self.0.to_string();
        let value = HeaderValue::from_str(&s)
            .expect("failed to create session header");
        values.extend(std::iter::once(value));
    }
}

/// Represents the `x-signed-message` header.
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
        let value = bs58::decode(&value)
            .into_vec()
            .map_err(|_| headers::Error::invalid())?;
        Ok(SignedMessage(value))
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let s = bs58::encode(&self.0).into_string();
        let value = HeaderValue::from_str(&s)
            .expect("failed to create signed message header");
        values.extend(std::iter::once(value));
    }
}

/// Represents the `x-commit-proof` header.
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
        let value = bs58::decode(value)
            .into_vec()
            .map_err(|_| headers::Error::invalid())?;
        let value: CommitProof =
            decode(&value).map_err(|_| headers::Error::invalid())?;
        Ok(CommitProofHeader(value))
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let v =
            encode(&self.0).expect("failed to encode commit proof header");
        let s = bs58::encode(&v).into_string();
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
