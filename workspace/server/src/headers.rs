use axum::headers::{self, Header, HeaderName, HeaderValue};

use once_cell::sync::Lazy;

pub static X_SIGNED_MESSAGE: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_static("x-signed-message"));

#[deprecated]
pub static X_CHANGE_SEQUENCE: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_static("x-change-sequence"));

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

/// Represents the `x-change-sequence` header.
#[deprecated]
#[derive(Debug, Eq, PartialEq)]
pub struct ChangeSequence(u32);

impl Header for ChangeSequence {
    fn name() -> &'static HeaderName {
        &X_CHANGE_SEQUENCE
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values.next().ok_or_else(headers::Error::invalid)?;
        let value: u32 = value
            .to_str()
            .map_err(|_| headers::Error::invalid())?
            .parse()
            .map_err(|_| headers::Error::invalid())?;
        Ok(ChangeSequence(value))
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let s = format!("{}", &self.0);
        let value = HeaderValue::from_str(&s)
            .expect("failed to create change sequence header");
        values.extend(std::iter::once(value));
    }
}

impl From<ChangeSequence> for u32 {
    fn from(value: ChangeSequence) -> Self {
        value.0
    }
}

/// Represents the `x-commit-hash` header.
///
/// An empty string indicates no commit hash is available
/// and can be used to indicate that all available data
/// should be returned by the server; for example, to fetch
/// an entire WAL file whan a client connects with no cached
/// WAL.
#[derive(Debug, Eq, PartialEq)]
pub struct CommitHash(Option<[u8; 32]>);

impl Header for CommitHash {
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

        if value.is_empty() {
            Ok(CommitHash(None))
        } else {
            if value.len() != 64 {
                return Err(headers::Error::invalid());
            }

            let value = hex::decode(value.as_bytes())
                .map_err(|_| headers::Error::invalid())?;

            let value: [u8; 32] = value
                .as_slice()
                .try_into()
                .map_err(|_| headers::Error::invalid())?;
            Ok(CommitHash(Some(value)))
        }
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let s = if let Some(value) = &self.0 {
            hex::encode(value)
        } else {
            String::new()
        };
        let value = HeaderValue::from_str(&s)
            .expect("failed to create commit hash header");
        values.extend(std::iter::once(value));
    }
}

impl From<CommitHash> for Option<[u8; 32]> {
    fn from(value: CommitHash) -> Self {
        value.0
    }
}

/// Represents the `x-commit-proof` header.
#[derive(Debug, Eq, PartialEq)]
pub struct CommitProof(Vec<u8>);

impl Header for CommitProof {
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
        Ok(CommitProof(value))
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

impl AsRef<[u8]> for CommitProof {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
