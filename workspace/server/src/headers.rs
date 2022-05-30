use axum::headers::{self, Header, HeaderName, HeaderValue};

use once_cell::sync::Lazy;

pub static X_SIGNED_MESSAGE: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_static("x-signed-message"));

pub static X_CHANGE_SEQUENCE: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_static("x-change-sequence"));

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
#[derive(Debug)]
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
