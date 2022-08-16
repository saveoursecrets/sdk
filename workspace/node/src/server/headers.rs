//! Custom typed headers.
use axum::headers::{self, Header, HeaderName, HeaderValue};

use uuid::Uuid;

use once_cell::sync::Lazy;

pub static X_SESSION: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_static(sos_core::constants::X_SESSION));

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
