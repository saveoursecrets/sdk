use serde::{Deserialize, Serialize};
use std::{
    fmt,
    hash::{Hash, Hasher},
};
use url::Url;

/// Remote server origin.
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct Origin {
    name: String,
    url: Url,
}

impl Origin {
    /// Create a new origin.
    pub fn new(name: String, url: Url) -> Self {
        Self { name, url }
    }

    /// Name of the origin server.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// URL of the origin server.
    pub fn url(&self) -> &Url {
        &self.url
    }
}

impl PartialEq for Origin {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl Hash for Origin {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url.hash(state);
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.url)
    }
}

impl From<Url> for Origin {
    fn from(url: Url) -> Self {
        let name = url.authority().to_owned();
        Self { name, url }
    }
}
