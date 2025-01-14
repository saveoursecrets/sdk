use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
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

/// Managae a collection of server origins.
#[async_trait]
pub trait RemoteOrigins {
    /// Error type.
    type Error: std::error::Error + std::fmt::Debug;

    /// Load server origins from the backing storage.
    async fn load_servers(&self) -> Result<HashSet<Origin>, Self::Error>;

    /// Add a server origin to the backing storage.
    async fn add_server(&mut self, origin: Origin)
        -> Result<(), Self::Error>;

    /// Update a server origin in the backing storage.
    async fn replace_server(
        &mut self,
        old_origin: &Origin,
        new_origin: Origin,
    ) -> Result<(), Self::Error>;

    /// Remove a server origin from the backing storage.
    async fn remove_server(
        &mut self,
        origin: &Origin,
    ) -> Result<(), Self::Error>;
}
