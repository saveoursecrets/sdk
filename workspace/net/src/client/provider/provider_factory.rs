//! Factory for creating providers.
use sos_sdk::{signer::ecdsa::BoxedEcdsaSigner, storage::StorageDirs};
use std::{fmt, sync::Arc};
use url::Url;
use web3_address::ethereum::Address;

use crate::client::{
    net::RpcClient,
    provider::{BoxedProvider, RemoteProvider},
    Error, Result,
};

use tokio::sync::RwLock;

use crate::client::provider::LocalProvider;

use std::{path::PathBuf, str::FromStr};

/// Provider that can be safely sent between threads.
pub type ArcProvider = Arc<RwLock<BoxedProvider>>;

/// Factory for creating providers.
#[derive(Debug, Clone)]
pub enum ProviderFactory {
    /// Local provider using the default cache location or 
    /// a specific location for files.
    Local(Option<PathBuf>),
    /// Remote server with local disc storage.
    Remote(Url),
}

impl fmt::Display for ProviderFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(dir) => {
                let path = if let Some(path) = dir {
                    path.to_path_buf()
                } else { PathBuf::new() };
                write!(f, "file://{}", path.display())
            }
            Self::Remote(remote) => write!(f, "{}", remote),
        }
    }
}

impl Default for ProviderFactory {
    fn default() -> Self {
        Self::Local(None)
    }
}

impl ProviderFactory {
    /// Create a new remote provider with local disc storage.
    pub async fn new_remote_file_provider(
        signer: BoxedEcdsaSigner,
        cache_dir: PathBuf,
        server: Url,
    ) -> Result<(BoxedProvider, Address)> {
        let address = signer.address()?;
        let client = RpcClient::new(server, signer);
        let dirs = StorageDirs::new(cache_dir, &address.to_string());
        let provider: BoxedProvider =
            Box::new(RemoteProvider::new(client, dirs).await?);
        Ok((provider, address))
    }

    /// Create a new local provider.
    pub async fn new_local_file_provider(
        signer: BoxedEcdsaSigner,
        cache_dir: PathBuf,
    ) -> Result<(BoxedProvider, Address)> {
        let address = signer.address()?;
        let dirs = StorageDirs::new(cache_dir, &address.to_string());
        let provider: BoxedProvider =
            Box::new(LocalProvider::new(dirs).await?);
        Ok((provider, address))
    }

    /// Create a provider.
    pub async fn create_provider(
        &self,
        signer: BoxedEcdsaSigner,
    ) -> Result<(BoxedProvider, Address)> {
        match self {
            Self::Local(dir) => {
                let dir = if let Some(dir) = dir {
                    dir.to_path_buf()
                } else {
                    StorageDirs::cache_dir().ok_or_else(|| Error::NoCache)?
                };
                Ok(Self::new_local_file_provider(signer, dir).await?)
            }
            /*
            Self::Directory(dir) => {
                if !dir.is_dir() {
                    return Err(Error::NotDirectory(dir.clone()));
                }
                Ok(Self::new_local_file_provider(signer, dir.clone()).await?)
            }
            */
            Self::Remote(remote) => {
                let dir =
                    StorageDirs::cache_dir().ok_or_else(|| Error::NoCache)?;
                Ok(Self::new_remote_file_provider(
                    signer,
                    dir,
                    remote.clone(),
                )
                .await?)
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl FromStr for ProviderFactory {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.parse::<Url>() {
            Ok(url) => {
                let scheme = url.scheme();
                if scheme == "http" || scheme == "https" {
                    Ok(Self::Remote(url))
                } else if scheme == "file" {
                    let path = s.trim_start_matches("file://");
                    if path.is_empty() {
                        Ok(Self::Local(None))
                    } else {
                        Ok(Self::Local(Some(PathBuf::from(path))))
                    }
                } else {
                    Err(Error::InvalidProvider(s.to_string()))
                }
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Spawn a change notification listener that
/// updates the local node cache.
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn_changes_listener(
    server: Url,
    signer: BoxedEcdsaSigner,
    cache: ArcProvider,
) {
    use crate::client::changes_listener::ChangesListener;
    let listener = ChangesListener::new(server, signer);
    listener.spawn(move |notification| {
        let cache = Arc::clone(&cache);
        async move {
            //println!("{:#?}", notification);
            let mut writer = cache.write().await;
            let _ = writer.handle_change(notification).await;
        }
    });
}
