//! Factory for creating providers.
use sos_core::signer::BoxedSigner;
use std::{
    fmt,
    sync::{Arc, RwLock},
};
use url::Url;
use web3_address::ethereum::Address;

use crate::client::{
    net::RpcClient,
    provider::{BoxedProvider, RemoteProvider},
    Error, Result,
};

#[cfg(not(target_arch = "wasm32"))]
use crate::{
    cache_dir,
    client::provider::{LocalProvider, StorageDirs},
};

#[cfg(not(target_arch = "wasm32"))]
use std::{path::PathBuf, str::FromStr};

/// Provider that can be safely sent between threads.
pub type ArcProvider = Arc<RwLock<BoxedProvider>>;

/// Factory for creating providers.
#[derive(Debug, Clone)]
pub enum ProviderFactory {
    /// Provider storing data in memory.
    Memory(Option<Url>),
    /// Local provider using the default cache location.
    #[cfg(not(target_arch = "wasm32"))]
    Local,
    /// Specific directory location.
    #[cfg(not(target_arch = "wasm32"))]
    Directory(PathBuf),
    /// Remote server with local disc storage.
    #[cfg(not(target_arch = "wasm32"))]
    Remote(Url),
}

impl fmt::Display for ProviderFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(remote) => {
                if let Some(remote) = remote {
                    write!(f, "mem+{}", remote)
                } else {
                    write!(f, "memory")
                }
            }
            #[cfg(not(target_arch = "wasm32"))]
            Self::Local => write!(f, "local"),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Directory(path) => write!(f, "{}", path.display()),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Remote(remote) => write!(f, "{}", remote),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for ProviderFactory {
    fn default() -> Self {
        Self::Local
        //Self::Remote(Url::parse("http://localhost:5053").unwrap())
    }
}

#[cfg(target_arch = "wasm32")]
impl Default for ProviderFactory {
    fn default() -> Self {
        Self::Memory(Some(Url::parse("http://localhost:5053").unwrap()))
    }
}

impl ProviderFactory {
    /// Create a provider.
    pub fn create_provider(
        &self,
        signer: BoxedSigner,
    ) -> Result<(BoxedProvider, Address)> {
        match self {
            #[cfg(target_arch = "wasm32")]
            Self::Memory(remote) => {
                if let Some(remote) = remote {
                    Ok(new_remote_memory_provider(signer, remote.clone())?)
                } else {
                    Err(Error::InvalidProvider(self.to_string()))
                }
            }
            #[cfg(not(target_arch = "wasm32"))]
            Self::Memory(remote) => {
                if let Some(remote) = remote {
                    Ok(new_remote_memory_provider(signer, remote.clone())?)
                } else {
                    Ok(new_local_memory_provider(signer)?)
                }
            }
            #[cfg(not(target_arch = "wasm32"))]
            Self::Local => {
                let dir = cache_dir().ok_or_else(|| Error::NoCache)?;
                Ok(new_local_file_provider(signer, dir)?)
            }
            #[cfg(not(target_arch = "wasm32"))]
            Self::Directory(dir) => {
                if !dir.is_dir() {
                    return Err(Error::NotDirectory(dir.clone()));
                }
                Ok(new_local_file_provider(signer, dir.clone())?)
            }
            #[cfg(not(target_arch = "wasm32"))]
            Self::Remote(remote) => {
                let dir = cache_dir().ok_or_else(|| Error::NoCache)?;
                Ok(new_remote_file_provider(signer, dir, remote.clone())?)
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl FromStr for ProviderFactory {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s == "memory" {
            Ok(Self::Memory(None))
        } else if s == "local" {
            Ok(Self::Local)
        } else {
            match s.parse::<Url>() {
                Ok(url) => {
                    let scheme = url.scheme();
                    if scheme == "http" || scheme == "https" {
                        Ok(Self::Remote(url))
                    } else if scheme == "file" {
                        let path = s.trim_start_matches("file://");
                        Ok(Self::Directory(PathBuf::from(path)))
                    } else if scheme == "mem+http" || scheme == "mem+https" {
                        let scheme = scheme.trim_start_matches("mem+");
                        let mut url = url.clone();
                        let result = url.set_scheme(scheme);
                        if result.is_err() {
                            return Err(Error::InvalidProvider(
                                s.to_string(),
                            ));
                        }
                        Ok(Self::Memory(Some(url)))
                    } else {
                        Err(Error::InvalidProvider(s.to_string()))
                    }
                }
                Err(e) => Err(e.into()),
            }
        }
    }
}

/// Spawn a change notification listener that
/// updates the local node cache.
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn_changes_listener(
    server: Url,
    signer: BoxedSigner,
    cache: ArcProvider,
) {
    use crate::client::changes_listener::ChangesListener;
    let listener = ChangesListener::new(server, signer);
    listener.spawn(move |notification| {
        let cache = Arc::clone(&cache);
        async move {
            //println!("{:#?}", notification);
            let mut writer = cache.write().unwrap();
            let _ = writer.handle_change(notification).await;
        }
    });
}

/// Create a new remote provider with local disc storage.
#[cfg(not(target_arch = "wasm32"))]
fn new_remote_file_provider(
    signer: BoxedSigner,
    cache_dir: PathBuf,
    server: Url,
) -> Result<(BoxedProvider, Address)> {
    let address = signer.address()?;
    let client = RpcClient::new(server, signer);
    let dirs = StorageDirs::new(cache_dir, &address.to_string());
    let provider: BoxedProvider =
        Box::new(RemoteProvider::new_file_cache(client, dirs)?);
    Ok((provider, address))
}

/// Create a new local provider.
#[cfg(not(target_arch = "wasm32"))]
fn new_local_file_provider(
    signer: BoxedSigner,
    cache_dir: PathBuf,
) -> Result<(BoxedProvider, Address)> {
    let address = signer.address()?;
    let dirs = StorageDirs::new(cache_dir, &address.to_string());
    let provider: BoxedProvider =
        Box::new(LocalProvider::new_file_storage(dirs)?);
    Ok((provider, address))
}

/// Create a new local memory provider.
#[cfg(not(target_arch = "wasm32"))]
fn new_local_memory_provider(
    signer: BoxedSigner,
) -> Result<(BoxedProvider, Address)> {
    let address = signer.address()?;
    let provider: BoxedProvider =
        Box::new(LocalProvider::new_memory_storage());
    Ok((provider, address))
}

/// Create a new remote provider with in-memory storage.
fn new_remote_memory_provider(
    signer: BoxedSigner,
    server: Url,
) -> Result<(BoxedProvider, Address)> {
    let address = signer.address()?;
    let client = RpcClient::new(server, signer);
    let provider: BoxedProvider =
        Box::new(RemoteProvider::new_memory_cache(client));
    Ok((provider, address))
}
