//! Client implementations for the SPOT (Single Point of Truth)
//! networking mode.

/// Client implementations that write to disc.
#[cfg(not(target_arch = "wasm32"))]
pub mod file {
    use crate::client::{
        changes_listener::ChangesListener, node_cache::NodeCache, Result,
    };
    use sos_core::{signer::BoxedSigner, wal::file::WalFile, PatchFile};
    use std::{
        path::PathBuf,
        sync::{Arc, RwLock},
    };
    use url::Url;

    /// Client that communicates with a single server and
    /// writes it's cache to disc.
    pub struct SpotFileClient {
        cache: Arc<RwLock<NodeCache<WalFile, PatchFile>>>,
        changes: ChangesListener,
    }

    impl SpotFileClient {
        /// Create a new SPOT file client.
        pub fn new(
            server: Url,
            cache_dir: PathBuf,
            signer: BoxedSigner,
        ) -> Result<Self> {
            let changes =
                ChangesListener::new(server.clone(), signer.clone());
            let cache = Arc::new(RwLock::new(NodeCache::new_file_cache(
                server, cache_dir, signer,
            )?));
            Ok(Self { cache, changes })
        }

        /// Get a clone of the underlying node cache.
        pub fn cache(&self) -> Arc<RwLock<NodeCache<WalFile, PatchFile>>> {
            Arc::clone(&self.cache)
        }

        /// Spawn a change notification listener that
        /// updates the local node cache.
        pub fn spawn_changes(&self) {
            let cache = self.cache();
            let listener = self.changes.clone();
            listener.spawn(move |notification| {
                let cache = Arc::clone(&cache);
                async move {
                    //println!("{:#?}", notification);
                    let mut writer = cache.write().unwrap();
                    let _ = writer.handle_change(notification).await;
                }
            });
        }
    }
}

/// Client implementation that stores data in memory.
#[cfg(target_arch = "wasm32")]
pub mod memory {
    use crate::client::{node_cache::NodeCache, Error, Result};
    use sos_core::{
        events::{SyncEvent, ChangeNotification}, signer::BoxedSigner, vault::Summary,
        wal::memory::WalMemory, PatchMemory,
    };
    use std::{
        future::Future,
        sync::{Arc, RwLock},
    };
    use url::Url;

    /// Type alias for an in-memory node cache.
    pub type MemoryCache =
        Arc<RwLock<NodeCache<WalMemory, PatchMemory<'static>>>>;

    /// Client that communicates with a single server and
    /// writes it's cache to memory.
    ///
    /// Uses static futures so that it can be used in webassembly.
    pub struct SpotMemoryClient {
        cache: MemoryCache,
        url: Url,
        signer: BoxedSigner,
    }

    impl SpotMemoryClient {
        /// Create a new SPOT memory client.
        pub fn new(server: Url, signer: BoxedSigner) -> Self {
            let url = server.clone();
            let client_signer = signer.clone();
            let cache = Arc::new(RwLock::new(NodeCache::new_memory_cache(
                server, signer,
            )));
            Self {
                cache,
                url,
                signer: client_signer,
            }
        }

        /// Get the URL of the remote node.
        pub fn url(&self) -> &Url {
            &self.url
        }

        /// Get the signer.
        pub fn signer(&self) -> &BoxedSigner {
            &self.signer
        }

        /// Get a clone of the underlying node cache.
        pub fn cache(&self) -> MemoryCache {
            Arc::clone(&self.cache)
        }

        /// Load the vaults.
        pub fn load_vaults(
            cache: MemoryCache,
        ) -> impl Future<Output = Result<Vec<Summary>>> + 'static {
            async move {
                let mut writer = cache.write().unwrap();
                let vaults = writer.load_vaults().await?;
                Ok::<Vec<Summary>, Error>(vaults.to_vec())
            }
        }

        /// Open a vault.
        pub fn open_vault(
            cache: MemoryCache,
            summary: Summary,
            passphrase: String,
        ) -> impl Future<Output = Result<()>> + 'static {
            async move {
                let mut writer = cache.write().unwrap();
                writer.open_vault(&summary, &passphrase).await?;
                Ok::<(), Error>(())
            }
        }

        /// Remove a vault.
        pub fn remove_vault(
            cache: MemoryCache,
            summary: Summary,
        ) -> impl Future<Output = Result<()>> + 'static {
            async move {
                let mut writer = cache.write().unwrap();
                writer.remove_vault(&summary).await?;
                Ok::<(), Error>(())
            }
        }

        /// Rename a vault.
        pub fn rename_vault(
            cache: MemoryCache,
            summary: Summary,
            name: String,
        ) -> impl Future<Output = Result<()>> + 'static {
            async move {
                let mut writer = cache.write().unwrap();
                writer.set_vault_name(&summary, &name).await?;
                Ok::<(), Error>(())
            }
        }

        /// Patch a vault.
        pub fn patch_vault(
            cache: MemoryCache,
            summary: Summary,
            events: Vec<SyncEvent<'static>>,
        ) -> impl Future<Output = Result<()>> + 'static {
            async move {
                let mut writer = cache.write().unwrap();
                writer.patch_vault(&summary, events).await?;
                Ok::<(), Error>(())
            }
        }

        /// Send a patch of events infallibly.
        ///
        /// This is used to send read secret events for
        /// audit logging.
        pub fn send_events(
            cache: MemoryCache,
            summary: Summary,
            events: Vec<SyncEvent<'static>>,
        ) -> impl Future<Output = ()> + 'static {
            async move {
                let mut writer = cache.write().unwrap();
                let _ = writer.patch_vault(&summary, events).await;
            }
        }

        /// Handle a change notification.
        pub fn handle_change(
            cache: MemoryCache,
            change: ChangeNotification,
        ) -> impl Future<Output = Result<()>> + 'static {
            async move {
                let mut writer = cache.write().unwrap();
                writer.handle_change(change).await?;
                Ok::<(), Error>(())
            }
        }
    }
}
