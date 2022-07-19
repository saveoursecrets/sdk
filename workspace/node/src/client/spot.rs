//! Client implementations for the SPOT (Single Point of Truth)
//! networking mode.

/// Client implementations that write to disc.
#[cfg(not(target_arch = "wasm32"))]
pub mod file {
    use crate::client::{
        changes_listener::ChangesListener, node_cache::NodeCache, LocalCache,
        RequestClient, Result,
    };
    use sos_core::{signer::SingleParty, wal::file::WalFile, PatchFile};
    use std::{
        path::PathBuf,
        sync::{Arc, RwLock},
    };

    /// Client that communicates with a single server and
    /// writes it's cache to disc.
    pub struct SpotFileClient {
        cache: Arc<RwLock<NodeCache<SingleParty, WalFile, PatchFile>>>,
        changes: ChangesListener<SingleParty>,
    }

    impl SpotFileClient {
        /// Create a new SPOT file client.
        pub fn new(
            cache_dir: PathBuf,
            client: RequestClient<SingleParty>,
        ) -> Result<Self> {
            let changes = ChangesListener::new(client.clone());
            let cache = Arc::new(RwLock::new(NodeCache::new_file_cache(
                client, cache_dir,
            )?));
            Ok(Self { cache, changes })
        }

        /// Get a clone of the underlying node cache.
        pub fn cache(
            &self,
        ) -> Arc<RwLock<NodeCache<SingleParty, WalFile, PatchFile>>> {
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

/// Client implementations that write to memory.
pub mod memory {
    use crate::client::node_cache::NodeCache;
    use sos_core::{
        signer::SingleParty, wal::memory::WalMemory, PatchMemory,
    };

    /// Client that communicates with a single server and
    /// writes it's cache to memory.
    pub struct SpotMemoryClient {
        cache: NodeCache<SingleParty, WalMemory, PatchMemory<'static>>,
    }
}
