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
