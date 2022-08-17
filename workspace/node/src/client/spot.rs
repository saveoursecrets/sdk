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
    use crate::client::{
        net::changes_uri, node_cache::NodeCache, Error, Result,
    };
    use secrecy::SecretString;
    use sos_core::{
        events::{ChangeNotification, SyncEvent},
        signer::BoxedSigner,
        vault::{Summary, Vault},
        wal::memory::WalMemory,
        PatchMemory,
    };
    use std::{
        future::Future,
        sync::{Arc, RwLock},
    };
    use url::Url;

    //use futures::stream::StreamExt;
    //use pharos::{Filter, Observable, ObserveConfig};
    //use wasm_bindgen::UnwrapThrowExt;
    //use wasm_bindgen_futures::spawn_local;
    //use ws_stream_wasm::{WsEvent, WsMessage, WsMeta};

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

        /// Authenticate for a session.
        pub fn authenticate(
            cache: MemoryCache,
        ) -> impl Future<Output = Result<()>> + 'static {
            async move {
                let mut writer = cache.write().unwrap();
                let vaults = writer.authenticate().await?;
                Ok::<(), Error>(())
            }
        }

        /// Create an account.
        pub fn create_account(
            cache: MemoryCache,
            buffer: Vec<u8>,
        ) -> impl Future<Output = Result<u16>> + 'static {
            async move {
                let mut writer = cache.write().unwrap();
                let status = writer.client().create_account(buffer).await?;
                Ok(status.into())
            }
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

        /// Create a vault.
        pub fn create_vault(
            cache: MemoryCache,
            name: String,
            passphrase: String,
        ) -> impl Future<Output = Result<Summary>> + 'static {
            async move {
                let mut writer = cache.write().unwrap();
                let (_, summary) =
                    writer.create_vault(name, Some(passphrase)).await?;
                Ok::<Summary, Error>(summary)
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

        /// Change the password for a vault.
        pub fn change_password(
            cache: MemoryCache,
            vault: Vault,
            current_passphrase: SecretString,
            new_passphrase: SecretString,
        ) -> impl Future<Output = Result<()>> + 'static {
            async move {
                let mut writer = cache.write().unwrap();
                writer
                    .change_password(
                        &vault,
                        current_passphrase,
                        new_passphrase,
                    )
                    .await?;
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

        /*
        /// Listen for changes notifications using a websocket
        /// and update the cache.
        pub fn listen_changes(cache: MemoryCache) {
            let listener = async move {
                let reader = cache.read().unwrap();
                let remote = reader.client().remote().clone();
                let mut session =
                    reader.client().new_session().await.expect_throw(
                        "failed to negotiate session for websocket",
                    );

                let url = changes_uri(
                    &remote,
                    reader.client().signer(),
                    &mut session,
                )
                .await
                .expect_throw("could not build websocket changes feed URL");

                let (mut ws, mut wsio) = WsMeta::connect(url, None)
                    .await
                    .expect_throw("could not connect to websocket");

                let mut evts = ws
                    .observe(Filter::Pointer(WsEvent::is_closed).into())
                    .await
                    .expect_throw("could not create websocket observer");

                while let Some(event) = evts.next().await {
                    match event {
                        WsEvent::Closed(_) => {
                            // TODO: try to reconnect???
                        }
                        _ => {}
                    }
                }

                while let Some(message) = wsio.next().await {
                    match message {
                        WsMessage::Text(value) => {
                            log::info!("Got change notification {}", value);

                            match serde_json::from_str::<ChangeNotification>(
                                &value,
                            ) {
                                Ok(change) => {
                                    let mut writer = cache.write().unwrap();
                                    writer.handle_change(change).await
                                        .expect_throw(
                                            "failed to handle change notification");
                                }
                                Err(e) => {
                                    log::error!("{}", e);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            };

            spawn_local(listener);
        }
        */
    }
}
