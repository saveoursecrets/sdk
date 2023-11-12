//! Factory for creating providers.
use sos_sdk::{
    mpc::Keypair,
    signer::ecdsa::BoxedEcdsaSigner,
    storage::{AppPaths, UserPaths},
    vfs,
};
use std::{fmt, sync::Arc};
use url::Url;
use web3_address::ethereum::Address;

use crate::client::{
    net::RpcClient,
    provider::{BoxedProvider, RemoteProvider},
    Error, Result,
};

use tokio::sync::RwLock;

use std::{path::PathBuf, str::FromStr};

/// Provider that can be safely sent between threads.
pub type ArcProvider = Arc<RwLock<BoxedProvider>>;

/// Spawn a change notification listener that
/// updates the local node cache.
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn_changes_listener(
    server: Url,
    server_public_key: Vec<u8>,
    signer: BoxedEcdsaSigner,
    keypair: Keypair,
    cache: ArcProvider,
) {
    use crate::client::changes_listener::ChangesListener;
    let listener =
        ChangesListener::new(server, server_public_key, signer, keypair);
    listener.spawn(move |notification| {
        let cache = Arc::clone(&cache);
        async move {
            //println!("{:#?}", notification);
            let mut writer = cache.write().await;
            let _ = writer.handle_change(notification).await;
        }
    });
}
