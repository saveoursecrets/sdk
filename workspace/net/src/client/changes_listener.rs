//! Listens for change notifications on a stream
//! and calls the handler with the incoming notifications.
use std::{future::Future, sync::Arc, thread};

use async_recursion::async_recursion;
use futures::StreamExt;
use std::time::Duration;
use tokio::{sync::RwLock, time::sleep};
use url::Url;

use super::{
    net::{
        changes::{changes, connect, WsStream},
        RpcClient,
    },
    Error, LocalProvider, Result,
};

use sos_sdk::{
    events::ChangeNotification, mpc::Keypair, signer::ecdsa::BoxedEcdsaSigner,
};

const INTERVAL_MS: u64 = 15000;

/// Spawn a change notification listener that
/// updates the local node cache.
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn_changes_listener(
    server: Url,
    server_public_key: Vec<u8>,
    signer: BoxedEcdsaSigner,
    keypair: Keypair,
    cache: Arc<RwLock<LocalProvider>>,
) {
    let listener =
        ChangesListener::new(server, server_public_key, signer, keypair);
    listener.spawn(move |notification| {
        let cache = Arc::clone(&cache);
        async move {
            println!("{:#?}", notification);
            let mut writer = cache.write().await;
            todo!("restore handling change event notifications");
            //let _ = writer.handle_change(notification).await;
        }
    });
}

/// Listen for changes and call a handler with the change notification.
#[derive(Clone)]
pub struct ChangesListener {
    remote: Url,
    remote_public_key: Vec<u8>,
    signer: BoxedEcdsaSigner,
    keypair: Keypair,
}

impl ChangesListener {
    /// Create a new changes listener.
    pub fn new(
        remote: Url,
        remote_public_key: Vec<u8>,
        signer: BoxedEcdsaSigner,
        keypair: Keypair,
    ) -> Self {
        Self {
            remote,
            remote_public_key,
            signer,
            keypair,
        }
    }

    /// Spawn a thread to listen for changes and apply incoming
    /// changes to the local cache.
    pub fn spawn<F>(
        self,
        handler: impl Fn(ChangeNotification) -> F + Send + Sync + 'static,
    ) -> thread::JoinHandle<()>
    where
        F: Future<Output = ()> + 'static,
    {
        thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let _ = runtime.block_on(async move {
                let _ = self.connect(&handler).await;
                Ok::<(), Error>(())
            });
        })
    }

    #[async_recursion(?Send)]
    async fn listen<F>(
        &self,
        stream: WsStream,
        client: Arc<RpcClient>,
        handler: &(impl Fn(ChangeNotification) -> F + Send + Sync + 'static),
    ) -> Result<()>
    where
        F: Future<Output = ()> + 'static,
    {
        let mut stream = changes(stream, client);
        while let Some(notification) = stream.next().await {
            let notification = notification?.await?;
            let future = handler(notification);
            future.await;
        }
        Ok(())
    }

    async fn stream(&self) -> Result<(WsStream, Arc<RpcClient>)> {
        connect(
            self.remote.clone(),
            self.remote_public_key.clone(),
            self.signer.clone(),
            self.keypair.clone(),
        )
        .await
    }

    async fn connect<F>(
        &self,
        handler: &(impl Fn(ChangeNotification) -> F + Send + Sync + 'static),
    ) -> Result<()>
    where
        F: Future<Output = ()> + 'static,
    {
        match self.stream().await {
            Ok((stream, client)) => {
                self.listen(stream, client, handler).await
            }
            Err(_) => self.delay_connect(handler).await,
        }
    }

    #[async_recursion(?Send)]
    async fn delay_connect<F>(
        &self,
        handler: &(impl Fn(ChangeNotification) -> F + Send + Sync + 'static),
    ) -> Result<()>
    where
        F: Future<Output = ()> + 'static,
    {
        loop {
            sleep(Duration::from_millis(INTERVAL_MS)).await;
            self.connect(handler).await?;
        }
    }
}
