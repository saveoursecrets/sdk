//! Listen for changes and instruct a cache implementation to
//! handle the change.
use std::{
    sync::{Arc, RwLock},
    thread,
};

use async_recursion::async_recursion;
use futures::StreamExt;
use std::time::Duration;
use tokio::time::sleep;

use super::{
    net::changes::{ChangeStream, ChangeStreamEvent},
    node_cache::NodeCache,
    Error, LocalCache, Result,
};

use sos_core::{events::ChangeNotification, wal::WalProvider, PatchProvider};

const INTERVAL_MS: u64 = 15000;

/// Listen for changes and update a local cache.
pub struct ChangesListener {}

impl ChangesListener {
    /// Create a new changes listener.
    pub fn new() -> Self {
        Self {}
    }

    /// Spawn a thread to listen for changes and apply incoming
    /// changes to the local cache.
    pub fn spawn<F>(&self, mut handler: F) -> thread::JoinHandle<()>
    where
        F: FnMut(ChangeNotification) + Send + Sync + 'static,
    {
        //let change_cache = Arc::clone(&self.cache);
        thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let _ = runtime.block_on(async move {
                let _ = ChangesListener::connect(&mut handler).await;
                Ok::<(), Error>(())
            });
        })
    }

    #[async_recursion(?Send)]
    async fn listen<F>(
        //cache: Arc<RwLock<NodeCache<W, P>>>,
        mut stream: ChangeStream,
        handler: &mut F,
    ) -> Result<()>
    where
        F: FnMut(ChangeNotification) + Send + Sync + 'static,
    {
        while let Some(event) = stream.next().await {
            match event {
                Ok(event) => match event {
                    ChangeStreamEvent::Message(notification) => {
                        /*
                        let mut writer = cache.write().unwrap();
                        writer.handle_change(notification).await?;
                        */
                        handler(notification)
                    }
                    ChangeStreamEvent::Open => {
                        tracing::info!("changes stream open");
                    }
                },
                Err(e) => {
                    tracing::error!(error = %e, "changes feed");

                    /*
                    let _ =
                        ChangesListener::delay_connect(Arc::clone(&cache))
                            .await;
                    */
                }
            }
        }
        Ok(())
    }

    async fn stream(//cache: Arc<RwLock<NodeCache<W, P>>>,
    ) -> Result<ChangeStream> {
        todo!()
        //let reader = cache.read().unwrap();
        //let stream = reader.client().changes().await?;
        //Ok(stream)
    }

    async fn connect<F>(handler: &mut F) -> Result<()>
    where
        F: FnMut(ChangeNotification) + Send + Sync + 'static,
    {
        match ChangesListener::stream().await {
            Ok(stream) => ChangesListener::listen(stream, handler).await,
            Err(_) => ChangesListener::delay_connect(handler).await,
        }
    }

    #[async_recursion(?Send)]
    async fn delay_connect<F>(
        handler: &mut F, //cache: Arc<RwLock<NodeCache<W, P>>>,
    ) -> Result<()>
    where
        F: FnMut(ChangeNotification) + Send + Sync + 'static,
    {
        loop {
            sleep(Duration::from_millis(INTERVAL_MS)).await;
            ChangesListener::connect(handler).await?;
        }
    }
}
