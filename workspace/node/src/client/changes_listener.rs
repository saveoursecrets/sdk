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
    file_cache::FileCache,
    net::changes::{ChangeStream, ChangeStreamEvent},
    Error, LocalCache, Result,
};

const INTERVAL_MS: u64 = 15000;

/// Listen for changes and update a local cache.
pub struct ChangesListener {
    cache: Arc<RwLock<FileCache>>,
}

impl ChangesListener {
    /// Create a new changes listener.
    pub fn new(cache: Arc<RwLock<FileCache>>) -> Self {
        Self { cache }
    }

    /// Spawn a thread to listen for changes and apply incoming
    /// changes to the local cache.
    pub fn spawn(&self) -> thread::JoinHandle<()> {
        let change_cache = Arc::clone(&self.cache);
        thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let _ = runtime.block_on(async move {
                let _ = ChangesListener::connect(change_cache).await;
                Ok::<(), Error>(())
            });
        })
    }

    #[async_recursion(?Send)]
    async fn listen(
        cache: Arc<RwLock<FileCache>>,
        mut stream: ChangeStream,
    ) -> Result<()> {
        while let Some(event) = stream.next().await {
            match event {
                Ok(event) => match event {
                    ChangeStreamEvent::Message(notification) => {
                        let mut writer = cache.write().unwrap();
                        writer.handle_change(notification).await?;
                    }
                    ChangeStreamEvent::Open => {
                        tracing::info!("changes stream open");
                    }
                },
                Err(e) => {
                    tracing::error!(error = %e, "changes feed");
                    let _ =
                        ChangesListener::delay_connect(Arc::clone(&cache))
                            .await;
                }
            }
        }
        Ok(())
    }

    async fn stream(cache: Arc<RwLock<FileCache>>) -> Result<ChangeStream> {
        let reader = cache.read().unwrap();
        let stream = reader.client().changes().await?;
        Ok(stream)
    }

    async fn connect(cache: Arc<RwLock<FileCache>>) -> Result<()> {
        match ChangesListener::stream(Arc::clone(&cache)).await {
            Ok(stream) => ChangesListener::listen(cache, stream).await,
            Err(_) => ChangesListener::delay_connect(cache).await,
        }
    }

    #[async_recursion(?Send)]
    async fn delay_connect(cache: Arc<RwLock<FileCache>>) -> Result<()> {
        loop {
            sleep(Duration::from_millis(INTERVAL_MS)).await;
            ChangesListener::connect(Arc::clone(&cache)).await?;
        }
    }
}
