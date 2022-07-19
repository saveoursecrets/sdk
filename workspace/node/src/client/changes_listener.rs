//! Listen for changes and instruct a cache implementation to
//! handle the change.
use std::{future::Future, thread};

use async_recursion::async_recursion;
use futures::StreamExt;
use std::time::Duration;
use tokio::time::sleep;

use super::{
    net::{
        changes::{ChangeStream, ChangeStreamEvent},
        RequestClient,
    },
    Error, Result,
};

use sos_core::{events::ChangeNotification, signer::Signer};

const INTERVAL_MS: u64 = 15000;

/// Listen for changes and update a local cache.
#[derive(Clone)]
pub struct ChangesListener<S>
where
    S: Signer + Send + Sync + 'static,
{
    client: RequestClient<S>,
}

impl<S> ChangesListener<S>
where
    S: Signer + Send + Sync + 'static,
{
    /// Create a new changes listener.
    pub fn new(client: RequestClient<S>) -> Self {
        Self { client }
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
        mut stream: ChangeStream,
        handler: &(impl Fn(ChangeNotification) -> F + Send + Sync + 'static),
    ) -> Result<()>
    where
        F: Future<Output = ()> + 'static,
    {
        while let Some(event) = stream.next().await {
            match event {
                Ok(event) => match event {
                    ChangeStreamEvent::Message(notification) => {
                        let future = handler(notification);
                        future.await;
                    }
                    ChangeStreamEvent::Open => {
                        tracing::info!("changes stream open");
                    }
                },
                Err(e) => {
                    tracing::error!(error = %e, "changes feed");
                    let _ = self.delay_connect(handler).await;
                }
            }
        }
        Ok(())
    }

    async fn stream(&self) -> Result<ChangeStream> {
        let stream = self.client.changes().await?;
        Ok(stream)
    }

    async fn connect<F>(
        &self,
        handler: &(impl Fn(ChangeNotification) -> F + Send + Sync + 'static),
    ) -> Result<()>
    where
        F: Future<Output = ()> + 'static,
    {
        match self.stream().await {
            Ok(stream) => self.listen(stream, handler).await,
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
