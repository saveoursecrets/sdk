//! Listens for change notifications on a stream
//! and calls the handler with the incoming notifications.
use std::{future::Future, thread};

use async_recursion::async_recursion;
use futures::StreamExt;
use std::time::Duration;
use tokio::time::sleep;
use url::Url;

use super::{
    net::{
        ws_changes::{changes, connect, WsStream},
        RpcClient,
    },
    Error, Result,
};

use crate::session::ClientSession;

use sos_core::{events::ChangeNotification, signer::BoxedSigner};

const INTERVAL_MS: u64 = 15000;

/// Listen for changes and call a handler with the change notification.
#[derive(Clone)]
pub struct ChangesListener {
    remote: Url,
    signer: BoxedSigner,
}

impl ChangesListener {
    /// Create a new changes listener.
    pub fn new(remote: Url, signer: BoxedSigner) -> Self {
        Self { remote, signer }
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
        session: ClientSession,
        handler: &(impl Fn(ChangeNotification) -> F + Send + Sync + 'static),
    ) -> Result<()>
    where
        F: Future<Output = ()> + 'static,
    {
        let mut stream = changes(stream, session);
        while let Some(notification) = stream.next().await {
            let notification = notification?;
            let future = handler(notification);
            future.await;
        }
        Ok(())
    }

    async fn stream(&self) -> Result<(WsStream, ClientSession)> {
        Ok(connect(self.remote.clone(), self.signer.clone()).await?)
    }

    async fn connect<F>(
        &self,
        handler: &(impl Fn(ChangeNotification) -> F + Send + Sync + 'static),
    ) -> Result<()>
    where
        F: Future<Output = ()> + 'static,
    {
        match self.stream().await {
            Ok((stream, session)) => {
                self.listen(stream, session, handler).await
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
