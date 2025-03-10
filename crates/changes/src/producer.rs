//! Producer for change notifications on a local socket.
use crate::{Error, Result};
use futures::sink::SinkExt;
use interprocess::local_socket::{tokio::prelude::*, GenericNamespaced};
use sos_core::events::changes_feed;
use tokio::{select, sync::watch};
use tokio_util::codec::LengthDelimitedCodec;

/// Handle to a producer.
pub struct ProducerHandle {
    cancel_tx: watch::Sender<bool>,
}

impl ProducerHandle {
    /// Stop listening for change events.
    pub fn cancel(&self) {
        self.cancel_tx.send_replace(true);
    }
}

/// Producer socket connection for change events.
pub struct ChangeProducer {
    socket_name: String,
}

impl ChangeProducer {
    /// Create a connection to the socket.
    pub fn new(socket_name: &str) -> Result<Self> {
        Ok(Self {
            socket_name: socket_name.to_owned(),
        })
    }

    /// Listen to the changes feed.
    ///
    /// For each event try to send it over the local socket,
    /// returns a handle that can be used to cancel the listener.
    #[allow(unreachable_code)]
    pub fn listen(&self) -> ProducerHandle {
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let tx = changes_feed();
        let mut rx = tx.subscribe();
        let socket_name = self.socket_name.clone();
        tokio::task::spawn(async move {
            loop {
                select! {
                    _ = cancel_rx.changed() => {
                        if *cancel_rx.borrow_and_update() {
                            break;
                        }
                    }
                    event = rx.changed() => {
                        match event {
                            Ok(_) => {
                                let event = rx.borrow_and_update().clone();
                                let name = socket_name
                                    .clone()
                                    .to_ns_name::<GenericNamespaced>()?;
                                match LocalSocketStream::connect(name).await {
                                    Ok(socket) => {
                                        let mut writer =
                                            LengthDelimitedCodec::builder()
                                                .native_endian()
                                                .new_write(socket);
                                        let message = serde_json::to_vec(&event)?;
                                        writer.send(message.into()).await?;
                                    }
                                    Err(_) => {}
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
            Ok::<_, Error>(())
        });
        ProducerHandle { cancel_tx }
    }
}
