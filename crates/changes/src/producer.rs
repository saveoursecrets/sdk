//! Producer for change notifications on a local socket.
use std::path::PathBuf;

use crate::Error;
use futures::sink::SinkExt;
use interprocess::local_socket::{tokio::prelude::*, GenericFilePath};
use sos_core::events::changes_feed;
use tokio::{select, sync::watch, sync::Mutex};
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
pub struct ChangeProducer;

impl ChangeProducer {
    /// Listen to the changes feed and send change events to
    /// active sockets.
    ///
    /// Returns a handle that can be used to cancel the listener.
    #[allow(unreachable_code)]
    pub fn listen(&self, sockets: Vec<PathBuf>) -> ProducerHandle {
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let tx = changes_feed();
        let mut rx = tx.subscribe();
        let sockets = Mutex::new(sockets);
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
                                let sockets = sockets.lock().await;
                                for path in &*sockets {
                                    let name = path.as_os_str().to_fs_name::<GenericFilePath>()?;
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
