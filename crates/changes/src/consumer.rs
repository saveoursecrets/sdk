//! Consumer for change notifications on a local socket.
use crate::{Error, Result, SocketFile};
use futures::stream::StreamExt;
use interprocess::local_socket::{
    tokio::prelude::*, GenericFilePath, ListenerOptions,
};
use sos_core::events::LocalChangeEvent;
use std::path::PathBuf;
use tokio::{
    select,
    sync::{mpsc, watch},
};
use tokio_util::codec::LengthDelimitedCodec;

/// Handle to a consumer.
///
/// Can be used to listen to incoming change events and
/// close the server task.
pub struct ConsumerHandle {
    receiver: mpsc::Receiver<LocalChangeEvent>,
    cancel_tx: watch::Sender<bool>,
}

impl ConsumerHandle {
    /// Channel for change events.
    pub fn changes(&mut self) -> &mut mpsc::Receiver<LocalChangeEvent> {
        &mut self.receiver
    }

    /// Stop listening for incoming events.
    pub fn cancel(&self) {
        self.cancel_tx.send_replace(true);
    }
}

/// Consumer socket connection for change events.
pub struct ChangeConsumer;

impl ChangeConsumer {
    /// Listen on change events.
    ///
    /// Returns a handle that can be used to consume the
    /// incoming events and stop listening.
    pub async fn listen(path: PathBuf) -> Result<ConsumerHandle> {
        let file = SocketFile::from(path);
        let name =
            file.as_ref().as_os_str().to_fs_name::<GenericFilePath>()?;
        let opts = ListenerOptions::new().name(name);
        let listener = match opts.create_tokio() {
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                tracing::error!(
                    "Error: could not start server because the socket file is occupied. Please check if {} is in use by another process and try again.",
                    file.as_ref().display(),
                );
                return Err(e.into());
            }
            x => x?,
        };

        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let (tx, rx) = mpsc::channel(32);

        #[allow(unreachable_code)]
        tokio::task::spawn(async move {
            loop {
                select! {
                    _ = cancel_rx.changed() => {
                        if *cancel_rx.borrow_and_update() {
                            break;
                        }
                    }
                    socket = listener.accept() => {
                        let socket = socket?;
                        let tx = tx.clone();
                        tokio::task::spawn(async move {
                            let mut reader = LengthDelimitedCodec::builder()
                                .native_endian()
                                .new_read(socket);
                            while let Some(Ok(buffer)) = reader.next().await {
                                let event: LocalChangeEvent =
                                    serde_json::from_slice(&buffer)?;
                                if let Err(e) = tx.send(event).await {
                                    tracing::warn!(error = %e);
                                }
                            }

                            Ok::<_, Error>(())
                        });
                    }
                }
            }
            Ok::<_, Error>(())
        });
        Ok(ConsumerHandle {
            receiver: rx,
            cancel_tx,
        })
    }
}
