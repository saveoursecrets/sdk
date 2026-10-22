//! Consumer for change notifications on a local socket.
use crate::{Error, Result, SocketFile};
use futures::stream::StreamExt;
use interprocess::local_socket::{
    GenericNamespaced, ListenerOptions, tokio::prelude::*,
};
use sos_core::{Paths, events::LocalChangeEvent};
use std::{path::PathBuf, sync::Arc};
use tokio::{
    select,
    sync::{mpsc, watch},
};
use tokio_util::codec::LengthDelimitedCodec;

/// Handle to a consumer.
///
/// Provides access to a receive channel for
/// incoming change events and can also be
/// used to cancel the listener.
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
    /// Listen for incoming change events.
    ///
    /// Returns a handle that can be used to consume the
    /// incoming events and stop listening.
    pub fn listen(paths: Arc<Paths>) -> Result<ConsumerHandle> {
        let path = socket_file(paths)?;
        tracing::trace!(
            socket_file = %path.display(),
            "changes::consumer::listen",
        );
        let ps_name = std::process::id().to_string();
        let file = SocketFile::from(path);
        let name = ps_name.to_ns_name::<GenericNamespaced>()?;
        let opts = ListenerOptions::new().name(name);
        let listener = match opts.create_tokio() {
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                tracing::error!(
                    socket_file = %file.as_ref().display(),
                    "changes::consumer::listen::addr_in_use",
                );
                return Err(e.into());
            }
            x => x?,
        };

        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let (tx, rx) = mpsc::channel(32);

        // Create the marker file so producers know
        // which processes to send change events to
        std::fs::File::create(file.as_ref())?;

        #[allow(unreachable_code)]
        tokio::task::spawn(async move {
            // Keep the RAII file guard alive
            let _guard = file;
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
                                    tracing::warn!(
                                        error = %e,
                                        "changes::consumer::send_error");
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

/// Standard path for a consumer socket file.
///
/// If the parent directory for socket files does not
/// exist it is created.
fn socket_file(paths: std::sync::Arc<sos_core::Paths>) -> Result<PathBuf> {
    let socks = paths.documents_dir().join(crate::SOCKS);
    if !socks.exists() {
        std::fs::create_dir(&socks)?;
    }
    let pid = std::process::id();
    let mut path = socks.join(pid.to_string());
    path.set_extension(crate::SOCK_EXT);
    Ok(path)
}
