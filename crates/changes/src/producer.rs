//! Producer for change notifications on a local socket.
use crate::{Error, Result};
use futures::sink::SinkExt;
use interprocess::local_socket::{tokio::prelude::*, GenericNamespaced};
use sos_core::{events::changes_feed, Paths};
use std::{sync::Arc, time::Duration};
use tokio::{
    select,
    sync::{watch, Mutex},
    time,
};
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
    /// The poll interval determines how frequently the socket
    /// directory is inspected. The directory is searched for files
    /// ending in .sock and with valid PIDs as the file stem.
    ///
    /// If `sysinfo` is supported it is checked to see if the process
    /// is running before being included in the list of socket file paths
    /// to attempt to notify of change events.
    ///
    /// Returns a handle that can be used to cancel the listener.
    #[allow(unreachable_code)]
    pub async fn listen(
        paths: Arc<Paths>,
        poll_interval: Duration,
    ) -> Result<ProducerHandle> {
        tracing::debug!(
            documents_dir = %paths.documents_dir().display(),
            poll_interval = ?poll_interval,
            "changes::producer::listen",
        );
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let tx = changes_feed();
        let mut rx = tx.subscribe();
        let sockets = find_active_sockets(paths.clone()).await?;
        let sockets = Mutex::new(sockets);
        let mut interval = time::interval(poll_interval);
        tokio::task::spawn(async move {
            loop {
                let paths = paths.clone();
                select! {
                    _ = cancel_rx.changed() => {
                        if *cancel_rx.borrow_and_update() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        let active = find_active_sockets(paths).await?;
                        let mut sockets = sockets.lock().await;
                        *sockets = active;
                    }
                    event = rx.changed() => {
                        match event {
                            Ok(_) => {
                                let event = rx.borrow_and_update().clone();
                                let sockets = sockets.lock().await;
                                for pid in &*sockets {
                                    let ps_name = pid.to_string();
                                    let name = ps_name.to_ns_name::<GenericNamespaced>()?;
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
        Ok(ProducerHandle { cancel_tx })
    }
}

/// Find active socket files for a producer.
async fn find_active_sockets(paths: Arc<Paths>) -> Result<Vec<u32>> {
    use std::fs::read_dir;
    let mut sockets = Vec::new();
    let socks = paths.documents_dir().join(crate::SOCKS);
    if socks.exists() {
        tracing::debug!(
            socks_dir = %socks.display(),
            "changes::producer::find_active_sockets",
        );
        for entry in read_dir(&socks)? {
            let entry = entry?;
            if let Some(stem) = entry.path().file_stem() {
                if let Ok(pid) =
                    stem.to_string_lossy().as_ref().parse::<u32>()
                {
                    tracing::debug!(
                        sock_file_pid = %pid,
                        "changes::producer::find_active_sockets",
                    );
                    sockets.push(pid);
                }
            }
        }
    }
    tracing::debug!(
        sockets_len = %sockets.len(),
        "changes::producer::find_active_sockets",
    );
    Ok(sockets)
}
