//! Producer for change notifications on a local socket.
use crate::{Error, Result};
use futures::sink::SinkExt;
use interprocess::local_socket::{tokio::prelude::*, GenericNamespaced};
use sos_core::{
    events::{changes_feed, LocalChangeEvent},
    Paths,
};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{select, sync::Mutex, time};
use tokio_util::{codec::LengthDelimitedCodec, sync::CancellationToken};

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
    ) -> Result<CancellationToken> {
        tracing::debug!(
            documents_dir = %paths.documents_dir().display(),
            poll_interval = ?poll_interval,
            "changes::producer::listen",
        );
        let cancel = CancellationToken::new();
        let child_cancel = cancel.child_token();

        let tx = changes_feed();
        let mut rx = tx.subscribe();
        let sockets = find_active_sockets(paths.clone()).await?;
        let sockets = Arc::new(Mutex::new(sockets));
        let mut interval = time::interval(poll_interval);
        tokio::task::spawn(async move {
            loop {
                let paths = paths.clone();
                select! {
                    // Explicit cancel notification
                    _ = child_cancel.cancelled() => {
                        break;
                    }
                    // Periodically refresh the list of consumer sockets
                    // to dispatch change events to
                    _ = interval.tick() => {
                        let active = find_active_sockets(paths).await?;
                        let mut sockets = sockets.lock().await;
                        *sockets = active;
                    }
                    // Proxy the change events to the consumer sockets
                    event = rx.changed() => {
                        if event.is_ok() {
                            let dispatch_event = rx.borrow_and_update().clone();
                            let sockets = sockets.lock().await;
                            dispatch_sockets(dispatch_event, &sockets).await?;
                        } else {
                            // Sender was dropped, can't receive any more events
                            break;
                        }
                    }
                }
            }
            Ok::<_, Error>(())
        });
        Ok(cancel)
    }
}

async fn dispatch_sockets(
    event: LocalChangeEvent,
    sockets: &[(u32, PathBuf)],
) -> Result<()> {
    for (pid, file) in sockets {
        let ps_name = pid.to_string();
        let name = ps_name.to_ns_name::<GenericNamespaced>()?;
        match LocalSocketStream::connect(name).await {
            Ok(socket) => {
                let mut writer = LengthDelimitedCodec::builder()
                    .native_endian()
                    .new_write(socket);
                let message = serde_json::to_vec(&event)?;
                writer.send(message.into()).await?;
            }
            Err(e) => {
                // If we can't connect to the socket
                // then treat the file as stale and
                // remove from disc.
                //
                // This could happen if the consumer
                // process aborted abnormally and
                // wasn't able to cleanly remove the file.
                let _ = std::fs::remove_file(file);
                tracing::warn!(
                    pid = %pid,
                    error = %e,
                    "changes::producer::connect_error");
            }
        }
    }
    Ok(())
}

/// Find active socket files for a producer.
async fn find_active_sockets(
    paths: Arc<Paths>,
) -> Result<Vec<(u32, PathBuf)>> {
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
            if let Some(stem) = entry.path().file_stem()
                && let Ok(pid) =
                    stem.to_string_lossy().as_ref().parse::<u32>()
                {
                    tracing::debug!(
                        sock_file_pid = %pid,
                        "changes::producer::find_active_sockets",
                    );
                    sockets.push((pid, entry.path().to_owned()));
                }
        }
    }
    tracing::debug!(
        sockets_len = %sockets.len(),
        "changes::producer::find_active_sockets",
    );
    Ok(sockets)
}
