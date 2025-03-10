//! Producer for change notifications on a local socket.
use crate::{Error, Result};
use futures::sink::SinkExt;
use interprocess::local_socket::{tokio::prelude::*, GenericFilePath};
use sos_core::{events::changes_feed, Paths};
use std::{path::PathBuf, sync::Arc, sync::LazyLock, time::Duration};
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};
use tokio::{
    select,
    sync::{watch, Mutex},
    time,
};
use tokio_util::codec::LengthDelimitedCodec;

static SYSTEM_PROCESSES: LazyLock<Mutex<sysinfo::System>> =
    LazyLock::new(|| {
        Mutex::new(System::new_with_specifics(
            RefreshKind::nothing()
                .with_processes(ProcessRefreshKind::everything()),
        ))
    });

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
        &self,
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
        Ok(ProducerHandle { cancel_tx })
    }
}

/// Find active socket files for a producer.
async fn find_active_sockets(paths: Arc<Paths>) -> Result<Vec<PathBuf>> {
    use std::fs::read_dir;

    if sysinfo::IS_SUPPORTED_SYSTEM {
        let mut system = SYSTEM_PROCESSES.lock().await;
        system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    }

    let mut sockets = Vec::new();
    let socks = paths.documents_dir().join(crate::SOCKS);
    if socks.exists() {
        tracing::trace!(
            socks_dir = %socks.display(),
            "changes::producer::find_active_sockets",
        );
        for entry in read_dir(&socks)? {
            let entry = entry?;
            if entry.path().ends_with(crate::SOCK_EXT) {
                if let Some(stem) = entry.path().file_stem() {
                    if let Ok(pid) =
                        stem.to_string_lossy().as_ref().parse::<u32>()
                    {
                        tracing::trace!(
                            sock_file = %entry.path().display(),
                            "changes::producer::find_active_sockets::pid_file",
                        );

                        if sysinfo::IS_SUPPORTED_SYSTEM {
                            let system = SYSTEM_PROCESSES.lock().await;
                            let pid = Pid::from_u32(pid);
                            tracing::trace!(
                                pid = %pid,
                                "changes::producer::find_active_sockets::pid_lookup",
                            );
                            if system.processes().contains_key(&pid) {
                                sockets.push(entry.path().to_owned());
                            }
                        } else {
                            #[cfg(any(windows, unix))]
                            sockets.push(entry.path().to_owned());
                        }
                    }
                }
            }
        }
        Ok(sockets)
    } else {
        Ok(sockets)
    }
}
