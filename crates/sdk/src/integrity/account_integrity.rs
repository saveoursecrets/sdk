//! Check integrity of the folders in an account.
use crate::{
    integrity::IntegrityFailure,
    prelude::{EventLogRecord, VaultRecord},
    vault::{Summary, VaultId},
    vfs, Error, Paths, Result,
};
use futures::{pin_mut, StreamExt};
use indexmap::IndexSet;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    watch, Mutex, Semaphore,
};

use super::{event_integrity, vault_integrity};

/// Event dispatched whilst generating an integrity report.
#[derive(Debug)]
pub enum FolderIntegrityEvent {
    /// Begin processing the given number of folders.
    Begin(usize),
    /// Integrity check failed.
    Failure(VaultId, IntegrityFailure),
    /// Started integrity check on a folder.
    OpenFolder(VaultId),
    /// Read a record in a vault.
    VaultRecord(VaultId, VaultRecord),
    /// Read a record in an event log.
    EventRecord(VaultId, EventLogRecord),
    /// Finished integrity check on a folder.
    ///
    /// This event is only sent when a folder integrity
    /// check completes successfully.
    ///
    /// Errors are reported as a failure event.
    CloseFolder(VaultId),
    /// Folder integrity check completed.
    Complete,
}

/// Generate an integrity report for the folders in an account.
pub async fn account_integrity_report(
    paths: Arc<Paths>,
    folders: IndexSet<Summary>,
    concurrency: usize,
) -> Result<(Receiver<FolderIntegrityEvent>, watch::Sender<()>)> {
    let (mut event_tx, event_rx) = mpsc::channel::<FolderIntegrityEvent>(64);
    let (cancel_tx, mut cancel_rx) = watch::channel(());

    notify_listeners(
        &mut event_tx,
        FolderIntegrityEvent::Begin(folders.len()),
    )
    .await;

    let paths: Vec<_> = folders
        .into_iter()
        .map(|folder| {
            (
                *folder.id(),
                paths.vault_path(folder.id()),
                paths.event_log_path(folder.id()),
            )
        })
        .collect();

    let num_files = paths.len();
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let cancel = cancel_tx.clone();
    tokio::task::spawn(async move {
        let mut stream = futures::stream::iter(paths);
        let completed = Arc::new(Mutex::new(0));
        loop {
            tokio::select! {
              biased;
              _ = cancel_rx.changed() => {
                break;
              }
              Some((folder_id, vault_path, event_path)) = stream.next() => {
                let semaphore = semaphore.clone();
                let cancel_tx = cancel.clone();
                let cancel_rx = cancel_rx.clone();
                let event_tx = event_tx.clone();
                let completed = completed.clone();
                tokio::task::spawn(async move {
                  let _permit = semaphore.acquire().await;

                  check_folder(
                    &folder_id,
                    vault_path,
                    event_path,
                    event_tx.clone(),
                    cancel_rx).await?;

                  let mut writer = completed.lock().await;
                  *writer += 1;
                  if *writer == num_files {
                    // Signal the shutdown event on the cancel channel
                    // to break out of this loop and cancel any existing
                    // file reader streams
                    if let Err(error) = cancel_tx.send(()) {
                      tracing::error!(error = ?error);
                    }
                  }
                  Ok::<_, crate::Error>(())
                });
              }
            }
        }

        notify_listeners(&mut event_tx, FolderIntegrityEvent::Complete).await;

        Ok::<_, crate::Error>(())
    });

    Ok((event_rx, cancel_tx))
}

async fn check_folder(
    folder_id: &VaultId,
    vault_path: PathBuf,
    event_path: PathBuf,
    mut integrity_tx: Sender<FolderIntegrityEvent>,
    mut cancel_rx: watch::Receiver<()>,
) -> Result<()> {
    notify_listeners(
        &mut integrity_tx,
        FolderIntegrityEvent::OpenFolder(*folder_id),
    )
    .await;

    let vault_id = *folder_id;
    let event_id = *folder_id;
    let mut vault_tx = integrity_tx.clone();
    let mut event_tx = integrity_tx.clone();
    let mut vault_cancel_rx = cancel_rx.clone();

    let v_jh = tokio::task::spawn(async move {
        if vfs::try_exists(&vault_path).await? {
            let vault_stream = vault_integrity(vault_path);
            pin_mut!(vault_stream);
            loop {
                tokio::select! {
                  biased;
                  _ = vault_cancel_rx.changed() => {
                    break;
                  }
                  Some(event) = vault_stream.next() => {
                    let record = event??;
                    notify_listeners(
                        &mut vault_tx,
                        FolderIntegrityEvent::VaultRecord(
                          vault_id, record),
                    )
                    .await;
                  }
                }
            }
        } else {
            notify_listeners(
                &mut vault_tx,
                FolderIntegrityEvent::Failure(
                    vault_id,
                    IntegrityFailure::Missing(vault_path),
                ),
            )
            .await;
        }

        Ok::<_, Error>(())
    });

    let e_jh = tokio::task::spawn(async move {
        if vfs::try_exists(&event_path).await? {
            let event_stream = event_integrity(event_path);
            pin_mut!(event_stream);

            loop {
                tokio::select! {
                  biased;
                  _ = cancel_rx.changed() => {
                    break;
                  }
                  Some(event) = event_stream.next() => {
                    let record = event??;
                    notify_listeners(
                        &mut event_tx,
                        FolderIntegrityEvent::EventRecord(event_id, record),
                    )
                    .await;
                  }
                }
            }
        } else {
            notify_listeners(
                &mut event_tx,
                FolderIntegrityEvent::Failure(
                    event_id,
                    IntegrityFailure::Missing(event_path),
                ),
            )
            .await;
        }

        Ok::<_, Error>(())
    });

    let results = futures::future::try_join_all(vec![v_jh, e_jh]).await?;
    let is_ok = results.iter().all(|r| r.is_ok());
    for result in results {
        if let Err(e) = result {
            notify_listeners(
                &mut integrity_tx,
                FolderIntegrityEvent::Failure(
                    *folder_id,
                    IntegrityFailure::Error(e),
                ),
            )
            .await;
        }
    }

    if is_ok {
        notify_listeners(
            &mut integrity_tx,
            FolderIntegrityEvent::CloseFolder(*folder_id),
        )
        .await;
    }

    Ok(())
}

async fn notify_listeners(
    tx: &mut Sender<FolderIntegrityEvent>,
    event: FolderIntegrityEvent,
) {
    if let Err(error) = tx.send(event).await {
        tracing::warn!(error = ?error);
    }
}
