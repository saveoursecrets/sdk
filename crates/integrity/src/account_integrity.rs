//! Check integrity of the folders in an account.
use crate::{
    event_integrity, vault_integrity, Error, IntegrityFailure, Result,
};
use futures::{pin_mut, StreamExt};
use sos_backend::BackendTarget;
use sos_core::{
    commit::CommitHash, events::EventRecord, AccountId, SecretId,
};
use sos_database::entity::FolderEntity;
use sos_vault::{Summary, VaultId};
use sos_vfs as vfs;
use std::sync::Arc;
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    watch, Mutex, Semaphore,
};

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
    VaultRecord(VaultId, (SecretId, CommitHash)),
    /// Read a record in an event log.
    EventRecord(VaultId, EventRecord),
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
pub async fn account_integrity(
    target: &BackendTarget,
    account_id: &AccountId,
    folders: Vec<Summary>,
    concurrency: usize,
) -> Result<(Receiver<FolderIntegrityEvent>, watch::Sender<()>)> {
    let (mut event_tx, event_rx) = mpsc::channel::<FolderIntegrityEvent>(64);
    let (cancel_tx, mut cancel_rx) = watch::channel(());

    notify_listeners(
        &mut event_tx,
        FolderIntegrityEvent::Begin(folders.len()),
    )
    .await;

    let num_folders = folders.len();
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let cancel = cancel_tx.clone();
    let account_id = *account_id;
    let target = target.clone();
    tokio::task::spawn(async move {
        let mut stream = futures::stream::iter(folders);
        let completed = Arc::new(Mutex::new(0));
        loop {
            tokio::select! {
              biased;
              _ = cancel_rx.changed() => {
                break;
              }
              Some(folder) = stream.next() => {
                let semaphore = semaphore.clone();
                let cancel_tx = cancel.clone();
                let cancel_rx = cancel_rx.clone();
                let event_tx = event_tx.clone();
                let completed = completed.clone();
                let target = target.clone();
                tokio::task::spawn(async move {
                  let _permit = semaphore.acquire().await;

                  check_folder(
                    target,
                    &account_id,
                    folder.id(),
                    event_tx.clone(),
                    cancel_rx).await?;

                  let mut writer = completed.lock().await;
                  *writer += 1;
                  if *writer == num_folders {
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
    target: BackendTarget,
    account_id: &AccountId,
    folder_id: &VaultId,
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

    let vault_target = target.clone();
    let event_target = target.clone();

    let account_id = *account_id;
    let folder_id = *folder_id;

    // Check folders exist
    match &target {
        BackendTarget::FileSystem(paths) => {
            let vault_path = paths.vault_path(&folder_id);
            if !vfs::try_exists(&vault_path).await? {
                notify_listeners(
                    &mut vault_tx,
                    FolderIntegrityEvent::Failure(
                        folder_id,
                        IntegrityFailure::MissingFolder,
                    ),
                )
                .await;

                return Ok(());
            }

            let events_path = paths.event_log_path(&folder_id);
            if !vfs::try_exists(&events_path).await? {
                notify_listeners(
                    &mut vault_tx,
                    FolderIntegrityEvent::Failure(
                        folder_id,
                        IntegrityFailure::MissingFolder,
                    ),
                )
                .await;

                return Ok(());
            }
        }
        BackendTarget::Database(_, client) => {
            let db_folder_id = folder_id;
            let folder_row = client
                .conn(move |conn| {
                    let folder_entity = FolderEntity::new(&conn);
                    folder_entity.find_optional(&db_folder_id)
                })
                .await?;

            if folder_row.is_none() {
                notify_listeners(
                    &mut vault_tx,
                    FolderIntegrityEvent::Failure(
                        folder_id,
                        IntegrityFailure::MissingFolder,
                    ),
                )
                .await;
                return Ok(());
            }
        }
    }

    let v_jh = tokio::task::spawn(async move {
        let vault_stream =
            vault_integrity(&vault_target, &account_id, &folder_id);
        pin_mut!(vault_stream);
        loop {
            tokio::select! {
              biased;
              _ = vault_cancel_rx.changed() => {
                break;
              }
              event = vault_stream.next() => {
                if let Some(record) = event {
                  match record {
                    Ok(record) => {
                      notify_listeners(
                          &mut vault_tx,
                          FolderIntegrityEvent::VaultRecord(
                            vault_id, record),
                      )
                      .await;
                    }
                    Err(e) => {
                      match e {
                        Error::VaultHashMismatch { commit, value, .. } => {
                          notify_listeners(
                              &mut vault_tx,
                              FolderIntegrityEvent::Failure(
                                vault_id, IntegrityFailure::CorruptedFolder {
                                  folder_id: vault_id,
                                  expected: commit,
                                  actual: value,
                                }),
                          )
                          .await;
                        }
                        _ => {
                          notify_listeners(
                              &mut vault_tx,
                              FolderIntegrityEvent::Failure(
                                vault_id, IntegrityFailure::Error(e)),
                          )
                          .await;
                        }
                      }
                    }
                  }
                } else {
                  break;
                }
              }
            }
        }

        Ok::<_, Error>(())
    });

    let e_jh = tokio::task::spawn(async move {
        let event_stream =
            event_integrity(&event_target, &account_id, &folder_id);
        pin_mut!(event_stream);

        loop {
            tokio::select! {
              biased;
              _ = cancel_rx.changed() => {
                break;
              }
              event = event_stream.next() => {
                if let Some(record) = event {
                  match record {
                    Ok(record) => {
                      notify_listeners(
                          &mut event_tx,
                          FolderIntegrityEvent::EventRecord(event_id, record),
                      )
                      .await;
                    }
                    Err(e) => {
                      match e {
                        Error::HashMismatch { commit, value, .. } => {
                          notify_listeners(
                              &mut event_tx,
                              FolderIntegrityEvent::Failure(
                                vault_id, IntegrityFailure::CorruptedFolder {
                                  folder_id: vault_id,
                                  expected: commit,
                                  actual: value,
                                }),
                          )
                          .await;
                        }
                        _ => {
                          notify_listeners(
                              &mut event_tx,
                              FolderIntegrityEvent::Failure(
                                vault_id, IntegrityFailure::Error(e)),
                          )
                          .await;
                        }
                      }
                    }
                  }
                } else {
                  break;
                }
              }
            }
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
                    folder_id,
                    IntegrityFailure::Error(e),
                ),
            )
            .await;
        }
    }

    if is_ok {
        notify_listeners(
            &mut integrity_tx,
            FolderIntegrityEvent::CloseFolder(folder_id),
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
        tracing::warn!(error = ?error.0, "account_integrity::send");
    }
}
