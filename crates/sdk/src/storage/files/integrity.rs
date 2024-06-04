//! Check integrity of external files.
use crate::{
    sha2::{Digest, Sha256},
    storage::files::{ExternalFile, ExternalFileName},
    vfs, Paths, Result,
};
use futures::StreamExt;
use indexmap::IndexSet;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    watch, Mutex, Semaphore,
};
use tokio_util::io::ReaderStream;

/// Reasons why an external file integrity check can fail.
#[derive(Debug)]
pub enum FailureReason {
    /// File is missing.
    Missing(PathBuf),
    /// Checksum mismatch, file is corrupted.
    Corrupted {
        /// File path.
        path: PathBuf,
        /// Expected file name checksum.
        expected: ExternalFileName,
        /// Actual file name checksum.
        actual: ExternalFileName,
    },
}

/// Event dispatched whilst generating an integrity report.
#[derive(Debug)]
pub enum IntegrityReportEvent {
    /// Begin processing the given number of files.
    Begin(usize),
    /// Integrity check failed.
    Failure(ExternalFile, FailureReason),
    /// File was opened.
    OpenFile(ExternalFile, u64),
    /// Read file buffer.
    ReadFile(ExternalFile, usize),
    /// File was closed.
    CloseFile(ExternalFile),
    /// File integrity check completed.
    Complete,
}

/// Generate an integrity report.
pub async fn integrity_report(
    paths: Arc<Paths>,
    external_files: IndexSet<ExternalFile>,
    concurrency: usize,
) -> Result<(Receiver<IntegrityReportEvent>, watch::Sender<()>)> {
    let (mut tx, rx) = mpsc::channel::<IntegrityReportEvent>(64);
    let (cancel_tx, mut cancel_rx) = watch::channel(());

    notify_listeners(
        &mut tx,
        IntegrityReportEvent::Begin(external_files.len()),
    )
    .await;

    let paths: Vec<_> = external_files
        .into_iter()
        .map(|file| {
            (
                file,
                paths.file_location(
                    file.vault_id(),
                    file.secret_id(),
                    file.file_name().to_string(),
                ),
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
              Some((file, path)) = stream.next() => {
                let semaphore = semaphore.clone();
                let ctx = cancel.clone();
                let mut crx = cancel_rx.clone();
                let mut tx = tx.clone();
                let completed = completed.clone();
                tokio::task::spawn(async move {
                  let _permit = semaphore.acquire().await;
                  check_file(file, path, &mut tx, &mut crx).await?;
                  let mut writer = completed.lock().await;
                  *writer += 1;
                  if *writer == num_files {
                    // Signal the shutdown event on the cancel channel
                    if let Err(error) = ctx.send(()) {
                      tracing::error!(error = ?error);
                    }
                  }
                  Ok::<_, crate::Error>(())
                });
              }
            }
        }

        notify_listeners(&mut tx, IntegrityReportEvent::Complete).await;

        Ok::<_, crate::Error>(())
    });

    Ok((rx, cancel_tx.clone()))
}

async fn check_file(
    file: ExternalFile,
    path: PathBuf,
    tx: &mut Sender<IntegrityReportEvent>,
    cancel_rx: &mut watch::Receiver<()>,
) -> Result<()> {
    if vfs::try_exists(&path).await? {
        let metadata = vfs::metadata(&path).await?;
        notify_listeners(
            tx,
            IntegrityReportEvent::OpenFile(file, metadata.len()),
        )
        .await;

        match compare_file(&file, path, tx, cancel_rx).await {
            Ok(result) => {
                if let Some(failure) = result {
                    notify_listeners(
                        tx,
                        IntegrityReportEvent::Failure(file, failure),
                    )
                    .await;
                }
                notify_listeners(tx, IntegrityReportEvent::CloseFile(file))
                    .await;
            }
            Err(e) => {
                notify_listeners(tx, IntegrityReportEvent::CloseFile(file))
                    .await;
                return Err(e);
            }
        }
    } else {
        notify_listeners(
            tx,
            IntegrityReportEvent::Failure(file, FailureReason::Missing(path)),
        )
        .await;
    }
    Ok(())
}

async fn compare_file(
    external_file: &ExternalFile,
    path: PathBuf,
    tx: &mut Sender<IntegrityReportEvent>,
    cancel_rx: &mut watch::Receiver<()>,
) -> Result<Option<FailureReason>> {
    let mut hasher = Sha256::new();
    let file = vfs::File::open(&path).await?;
    let mut reader_stream = ReaderStream::new(file);
    loop {
        tokio::select! {
          biased;
          _ = cancel_rx.changed() => {
            break;
          }
          chunk = reader_stream.next() => {
            if let Some(chunk) = chunk {
              let chunk = chunk?;
              hasher.update(&chunk);
              notify_listeners(
                  tx,
                  IntegrityReportEvent::ReadFile(*external_file, chunk.len()),
              )
              .await;
            } else {
              break;
            }
          }
        }
    }

    let digest = hasher.finalize();
    if digest.as_slice() != external_file.file_name().as_ref() {
        let slice: [u8; 32] = digest.as_slice().try_into()?;
        Ok(Some(FailureReason::Corrupted {
            path,
            expected: *external_file.file_name(),
            actual: slice.into(),
        }))
    } else {
        Ok(None)
    }
}

async fn notify_listeners(
    tx: &mut Sender<IntegrityReportEvent>,
    event: IntegrityReportEvent,
) {
    if let Err(error) = tx.send(event).await {
        tracing::warn!(error = ?error);
    }
}
