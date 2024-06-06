//! Check integrity of external files.
use crate::{
    integrity::IntegrityFailure,
    sha2::{Digest, Sha256},
    storage::files::ExternalFile,
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

/// Event dispatched whilst generating an integrity report.
#[derive(Debug)]
pub enum FileIntegrityEvent {
    /// Begin processing the given number of files.
    Begin(usize),
    /// Integrity check failed.
    Failure(ExternalFile, IntegrityFailure),
    /// File was opened.
    OpenFile(ExternalFile, u64),
    /// Read file buffer.
    ReadFile(ExternalFile, usize),
    /// File was closed.
    ///
    /// This event is only sent when a file integrity
    /// check completes successfully.
    ///
    /// Errors are reported as a failure event.
    CloseFile(ExternalFile),
    /// File integrity check completed.
    Complete,
}

/// Iterate a collection of external files and verify the integrity
/// by checking the files exist on disc and the checksum of the disc
/// contents matches the expected checksum.
pub async fn file_integrity(
    paths: Arc<Paths>,
    external_files: IndexSet<ExternalFile>,
    concurrency: usize,
) -> Result<(Receiver<FileIntegrityEvent>, watch::Sender<()>)> {
    let (mut event_tx, event_rx) = mpsc::channel::<FileIntegrityEvent>(64);
    let (cancel_tx, mut cancel_rx) = watch::channel(());

    notify_listeners(
        &mut event_tx,
        FileIntegrityEvent::Begin(external_files.len()),
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
                let cancel_tx = cancel.clone();
                let mut cancel_rx = cancel_rx.clone();
                let mut event_tx = event_tx.clone();
                let completed = completed.clone();
                tokio::task::spawn(async move {
                  let _permit = semaphore.acquire().await;
                  check_file(file, path, &mut event_tx, &mut cancel_rx).await?;
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

        notify_listeners(&mut event_tx, FileIntegrityEvent::Complete).await;

        Ok::<_, crate::Error>(())
    });

    Ok((event_rx, cancel_tx))
}

async fn check_file(
    file: ExternalFile,
    path: PathBuf,
    tx: &mut Sender<FileIntegrityEvent>,
    cancel_rx: &mut watch::Receiver<()>,
) -> Result<()> {
    if vfs::try_exists(&path).await? {
        let metadata = vfs::metadata(&path).await?;
        notify_listeners(
            tx,
            FileIntegrityEvent::OpenFile(file, metadata.len()),
        )
        .await;

        match compare_file(&file, path, tx, cancel_rx).await {
            Ok(result) => {
                if let Some(failure) = result {
                    notify_listeners(
                        tx,
                        FileIntegrityEvent::Failure(file, failure),
                    )
                    .await;
                }
                notify_listeners(tx, FileIntegrityEvent::CloseFile(file))
                    .await;
            }
            Err(e) => {
                notify_listeners(
                    tx,
                    FileIntegrityEvent::Failure(
                        file,
                        IntegrityFailure::Error(e),
                    ),
                )
                .await;
            }
        }
    } else {
        notify_listeners(
            tx,
            FileIntegrityEvent::Failure(
                file,
                IntegrityFailure::Missing(path),
            ),
        )
        .await;
    }
    Ok(())
}

async fn compare_file(
    external_file: &ExternalFile,
    path: PathBuf,
    tx: &mut Sender<FileIntegrityEvent>,
    cancel_rx: &mut watch::Receiver<()>,
) -> Result<Option<IntegrityFailure>> {
    let mut hasher = Sha256::new();
    let file = vfs::File::open(&path).await?;
    let metadata = vfs::metadata(&path).await?;
    let bytes_total = metadata.len();
    let mut bytes_read = 0;
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
              bytes_read += chunk.len();
              notify_listeners(
                  tx,
                  FileIntegrityEvent::ReadFile(*external_file, chunk.len()),
              )
              .await;
            } else {
              break;
            }
          }
        }
    }

    let digest = hasher.finalize();
    let is_completed = bytes_read as u64 == bytes_total;
    // Only check for checksum mismatch if we actually
    // read all the bytes; if we receive a cancellation
    // then we don't want to send an integrity failure.
    if is_completed && digest.as_slice() != external_file.file_name().as_ref()
    {
        let slice: [u8; 32] = digest.as_slice().try_into()?;
        Ok(Some(IntegrityFailure::Corrupted {
            path,
            expected: external_file.file_name().to_string(),
            actual: hex::encode(&slice),
        }))
    } else {
        Ok(None)
    }
}

async fn notify_listeners(
    tx: &mut Sender<FileIntegrityEvent>,
    event: FileIntegrityEvent,
) {
    if let Err(error) = tx.send(event).await {
        tracing::warn!(error = ?error.0, "file_integrity::send");
    }
}
