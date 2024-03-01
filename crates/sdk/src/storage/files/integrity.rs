//! Check integrity of external files.
use crate::{
    events::{FileEventLog, FileReducer},
    sha2::{Digest, Sha256},
    storage::files::{ExternalFile, ExternalFileName},
    vfs, Paths, Result,
};
use futures::StreamExt;
use indexmap::IndexSet;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::mpsc::{self, Receiver, Sender};
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
}

/// Generate an integrity report.
pub async fn integrity_report(
    paths: Arc<Paths>,
    event_log: &FileEventLog,
    concurrency: usize,
) -> Result<Receiver<Result<IntegrityReportEvent>>> {
    let (tx, rx) = mpsc::channel::<Result<IntegrityReportEvent>>(512);

    // Canonical list of external files.
    let reducer = FileReducer::new(event_log);

    #[cfg(feature = "sync")]
    let external_files = reducer.reduce(None).await?;
    #[cfg(not(feature = "sync"))]
    let external_files = reducer.reduce().await?;

    let _ = tx
        .send(Ok(IntegrityReportEvent::Begin(external_files.len())))
        .await;

    tokio::task::spawn(run_integrity_report(
        paths,
        external_files,
        concurrency,
        tx,
    ));
    Ok(rx)
}

async fn run_integrity_report(
    paths: Arc<Paths>,
    external_files: IndexSet<ExternalFile>,
    concurrency: usize,
    tx: Sender<Result<IntegrityReportEvent>>,
) {
    let chunk_size = concurrency;
    let list: Vec<_> = external_files.into_iter().collect();

    for chunk in list.chunks(chunk_size) {
        let files: Vec<_> = chunk
            .iter()
            .map(|file| {
                let path = paths.file_location(
                    file.vault_id(),
                    file.secret_id(),
                    file.file_name().to_string(),
                );
                check_file(*file, path, tx.clone())
            })
            .collect();

        if let Err(e) = futures::future::try_join_all(files).await {
            let _ = tx.send(Err(e)).await;
        }
    }
}

async fn check_file(
    file: ExternalFile,
    path: PathBuf,
    tx: Sender<Result<IntegrityReportEvent>>,
) -> Result<()> {
    if vfs::try_exists(&path).await? {
        let metadata = vfs::metadata(&path).await?;
        let _ = tx
            .send(Ok(IntegrityReportEvent::OpenFile(file, metadata.len())))
            .await;

        match compare_file(&file, path, tx.clone()).await {
            Ok(result) => {
                if let Some(failure) = result {
                    let _ = tx
                        .send(Ok(IntegrityReportEvent::Failure(
                            file, failure,
                        )))
                        .await;
                }
                let _ =
                    tx.send(Ok(IntegrityReportEvent::CloseFile(file))).await;
            }
            Err(e) => {
                let _ =
                    tx.send(Ok(IntegrityReportEvent::CloseFile(file))).await;
                return Err(e);
            }
        }
    } else {
        let _ = tx
            .send(Ok(IntegrityReportEvent::Failure(
                file,
                FailureReason::Missing(path),
            )))
            .await;
    }
    Ok(())
}

async fn compare_file(
    external_file: &ExternalFile,
    path: PathBuf,
    tx: Sender<Result<IntegrityReportEvent>>,
) -> Result<Option<FailureReason>> {
    let mut hasher = Sha256::new();
    let file = vfs::File::open(&path).await?;
    let mut reader_stream = ReaderStream::new(file);
    while let Some(chunk) = reader_stream.next().await {
        let chunk = chunk?;
        hasher.update(&chunk);
        let _ = tx
            .send(Ok(IntegrityReportEvent::ReadFile(
                *external_file,
                chunk.len(),
            )))
            .await;
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
