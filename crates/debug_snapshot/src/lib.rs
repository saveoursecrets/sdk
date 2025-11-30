//! Create a debug snapshot of events.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
use sos_archive::ZipWriter;
use sos_client_storage::{
    ClientBaseStorage, ClientFolderStorage, ClientStorage,
};
use sos_logs::LOG_FILE_NAME;
use sos_sync::SyncStorage;
use sos_vfs as vfs;
use std::path::Path;

mod error;
pub use error::Error;

#[cfg(feature = "audit")]
use futures::{pin_mut, StreamExt};

/// Options for debug snapshots.
#[derive(Debug)]
pub struct DebugSnapshotOptions {
    /// Include log files in the archive.
    pub include_log_files: bool,
    /// Include audit trail for the first configured
    /// audit provider.
    pub include_audit_trail: bool,
}

impl Default for DebugSnapshotOptions {
    fn default() -> Self {
        Self {
            include_log_files: true,
            include_audit_trail: false,
        }
    }
}

/// Export a ZIP archive containing a snapshot of an
/// account state; if the file exists it is overwritten.
///
/// # Privacy
///
/// No secret information is included but it does include the
/// account identifier and folder names.
pub async fn export_debug_snapshot(
    source: &ClientStorage,
    file: impl AsRef<Path>,
    options: DebugSnapshotOptions,
) -> Result<(), Error> {
    let zip_file = vfs::File::create(file.as_ref()).await?;
    let mut zip_writer = ZipWriter::new(zip_file);

    let account_id = *source.account_id();
    let debug_tree = source.debug_account_tree(account_id).await?;

    let buffer = serde_json::to_vec_pretty(&debug_tree)?;
    zip_writer.add_file("account.json", &buffer).await?;

    let login = source.read_login_vault().await?;
    let buffer = serde_json::to_vec_pretty(login.summary())?;
    zip_writer.add_file("login.json", &buffer).await?;

    if let Some(device) = source.read_device_vault().await? {
        let buffer = serde_json::to_vec_pretty(device.summary())?;
        zip_writer.add_file("device.json", &buffer).await?;
    }

    let target = source.backend_target();
    let paths = target.paths();

    if options.include_log_files {
        let logs = paths.logs_dir();
        let mut dir = vfs::read_dir(logs).await?;
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if let Some(name) = path.file_name() {
                if name.to_string_lossy().starts_with(LOG_FILE_NAME) {
                    let buffer = vfs::read(&path).await?;
                    zip_writer
                        .add_file(
                            &format!("logs/{}.jsonl", name.to_string_lossy()),
                            &buffer,
                        )
                        .await?;
                }
            }
        }
    }

    #[cfg(feature = "audit")]
    if options.include_audit_trail {
        if let Some(providers) = sos_backend::audit::providers() {
            for (index, provider) in providers.iter().enumerate() {
                let stream = provider.audit_stream(false).await?;
                pin_mut!(stream);

                let events = stream
                    .filter_map(|e| async move { e.ok() })
                    .filter_map(|e| async move {
                        if e.account_id() == &account_id {
                            Some(e)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .await;

                let buffer = serde_json::to_vec_pretty(&events)?;
                zip_writer
                    .add_file(&format!("audit/{}.json", index), &buffer)
                    .await?;
            }
        }
    }

    zip_writer.finish().await?;

    Ok(())
}
