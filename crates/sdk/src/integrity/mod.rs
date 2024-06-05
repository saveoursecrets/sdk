//! Integrity checks for vaults, event logs and external files.
#[cfg(feature = "files")]
mod file_integrity;
mod folder_integrity;

pub use folder_integrity::{
    event_log_commit_tree_file, vault_commit_tree_file,
};

#[cfg(feature = "files")]
pub use file_integrity::{
    integrity_report, FailureReason, IntegrityReportEvent,
};
