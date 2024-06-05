//! Integrity checks for vaults, event logs and external files.
mod event_integrity;
#[cfg(feature = "files")]
mod file_integrity;
mod vault_integrity;

pub use event_integrity::event_integrity;
pub use vault_integrity::vault_integrity;

#[cfg(feature = "files")]
pub use file_integrity::{
    file_integrity_report, FailureReason, IntegrityReportEvent,
};
