//! Network aware user storage and search index.

#[cfg(feature = "device")]
mod devices;

mod file_manager;
mod search_index;
mod security_report;
mod user_storage;

#[cfg(feature = "device")]
pub use devices::DeviceManager;

#[cfg(feature = "migrate")]
pub use sos_migrate::{
    import::{ImportFormat, ImportTarget},
    Convert,
};

pub use file_manager::FileProgress;
pub use search_index::{ArchiveFilter, DocumentView, QueryFilter, UserIndex};
pub use security_report::{
    PasswordReport, SecurityReport, SecurityReportOptions, SecurityReportRecord,
};
pub use user_storage::{
    AccountData, SecretOptions, UserStatistics, UserStorage,
};

#[cfg(feature = "contacts")]
pub use user_storage::ContactImportProgress;
