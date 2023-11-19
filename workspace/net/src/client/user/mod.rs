//! Network aware user account storage.

#[cfg(feature = "device")]
mod devices;

mod file_manager;
mod local_provider;
mod macros;
mod remote;
mod search_index;
#[cfg(feature = "security-report")]
mod security_report;
mod user_storage;

pub use local_provider::{LocalProvider, LocalState};
pub use remote::{RemoteProvider, Origin, Remote, Remotes};

#[cfg(feature = "device")]
pub use devices::DeviceManager;

#[cfg(feature = "migrate")]
pub use sos_migrate::{
    import::{ImportFormat, ImportTarget},
    Convert,
};

pub use file_manager::FileProgress;
pub use search_index::{ArchiveFilter, DocumentView, QueryFilter, UserIndex};

#[cfg(feature = "security-report")]
pub use security_report::{
    SecurityReport, SecurityReportOptions, SecurityReportRecord,
    SecurityReportRow, SecurityReportTarget,
};
pub use user_storage::{
    AccountData, DetachedView, SecretOptions,
    UserStatistics, UserStorage,
};

#[cfg(feature = "contacts")]
pub use user_storage::ContactImportProgress;
