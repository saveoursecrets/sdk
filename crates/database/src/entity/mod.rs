//! Database entities.
mod account;
#[cfg(feature = "audit")]
mod audit;
mod event;
// #[cfg(feature = "files")]
// mod file;
mod folder;
#[cfg(feature = "preferences")]
mod preference;
mod server;
mod shared_folder;
#[cfg(feature = "system-messages")]
mod system_message;

pub use account::{AccountEntity, AccountRecord, AccountRow};
#[cfg(feature = "audit")]
pub use audit::{AuditEntity, AuditRecord, AuditRow};
pub use event::{CommitRecord, EventEntity, EventRecordRow};
// #[cfg(feature = "files")]
// pub use file::FileEntity;
pub use folder::{
    FolderEntity, FolderRecord, FolderRow, SecretRecord, SecretRow,
};
#[cfg(feature = "preferences")]
pub use preference::{PreferenceEntity, PreferenceRow};
pub use server::{ServerEntity, ServerRow};
pub use shared_folder::SharedFolderEntity;
#[cfg(feature = "system-messages")]
pub use system_message::{SystemMessageEntity, SystemMessageRow};
