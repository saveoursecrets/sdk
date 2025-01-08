//! Event log types and traits.

// Backwards compatible re-exports - DO NOT USE
pub use sos_core::events::patch;
pub use sos_core::events::EventRecord;

mod file;
mod reducer;

#[cfg(feature = "files")]
pub use file::FileEventLog;

#[cfg(feature = "files")]
pub use reducer::FileReducer;

pub use file::{
    AccountEventLog, DeviceEventLog, DiscData, DiscEventLog, DiscLog,
    EventLogExt, FolderEventLog, MemoryData, MemoryEventLog, MemoryFolderLog,
    MemoryLog,
};
pub use reducer::DeviceReducer;
