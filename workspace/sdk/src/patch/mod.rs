//! Patch represents a changeset of events to apply to a vault.

use crate::events::EventRecord;

mod file;
pub use file::PatchFile;

/// Patch wraps a changeset of events to be sent across the network.
#[derive(Clone, Debug, Default)]
pub struct Patch(pub Vec<EventRecord>);
