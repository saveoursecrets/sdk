//! Patch represents a changeset of events to apply to a vault.

use crate::events::WriteEvent;

mod file;
pub use file::PatchFile;

/// Patch wraps a changeset of events to be sent across the network.
#[derive(Clone, Debug, Default)]
pub struct Patch<'a>(pub Vec<WriteEvent<'a>>);

impl Patch<'_> {
    /// Convert all events encapsulated by this patch into owned variants.
    pub fn into_owned(self) -> Patch<'static> {
        let events = self
            .0
            .into_iter()
            .map(|e| e.into_owned())
            .collect::<Vec<_>>();
        Patch(events)
    }
}
