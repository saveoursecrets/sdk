use crate::{
    events::{AccountEvent, EventRecord, WriteEvent},
    Result,
};
use binary_stream::futures::{Decodable, Encodable};
use std::marker::PhantomData;

#[cfg(feature = "device")]
use crate::events::DeviceEvent;

#[cfg(feature = "files")]
use crate::events::FileEvent;

/// Patch of account events.
pub type AccountPatch = Patch<AccountEvent>;

/// Patch of folder events.
pub type FolderPatch = Patch<WriteEvent>;

/// Patch of device events.
#[cfg(feature = "device")]
pub type DevicePatch = Patch<DeviceEvent>;

/// Patch of file events.
#[cfg(feature = "files")]
pub type FilePatch = Patch<FileEvent>;

/// Patch wraps a changeset of events to be sent across the network.
#[derive(Clone, Debug, Default)]
pub struct Patch<T>(Vec<EventRecord>, PhantomData<T>);

impl<T> Patch<T> {
    /// Create a new patch from event records.
    pub fn new(records: Vec<EventRecord>) -> Self {
        Self(records, PhantomData)
    }

    /// Number of events in this patch.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this patch is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterator of the event records.
    pub fn iter(&self) -> impl Iterator<Item = &EventRecord> {
        self.0.iter()
    }

    /// Mutable event records.
    pub fn records(&self) -> &[EventRecord] {
        self.0.as_slice()
    }

    /// Decode this patch into the events.
    pub async fn into_events<E: Default + Decodable + Encodable>(
        &self,
    ) -> Result<Vec<E>> {
        let mut events = Vec::with_capacity(self.0.len());
        for record in &self.0 {
            events.push(record.decode_event::<E>().await?);
        }
        Ok(events)
    }
}

impl<T> From<Patch<T>> for Vec<EventRecord> {
    fn from(value: Patch<T>) -> Self {
        value.0
    }
}
