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
pub struct Patch<T: Default + Encodable + Decodable>(
    Vec<EventRecord>,
    PhantomData<T>,
);

impl<T: Default + Encodable + Decodable> Patch<T> {
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
    pub async fn into_events(&self) -> Result<Vec<T>> {
        let mut events = Vec::with_capacity(self.0.len());
        for record in &self.0 {
            events.push(record.decode_event::<T>().await?);
        }
        Ok(events)
    }

    /// Append an event record to this patch.
    pub(crate) fn append(&mut self, record: EventRecord) {
        self.0.push(record);
    }
}

/*
impl<T: Default + Encodable + Decodable> From<Vec<T>> for Patch<T> {
    fn from(value: Vec<T>) -> Self {
        Self(value)
    }
}

impl<T: Default + Encodable + Decodable> From<Patch<T>> for Vec<T> {
    fn from(value: Patch<T>) -> Self {
        value.0
    }
}

impl<'a, T: Default + Encodable + Decodable> From<&'a Patch<T>>
    for Vec<&'a T>
{
    fn from(value: &'a Patch<T>) -> Self {
        value.0.iter().collect()
    }
}
*/
