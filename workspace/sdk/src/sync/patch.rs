use crate::{events::EventRecord, Error, Result};
use binary_stream::futures::{Decodable, Encodable};

/// Patch wraps a changeset of events to be sent across the network.
#[derive(Clone, Debug, Default)]
pub struct Patch<T: Default + Encodable + Decodable>(Vec<T>);

impl<T: Default + Encodable + Decodable> Patch<T> {
    /// Create a new patch from event records.
    pub async fn new(records: Vec<EventRecord>) -> Result<Self> {
        let mut events = Vec::new();
        for record in &records {
            let event = record.decode_event::<T>().await?;
            events.push(event);
        }
        Ok(events.into())
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
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter()
    }

    /// Append an event record to this patch.
    pub fn append(&mut self, record: T) {
        self.0.push(record);
    }
}

impl<T: Default + Encodable + Decodable> From<Vec<T>> for Patch<T> {
    fn from(value: Vec<T>) -> Self {
        Self(value)
    }
}
