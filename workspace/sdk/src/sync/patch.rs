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

    /// Iterator of the events.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter()
    }

    /// Iterator of the owned events.
    pub fn into_iter(self) -> impl Iterator<Item = T> {
        self.0.into_iter()
    }

    /// Append an event record to this patch.
    pub(crate) fn append(&mut self, record: T) {
        self.0.push(record);
    }
}

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
