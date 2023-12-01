use crate::Result;
use binary_stream::futures::Decodable;
use sos_sdk::prelude::EventRecord;

/// Patch wraps a changeset of events to be sent across the network.
#[derive(Clone, Debug, Default)]
pub struct Patch(Vec<EventRecord>);

impl Patch {
    /// Convert this patch into a collection of events.
    pub async fn into_events<T: Default + Decodable>(
        &self,
    ) -> Result<Vec<T>> {
        let mut events = Vec::new();
        for record in &self.0 {
            let event = record.decode_event::<T>().await?;
            events.push(event);
        }
        Ok(events)
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

    /// Append an event record to this patch.
    pub fn append(&mut self, record: EventRecord) {
        self.0.push(record);
    }
}

impl From<Vec<EventRecord>> for Patch {
    fn from(value: Vec<EventRecord>) -> Self {
        Self(value)
    }
}
