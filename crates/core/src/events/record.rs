use crate::{
    commit::{CommitHash, CommitTree},
    decode, encode, Result, UtcDateTime,
};
use binary_stream::futures::{Decodable, Encodable};

/// Record for a row in an event log.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct EventRecord(
    pub(crate) UtcDateTime,
    pub(crate) CommitHash,
    pub(crate) CommitHash,
    pub(crate) Vec<u8>,
);

impl EventRecord {
    /// Create an event record.
    pub fn new(
        time: UtcDateTime,
        last_commit: CommitHash,
        commit: CommitHash,
        event: Vec<u8>,
    ) -> Self {
        Self(time, last_commit, commit, event)
    }

    /// Date and time the record was created.
    pub fn time(&self) -> &UtcDateTime {
        &self.0
    }

    /// Set the record time.
    pub fn set_time(&mut self, time: UtcDateTime) {
        self.0 = time;
    }

    /// Last commit hash for the record.
    pub fn last_commit(&self) -> &CommitHash {
        &self.1
    }

    /// Set last commit hash for the record.
    pub fn set_last_commit(&mut self, commit: Option<CommitHash>) {
        self.1 = commit.unwrap_or_default();
    }

    /// Commit hash for the record.
    pub fn commit(&self) -> &CommitHash {
        &self.2
    }

    /// Record event bytes.
    pub fn event_bytes(&self) -> &[u8] {
        self.3.as_slice()
    }

    /// Size of the event buffer.
    pub fn size(&self) -> usize {
        self.3.len()
    }

    /// Decode this event record.
    pub async fn decode_event<T: Default + Decodable>(&self) -> Result<T> {
        decode(&self.3).await
    }

    /// Encode an event into an event record.
    ///
    /// Encodes using a zero last commit and now
    /// as the date time.
    pub async fn encode_event<T: Default + Encodable>(
        event: &T,
    ) -> Result<Self> {
        let bytes = encode(event).await?;
        let commit = CommitHash(CommitTree::hash(&bytes));
        Ok(EventRecord(
            Default::default(),
            Default::default(),
            commit,
            bytes,
        ))
    }
}

impl From<EventRecord> for (UtcDateTime, CommitHash, CommitHash, Vec<u8>) {
    fn from(value: EventRecord) -> Self {
        (value.0, value.1, value.2, value.3)
    }
}
