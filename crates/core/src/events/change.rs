use crate::{commit::CommitSpan, events::EventLogType, AccountId};

/// Change event sent over a local socket.
pub struct LocalChangeEvent {
    /// Account identifier.
    pub account_id: AccountId,
    /// Detail about the event.
    pub detail: LocalChangeDetail,
}

/// Detail for the event.
pub enum LocalChangeDetail {
    /// Change to an event log.
    EventLog {
        /// Type of the event log.
        log_type: EventLogType,
        /// Span of commit hashes.
        commit_span: CommitSpan,
    },
}
