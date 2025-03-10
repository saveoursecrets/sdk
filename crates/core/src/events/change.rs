use crate::{commit::CommitSpan, events::EventLogType, AccountId};
use std::sync::OnceLock;
use tokio::sync::watch;

static CHANGES_FEED: OnceLock<watch::Sender<LocalChangeEvent>> =
    OnceLock::new();

/// Change event.
///
/// Used for IPC communication when a process needs
/// to know if changes have been made externally,
///
/// For example, the browser extension helper executable
/// can detect changes made by the app and update it's
/// view.
#[derive(Default, Debug)]
pub enum LocalChangeEvent {
    /// Changes feed was initialized.
    #[default]
    Init,
    /// Account was created.
    AccountCreated(AccountId),
    /// Account was modified.
    AccountModified {
        /// Account identifier.
        account_id: AccountId,
        /// Type of the event log.
        log_type: EventLogType,
        /// Span of commit hashes.
        commit_span: CommitSpan,
    },
    /// Account was deleted.
    AccountDeleted(AccountId),
}

/// Feed of change events.
pub fn changes_feed<'a>() -> &'a watch::Sender<LocalChangeEvent> {
    CHANGES_FEED.get_or_init(|| {
        let (tx, _) = watch::channel(LocalChangeEvent::default());
        tx
    })
}
