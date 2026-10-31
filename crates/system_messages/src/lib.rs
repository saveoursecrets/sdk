//! System messages are persistent user notifications.
//!
//! They can be used to surface information such as
//! a failed synchronization, software update, due date for backup,
//! automated security report or other information about an account.
//!
//! System messages use keys so that we don't write lots
//! of failed synchronization messages, instead the last
//! failure would overwrite the previous messages. To avoid
//! this behavior use a unique key such as a UUID.
//!
//! Use [SystemMessages::subscribe] to listen for
//! changes to the underlying collection. This allows
//! an interface to show the number of unread system
//! messages.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
mod system_messages;

pub use error::Error;
pub use system_messages::*;
