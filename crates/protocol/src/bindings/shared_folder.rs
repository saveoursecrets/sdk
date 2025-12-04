include!(concat!(env!("OUT_DIR"), "/shared_folder.rs"));

use crate::{Error, ProtoBinding, Result};
use sos_core::Recipient;

/// Request to create a shared folder on a remote.
///
/// Used during auto merge to force push a combined collection
/// of events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFolderRequest {
    /// Encoded vault.
    pub vault: Vec<u8>,
    /// List of recipients.
    pub recipients: Vec<Recipient>,
}

impl ProtoBinding for SharedFolderRequest {
    type Inner = WireSharedFolderRequest;
}

impl TryFrom<WireSharedFolderRequest> for SharedFolderRequest {
    type Error = Error;

    fn try_from(value: WireSharedFolderRequest) -> Result<Self> {
        let mut recipients = Vec::with_capacity(value.recipients.len());
        for recipient in value.recipients {
            recipients.push(recipient.try_into()?);
        }
        Ok(Self {
            vault: value.vault,
            recipients,
        })
    }
}

impl From<SharedFolderRequest> for WireSharedFolderRequest {
    fn from(value: SharedFolderRequest) -> WireSharedFolderRequest {
        Self {
            vault: value.vault,
            recipients: value
                .recipients
                .into_iter()
                .map(|r| r.into())
                .collect(),
        }
    }
}

/// Response from a patch request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFolderResponse {}

impl ProtoBinding for SharedFolderResponse {
    type Inner = WireSharedFolderResponse;
}

impl TryFrom<WireSharedFolderResponse> for SharedFolderResponse {
    type Error = Error;

    fn try_from(value: WireSharedFolderResponse) -> Result<Self> {
        Ok(Self {})
    }
}

impl From<SharedFolderResponse> for WireSharedFolderResponse {
    fn from(value: SharedFolderResponse) -> WireSharedFolderResponse {
        Self {}
    }
}
