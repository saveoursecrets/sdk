include!(concat!(env!("OUT_DIR"), "/shared_folder.rs"));

use crate::{Error, ProtoBinding, Result};
use sos_core::Recipient;

/// Request to create or update recipient information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetRecipientRequest {
    /// Recipient information.
    pub recipient: Recipient,
}

impl ProtoBinding for SetRecipientRequest {
    type Inner = WireSetRecipientRequest;
}

impl TryFrom<WireSetRecipientRequest> for SetRecipientRequest {
    type Error = Error;

    fn try_from(value: WireSetRecipientRequest) -> Result<Self> {
        Ok(Self {
            recipient: value.recipient.unwrap().try_into()?,
        })
    }
}

impl From<SetRecipientRequest> for WireSetRecipientRequest {
    fn from(value: SetRecipientRequest) -> WireSetRecipientRequest {
        Self {
            recipient: Some(value.recipient.into()),
        }
    }
}

/// Response from a request to set recipient information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetRecipientResponse {}

impl ProtoBinding for SetRecipientResponse {
    type Inner = WireSetRecipientResponse;
}

impl TryFrom<WireSetRecipientResponse> for SetRecipientResponse {
    type Error = Error;

    fn try_from(_value: WireSetRecipientResponse) -> Result<Self> {
        Ok(Self {})
    }
}

impl From<SetRecipientResponse> for WireSetRecipientResponse {
    fn from(_value: SetRecipientResponse) -> WireSetRecipientResponse {
        Self {}
    }
}

/// Response with recipient information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetRecipientResponse {
    /// Recipient information.
    pub recipient: Option<Recipient>,
}

impl ProtoBinding for GetRecipientResponse {
    type Inner = WireGetRecipientResponse;
}

impl TryFrom<WireGetRecipientResponse> for GetRecipientResponse {
    type Error = Error;

    fn try_from(value: WireGetRecipientResponse) -> Result<Self> {
        let recipient = if let Some(recipient) = value.recipient {
            Some(recipient.try_into()?)
        } else {
            None
        };
        Ok(Self { recipient })
    }
}

impl From<GetRecipientResponse> for WireGetRecipientResponse {
    fn from(value: GetRecipientResponse) -> WireGetRecipientResponse {
        Self {
            recipient: value.recipient.map(|r| r.into()),
        }
    }
}

/// Request to get recipient information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetRecipientRequest {}

impl ProtoBinding for GetRecipientRequest {
    type Inner = WireGetRecipientRequest;
}

impl TryFrom<WireGetRecipientRequest> for GetRecipientRequest {
    type Error = Error;

    fn try_from(_value: WireGetRecipientRequest) -> Result<Self> {
        Ok(Self {})
    }
}

impl From<GetRecipientRequest> for WireGetRecipientRequest {
    fn from(_value: GetRecipientRequest) -> WireGetRecipientRequest {
        Self {}
    }
}

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

/// Response from a create shared folder request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFolderResponse {}

impl ProtoBinding for SharedFolderResponse {
    type Inner = WireSharedFolderResponse;
}

impl TryFrom<WireSharedFolderResponse> for SharedFolderResponse {
    type Error = Error;

    fn try_from(_value: WireSharedFolderResponse) -> Result<Self> {
        Ok(Self {})
    }
}

impl From<SharedFolderResponse> for WireSharedFolderResponse {
    fn from(_value: SharedFolderResponse) -> WireSharedFolderResponse {
        Self {}
    }
}
