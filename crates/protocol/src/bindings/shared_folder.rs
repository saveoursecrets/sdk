include!(concat!(env!("OUT_DIR"), "/shared_folder.rs"));

use crate::{
    Error, ProtoBinding, Result, bindings::common::WireInviteStatus,
};
use serde::{Deserialize, Serialize};
use sos_core::{FolderInvite, InviteStatus, Recipient, VaultId};

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

/// Request to get folder invites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetFolderInvitesRequest {
    /// Invite status.
    pub invite_status: Option<InviteStatus>,
    /// Limit the number of rows.
    pub limit: Option<usize>,
}

impl ProtoBinding for GetFolderInvitesRequest {
    type Inner = WireGetFolderInvitesRequest;
}

impl TryFrom<WireGetFolderInvitesRequest> for GetFolderInvitesRequest {
    type Error = Error;

    fn try_from(value: WireGetFolderInvitesRequest) -> Result<Self> {
        let invite_status = if let Some(invite_status) = value.invite_status {
            Some(invite_status.try_into()?)
        } else {
            None
        };
        Ok(Self {
            invite_status,
            limit: value.limit.map(|l| l as usize),
        })
    }
}

impl From<GetFolderInvitesRequest> for WireGetFolderInvitesRequest {
    fn from(value: GetFolderInvitesRequest) -> WireGetFolderInvitesRequest {
        Self {
            invite_status: value
                .invite_status
                .map(|s| WireInviteStatus::from(s) as i32),
            limit: value.limit.map(|l| l as u32),
        }
    }
}

/// Response from a request to get folder invites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetFolderInvitesResponse {
    /// Folder invites.
    pub folder_invites: Vec<FolderInvite>,
}

impl ProtoBinding for GetFolderInvitesResponse {
    type Inner = WireGetFolderInvitesResponse;
}

impl TryFrom<WireGetFolderInvitesResponse> for GetFolderInvitesResponse {
    type Error = Error;

    fn try_from(value: WireGetFolderInvitesResponse) -> Result<Self> {
        let mut folder_invites =
            Vec::with_capacity(value.folder_invites.len());
        for invite in value.folder_invites {
            folder_invites.push(invite.try_into()?);
        }
        Ok(Self { folder_invites })
    }
}

impl From<GetFolderInvitesResponse> for WireGetFolderInvitesResponse {
    fn from(value: GetFolderInvitesResponse) -> WireGetFolderInvitesResponse {
        Self {
            folder_invites: value
                .folder_invites
                .into_iter()
                .map(|f| f.into())
                .collect(),
        }
    }
}

/// Request to update a folder invite with a new status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFolderInviteRequest {
    /// New update status.
    pub invite_status: InviteStatus,
    /// Public key of the recipient that sent the invite.
    pub from_public_key: age::x25519::Recipient,
    /// Folder identifier.
    pub folder_id: VaultId,
}

impl ProtoBinding for UpdateFolderInviteRequest {
    type Inner = WireUpdateFolderInviteRequest;
}

impl TryFrom<WireUpdateFolderInviteRequest> for UpdateFolderInviteRequest {
    type Error = Error;

    fn try_from(value: WireUpdateFolderInviteRequest) -> Result<Self> {
        Ok(Self {
            invite_status: value.invite_status.try_into()?,
            from_public_key: value
                .from_public_key
                .parse()
                .map_err(Error::AgeX25519Parse)?,
            folder_id: value.folder_id.parse()?,
        })
    }
}

impl From<UpdateFolderInviteRequest> for WireUpdateFolderInviteRequest {
    fn from(
        value: UpdateFolderInviteRequest,
    ) -> WireUpdateFolderInviteRequest {
        Self {
            invite_status: WireInviteStatus::from(value.invite_status) as i32,
            from_public_key: value.from_public_key.to_string(),
            folder_id: value.folder_id.to_string(),
        }
    }
}

/// Response from a request to get folder invites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFolderInviteResponse {}

impl ProtoBinding for UpdateFolderInviteResponse {
    type Inner = WireUpdateFolderInviteResponse;
}

impl TryFrom<WireUpdateFolderInviteResponse> for UpdateFolderInviteResponse {
    type Error = Error;

    fn try_from(_value: WireUpdateFolderInviteResponse) -> Result<Self> {
        Ok(Self {})
    }
}

impl From<UpdateFolderInviteResponse> for WireUpdateFolderInviteResponse {
    fn from(
        _value: UpdateFolderInviteResponse,
    ) -> WireUpdateFolderInviteResponse {
        Self {}
    }
}
