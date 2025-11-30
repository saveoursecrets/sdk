use crate::Result;

/// Represents a recipient.
pub struct RecipientRow {
    recipient_id: i64,
    account_id: i64,
    created_at: String,
    modified_at: String,
    recipient_name: String,
    recipient_email: Option<String>,
    recipient_public_key: String,
    revoked: i64,
}

/// Join table for shared folders.
pub struct AccountSharedFolderRow {
    account_id: i64,
    folder_id: i64,
}

/// Represents an invite to a shared folder.
pub struct FolderInviteRow {
    folder_invite_id: i64,
    created_at: String,
    from_recipient: i64,
    to_recipient: i64,
    folder_id: i64,
}

pub struct SharedFolderEntity;

impl SharedFolderEntity {
    /// Create or update recipient information for an account.
    pub async fn upsert_recipient(
        account_id: i64,
        recipient_name: String,
        recipient_email: Option<String>,
        recipient_public_key: String,
    ) -> Result<()> {
        todo!();
    }
}
