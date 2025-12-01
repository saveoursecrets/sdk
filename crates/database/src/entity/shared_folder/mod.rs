use crate::entity::{AccountEntity, FolderEntity};
use crate::{Error, Result};
use async_sqlite::rusqlite::Connection;
use sos_core::{AccountId, UtcDateTime, VaultId};
use sql_query_builder as sql;

mod folder_invites;
mod recipient;

pub use folder_invites::{FolderInviteEntity, FolderInviteRecord};
use recipient::RecipientRow;
pub use recipient::{RecipientEntity, RecipientRecord};

/// Join table for shared folders.
struct AccountSharedFolderRow {
    account_id: i64,
    folder_id: i64,
}

/// Shared folder entity.
pub struct SharedFolderEntity<'conn> {
    conn: &'conn mut Connection,
}

impl<'conn> SharedFolderEntity<'conn> {
    /// Create a new shared folder entity.
    pub fn new(conn: &'conn mut Connection) -> Self {
        Self { conn }
    }

    /// Create or update recipient information for an account.
    pub fn upsert_recipient(
        &mut self,
        account_id: AccountId,
        recipient_name: String,
        recipient_email: Option<String>,
        recipient_public_key: String,
    ) -> Result<i64> {
        let tx = self.conn.transaction()?;

        let account = AccountEntity::new(&tx);
        let account_row = account.find_one(&account_id)?;

        let recipient_entity = RecipientEntity::new(&tx);
        let recipient_id = if let Some(recipient_row) =
            recipient_entity.find_optional(account_row.row_id)?
        {
            let recipient_row = recipient_row.new_update(
                recipient_name,
                recipient_email,
                recipient_public_key,
            )?;
            recipient_entity.update_recipient(&recipient_row)?;
            recipient_row.recipient_id
        } else {
            let recipient_row = RecipientRow::new_insert(
                account_row.row_id,
                recipient_name,
                recipient_email,
                recipient_public_key,
            )?;
            recipient_entity.insert_recipient(&recipient_row)?
        };
        tx.commit()?;
        Ok(recipient_id)
    }

    /// Try to find recipient information for an account.
    pub fn find_recipient(
        &mut self,
        account_id: AccountId,
    ) -> Result<Option<RecipientRecord>> {
        let account = AccountEntity::new(&self.conn);
        if let Some(account_row) = account.find_optional(&account_id)? {
            let recipient_entity = RecipientEntity::new(&self.conn);
            if let Some(recipient) =
                recipient_entity.find_optional(account_row.row_id)?
            {
                Ok(Some(recipient.try_into()?))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Invite a recipient to a folder.
    pub fn invite_recipient(
        &mut self,
        account_id: &AccountId,
        recipient_public_key: &str,
        folder_id: &VaultId,
    ) -> Result<i64> {
        let tx = self.conn.transaction()?;

        let account = AccountEntity::new(&tx);
        let account = account
            .find_optional(account_id)?
            .ok_or(Error::SharingInviteNoAccount(*account_id))?;

        let recipient = RecipientEntity::new(&tx);
        let from_recipient = recipient
            .find_optional(account.row_id)?
            .ok_or(Error::SharingInviteRecipientNotCreated(*account_id))?;
        let to_recipient = recipient
            .find_by_public_key(recipient_public_key)?
            .ok_or(Error::SharingInviteNoRecipient(
                recipient_public_key.to_owned(),
            ))?;

        let folder = FolderEntity::new(&tx);
        let folder = folder
            .find_optional(folder_id)?
            .ok_or(Error::SharingInviteNoFolder(*folder_id))?;

        let query = sql::Insert::new()
            .insert_into(
                r#"
                folder_invites
                (
                    created_at,
                    modified_at,
                    from_recipient_id,
                    to_recipient_id,
                    folder_id,
                    invite_status
                )
            "#,
            )
            .values("(?1, ?2, ?3, ?4, ?5, ?6)");

        let params = (
            UtcDateTime::default().to_rfc3339()?,
            UtcDateTime::default().to_rfc3339()?,
            from_recipient.recipient_id,
            to_recipient.recipient_id,
            folder.row_id,
            0,
        );

        let row_id = {
            let mut stmt = tx.prepare_cached(&query.as_string())?;
            stmt.execute(params)?;
            tx.last_insert_rowid()
        };

        tx.commit()?;
        Ok(row_id)
    }

    /// Folder invites sent to this account.
    pub fn received_folder_invites(
        &mut self,
        account_id: &AccountId,
        limit: Option<usize>,
    ) -> Result<Vec<FolderInviteRecord>> {
        // TODO: optimize to use joins
        let tx = self.conn.transaction()?;

        let account = AccountEntity::new(&tx);
        let account = account
            .find_optional(account_id)?
            .ok_or(Error::SharingInviteNoAccount(*account_id))?;

        let recipient = RecipientEntity::new(&tx);
        let recipient = recipient
            .find_optional(account.row_id)?
            .ok_or(Error::SharingInviteRecipientNotCreated(*account_id))?;

        let folder_invites = FolderInviteEntity::new(&tx);
        let records = folder_invites
            .find_all_by_to_recipient_id(recipient.recipient_id, limit)?;

        tx.commit()?;

        Ok(records)
    }

    /// Folder invites sent to from this account.
    pub fn sent_folder_invites(
        &mut self,
        account_id: &AccountId,
        limit: Option<usize>,
    ) -> Result<Vec<FolderInviteRecord>> {
        // TODO: optimize to use joins
        let tx = self.conn.transaction()?;

        let account = AccountEntity::new(&tx);
        let account = account
            .find_optional(account_id)?
            .ok_or(Error::SharingInviteNoAccount(*account_id))?;

        let recipient = RecipientEntity::new(&tx);
        let recipient = recipient
            .find_optional(account.row_id)?
            .ok_or(Error::SharingInviteRecipientNotCreated(*account_id))?;

        let folder_invites = FolderInviteEntity::new(&tx);
        let records = folder_invites
            .find_all_by_from_recipient_id(recipient.recipient_id, limit)?;

        tx.commit()?;

        Ok(records)
    }
}
