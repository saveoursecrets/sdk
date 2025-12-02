use crate::entity::{AccountEntity, FolderEntity};
use crate::{Error, Result};
use async_sqlite::rusqlite::{Connection, Row};
use sos_core::{AccountId, UtcDateTime, VaultId};
use sql_query_builder as sql;

mod folder_invites;
mod recipient;

pub use folder_invites::{FolderInviteRecord, InviteStatus};
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

    /// Folder invites received by this account.
    pub fn received_folder_invites(
        &mut self,
        account_id: &AccountId,
        limit: Option<usize>,
        invite_status: Option<InviteStatus>,
    ) -> Result<Vec<FolderInviteRecord>> {
        self.list_folder_invites(account_id, limit, false, invite_status)
    }

    /// Folder invites sent from this account.
    pub fn sent_folder_invites(
        &mut self,
        account_id: &AccountId,
        limit: Option<usize>,
        invite_status: Option<InviteStatus>,
    ) -> Result<Vec<FolderInviteRecord>> {
        self.list_folder_invites(account_id, limit, true, invite_status)
    }

    /// Folder invites sent from this account.
    fn list_folder_invites(
        &mut self,
        account_id: &AccountId,
        limit: Option<usize>,
        from_recipient: bool,
        invite_status: Option<InviteStatus>,
    ) -> Result<Vec<FolderInviteRecord>> {
        let limit =
            limit.map(|l| l.to_string()).unwrap_or(String::from("10"));

        let mut query = sql::Select::new()
            .select(
                r#"
                  fi.folder_invite_id,
                  fi.created_at,
                  fi.modified_at,
                  fi.from_recipient_id,
                  fi.to_recipient_id,
                  fi.folder_id,
                  fi.invite_status,
                  f.name,
                  r.recipient_name,
                  r.recipient_email,
                  r.recipient_public_key
              "#,
            )
            .from("folder_invites AS fi");

        if from_recipient {
            // For sent invites, join to_recipient to get their info
            query = query
                .inner_join(
                    "recipients AS r ON fi.to_recipient_id =
  r.recipient_id",
                )
                .inner_join(
                    "recipients AS sender ON fi.from_recipient_id =
  sender.recipient_id",
                )
                .inner_join(
                    "accounts AS a ON sender.account_id = a.account_id",
                );
        } else {
            // For received invites, join from_recipient to get their info
            query = query
                .inner_join(
                    "recipients AS r ON fi.from_recipient_id =
  r.recipient_id",
                )
                .inner_join(
                    "recipients AS receiver ON fi.to_recipient_id =
  receiver.recipient_id",
                )
                .inner_join(
                    "accounts AS a ON receiver.account_id = a.account_id",
                );
        }

        query = query
            .inner_join("folders AS f ON fi.folder_id = f.folder_id")
            .where_clause("a.identifier = ?1");

        if invite_status.is_some() {
            query = query.where_and("fi.invite_status = ?2")
        }

        query = query.limit(&limit).order_by("fi.modified_at DESC");

        let mut stmt = self.conn.prepare_cached(&query.as_string())?;

        fn convert_row(
            row: &Row<'_>,
        ) -> Result<folder_invites::FolderInviteRow> {
            Ok(row.try_into()?)
        }

        let rows = match invite_status {
            Some(invite_status) => stmt.query_and_then(
                (account_id.to_string(), invite_status as u8),
                convert_row,
            )?,
            None => {
                stmt.query_and_then([account_id.to_string()], convert_row)?
            }
        };

        let mut invites = Vec::new();
        for row in rows {
            invites.push(row?.try_into()?);
        }
        Ok(invites)
    }

    /// Update folder invite with a new status.
    pub fn update_folder_invite(
        &mut self,
        account_id: &AccountId,
        from_recipient_public_key: String,
        invite_status: InviteStatus,
    ) -> Result<Vec<FolderInviteRecord>> {
        assert!(matches!(
            invite_status,
            InviteStatus::Accepted | InviteStatus::Declined
        ));
        todo!();
    }
}
