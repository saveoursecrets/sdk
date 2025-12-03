use crate::entity::{
    AccountEntity, AccountRecord, AccountRow, FolderEntity, FolderRecord,
    FolderRow,
};
use crate::{Result, SharingError};
use async_sqlite::Client;
use async_sqlite::rusqlite::{Connection, Row};
use sos_core::{AccountId, Recipient, UtcDateTime, VaultId};
use sos_vault::Vault;
use sql_query_builder as sql;

mod folder_invites;
mod recipient;

pub use folder_invites::{FolderInviteRecord, InviteStatus};
use recipient::RecipientRow;
pub use recipient::{RecipientEntity, RecipientRecord};

/// Record for a shared folder.
#[derive(Debug)]
pub struct SharedFolderRecord {
    /// Account information.
    pub account: AccountRecord,
    /// Folder information.
    pub folder: FolderRecord,
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
            .ok_or(SharingError::InviteNoAccount(*account_id))?;

        let recipient = RecipientEntity::new(&tx);
        let from_recipient = recipient
            .find_optional(account.row_id)?
            .ok_or(SharingError::RecipientNotCreated(*account_id))?;
        let to_recipient = recipient
            .find_by_public_key(recipient_public_key)?
            .ok_or(SharingError::InviteNoRecipient(
                recipient_public_key.to_owned(),
            ))?;

        let folder = FolderEntity::new(&tx);
        let folder = folder
            .find_optional(folder_id)?
            .ok_or(SharingError::InviteNoFolder(*folder_id))?;

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
        from_recipient_public_key: &str,
        invite_status: InviteStatus,
    ) -> Result<()> {
        assert!(matches!(
            invite_status,
            InviteStatus::Accepted | InviteStatus::Declined
        ));

        let tx = self.conn.transaction()?;

        let subquery = sql::Select::new()
            .select("fi.folder_invite_id")
            .from("folder_invites AS fi")
            .inner_join(
                "recipients AS from_r ON fi.from_recipient_id = from_r.recipient_id",
            )
            .inner_join(
                "recipients AS to_r ON fi.to_recipient_id = to_r.recipient_id",
            )
            .inner_join("accounts AS a ON to_r.account_id = a.account_id")
            .where_clause("from_r.recipient_public_key = ?3")
            .where_and("a.identifier = ?4");

        let query = sql::Update::new()
            .update("folder_invites")
            .set(
                r#"
                modified_at = ?1,
                invite_status = ?2
            "#,
            )
            .where_clause(&format!(
                "folder_invite_id IN ({})",
                subquery.as_string()
            ));

        {
            let mut stmt = tx.prepare_cached(&query.as_string())?;
            stmt.execute((
                UtcDateTime::default().to_rfc3339()?,
                invite_status as u8,
                from_recipient_public_key,
                account_id.to_string(),
            ))?;
        }

        // Create join between recipient account and shared folder when accepted
        if matches!(invite_status, InviteStatus::Accepted) {
            let select_query = sql::Select::new()
                .select("a.account_id, fi.folder_id")
                .from("folder_invites AS fi")
                .inner_join(
                    "recipients AS from_r ON fi.from_recipient_id = from_r.recipient_id",
                )
                .inner_join(
                    "recipients AS to_r ON fi.to_recipient_id = to_r.recipient_id",
                )
                .inner_join("accounts AS a ON to_r.account_id = a.account_id")
                .where_clause("from_r.recipient_public_key = ?1")
                .where_and("a.identifier = ?2");

            let insert_query = sql::Insert::new()
                .insert_into("shared_folders (account_id, folder_id)")
                .select(select_query);

            let mut stmt = tx.prepare_cached(&insert_query.as_string())?;
            stmt.execute((
                from_recipient_public_key,
                account_id.to_string(),
            ))?;
        }

        tx.commit()?;
        Ok(())
    }

    #[doc(hidden)]
    pub fn list_shared_folders(
        &self,
        account_id: &AccountId,
    ) -> Result<Vec<(AccountRow, FolderRow)>> {
        let query = sql::Select::new()
            .select(
                r#"
                a.account_id,
                a.created_at,
                a.modified_at,
                a.identifier,
                a.name,
                f.folder_id,
                f.created_at,
                f.modified_at,
                f.identifier,
                f.name,
                f.salt,
                f.meta,
                f.seed,
                f.version,
                f.cipher,
                f.kdf,
                f.flags,
                f.shared_access
            "#,
            )
            .from("shared_folders AS asf")
            .inner_join("accounts AS a ON asf.account_id = a.account_id")
            .inner_join("folders AS f ON asf.folder_id = f.folder_id")
            .where_clause("a.identifier = ?1");

        let mut stmt = self.conn.prepare_cached(&query.as_string())?;

        fn convert_row(row: &Row<'_>) -> Result<(AccountRow, FolderRow)> {
            let account = AccountRow {
                row_id: row.get(0)?,
                created_at: row.get(1)?,
                modified_at: row.get(2)?,
                identifier: row.get(3)?,
                name: row.get(4)?,
            };
            let folder = FolderRow {
                row_id: row.get(5)?,
                created_at: row.get(6)?,
                modified_at: row.get(7)?,
                identifier: row.get(8)?,
                name: row.get(9)?,
                salt: row.get(10)?,
                meta: row.get(11)?,
                seed: row.get(12)?,
                version: row.get(13)?,
                cipher: row.get(14)?,
                kdf: row.get(15)?,
                flags: row.get(16)?,
                shared_access: row.get(17)?,
            };
            Ok((account, folder))
        }

        let rows =
            stmt.query_and_then([account_id.to_string()], convert_row)?;

        let mut shared_folders = Vec::new();
        for row in rows {
            shared_folders.push(row?);
        }
        Ok(shared_folders)
    }

    #[doc(hidden)]
    /// Convert shared folders rows.
    pub async fn from_rows(
        rows: Vec<(AccountRow, FolderRow)>,
    ) -> Result<Vec<SharedFolderRecord>> {
        // TODO: if FolderRecord::from_row() was sync we could use
        // TODO: a much cleaner API; this would require
        // TODO: using sync versions of encode() and decode()
        // TODO: which is a big refactor so deferred for another time

        let mut shared_folders = Vec::new();
        for (account_row, folder_row) in rows {
            let account: AccountRecord = account_row.try_into()?;
            let folder = FolderRecord::from_row(folder_row).await?;
            shared_folders.push(SharedFolderRecord { account, folder });
        }
        Ok(shared_folders)
    }

    /// Create a shared folder.
    pub async fn create_shared_folder(
        client: &Client,
        account_id: &AccountId,
        vault: &Vault,
        recipients: &[Recipient],
    ) -> Result<()> {
        // Validate owner account exists
        let account_check_id = *account_id;
        let account_row = client
            .conn_and_then(move |conn| {
                let account = AccountEntity::new(&conn);
                account.find_one(&account_check_id).map_err(async_sqlite::Error::Rusqlite)
            })
            .await?;
            
        // Validate owner has recipient record
        let owner_recipient = client
            .conn_and_then(move |conn| {
                let recipient_entity = RecipientEntity::new(&conn);
               recipient_entity.find_optional(account_row.row_id).map_err(async_sqlite::Error::Rusqlite)
            })
            .await?
            .ok_or(SharingError::RecipientNotCreated(*account_id))?;

        // Find owner in recipients slice
        if !recipients.iter().any(|r| r.public_key.to_string() == owner_recipient.recipient_public_key) {
            return Err(SharingError::OwnerNotInRecipients(*account_id).into());
        }

        let owner_public_key_str = owner_recipient.recipient_public_key.clone();
        let owner_recipient_id = owner_recipient.recipient_id;

        // Collect and validate all recipient records
        let recipient_keys = recipients.iter().map(|r| r.public_key.to_string()).collect::<Vec<_>>();
        let num_recipients = recipient_keys.len();
        let recipient_records = client
            .conn_and_then(move |conn| {
                let recipient_entity = RecipientEntity::new(&conn);
                recipient_entity.find_all_by_public_keys(recipient_keys.as_slice()).map_err(async_sqlite::Error::Rusqlite)
            })
            .await?;
        if recipient_records.len() != num_recipients {
            return Err(SharingError::MissingRecipients.into());
        }

        // Prepare vault data
        let folder_row = FolderRow::new_insert_from_vault(vault).await?;

        // Insert folder, create shared folder and shared folder recipients
        // and insert folder invites for recipients other than the owner
        client
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;

                // Insert folder
                let folder_entity = FolderEntity::new(&tx);
                let folder_row_id =
                    folder_entity.insert_folder(account_row.row_id, &folder_row)?;

                // Insert shared_folder join for each recipient
                let mut shared_folder_ids = std::collections::HashMap::new();
                for row in &recipient_records
                {
                    let query = sql::Insert::new()
                        .insert_into("shared_folders (account_id, folder_id)")
                        .values("(?1, ?2)");

                    let mut stmt = tx.prepare_cached(&query.as_string())?;
                    stmt.execute((row.account_id, folder_row_id))?;
                    let shared_folder_id = tx.last_insert_rowid();

                    shared_folder_ids.insert(
                        row.recipient_public_key.clone(),
                        (shared_folder_id, row.recipient_id),
                    );
                }

                // Insert shared_folder_recipients
                for (public_key, (shared_folder_id, recipient_id)) in
                    &shared_folder_ids
                {
                    let is_creator =
                        if public_key == &owner_public_key_str { 1 } else { 0 };

                    let query = sql::Insert::new()
                        .insert_into("shared_folder_recipients (shared_folder_id, recipient_id, is_creator)")
                        .values("(?1, ?2, ?3)");

                    let mut stmt = tx.prepare_cached(&query.as_string())?;
                    stmt.execute((shared_folder_id, recipient_id, is_creator))?;
                }

                // Create invites for all recipients except owner
                for (public_key, (_, recipient_id)) in shared_folder_ids {
                    // Skip owner
                    if public_key == owner_public_key_str {
                        continue;
                    }

                    let query = sql::Insert::new()
                        .insert_into(
                            r#"
                            folder_invites
                            (
                                created_at,
                                modified_at,
                                from_recipient_id,
                                to_recipient_id,
                                folder_id
                            )
                        "#,
                        )
                        .values("(?1, ?2, ?3, ?4, ?5)");

                    let params = (
                        UtcDateTime::default().to_rfc3339()?,
                        UtcDateTime::default().to_rfc3339()?,
                        owner_recipient_id,
                        recipient_id,
                        folder_row_id,
                    );

                    let mut stmt = tx.prepare_cached(&query.as_string())?;
                    stmt.execute(params)?;
                }

                tx.commit()?;
                Ok::<_, crate::Error>(())
            })
            .await?;

        Ok(())
    }
}
