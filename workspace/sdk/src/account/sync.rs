use crate::{
    sync::{AccountDiff, CheckedPatch, FolderDiff, SyncDiff},
    vault::VaultId,
    Result,
};
use std::collections::HashMap;

use super::account::Account;

impl<D> Account<D> {
    /// Merge a diff into this account.
    pub async fn merge_diff(&mut self, diff: &SyncDiff) -> Result<usize> {
        let mut num_changes = 0;

        if let Some(diff) = &diff.identity {
            num_changes += self.merge_identity(diff).await?;
        }

        if let Some(diff) = &diff.account {
            num_changes += self.merge_account(diff).await?;
        }

        num_changes += self.merge_folders(&diff.folders).await?;

        Ok(num_changes)
    }

    async fn merge_identity(&mut self, diff: &FolderDiff) -> Result<usize> {
        self.user_mut()?.identity_mut()?.merge_diff(diff).await?;
        Ok(diff.patch.len())
    }

    async fn merge_account(&mut self, diff: &AccountDiff) -> Result<usize> {
        todo!("client replay account events");
    }

    async fn merge_folders(
        &mut self,
        folders: &HashMap<VaultId, FolderDiff>,
    ) -> Result<usize> {
        todo!("client replay folder events");
    }
}
