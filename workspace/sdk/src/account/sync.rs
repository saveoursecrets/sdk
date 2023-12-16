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
            num_changes += self.replay_identity_events(diff).await?;
        }

        if let Some(diff) = &diff.account {
            num_changes += self.replay_account_events(diff).await?;
        }

        num_changes += self.replay_folder_events(&diff.folders).await?;

        Ok(num_changes)
    }

    async fn replay_identity_events(
        &mut self,
        diff: &FolderDiff,
    ) -> Result<usize> {
        todo!("client replay identity events");
    }

    async fn replay_account_events(
        &mut self,
        diff: &AccountDiff,
    ) -> Result<usize> {
        todo!("client replay account events");
    }

    async fn replay_folder_events(
        &mut self,
        folders: &HashMap<VaultId, FolderDiff>,
    ) -> Result<usize> {
        todo!("client replay folder events");
    }
}
