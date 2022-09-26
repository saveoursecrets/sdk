use std::collections::HashSet;

use super::Result;

use sos_core::{
    events::{ChangeAction, ChangeEvent, ChangeNotification},
    secret::SecretRef,
    wal::WalProvider,
    PatchProvider,
};

use crate::{client::provider::StorageProvider, sync::SyncStatus};

/// Respond to a change notification.
///
/// The return flag indicates whether the change was made
/// by this node which is determined by comparing the session
/// identifier on the change notification with the current
/// session identifier for this node.
pub async fn handle_change<W, P>(
    provider: &mut (impl StorageProvider<W, P> + Send + Sync + 'static),
    change: ChangeNotification,
) -> Result<HashSet<ChangeAction>>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    // Gather actions corresponding to the events
    let mut actions = HashSet::new();
    for event in change.changes() {
        let action = match event {
            ChangeEvent::CreateVault(summary) => {
                ChangeAction::Create(summary.clone())
            }
            ChangeEvent::DeleteVault => {
                ChangeAction::Remove(*change.vault_id())
            }
            _ => ChangeAction::Pull(*change.vault_id()),
        };
        actions.insert(action);
    }

    // Consume and react to the actions
    for action in &actions {
        let summary = provider
            .state()
            .find_vault(&SecretRef::Id(*change.vault_id()))
            .cloned();

        if let Some(summary) = &summary {
            match action {
                ChangeAction::Pull(_) => {
                    let tree = provider
                        .commit_tree(summary)
                        .ok_or(sos_core::Error::NoRootCommit)?;
                    let head = tree.head()?;

                    tracing::debug!(
                        vault_id = ?summary.id(),
                        change_root = ?change.proof().root_hex(),
                        root = ?head.root_hex(),
                        "handle_change");

                    // Looks like the change was made elsewhere
                    // and we should attempt to sync with the server
                    if change.proof().root() != head.root() {
                        let (status, _) = provider.status(summary).await?;
                        match status {
                            SyncStatus::Behind(_, _) => {
                                provider.pull(summary, false).await?;
                            }
                            SyncStatus::Diverged(_) => {
                                if let Some(_) = change
                                    .changes()
                                    .into_iter()
                                    .find(|c| *c == &ChangeEvent::UpdateVault)
                                {
                                    // If the trees have diverged and the other
                                    // node indicated it did an update to the
                                    // entire vault then we need a force pull to
                                    // stay in sync
                                    provider.pull(summary, true).await?;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                ChangeAction::Remove(_) => {
                    provider.remove_local_cache(summary).await?;
                }
                _ => {}
            }
        } else {
            match action {
                ChangeAction::Create(summary) => {
                    provider.add_local_cache(summary.clone())?;
                }
                _ => {}
            }
        }
    }

    Ok(actions)
}
