//! Account search index.
use crate::{
    crypto::AccessKey,
    storage::search::*,
    vault::{
        secret::{SecretId, SecretType},
        Gatekeeper, Summary, Vault, VaultId,
    },
    vcard4, Result,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;

use super::account::Account;

impl<D> Account<D> {
    /// Compute the account statistics.
    ///
    /// If the account is not authenticated returns
    /// a default statistics object (all values will be zero).
    pub async fn statistics(&self) -> AccountStatistics {
        if self.authenticated.is_some() {
            let storage = self.storage().unwrap();
            let reader = storage.read().await;
            if let Ok(index) = reader.index() {
                let search_index = index.search();
                let index = search_index.read().await;
                let statistics = index.statistics();
                let count = statistics.count();

                let documents: usize = count.vaults().values().sum();
                let mut folders = Vec::new();
                let mut types = HashMap::new();

                for (id, v) in count.vaults() {
                    if let Some(summary) = self.find(|s| s.id() == id).await {
                        folders.push((summary, *v));
                    }
                }

                for (k, v) in count.kinds() {
                    if let Ok(kind) = SecretType::try_from(*k) {
                        types.insert(kind, *v);
                    }
                }

                AccountStatistics {
                    documents,
                    folders,
                    types,
                    tags: count.tags().clone(),
                    favorites: count.favorites(),
                }
            } else {
                Default::default()
            }
        } else {
            Default::default()
        }
    }

    /// Search index for the account.
    pub async fn index(&self) -> Result<Arc<RwLock<SearchIndex>>> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        Ok(reader.index()?.search())
    }

    /// Query with document views.
    pub async fn query_view(
        &self,
        views: Vec<DocumentView>,
        archive: Option<ArchiveFilter>,
    ) -> Result<Vec<Document>> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        reader.index()?.query_view(views, archive).await
    }

    /// Query the search index.
    pub async fn query_map(
        &self,
        query: &str,
        filter: QueryFilter,
    ) -> Result<Vec<Document>> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        reader.index()?.query_map(query, filter).await
    }

    /// Get the search index document count statistics.
    pub async fn document_count(&self) -> Result<DocumentCount> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        let search = reader.index()?.search();
        let index = search.read().await;
        Ok(index.statistics().count().clone())
    }

    /// Determine if a document exists in a folder.
    pub async fn document_exists_in_folder(
        &self,
        vault_id: &VaultId,
        label: &str,
        id: Option<&SecretId>,
    ) -> Result<bool> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        let search = reader.index()?.search();
        let index = search.read().await;
        Ok(index.find_by_label(vault_id, label, id).is_some())
    }
}
