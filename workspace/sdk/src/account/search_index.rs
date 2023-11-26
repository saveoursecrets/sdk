//! User search index.
use std::{collections::HashSet, sync::Arc};

use crate::{
    crypto::AccessKey,
    search::{Document, DocumentCount, SearchIndex},
    vault::{
        secret::{SecretId, SecretType},
        Gatekeeper, Vault, VaultId,
    },
    vcard4, Result,
};

use tokio::sync::RwLock;

/// Modify and query a search index.
pub struct UserIndex {
    /// Search index.
    pub(super) search_index: Arc<RwLock<SearchIndex>>,
}

impl UserIndex {
    /// Create a new user search index.
    pub fn new() -> Self {
        Self {
            search_index: Arc::new(RwLock::new(SearchIndex::new())),
        }
    }

    /// Get a reference to the search index.
    pub fn search(&self) -> &Arc<RwLock<SearchIndex>> {
        &self.search_index
    }

    /// Clear the entire search index.
    pub async fn clear(&mut self) {
        tracing::debug!("clear search index");
        let mut writer = self.search_index.write().await;
        writer.remove_all();
    }

    /// Remove a folder from the search index.
    pub async fn remove_folder_from_search_index(&self, vault_id: &VaultId) {
        // Clean entries from the search index
        let mut writer = self.search_index.write().await;
        writer.remove_vault(vault_id);
    }

    /// Add a folder to the search index.
    pub async fn add_folder_to_search_index(
        &self,
        vault: Vault,
        key: AccessKey,
    ) -> Result<()> {
        let index = Arc::clone(&self.search_index);
        let mut keeper = Gatekeeper::new(vault, Some(index));
        keeper.unlock(key).await?;
        keeper.create_search_index().await?;
        keeper.lock();
        Ok(())
    }

    /// Get the search index document count statistics.
    pub async fn document_count(&self) -> DocumentCount {
        let reader = self.search_index.read().await;
        reader.statistics().count().clone()
    }

    /// Determine if a document exists in a folder.
    pub async fn document_exists_in_folder(
        &self,
        vault_id: &VaultId,
        label: &str,
        id: Option<&SecretId>,
    ) -> bool {
        let reader = self.search_index.read().await;
        reader.find_by_label(vault_id, label, id).is_some()
    }

    /// Query with document views.
    pub async fn query_view(
        &self,
        views: Vec<DocumentView>,
        archive: Option<ArchiveFilter>,
    ) -> Result<Vec<Document>> {
        let index_reader = self.search_index.read().await;
        let mut docs = Vec::with_capacity(index_reader.len());
        for doc in index_reader.values_iter() {
            for view in &views {
                if view.test(doc, archive.as_ref()) {
                    docs.push(doc.clone());
                }
            }
        }
        Ok(docs)
    }

    /// Query the search index.
    pub async fn query_map(
        &self,
        query: &str,
        filter: QueryFilter,
    ) -> Result<Vec<Document>> {
        let index_reader = self.search_index.read().await;
        let mut docs = Vec::new();
        let tags: HashSet<_> = filter.tags.iter().cloned().collect();
        let predicate = self.query_predicate(filter, tags, None);
        if !query.is_empty() {
            for doc in index_reader.query_map(query, predicate) {
                docs.push(doc.clone());
            }
        } else {
            for doc in index_reader.values_iter() {
                if predicate(doc) {
                    docs.push(doc.clone());
                }
            }
        }
        Ok(docs)
    }

    fn query_predicate(
        &self,
        filter: QueryFilter,
        tags: HashSet<String>,
        _archive: Option<ArchiveFilter>,
    ) -> impl Fn(&Document) -> bool {
        move |doc| {
            let tag_match = filter.tags.is_empty() || {
                !tags
                    .intersection(doc.meta().tags())
                    .collect::<HashSet<_>>()
                    .is_empty()
            };

            let vault_id = doc.vault_id();
            let folder_match = filter.folders.is_empty()
                || filter.folders.contains(vault_id);

            let type_match = filter.types.is_empty()
                || filter.types.contains(doc.meta().kind());

            tag_match && folder_match && type_match
        }
    }
}

impl Default for UserIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// View of documents in the search index.
pub enum DocumentView {
    /// View all documents in the search index.
    All {
        /// List of secret types to ignore.
        ignored_types: Option<Vec<SecretType>>,
    },
    /// View all the documents for a folder.
    Vault(VaultId),
    /// View documents across all vaults by type identifier.
    TypeId(SecretType),
    /// View for all favorites.
    Favorites,
    /// View documents that have one or more tags.
    Tags(Vec<String>),
    /// Contacts of the given types.
    Contact {
        /// Contact types to include in the results.
        include_types: Option<Vec<vcard4::property::Kind>>,
    },
    /// Documents with the specific identifiers.
    Documents {
        /// Vault identifier.
        vault_id: VaultId,
        /// Secret identifiers.
        identifiers: Vec<SecretId>,
    },
}

impl DocumentView {
    /// Test this view against a search result document.
    pub fn test(
        &self,
        doc: &Document,
        archive: Option<&ArchiveFilter>,
    ) -> bool {
        if let Some(filter) = archive {
            if !filter.include_documents && doc.vault_id() == &filter.id {
                return false;
            }
        }

        match self {
            DocumentView::All { ignored_types } => {
                if let Some(ignored_types) = ignored_types {
                    return !ignored_types.contains(doc.meta().kind());
                }
                true
            }
            DocumentView::Vault(vault_id) => doc.vault_id() == vault_id,
            DocumentView::TypeId(type_id) => doc.meta().kind() == type_id,
            DocumentView::Favorites => doc.meta().favorite(),
            DocumentView::Tags(tags) => {
                let tags: HashSet<_> = tags.iter().cloned().collect();
                !tags
                    .intersection(doc.meta().tags())
                    .collect::<HashSet<_>>()
                    .is_empty()
            }
            DocumentView::Contact { include_types } => {
                if doc.meta().kind() == &SecretType::Contact {
                    if let Some(include_types) = include_types {
                        if let Some(contact_type) = &doc.extra().contact_type
                        {
                            let contact_type: vcard4::property::Kind =
                                contact_type.clone();
                            return include_types.contains(&contact_type);
                        } else {
                            return false;
                        }
                    }
                    return true;
                }
                false
            }
            DocumentView::Documents {
                vault_id,
                identifiers,
            } => doc.vault_id() == vault_id && identifiers.contains(doc.id()),
        }
    }
}

/// Filter for a search query.
pub struct QueryFilter {
    /// List of tags.
    pub tags: Vec<String>,
    /// List of vault identifiers.
    pub folders: Vec<VaultId>,
    /// List of type identifiers.
    pub types: Vec<SecretType>,
}

/// Filter for archived documents.
pub struct ArchiveFilter {
    /// Identifier of the archive vault.
    pub id: VaultId,
    /// Whether to include archived documents.
    pub include_documents: bool,
}
