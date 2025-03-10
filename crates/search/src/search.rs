//! Search provides an in-memory index for secret meta data.
use crate::{Error, Result};
use probly_search::{score::bm25, Index, QueryResult};
use serde::{Deserialize, Serialize};
use sos_backend::AccessPoint;
use sos_core::{crypto::AccessKey, VaultId};
use sos_vault::{
    secret::{Secret, SecretId, SecretMeta, SecretRef, SecretType},
    SecretAccess, Summary, Vault,
};
use std::{
    borrow::Cow,
    collections::{btree_map::Values, BTreeMap, HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;
use unicode_segmentation::UnicodeSegmentation;
use url::Url;

/// Create a set of ngrams of the given size.
#[doc(hidden)]
pub fn ngram_slice(s: &str, n: usize) -> HashSet<&str> {
    let mut items: HashSet<&str> = HashSet::new();
    let graphemes: Vec<usize> =
        s.grapheme_indices(true).map(|v| v.0).collect();
    for (index, offset) in graphemes.iter().enumerate() {
        if let Some(end_offset) = graphemes.get(index + n) {
            items.insert(&s[*offset..*end_offset]);
        } else {
            let mut end_offset = offset;
            for i in 1..n {
                if let Some(end) = graphemes.get(index + i) {
                    end_offset = end;
                }
            }
            if end_offset > offset {
                let val = &s[*offset..*end_offset];
                items.insert(val);
            }
        }
    }
    items
}

/// Key for meta data documents.
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DocumentKey(String, VaultId, SecretId);

// Index tokenizer.
fn tokenizer(s: &str) -> Vec<Cow<'_, str>> {
    let words = s.split(' ').collect::<HashSet<_>>();

    let ngram2 = ngram_slice(s, 2);
    let ngram3 = ngram_slice(s, 3);
    let ngram4 = ngram_slice(s, 4);
    let ngram5 = ngram_slice(s, 5);
    let ngram: HashSet<&str> = ngram2.union(&ngram3).map(|s| &**s).collect();
    let ngram: HashSet<&str> = ngram.union(&ngram4).map(|s| &**s).collect();
    let ngram: HashSet<&str> = ngram.union(&ngram5).map(|s| &**s).collect();

    let mut tokens: Vec<Cow<str>> = Vec::new();
    for token in ngram.union(&words) {
        tokens.push(Cow::Owned(token.to_lowercase()))
    }
    tokens
}

// Query tokenizer.
fn query_tokenizer(s: &str) -> Vec<Cow<'_, str>> {
    s.split(' ')
        .map(|s| s.to_lowercase())
        .map(Cow::Owned)
        .collect::<Vec<_>>()
}

// Label
fn label_extract(d: &Document) -> Vec<&str> {
    vec![d.meta().label()]
}

// Tags
fn tags_extract(d: &Document) -> Vec<&str> {
    d.meta().tags().iter().map(|s| &s[..]).collect()
}

// Comment
fn comment_extract(d: &Document) -> Vec<&str> {
    if let Some(comment) = d.extra().comment() {
        vec![comment]
    } else {
        vec![""]
    }
}

// Website
fn website_extract(d: &Document) -> Vec<&str> {
    if let Some(websites) = d.extra().websites() {
        websites
        // vec![]
    } else {
        vec![]
    }
}

/// Count of documents by vault identitier and secret kind.
#[derive(Default, Debug, Clone)]
pub struct DocumentCount {
    /// Count number of documents in each vault.
    vaults: HashMap<VaultId, usize>,
    /// Count number of documents across all vaults by secret kind.
    kinds: HashMap<u8, usize>,
    /// Map tags to counts.
    tags: HashMap<String, usize>,
    /// Count number of favorites.
    favorites: usize,
    /// Identifier for an archive vault.
    ///
    /// Documents in an archive vault are omitted from the kind counts
    /// so that client implementations can show correct counts when
    /// ignoring archived items from lists.
    archive: Option<VaultId>,
}

impl DocumentCount {
    /// Create a new document count.
    pub fn new(archive: Option<VaultId>) -> Self {
        Self {
            vaults: Default::default(),
            kinds: Default::default(),
            tags: Default::default(),
            favorites: Default::default(),
            archive,
        }
    }

    /// Set the identifier for an archive vault.
    pub fn set_archive_id(&mut self, archive: Option<VaultId>) {
        self.archive = archive;
    }

    /// Get the counts by vault.
    pub fn vaults(&self) -> &HashMap<VaultId, usize> {
        &self.vaults
    }

    /// Get the counts by kinds.
    pub fn kinds(&self) -> &HashMap<u8, usize> {
        &self.kinds
    }

    /// Get the counts by tags.
    pub fn tags(&self) -> &HashMap<String, usize> {
        &self.tags
    }

    /// Get the count of favorites.
    pub fn favorites(&self) -> usize {
        self.favorites
    }

    /// Determine if a document vault identifier matches
    /// an archive vault.
    fn is_archived(&self, folder_id: &VaultId) -> bool {
        if let Some(archive) = &self.archive {
            return folder_id == archive;
        }
        false
    }

    /// Document was removed, update the count.
    fn remove(
        &mut self,
        folder_id: VaultId,
        mut options: Option<(u8, HashSet<String>, bool)>,
    ) {
        self.vaults
            .entry(folder_id)
            .and_modify(|counter| {
                if *counter > 0 {
                    *counter -= 1;
                }
            })
            .or_insert(0);

        if let Some((kind, tags, favorite)) = options.take() {
            if !self.is_archived(&folder_id) {
                self.kinds
                    .entry(kind)
                    .and_modify(|counter| {
                        if *counter > 0 {
                            *counter -= 1;
                        }
                    })
                    .or_insert(0);
            }

            for tag in &tags {
                self.tags
                    .entry(tag.to_owned())
                    .and_modify(|counter| {
                        if *counter > 0 {
                            *counter -= 1;
                        }
                    })
                    .or_insert(0);

                // Clean up the tag when count reaches zero
                let value = self.tags.get(tag).unwrap_or(&0);
                if *value == 0 {
                    self.tags.remove(tag);
                }
            }

            if favorite && self.favorites > 0 {
                self.favorites -= 1;
            }
        }
    }

    /// Document was added, update the count.
    fn add(
        &mut self,
        folder_id: VaultId,
        kind: u8,
        tags: &HashSet<String>,
        favorite: bool,
    ) {
        self.vaults
            .entry(folder_id)
            .and_modify(|counter| *counter += 1)
            .or_insert(1);

        if !self.is_archived(&folder_id) {
            self.kinds
                .entry(kind)
                .and_modify(|counter| *counter += 1)
                .or_insert(1);
        }
        for tag in tags {
            self.tags
                .entry(tag.to_owned())
                .and_modify(|counter| *counter += 1)
                .or_insert(1);
        }

        if favorite {
            self.favorites += 1;
        }
    }
}

/// Collection of statistics for the search index.
#[derive(Debug)]
pub struct IndexStatistics {
    /// Document counts.
    count: DocumentCount,
}

impl IndexStatistics {
    /// Create new statistics.
    pub fn new(archive: Option<VaultId>) -> Self {
        Self {
            count: DocumentCount::new(archive),
        }
    }

    /// Set the identifier for an archive vault.
    pub fn set_archive_id(&mut self, archive: Option<VaultId>) {
        self.count.set_archive_id(archive);
    }

    /// Get the statistics count.
    pub fn count(&self) -> &DocumentCount {
        &self.count
    }
}

/// Additional fields that can exposed via search results
/// that are extracted from the secret data but safe to
/// be exposed.
#[typeshare::typeshare]
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ExtraFields {
    /// Comment about a secret.
    pub comment: Option<String>,
    /// Contact type for contact secrets.
    pub contact_type: Option<vcard4::property::Kind>,
    /// Collection of websites.
    pub websites: Option<Vec<String>>,
}

impl From<&Secret> for ExtraFields {
    fn from(value: &Secret) -> Self {
        let mut extra = ExtraFields {
            comment: value.user_data().comment().map(|c| c.to_owned()),
            websites: value
                .websites()
                .map(|w| w.into_iter().map(|u| u.to_string()).collect()),
            ..Default::default()
        };
        if let Secret::Contact { vcard, .. } = value {
            extra.contact_type = vcard
                .kind
                .as_ref()
                .map(|p| p.value.clone())
                .or(Some(vcard4::property::Kind::Individual));
        }
        extra
    }
}

impl ExtraFields {
    /// Optional comment.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_ref().map(|c| &c[..])
    }

    /// Optional websites.
    pub fn websites(&self) -> Option<Vec<&str>> {
        self.websites
            .as_ref()
            .map(|u| u.into_iter().map(|u| &u[..]).collect())
    }
}

/// Document that can be indexed.
#[typeshare::typeshare]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    /// Folder identifier.
    pub folder_id: VaultId,
    /// Secret identifier.
    pub secret_id: SecretId,
    /// Secret meta data.
    pub meta: SecretMeta,
    /// Extra fields for the document.
    pub extra: ExtraFields,
}

impl Document {
    /// Get the vault identifier.
    pub fn folder_id(&self) -> &VaultId {
        &self.folder_id
    }

    /// Get the secret identifier.
    pub fn id(&self) -> &SecretId {
        &self.secret_id
    }

    /// Get the secret meta data.
    pub fn meta(&self) -> &SecretMeta {
        &self.meta
    }

    /// Get the extra fields.
    pub fn extra(&self) -> &ExtraFields {
        &self.extra
    }
}

/// Exposes access to a search index of meta data.
pub struct SearchIndex {
    index: Index<(VaultId, SecretId)>,
    documents: BTreeMap<DocumentKey, Document>,
    statistics: IndexStatistics,
}

impl Default for SearchIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchIndex {
    /// Create a new search index.
    pub fn new() -> Self {
        // Create index with N fields
        let index = Index::<(VaultId, SecretId)>::new(4);
        Self {
            index,
            documents: Default::default(),
            statistics: IndexStatistics::new(None),
        }
    }

    /// Set the identifier for an archive vault.
    pub fn set_archive_id(&mut self, archive: Option<VaultId>) {
        self.statistics.set_archive_id(archive);
    }

    /// Search index statistics.
    pub fn statistics(&self) -> &IndexStatistics {
        &self.statistics
    }

    /// Collection of documents.
    pub fn documents(&self) -> &BTreeMap<DocumentKey, Document> {
        &self.documents
    }

    /// List of the document values.
    pub fn values(&self) -> Vec<&Document> {
        self.documents.values().collect::<Vec<_>>()
    }

    /// Iterator over all the values.
    pub fn values_iter(&self) -> Values<'_, DocumentKey, Document> {
        self.documents.values()
    }

    /// Number of documents in the index.
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    /// Determine if the search index is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Find document by label.
    ///
    // FIXME: use _name suffix to be consistent with attachment handling
    pub fn find_by_label<'a>(
        &'a self,
        folder_id: &VaultId,
        label: &str,
        id: Option<&SecretId>,
    ) -> Option<&'a Document> {
        self.documents
            .values()
            .filter(|d| {
                if let Some(id) = id {
                    id != d.id()
                } else {
                    true
                }
            })
            .find(|d| d.folder_id() == folder_id && d.meta().label() == label)
    }

    /// Find document by label in any vault.
    pub fn find_by_label_any<'a>(
        &'a self,
        label: &str,
        id: Option<&SecretId>,
        case_insensitive: bool,
    ) -> Option<&'a Document> {
        self.documents
            .values()
            .filter(|d| {
                if let Some(id) = id {
                    id != d.id()
                } else {
                    true
                }
            })
            .find(|d| {
                if case_insensitive {
                    d.meta().label().to_lowercase() == label.to_lowercase()
                } else {
                    d.meta().label() == label
                }
            })
    }

    /// Find all documents with the given label ignoring
    /// a particular identifier.
    ///
    // FIXME: use _name suffix to be consistent with attachment handling
    pub fn find_all_by_label<'a>(
        &'a self,
        label: &str,
        id: Option<&SecretId>,
    ) -> Vec<&'a Document> {
        self.documents
            .iter()
            .filter(|(k, v)| {
                if let Some(id) = id {
                    if id == &k.1 {
                        false
                    } else {
                        v.meta().label() == label
                    }
                } else {
                    v.meta().label() == label
                }
            })
            .map(|(_, v)| v)
            .collect::<Vec<_>>()
    }

    /// Find document by id.
    pub fn find_by_id<'a>(
        &'a self,
        folder_id: &VaultId,
        id: &SecretId,
    ) -> Option<&'a Document> {
        self.documents
            .values()
            .find(|d| d.folder_id() == folder_id && d.id() == id)
    }

    /// Find secret meta by uuid or label.
    ///
    // FIXME: use _name suffix to be consistent with attachment handling
    pub fn find_by_uuid_or_label<'a>(
        &'a self,
        folder_id: &VaultId,
        target: &SecretRef,
    ) -> Option<&'a Document> {
        match target {
            SecretRef::Id(id) => self.find_by_id(folder_id, id),
            SecretRef::Name(name) => {
                self.find_by_label(folder_id, name, None)
            }
        }
    }

    /// Prepare a document for insertion.
    ///
    /// If a document with the given identifiers exists
    /// then no document is created.
    pub fn prepare(
        &self,
        folder_id: &VaultId,
        id: &SecretId,
        meta: &SecretMeta,
        secret: &Secret,
    ) -> Option<(DocumentKey, Document)> {
        // Prevent duplicates
        if self.find_by_id(folder_id, id).is_none() {
            let doc = Document {
                folder_id: *folder_id,
                secret_id: *id,
                meta: meta.clone(),
                extra: secret.into(),
            };

            // Listing key includes the identifier so that
            // secrets with the same label do not overwrite each other
            let key = DocumentKey(
                doc.meta().label().to_lowercase(),
                *folder_id,
                *id,
            );

            Some((key, doc))
        } else {
            None
        }
    }

    /// Commit a prepared key and document.
    pub fn commit(&mut self, doc: Option<(DocumentKey, Document)>) {
        // Prevent duplicates
        if let Some((key, doc)) = doc {
            let exists = self.documents.get(&key).is_some();
            let doc = self.documents.entry(key).or_insert(doc);
            if !exists {
                self.index.add_document(
                    &[
                        label_extract,
                        tags_extract,
                        comment_extract,
                        website_extract,
                    ],
                    tokenizer,
                    (doc.folder_id, doc.secret_id),
                    doc,
                );

                self.statistics.count.add(
                    doc.folder_id,
                    doc.meta().kind().into(),
                    doc.meta().tags(),
                    doc.meta().favorite(),
                );
            }
        }
    }

    /// Add a document to the index.
    pub fn add(
        &mut self,
        folder_id: &VaultId,
        id: &SecretId,
        meta: &SecretMeta,
        secret: &Secret,
    ) {
        self.commit(self.prepare(folder_id, id, meta, secret));
    }

    /// Update a document in the index.
    pub fn update(
        &mut self,
        folder_id: &VaultId,
        id: &SecretId,
        meta: &SecretMeta,
        secret: &Secret,
    ) {
        self.remove(folder_id, id);
        self.add(folder_id, id, meta, secret);
    }

    /// Add the meta data from the entries in a folder
    /// to this search index.
    pub async fn add_folder(&mut self, folder: &AccessPoint) -> Result<()> {
        let vault = folder.vault();
        for id in vault.keys() {
            let (meta, secret, _) = folder
                .read_secret(id)
                .await?
                .ok_or_else(|| Error::NoSecretId(*folder.id(), *id))?;
            self.add(folder.id(), id, &meta, &secret);
        }
        Ok(())
    }

    /// Remove the meta data from the entries in a folder.
    pub async fn remove_folder(
        &mut self,
        folder: &AccessPoint,
    ) -> Result<()> {
        let vault = folder.vault();
        for id in vault.keys() {
            self.remove(folder.id(), id);
        }
        Ok(())
    }

    /// Remove and vacuum a document from the index.
    pub fn remove(&mut self, folder_id: &VaultId, id: &SecretId) {
        let key = self
            .documents
            .keys()
            .find(|key| &key.1 == folder_id && &key.2 == id)
            .cloned();
        let doc_info = if let Some(key) = &key {
            let doc = self.documents.remove(key);
            doc.map(|doc| {
                let kind: u8 = doc.meta().kind().into();
                (kind, doc.meta().tags().clone(), doc.meta().favorite())
            })
        } else {
            None
        };

        self.index.remove_document((*folder_id, *id));
        // Vacuum to remove completely
        self.index.vacuum();

        self.statistics.count.remove(*folder_id, doc_info);
    }

    /// Remove all the documents for a given vault identifier from the index.
    pub fn remove_vault(&mut self, folder_id: &VaultId) {
        let keys: Vec<DocumentKey> = self
            .documents
            .keys()
            .filter(|k| &k.1 == folder_id)
            .cloned()
            .collect();
        for key in keys {
            self.remove(&key.1, &key.2);
            self.documents.remove(&key);
        }
    }

    /// Remove all documents from the index.
    ///
    /// This should be called before creating a new index using
    /// the same search index instance.
    pub fn remove_all(&mut self) {
        let keys: Vec<DocumentKey> = self.documents.keys().cloned().collect();
        for key in keys {
            self.remove(&key.1, &key.2);
            self.documents.remove(&key);
        }
    }

    /// Query the index.
    pub fn query(
        &self,
        needle: &str,
    ) -> Vec<QueryResult<(VaultId, SecretId)>> {
        self.index.query(
            needle,
            &mut bm25::new(),
            query_tokenizer,
            &[1., 1., 1., 1.],
        )
    }

    /// Query the index and map each result to the corresponding document.
    ///
    /// If a corresponding document could not be located the search result
    /// will be ignored.
    pub fn query_map(
        &self,
        needle: &str,
        predicate: impl Fn(&Document) -> bool,
    ) -> Vec<&Document> {
        let results = self.query(needle);
        results
            .into_iter()
            .filter_map(|r| {
                self.find_by_id(&r.key.0, &r.key.1)
                    .filter(|&doc| predicate(doc))
            })
            .collect::<Vec<_>>()
    }
}

/// Account statistics derived from the search index.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct AccountStatistics {
    /// Number of documents in the search index.
    pub documents: usize,
    /// Folder counts.
    pub folders: Vec<(Summary, usize)>,
    /// Tag counts.
    pub tags: HashMap<String, usize>,
    /// Types.
    pub types: HashMap<SecretType, usize>,
    /// Number of favorites.
    pub favorites: usize,
}

/// Modify and query the search index for an account.
pub struct AccountSearch {
    /// Search index.
    pub search_index: Arc<RwLock<SearchIndex>>,
}

impl Default for AccountSearch {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountSearch {
    /// Create a new user search index.
    pub fn new() -> Self {
        Self {
            search_index: Arc::new(RwLock::new(SearchIndex::new())),
        }
    }

    /// Get a reference to the search index.
    #[doc(hidden)]
    pub fn search(&self) -> Arc<RwLock<SearchIndex>> {
        Arc::clone(&self.search_index)
    }

    /// Clear the entire search index.
    pub async fn clear(&mut self) {
        let mut writer = self.search_index.write().await;
        writer.remove_all();
    }

    /// Add a folder which must be unlocked.
    pub async fn add_folder(&self, folder: &AccessPoint) -> Result<()> {
        let mut index = self.search_index.write().await;
        index.add_folder(folder).await
    }

    /// Remove a folder from the search index.
    pub async fn remove_folder(&self, folder_id: &VaultId) {
        // Clean entries from the search index
        let mut writer = self.search_index.write().await;
        writer.remove_vault(folder_id);
    }

    /// Add a vault to the search index.
    pub async fn add_vault(
        &self,
        vault: Vault,
        key: &AccessKey,
    ) -> Result<()> {
        let mut index = self.search_index.write().await;
        let mut keeper = AccessPoint::from_vault(vault);
        keeper.unlock(key).await?;
        index.add_folder(&keeper).await?;
        keeper.lock();
        Ok(())
    }

    /// Get the search index document count statistics.
    pub async fn document_count(&self) -> DocumentCount {
        let reader = self.search_index.read().await;
        reader.statistics().count().clone()
    }

    /// Determine if a document exists in a folder.
    pub async fn document_exists(
        &self,
        folder_id: &VaultId,
        label: &str,
        id: Option<&SecretId>,
    ) -> bool {
        let reader = self.search_index.read().await;
        reader.find_by_label(folder_id, label, id).is_some()
    }

    /// Query with document views.
    pub async fn query_view(
        &self,
        views: &[DocumentView],
        archive: Option<&ArchiveFilter>,
    ) -> Result<Vec<Document>> {
        let index_reader = self.search_index.read().await;
        let mut docs = Vec::with_capacity(index_reader.len());
        for doc in index_reader.values_iter() {
            for view in views {
                if view.test(doc, archive) {
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
        let predicate = self.query_predicate(filter, tags);
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
    ) -> impl Fn(&Document) -> bool {
        move |doc| {
            let tag_match = filter.tags.is_empty() || {
                !tags
                    .intersection(doc.meta().tags())
                    .collect::<HashSet<_>>()
                    .is_empty()
            };

            let folder_id = doc.folder_id();
            let folder_match = filter.folders.is_empty()
                || filter.folders.contains(folder_id);

            let type_match = filter.types.is_empty()
                || filter.types.contains(doc.meta().kind());

            tag_match && folder_match && type_match
        }
    }
}

/// View of documents in the search index.
#[typeshare::typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "body")]
pub enum DocumentView {
    /// View all documents in the search index.
    All {
        /// List of secret types to ignore.
        #[serde(rename = "ignoredTypes")]
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
        ///
        /// If no types are specified all types are included.
        include_types: Option<Vec<vcard4::property::Kind>>,
    },
    /// Documents with the specific identifiers.
    Documents {
        /// Vault identifier.
        #[serde(rename = "folderId")]
        folder_id: VaultId,
        /// Secret identifiers.
        identifiers: Vec<SecretId>,
    },
    /// Secrets with the associated websites.
    Websites {
        /// Secrets that match the given target URLs.
        matches: Option<Vec<Url>>,
        /// Exact match requires that the match targets and
        /// websites are exactly equal. Otherwise, comparison
        /// is performed using the URL origin.
        exact: bool,
    },
}

impl Default for DocumentView {
    fn default() -> Self {
        Self::All {
            ignored_types: None,
        }
    }
}

impl DocumentView {
    /// Test this view against a search result document.
    pub fn test(
        &self,
        doc: &Document,
        archive: Option<&ArchiveFilter>,
    ) -> bool {
        if let Some(filter) = archive {
            if !filter.include_documents && doc.folder_id() == &filter.id {
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
            DocumentView::Vault(folder_id) => doc.folder_id() == folder_id,
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
                folder_id,
                identifiers,
            } => {
                doc.folder_id() == folder_id && identifiers.contains(doc.id())
            }
            DocumentView::Websites { matches, exact } => {
                if let Some(sites) = doc.extra().websites() {
                    if sites.is_empty() {
                        false
                    } else {
                        if let Some(targets) = matches {
                            // Search index stores as string but
                            // we need to compare as URLs
                            let mut urls: Vec<Url> =
                                Vec::with_capacity(sites.len());
                            for site in sites {
                                match site.parse() {
                                    Ok(url) => urls.push(url),
                                    Err(e) => {
                                        tracing::warn!(
                                            error = %e,
                                            "search::url_parse");
                                    }
                                }
                            }

                            if *exact {
                                for url in targets {
                                    if urls.contains(url) {
                                        return true;
                                    }
                                }
                                false
                            } else {
                                for url in targets {
                                    for site in &urls {
                                        if url.origin() == site.origin() {
                                            return true;
                                        }
                                    }
                                }
                                false
                            }
                        } else {
                            // No target matches but has some
                            // associated websites so include in the view
                            true
                        }
                    }
                } else {
                    false
                }
            }
        }
    }
}

/// Filter for a search query.
#[typeshare::typeshare]
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct QueryFilter {
    /// List of tags.
    pub tags: Vec<String>,
    /// List of vault identifiers.
    pub folders: Vec<VaultId>,
    /// List of type identifiers.
    pub types: Vec<SecretType>,
}

/// Filter for archived documents.
#[typeshare::typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveFilter {
    /// Identifier of the archive vault.
    pub id: VaultId,
    /// Whether to include archived documents.
    pub include_documents: bool,
}
