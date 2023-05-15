//! Search provides an in-memory index for secret meta data.
use probly_search::{score::bm25, Index, QueryResult};
use serde::Serialize;
use std::{
    borrow::Cow,
    collections::{btree_map::Values, BTreeMap, HashMap, HashSet},
};

use unicode_segmentation::UnicodeSegmentation;
use urn::Urn;

use crate::vault::{
    secret::{Secret, SecretId, SecretMeta, SecretRef},
    VaultId,
};

/// Create a set of ngrams of the given size.
fn ngram_slice(s: &str, n: usize) -> HashSet<&str> {
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
                let val = &s[*offset..=*end_offset];
                items.insert(val);
            }
        }
    }
    items
}

/// Key for meta data documents.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DocumentKey(String, VaultId, SecretId);

// Index tokenizer.
fn tokenizer(s: &str) -> Vec<Cow<'_, str>> {
    let ngrams = ngram_slice(s, 2);
    let words = s.split(' ').collect::<HashSet<_>>();

    let mut tokens: Vec<Cow<str>> = Vec::new();
    for token in words.union(&ngrams) {
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

/// Count of documents by vault identitier and secret kind.
#[derive(Debug, Clone)]
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
    fn is_archived(&self, vault_id: &VaultId) -> bool {
        if let Some(archive) = &self.archive {
            return vault_id == archive;
        }
        false
    }

    /// Document was removed, update the count.
    fn remove(
        &mut self,
        vault_id: VaultId,
        mut options: Option<(u8, HashSet<String>, bool)>,
    ) {
        self.vaults
            .entry(vault_id)
            .and_modify(|counter| {
                if *counter > 0 {
                    *counter -= 1;
                }
            })
            .or_insert(0);
        if let Some((kind, tags, favorite)) = options.take() {
            if !self.is_archived(&vault_id) {
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
        vault_id: VaultId,
        kind: u8,
        tags: &HashSet<String>,
        favorite: bool,
    ) {
        self.vaults
            .entry(vault_id)
            .and_modify(|counter| *counter += 1)
            .or_insert(1);

        if !self.is_archived(&vault_id) {
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
pub struct SearchStatistics {
    /// Document counts.
    count: DocumentCount,
}

impl SearchStatistics {
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
#[derive(Default, Debug, Serialize, Clone)]
pub struct ExtraFields {
    /// The contact type for contact secrets.
    pub contact_type: Option<vcard4::property::Kind>,
}

impl From<&Secret> for ExtraFields {
    fn from(value: &Secret) -> Self {
        let mut extra: ExtraFields = Default::default();
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

/// Document that can be indexed.
#[derive(Debug, Serialize, Clone)]
pub struct Document {
    /// The vault identifier.
    pub vault_id: VaultId,
    /// The secret identifier.
    pub secret_id: SecretId,
    /// The secret meta data.
    pub meta: SecretMeta,
    /// The extra fields for the document.
    pub extra: ExtraFields,
}

impl Document {
    /// Get the vault identifier.
    pub fn vault_id(&self) -> &VaultId {
        &self.vault_id
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
    statistics: SearchStatistics,
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
        let index = Index::<(VaultId, SecretId)>::new(2);
        Self {
            index,
            documents: Default::default(),
            statistics: SearchStatistics::new(None),
        }
    }

    /// Set the identifier for an archive vault.
    pub fn set_archive_id(&mut self, archive: Option<VaultId>) {
        self.statistics.set_archive_id(archive);
    }

    /// Search index statistics.
    pub fn statistics(&self) -> &SearchStatistics {
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

    /// Find document by URN.
    pub fn find_by_urn<'a>(
        &'a self,
        vault_id: &VaultId,
        urn: &Urn,
    ) -> Option<&'a Document> {
        self.documents
            .values()
            .find(|d| d.vault_id() == vault_id && d.meta().urn() == Some(urn))
    }

    /// Find document by label.
    pub fn find_by_label<'a>(
        &'a self,
        vault_id: &VaultId,
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
            .find(|d| d.vault_id() == vault_id && d.meta().label() == label)
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
        vault_id: &VaultId,
        id: &SecretId,
    ) -> Option<&'a Document> {
        self.documents
            .values()
            .find(|d| d.vault_id() == vault_id && d.id() == id)
    }

    /// Find secret meta by uuid or label.
    pub fn find_by_uuid_or_label<'a>(
        &'a self,
        vault_id: &VaultId,
        target: &SecretRef,
    ) -> Option<&'a Document> {
        match target {
            SecretRef::Id(id) => self.find_by_id(vault_id, id),
            SecretRef::Name(name) => self.find_by_label(vault_id, name, None),
        }
    }

    /// Add a document to the index.
    pub fn add(
        &mut self,
        vault_id: &VaultId,
        id: &SecretId,
        meta: SecretMeta,
        secret: &Secret,
    ) {
        // Prevent duplicates
        if self.find_by_id(vault_id, id).is_none() {
            let kind = *meta.kind();

            let doc = Document {
                vault_id: *vault_id,
                secret_id: *id,
                meta,
                extra: secret.into(),
            };

            // Listing key includes the identifier so that
            // secrets with the same label do not overwrite each other
            let key = DocumentKey(
                doc.meta().label().to_lowercase(),
                *vault_id,
                *id,
            );
            let doc = self.documents.entry(key).or_insert(doc);

            self.index.add_document(
                &[label_extract, tags_extract],
                tokenizer,
                (*vault_id, *id),
                doc,
            );

            self.statistics.count.add(
                *vault_id,
                kind.into(),
                doc.meta().tags(),
                doc.meta().favorite(),
            );
        }
    }

    /// Update a document in the index.
    pub fn update(
        &mut self,
        vault_id: &VaultId,
        id: &SecretId,
        meta: SecretMeta,
        secret: &Secret,
    ) {
        self.remove(vault_id, id);
        self.add(vault_id, id, meta, secret);
    }

    /// Remove and vacuum a document from the index.
    pub fn remove(&mut self, vault_id: &VaultId, id: &SecretId) {
        let key = self
            .documents
            .keys()
            .find(|key| &key.1 == vault_id && &key.2 == id)
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

        self.index.remove_document((*vault_id, *id));
        // Vacuum to remove completely
        self.index.vacuum();

        self.statistics.count.remove(*vault_id, doc_info);
    }

    /// Remove all the documents for a given vault identifier from the index.
    pub fn remove_vault(&mut self, vault_id: &VaultId) {
        let keys: Vec<DocumentKey> = self
            .documents
            .keys()
            .filter(|k| &k.1 == vault_id)
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
        self.index
            .query(needle, &mut bm25::new(), query_tokenizer, &[1., 1.])
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::vault::secret::{SecretMeta, SecretType};
    use secrecy::SecretString;
    use uuid::Uuid;

    #[test]
    fn search_index() {
        let vault_id = Uuid::new_v4();

        let mut idx = SearchIndex::new();

        let secret_kind = SecretType::Link;
        let expected_secret_kind: u8 = secret_kind.into();

        let id1 = Uuid::new_v4();
        let meta1 = SecretMeta::new("mock secret".to_owned(), secret_kind);
        let secret1 = Secret::Link {
            url: SecretString::new("https://example.com/one".to_string()),
            title: None,
            label: None,
            user_data: Default::default(),
        };

        let id2 = Uuid::new_v4();
        let meta2 =
            SecretMeta::new("foo bar baz secret".to_owned(), secret_kind);
        let secret2 = Secret::Link {
            url: SecretString::new("https://example.com/two".to_string()),
            title: None,
            label: None,
            user_data: Default::default(),
        };

        idx.add(&vault_id, &id1, meta1, &secret1);
        assert_eq!(1, idx.documents().len());
        idx.add(&vault_id, &id2, meta2, &secret2);
        assert_eq!(2, idx.documents().len());

        assert_eq!(2, *idx.statistics.count.vaults.get(&vault_id).unwrap());
        assert_eq!(
            2,
            *idx.statistics
                .count
                .kinds
                .get(&expected_secret_kind)
                .unwrap()
        );

        let docs = idx.query("mock");
        assert_eq!(1, docs.len());

        let docs = idx.query("secret");
        assert_eq!(2, docs.len());

        idx.remove(&vault_id, &id1);

        assert_eq!(1, *idx.statistics.count.vaults.get(&vault_id).unwrap());
        assert_eq!(
            1,
            *idx.statistics
                .count
                .kinds
                .get(&expected_secret_kind)
                .unwrap()
        );

        let docs = idx.query("mock");
        assert_eq!(0, docs.len());

        let docs = idx.query("secret");
        assert_eq!(1, docs.len());

        let docs = idx.query_map("secret", |_| true);
        assert_eq!(1, docs.len());
        assert_eq!(&id2, docs.get(0).unwrap().id());

        idx.remove(&vault_id, &id2);
        assert_eq!(0, idx.documents.len());

        assert_eq!(0, *idx.statistics.count.vaults.get(&vault_id).unwrap());
        assert_eq!(
            0,
            *idx.statistics
                .count
                .kinds
                .get(&expected_secret_kind)
                .unwrap()
        );

        // Duplicate removal when no more documents
        // to ensure it does not panic
        idx.remove(&vault_id, &id2);
    }
}
