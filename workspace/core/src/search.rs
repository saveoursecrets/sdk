//! Search provides a search index for the meta data
//! of an open vault.
use probly_search::{score::bm25, Index, QueryResult};
use serde::Serialize;
use std::{
    borrow::Cow,
    collections::{btree_map::Values, BTreeMap, HashSet},
};

use unicode_segmentation::UnicodeSegmentation;

use crate::{
    secret::{SecretId, SecretMeta, SecretRef},
    vault::VaultId,
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
    let words = s.split(' ').into_iter().collect::<HashSet<_>>();

    let mut tokens: Vec<Cow<str>> = Vec::new();
    for token in words.union(&ngrams) {
        tokens.push(Cow::Owned(token.to_lowercase()))
    }
    tokens
}

// Query tokenizer.
fn query_tokenizer(s: &str) -> Vec<Cow<'_, str>> {
    s.split(' ')
        .into_iter()
        .map(|s| s.to_lowercase())
        .map(Cow::Owned)
        .collect::<Vec<_>>()
}

// Label
fn label_extract(d: &Document) -> Vec<&str> {
    vec![d.2.label()]
}

// Tags
fn tags_extract(d: &Document) -> Vec<&str> {
    d.2.tags().iter().map(|s| &s[..]).collect()
}

/// Document that can be indexed.
#[derive(Debug, Serialize)]
pub struct Document(pub VaultId, pub SecretId, pub SecretMeta);

impl Document {
    /// Get the vault identifier.
    pub fn vault_id(&self) -> &VaultId {
        &self.0
    }

    /// Get the secret identifier.
    pub fn id(&self) -> &SecretId {
        &self.1
    }

    /// Get the secret meta data.
    pub fn meta(&self) -> &SecretMeta {
        &self.2
    }
}

/// Exposes access to a search index of meta data.
pub struct SearchIndex {
    index: Index<(VaultId, SecretId)>,
    documents: BTreeMap<DocumentKey, Document>,
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
        }
    }

    /// Get the collection of documents.
    pub fn documents(&self) -> &BTreeMap<DocumentKey, Document> {
        &self.documents
    }

    /// Get a list of the document values.
    pub fn values(&self) -> Vec<&Document> {
        self.documents.values().collect::<Vec<_>>()
    }

    /// Get an iterator over all the values.
    pub fn values_iter(&self) -> Values<'_, DocumentKey, Document> {
        self.documents.values()
    }

    /// Get the number of documents in the index.
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    /// Determine if the search index is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Find document by label.
    pub fn find_by_label<'a>(
        &'a self,
        vault_id: &VaultId,
        label: &str,
    ) -> Option<&'a Document> {
        self.documents
            .values()
            .find(|d| d.vault_id() == vault_id && d.meta().label() == label)
    }

    /// Find all documents with the given label ignoring
    /// a particular identifier.
    pub fn find_all_by_label<'a>(
        &'a self,
        label: &str,
        id: Option<SecretId>,
    ) -> Vec<&'a Document> {
        self.documents
            .iter()
            .filter(|(k, v)| {
                if let Some(id) = &id {
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
            SecretRef::Name(name) => self.find_by_label(vault_id, name),
        }
    }

    /// Add a document to the index.
    pub fn add(
        &mut self,
        vault_id: &VaultId,
        id: &SecretId,
        meta: SecretMeta,
    ) {
        let doc = Document(*vault_id, *id, meta);

        // Listing key includes the identifier so that
        // secrets with the same label do not overwrite each other
        let key =
            DocumentKey(doc.meta().label().to_lowercase(), *vault_id, *id);
        let doc = self.documents.entry(key).or_insert(doc);

        self.index.add_document(
            &[label_extract, tags_extract],
            tokenizer,
            (*vault_id, *id),
            doc,
        );
    }

    /// Update a document in the index.
    pub fn update(
        &mut self,
        vault_id: &VaultId,
        id: &SecretId,
        meta: SecretMeta,
    ) {
        self.remove(vault_id, id);
        self.add(vault_id, id, meta);
    }

    /// Remove and vacuum a document from the index.
    pub fn remove(&mut self, vault_id: &VaultId, id: &SecretId) {
        let key = self
            .documents
            .keys()
            .find(|key| &key.1 == vault_id && &key.2 == id)
            .cloned();
        if let Some(key) = &key {
            self.documents.remove(key);
        }

        //let mut removed_docs = HashSet::new();
        self.index.remove_document((*vault_id, *id));
        // Vacuum to remove completely
        self.index.vacuum();
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
                if let Some(doc) = self.find_by_id(&r.key.0, &r.key.1) {
                    if predicate(doc) {
                        Some(doc)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::secret::SecretMeta;
    use uuid::Uuid;

    #[test]
    fn search_index() {
        let vault_id = Uuid::new_v4();

        let mut idx = SearchIndex::new();

        let id1 = Uuid::new_v4();
        let meta1 = SecretMeta::new("mock secret".to_owned(), 1);

        let id2 = Uuid::new_v4();
        let meta2 = SecretMeta::new("foo bar baz secret".to_owned(), 1);

        idx.add(&vault_id, &id1, meta1);
        assert_eq!(1, idx.documents().len());
        idx.add(&vault_id, &id2, meta2);
        assert_eq!(2, idx.documents().len());

        let docs = idx.query("mock");
        assert_eq!(1, docs.len());

        let docs = idx.query("secret");
        assert_eq!(2, docs.len());

        idx.remove(&vault_id, &id1);

        let docs = idx.query("mock");
        assert_eq!(0, docs.len());

        let docs = idx.query("secret");
        assert_eq!(1, docs.len());

        let docs = idx.query_map("secret", |_| true);
        assert_eq!(1, docs.len());
        assert_eq!(&id2, docs.get(0).unwrap().id());
    }
}
