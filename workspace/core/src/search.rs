//! Search provides a search index for the meta data
//! of an open vault.
use probly_search::{score::bm25, Index, QueryResult};
use serde::Serialize;
use std::{borrow::Cow, collections::BTreeMap};

use crate::secret::{SecretId, SecretMeta, SecretRef};

/// Key for meta data documents.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DocumentKey(String, SecretId);

// Tokenizer used for indexing.
fn tokenizer(s: &str) -> Vec<Cow<'_, str>> {
    s.split(' ').map(Cow::Borrowed).collect::<Vec<_>>()
}

// Label
fn label_extract<'a>(d: &'a Document) -> Option<&'a str> {
    Some(d.1.label())
}

/// Document that can be indexed.
#[derive(Debug, Serialize)]
pub struct Document(pub SecretId, pub SecretMeta);

impl Document {
    /// Get the secret identifier.
    pub fn id(&self) -> &SecretId {
        &self.0
    }

    /// Get the secret meta data.
    pub fn meta(&self) -> &SecretMeta {
        &self.1
    }
}

/// Exposes access to a search index of meta data.
pub struct SearchIndex {
    index: Index<SecretId>,
    documents: BTreeMap<DocumentKey, Document>,
}

impl SearchIndex {
    /// Create a new search index.
    pub fn new() -> Self {
        // Create index with N fields
        let index = Index::<SecretId>::new(1);
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

    /// Find document by label.
    pub fn find_by_label<'a>(&'a self, label: &str) -> Option<&'a Document> {
        self.documents.values().find(|d| d.meta().label() == label)
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
    pub fn find_by_id<'a>(&'a self, id: &SecretId) -> Option<&'a Document> {
        self.documents.values().find(|d| d.id() == id)
    }

    /// Find secret meta by uuid or label.
    pub fn find_by_uuid_or_label<'a>(
        &'a self,
        target: &SecretRef,
    ) -> Option<&'a Document> {
        match target {
            SecretRef::Id(id) => self.find_by_id(id),
            SecretRef::Name(name) => self.find_by_label(name),
        }
    }

    /// Add a document to the index.
    pub fn add(&mut self, id: &SecretId, meta: SecretMeta) {
        let doc = Document(*id, meta);

        // Listing key includes the identifier so that
        // secrets with the same label do not overwrite each other
        let key =
            DocumentKey(doc.meta().label().to_lowercase().to_owned(), *id);
        let doc = self.documents.entry(key).or_insert(doc);

        self.index
            .add_document(&[label_extract], tokenizer, *id, &doc);
    }

    /// Update a document in the index.
    pub fn update(&mut self, id: &SecretId, meta: SecretMeta) {
        self.remove(id);
        self.add(id, meta);
    }

    /// Remove and vacuum a document from the index.
    pub fn remove(&mut self, id: &SecretId) {
        let key = self
            .documents
            .keys()
            .find(|key| &key.1 == id)
            .map(|k| k.clone());
        if let Some(key) = &key {
            self.documents.remove(key);
        }

        //let mut removed_docs = HashSet::new();
        self.index.remove_document(*id);
        // Vacuum to remove completely
        self.index.vacuum();
    }

    /// Query the index.
    pub fn query(&self, needle: &str) -> Vec<QueryResult<SecretId>> {
        self.index
            .query(needle, &mut bm25::new(), tokenizer, &[1., 1.])
    }

    /// Query the index and map each result to the corresponding document.
    ///
    /// If a corresponding document could not be located the search result
    /// will be ignored.
    pub fn query_map(&self, needle: &str) -> Vec<&Document> {
        let results = self.query(needle);
        results
            .into_iter()
            .filter_map(|r| {
                if let Some(doc) = self.find_by_id(&r.key) {
                    Some(doc)
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
        let mut idx = SearchIndex::new();

        let id1 = Uuid::new_v4();
        let meta1 = SecretMeta::new("mock secret".to_owned(), 1);

        let id2 = Uuid::new_v4();
        let meta2 = SecretMeta::new("foo bar baz secret".to_owned(), 1);

        idx.add(&id1, meta1);
        assert_eq!(1, idx.documents().len());
        idx.add(&id2, meta2);
        assert_eq!(2, idx.documents().len());

        let docs = idx.query("mock");
        assert_eq!(1, docs.len());

        let docs = idx.query("secret");
        assert_eq!(2, docs.len());

        idx.remove(&id1);

        let docs = idx.query("mock");
        assert_eq!(0, docs.len());

        let docs = idx.query("secret");
        assert_eq!(1, docs.len());

        let docs = idx.query_map("secret");
        assert_eq!(1, docs.len());
        assert_eq!(&id2, docs.get(0).unwrap().id());
    }
}
