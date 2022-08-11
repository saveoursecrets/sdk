//! Search provides a search index for the meta data
//! of an open vault.

use probly_search::{
    index::{
        add_document_to_index, create_index, remove_document_from_index,
        vacuum_index, Index,
    },
    query::{query, score::default::bm25, QueryResult},
};
use std::collections::{BTreeMap, HashSet};

use crate::secret::{SecretId, SecretMeta};

/// Key for meta data documents.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct DocumentKey(String, SecretId);

// A white space tokenizer
fn tokenizer(s: &str) -> Vec<String> {
    s.split(' ')
        .map(|slice| slice.to_owned())
        .collect::<Vec<String>>()
}

// Label
fn label_extract<'a>(d: &'a Document) -> Option<&'a str> {
    Some(d.meta.label())
}

// A no-op filter
fn filter(s: &str) -> String {
    s.to_owned()
}

// FIXME: remove Clone here

/// Document that can be indexed.
#[derive(Debug, Clone)]
pub struct Document {
    id: SecretId,
    meta: SecretMeta,
}

impl From<(SecretId, SecretMeta)> for Document {
    fn from(value: (SecretId, SecretMeta)) -> Self {
        Self {
            id: value.0,
            meta: value.1,
        }
    }
}

/// Exposes access to a search index of meta data.
pub struct SearchIndex {
    index: Index<SecretId>,
    items: BTreeMap<DocumentKey, Document>,
}

impl SearchIndex {
    /// Create a new search index.
    pub fn new() -> Self {
        // Create index with N fields
        let mut index = create_index::<SecretId>(1);
        Self {
            index,
            items: Default::default(),
        }
    }

    /// Get the collection of documents.
    pub fn documents(
        &self,
    ) -> &BTreeMap<DocumentKey, Document> {
        &self.items
    }

    /// Add a document to the index.
    pub fn add(&mut self, id: &SecretId, meta: SecretMeta) {
        let doc: Document = (*id, meta).into();

        // Listing key includes the identifier so that
        // secrets with the same label do not overwrite each other
        let key = DocumentKey(doc.meta.label().to_lowercase().to_owned(), *id);
        let doc = self.items.entry(key).or_insert(doc);

        add_document_to_index(
            &mut self.index,
            &[label_extract],
            tokenizer,
            filter,
            *id,
            // FIXME: remove clone() here
            // SEE: https://github.com/quantleaf/probly-search/pull/11
            doc.clone(), 
        );
    }

    /// Remove and vacuum a document from the index.
    pub fn remove(&mut self, id: &SecretId) {
        let key = self
            .items
            .keys()
            .find(|key| &key.1 == id)
            .map(|k| k.clone());
        if let Some(key) = &key {
            self.items.remove(key);
        }

        let mut removed_docs = HashSet::new();
        remove_document_from_index(&mut self.index, &mut removed_docs, *id);
        // Vacuum to remove completely
        vacuum_index(&mut self.index, &mut removed_docs);
    }

    /// Query the index.
    pub fn query(&mut self, needle: &str) -> Vec<QueryResult<SecretId>> {
        query(
            &mut self.index,
            needle,
            &mut bm25::new(),
            tokenizer,
            filter,
            &[1., 1.],
            None,
        )
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
    }
}
