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

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct ListingKey(String, SecretId);

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

/// Document that can be indexed.
pub struct Document<'a> {
    id: SecretId,
    meta: &'a SecretMeta,
}

impl<'a> From<(&SecretId, &'a SecretMeta)> for Document<'a> {
    fn from(value: (&SecretId, &'a SecretMeta)) -> Self {
        Self {
            id: *value.0,
            meta: value.1,
        }
    }
}

/// Exposes access to a search index of meta data.
pub struct SearchIndex<'a> {
    index: Index<SecretId>,
    list: BTreeMap<ListingKey, (&'a SecretId, SecretMeta)>,
}

/*
    fn sort_meta_data(
        &self,
        keeper: &Gatekeeper,
    ) -> Result<BTreeMap<String, (SecretId, SecretMeta)>, JsError> {
        Ok(keeper
            .meta_data()?
            .into_iter()
            .map(|(k, v)| {
                let key = format!("{} {}", v.label().to_lowercase(), k);
                (key, (*k, v))
            })
            .collect())
    }
*/

impl<'a> SearchIndex<'a> {
    /// Create a new search index.
    pub fn new() -> Self {
        // Create index with N fields
        let mut index = create_index::<SecretId>(1);
        Self {
            index,
            list: Default::default(),
        }
    }

    /// Add a document to the index.
    pub fn add(&mut self, id: &'a SecretId, meta: SecretMeta) {
        // Listing key includes the identifier so that
        // secrets with the same label do not overwrite each other
        let key = ListingKey(meta.label().to_lowercase().to_owned(), *id);
        let (_, meta) = self.list.entry(key).or_insert((id, meta));
        let doc: Document = (id, &*meta).into();

        add_document_to_index(
            &mut self.index,
            &[label_extract],
            tokenizer,
            filter,
            *id,
            doc,
        );
    }

    /// Remove and vacuum a document from the index.
    pub fn remove(&mut self, id: &SecretId) {
        let key =
            self.list.keys().find(|key| &key.1 == id).map(|k| k.clone());
        if let Some(key) = &key {
            self.list.remove(key);
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
