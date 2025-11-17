use sos_search::*;
use sos_vault::secret::{Secret, SecretMeta, SecretType};
use uuid::Uuid;

#[test]
fn ngram_slice_with_multi_byte() {
    let specs = &["бывшая", "Марина Маркеш"];
    for s in specs {
        ngram_slice(s, 2);
        ngram_slice(s, 3);
        ngram_slice(s, 4);
        ngram_slice(s, 5);
    }
}

#[test]
fn search_index() {
    let folder_id = Uuid::new_v4();

    let mut idx = SearchIndex::new();

    let secret_kind = SecretType::Link;
    let expected_secret_kind: u8 = secret_kind.into();

    let id1 = Uuid::new_v4();
    let meta1 = SecretMeta::new("mock secret".to_owned(), secret_kind);
    let secret1 = Secret::Link {
        url: "https://example.com/one".to_string().into(),
        title: None,
        label: None,
        user_data: Default::default(),
    };

    let id2 = Uuid::new_v4();
    let meta2 = SecretMeta::new("foo bar baz secret".to_owned(), secret_kind);
    let secret2 = Secret::Link {
        url: "https://example.com/two".to_string().into(),
        title: None,
        label: None,
        user_data: Default::default(),
    };

    idx.add(&folder_id, &id1, &meta1, &secret1);
    assert_eq!(1, idx.documents().len());
    idx.add(&folder_id, &id2, &meta2, &secret2);
    assert_eq!(2, idx.documents().len());

    assert_eq!(
        2,
        *idx.statistics().count().vaults().get(&folder_id).unwrap()
    );
    assert_eq!(
        2,
        *idx.statistics()
            .count()
            .kinds()
            .get(&expected_secret_kind)
            .unwrap()
    );

    let docs = idx.query("mock");
    assert_eq!(1, docs.len());

    let docs = idx.query("secret");
    assert_eq!(2, docs.len());

    idx.remove(&folder_id, &id1);

    assert_eq!(
        1,
        *idx.statistics().count().vaults().get(&folder_id).unwrap()
    );
    assert_eq!(
        1,
        *idx.statistics()
            .count()
            .kinds()
            .get(&expected_secret_kind)
            .unwrap()
    );

    let docs = idx.query("mock");
    assert_eq!(0, docs.len());

    let docs = idx.query("secret");
    assert_eq!(1, docs.len());

    let docs = idx.query_map("secret", |_| true);
    assert_eq!(1, docs.len());
    assert_eq!(&id2, docs.first().unwrap().id());

    idx.remove(&folder_id, &id2);
    assert_eq!(0, idx.len());

    assert_eq!(
        0,
        *idx.statistics().count().vaults().get(&folder_id).unwrap()
    );
    assert_eq!(
        0,
        *idx.statistics()
            .count()
            .kinds()
            .get(&expected_secret_kind)
            .unwrap()
    );

    // Duplicate removal when no more documents
    // to ensure it does not panic
    idx.remove(&folder_id, &id2);
}
