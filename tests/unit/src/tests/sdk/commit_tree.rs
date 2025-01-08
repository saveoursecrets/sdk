use anyhow::Result;
use sos_core::commit::{CommitTree, Comparison};
use sos_sdk::prelude::*;
use sos_test_utils::mock;

fn vault_to_commit_tree(value: &Vault) -> CommitTree {
    let mut commit_tree = CommitTree::new();
    for (_, commit) in value.commits() {
        commit_tree.insert(commit.into());
    }
    commit_tree.commit();
    commit_tree
}

async fn mock_commit_tree() -> Result<CommitTree> {
    let (encryption_key, _, passphrase) = mock::encryption_key()?;
    let mut vault = VaultBuilder::new()
        .build(BuilderCredentials::Password(passphrase, None))
        .await?;

    let secrets = [
        ("Note one", "First note"),
        ("Note two", "Second note"),
        ("Note three", "Third note"),
    ];

    for (label, note) in secrets {
        let (_secret_meta, _secret_value, meta_bytes, secret_bytes) =
            mock::secret_note(label, note).await?;
        let meta_aead = vault.encrypt(&encryption_key, &meta_bytes).await?;
        let secret_aead =
            vault.encrypt(&encryption_key, &secret_bytes).await?;
        let (commit, _) =
            Vault::commit_hash(&meta_aead, &secret_aead).await?;
        let _secret_id = match vault
            .create_secret(commit, VaultEntry(meta_aead, secret_aead))
            .await?
        {
            WriteEvent::CreateSecret(secret_id, _) => secret_id,
            _ => unreachable!(),
        };
    }

    Ok(vault_to_commit_tree(&vault))
}

#[tokio::test]
async fn commit_tree_from_vault() -> Result<()> {
    let commit_tree = mock_commit_tree().await?;
    assert!(commit_tree.root().is_some());
    Ok(())
}

#[test]
fn commit_proof_compare() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");
    let hash2 = CommitTree::hash(b"world");
    let hash3 = CommitTree::hash(b"goodbye");

    let mut tree1 = CommitTree::new();
    tree1.insert(hash1);
    tree1.commit();

    let mut tree2 = CommitTree::new();
    tree2.insert(hash1);
    tree2.commit();

    let mut tree3 = CommitTree::new();
    tree3.insert(hash3);
    tree3.commit();

    assert!(tree1.root().is_some());
    assert!(tree2.root().is_some());

    assert_eq!(tree1.root(), tree2.root());

    let proof = tree1.proof(&[0])?;
    let comparison = tree2.compare(&proof)?;

    assert_eq!(Comparison::Equal, comparison);

    // Add another hash
    tree2.insert(hash2);
    tree2.commit();

    assert_ne!(tree1.root(), tree2.root());

    let proof = tree1.proof(&[0])?;
    let comparison = tree2.compare(&proof)?;
    assert!(matches!(comparison, Comparison::Contains(_)));

    let proof = tree2.proof(&[0])?;
    let comparison = tree1.compare(&proof)?;
    assert!(matches!(comparison, Comparison::Contains(_)));

    // Completely different trees
    let proof = tree1.proof(&[0])?;
    let comparison = tree3.compare(&proof)?;
    assert!(matches!(comparison, Comparison::Unknown));

    // Completely different trees
    let proof = tree3.proof(&[0])?;
    let comparison = tree2.compare(&proof)?;
    assert!(matches!(comparison, Comparison::Unknown));

    Ok(())
}
