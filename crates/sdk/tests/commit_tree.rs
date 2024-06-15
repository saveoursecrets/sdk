use anyhow::Result;
use sos_sdk::prelude::*;
use sos_test_utils::{mock_encryption_key, mock_secret_note};

async fn mock_commit_tree() -> Result<CommitTree> {
    let (encryption_key, _, passphrase) = mock_encryption_key()?;
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
            mock_secret_note(label, note).await?;
        let meta_aead = vault.encrypt(&encryption_key, &meta_bytes).await?;
        let secret_aead =
            vault.encrypt(&encryption_key, &secret_bytes).await?;
        let (commit, _) =
            Vault::commit_hash(&meta_aead, &secret_aead).await?;
        let _secret_id = match vault
            .create(commit, VaultEntry(meta_aead, secret_aead))
            .await?
        {
            WriteEvent::CreateSecret(secret_id, _) => secret_id,
            _ => unreachable!(),
        };
    }

    Ok((&vault).into())
}

#[tokio::test]
async fn commit_tree_from_vault() -> Result<()> {
    let commit_tree = mock_commit_tree().await?;
    assert!(commit_tree.root().is_some());
    Ok(())
}

#[tokio::test]
async fn commit_proof_serde() -> Result<()> {
    let commit_tree = mock_commit_tree().await?;
    let proof = commit_tree.head()?;

    let json = serde_json::to_string_pretty(&proof)?;
    let commit_proof: CommitProof = serde_json::from_str(&json)?;

    assert_eq!(proof.root, commit_proof.root);
    assert_eq!(
        proof.proof.proof_hashes(),
        commit_proof.proof.proof_hashes()
    );
    assert_eq!(proof.length, commit_proof.length);
    assert_eq!(proof.indices, commit_proof.indices);

    Ok(())
}

#[test]
fn commit_proof_at() -> Result<()> {
    let n = 10;
    let mut trees = Vec::with_capacity(n);
    let hashes = (0..n)
        .into_iter()
        .map(|n| {
            trees.push(CommitTree::new());
            CommitTree::hash(n.to_string().as_bytes())
        })
        .collect::<Vec<_>>();

    let mut merkle_trees = Vec::new();

    for (index, mut tree) in trees.into_iter().enumerate() {
        for i in 0..index + 1 {
            tree.append(&mut vec![hashes.get(i).cloned().unwrap()]);
        }
        tree.commit();
        merkle_trees.push(tree);
    }

    let roots = merkle_trees
        .iter()
        .map(|t| t.root().unwrap())
        .enumerate()
        .collect::<Vec<_>>();

    for (index, root) in roots {
        println!("{} {}", index, root);
    }

    println!("---");

    let all_nodes = merkle_trees.last().unwrap();
    let leaves = all_nodes.leaves().unwrap_or_default();
    for (index, leaf) in leaves.into_iter().enumerate() {
        // println!("{} {}", index, CommitHash(leaf));
        let proof = all_nodes.proof_at(index, leaf)?;
        println!("{} {}", index, proof.root);
    }

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
    assert!(matches!(comparison, Comparison::Contains(_, _)));

    let proof = tree2.proof(&[0])?;
    let comparison = tree1.compare(&proof)?;
    assert!(matches!(comparison, Comparison::Contains(_, _)));

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
