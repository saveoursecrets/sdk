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

/*
#[test]
fn commit_proof_relationship_equal() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");

    let mut local = CommitTree::new();
    local.insert(hash1);
    local.commit();

    let mut remote = CommitTree::new();
    remote.insert(hash1);
    remote.commit();

    let local_proof = local.head()?;

    // Local sends proof to remote and remote indicates
    // if proof is contained in the remote tree.
    //
    // Remote replies with it's latest head proof
    // and the optional match proof.
    let match_proof = remote.contains(&local_proof)?;
    let remote_proof = remote.head()?;

    // Local can now determine the relationship between the two trees
    let relationship = local.relationship(remote_proof, match_proof)?;

    assert!(matches!(relationship, CommitRelationship::Equal(_)));

    Ok(())
}

#[test]
fn commit_proof_relationship_diverged() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");
    let hash2 = CommitTree::hash(b"world");

    let mut local = CommitTree::new();
    local.insert(hash1);
    local.commit();

    let mut remote = CommitTree::new();
    remote.insert(hash2);
    remote.commit();

    let local_proof = local.head()?;

    // Local sends proof to remote and remote indicates
    // if proof is contained in the remote tree.
    //
    // Remote replies with it's latest head proof
    // and the optional match proof.
    let match_proof = remote.contains(&local_proof)?;
    let remote_proof = remote.head()?;

    // Local can now determine the relationship between the two trees
    let relationship = local.relationship(remote_proof, match_proof)?;

    assert!(matches!(relationship, CommitRelationship::Diverged(_)));

    Ok(())
}

#[test]
fn commit_proof_relationship_behind() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");
    let hash2 = CommitTree::hash(b"world");

    let mut local = CommitTree::new();
    local.insert(hash1);
    local.commit();

    let mut remote = CommitTree::new();
    remote.insert(hash1);
    remote.insert(hash2);
    remote.commit();

    let local_proof = local.head()?;

    // Local sends proof to remote and remote indicates
    // if proof is contained in the remote tree.
    //
    // Remote replies with it's latest head proof
    // and the optional match proof.
    let match_proof = remote.contains(&local_proof)?;
    let remote_proof = remote.head()?;

    // Local can now determine the relationship between the two trees
    let relationship = local.relationship(remote_proof, match_proof)?;

    assert!(matches!(relationship, CommitRelationship::Behind(_, _)));

    Ok(())
}
*/

/*
#[test]
fn commit_proof_relationship_ahead() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");
    let hash2 = CommitTree::hash(b"world");

    let mut local = CommitTree::new();
    local.insert(hash1);
    local.insert(hash2);
    local.commit();

    let mut remote = CommitTree::new();
    remote.insert(hash1);
    remote.commit();

    let local_proof = local.head()?;

    // Local sends proof to remote and remote indicates
    // if proof is contained in the remote tree.
    //
    // Remote replies with it's latest head proof
    // and the optional match proof.
    let match_proof = remote.contains(&local_proof)?;
    let remote_proof = remote.head()?;

    // Local can now determine the relationship between the two trees
    let relationship = local.relationship(remote_proof, match_proof)?;

    assert!(matches!(relationship, CommitRelationship::Ahead(_, _)));

    Ok(())
}
*/

/*
#[test]
fn commit_multi_equal() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");
    let hash2 = CommitTree::hash(b"world");

    let tree_id1 = Uuid::new_v4();
    let tree_id2 = Uuid::new_v4();

    let mut local_tree1 = CommitTree::new();
    local_tree1.insert(hash1);
    local_tree1.commit();

    let mut local_tree2 = CommitTree::new();
    local_tree2.insert(hash2);
    local_tree2.commit();

    let mut local: MultiTree<Uuid> = Default::default();
    local.insert(tree_id1, &local_tree1);
    local.insert(tree_id2, &local_tree2);

    let mut remote_tree1 = CommitTree::new();
    remote_tree1.insert(hash1);
    remote_tree1.commit();

    let mut remote_tree2 = CommitTree::new();
    remote_tree2.insert(hash2);
    remote_tree2.commit();

    let mut remote: MultiTree<Uuid> = Default::default();
    remote.insert(tree_id1, &remote_tree1);
    remote.insert(tree_id2, &remote_tree2);

    let local_proofs = local.head()?;
    let match_proofs = remote.contains(&local_proofs)?;
    let remote_proofs = remote.head()?;

    let mut relationships =
        local.relationship(&remote_proofs, &match_proofs)?;

    assert!(matches!(
        relationships.remove(&tree_id1).unwrap(),
        CommitRelationship::Equal(_)
    ));

    assert!(matches!(
        relationships.remove(&tree_id2).unwrap(),
        CommitRelationship::Equal(_)
    ));

    Ok(())
}
*/

/*
#[test]
fn commit_multi_ahead() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");
    let hash2 = CommitTree::hash(b"world");
    let hash3 = CommitTree::hash(b"goodbye");

    let tree_id1 = Uuid::new_v4();
    let tree_id2 = Uuid::new_v4();

    let mut local_tree1 = CommitTree::new();
    local_tree1.insert(hash1);
    local_tree1.commit();

    let mut local_tree2 = CommitTree::new();
    local_tree2.insert(hash2);
    local_tree2.insert(hash3); // Makes this tree ahead
    local_tree2.commit();

    let mut local: MultiTree<Uuid> = Default::default();
    local.insert(tree_id1, &local_tree1);
    local.insert(tree_id2, &local_tree2);

    let mut remote_tree1 = CommitTree::new();
    remote_tree1.insert(hash1);
    remote_tree1.commit();

    let mut remote_tree2 = CommitTree::new();
    remote_tree2.insert(hash2);
    remote_tree2.commit();

    let mut remote: MultiTree<Uuid> = Default::default();
    remote.insert(tree_id1, &remote_tree1);
    remote.insert(tree_id2, &remote_tree2);

    let local_proofs = local.head()?;
    let match_proofs = remote.contains(&local_proofs)?;
    let remote_proofs = remote.head()?;

    let mut relationships =
        local.relationship(&remote_proofs, &match_proofs)?;

    assert!(matches!(
        relationships.remove(&tree_id1).unwrap(),
        CommitRelationship::Equal(_)
    ));

    assert!(matches!(
        relationships.remove(&tree_id2).unwrap(),
        CommitRelationship::Ahead(_, _)
    ));

    Ok(())
}
*/

/*
#[test]
fn commit_multi_behind() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");
    let hash2 = CommitTree::hash(b"world");
    let hash3 = CommitTree::hash(b"goodbye");

    let tree_id1 = Uuid::new_v4();
    let tree_id2 = Uuid::new_v4();

    let mut local_tree1 = CommitTree::new();
    local_tree1.insert(hash1);
    local_tree1.commit();

    let mut local_tree2 = CommitTree::new();
    local_tree2.insert(hash2);
    local_tree2.commit();

    let mut local: MultiTree<Uuid> = Default::default();
    local.insert(tree_id1, &local_tree1);
    local.insert(tree_id2, &local_tree2);

    let mut remote_tree1 = CommitTree::new();
    remote_tree1.insert(hash1);
    remote_tree1.commit();

    let mut remote_tree2 = CommitTree::new();
    remote_tree2.insert(hash2);
    remote_tree2.insert(hash3); // Makes this tree ahead
    remote_tree2.commit();

    let mut remote: MultiTree<Uuid> = Default::default();
    remote.insert(tree_id1, &remote_tree1);
    remote.insert(tree_id2, &remote_tree2);

    let local_proofs = local.head()?;
    let match_proofs = remote.contains(&local_proofs)?;
    let remote_proofs = remote.head()?;

    let mut relationships =
        local.relationship(&remote_proofs, &match_proofs)?;

    assert!(matches!(
        relationships.remove(&tree_id1).unwrap(),
        CommitRelationship::Equal(_)
    ));

    assert!(matches!(
        relationships.remove(&tree_id2).unwrap(),
        CommitRelationship::Behind(_, _)
    ));

    Ok(())
}
*/

/*
#[test]
fn commit_multi_diverged() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");
    let hash2 = CommitTree::hash(b"world");

    let tree_id1 = Uuid::new_v4();
    let tree_id2 = Uuid::new_v4();

    let mut local_tree1 = CommitTree::new();
    local_tree1.insert(hash1);
    local_tree1.commit();

    let mut local_tree2 = CommitTree::new();
    local_tree2.insert(hash2);
    local_tree2.commit();

    let mut local: MultiTree<Uuid> = Default::default();
    local.insert(tree_id1, &local_tree1);
    local.insert(tree_id2, &local_tree2);

    // Flip the hashes so the trees are diverged
    let mut remote_tree1 = CommitTree::new();
    remote_tree1.insert(hash2);
    remote_tree1.commit();

    let mut remote_tree2 = CommitTree::new();
    remote_tree2.insert(hash1);
    remote_tree2.commit();

    let mut remote: MultiTree<Uuid> = Default::default();
    remote.insert(tree_id1, &remote_tree1);
    remote.insert(tree_id2, &remote_tree2);

    let local_proofs = local.head()?;
    let match_proofs = remote.contains(&local_proofs)?;
    let remote_proofs = remote.head()?;

    let mut relationships =
        local.relationship(&remote_proofs, &match_proofs)?;

    assert!(matches!(
        relationships.remove(&tree_id1).unwrap(),
        CommitRelationship::Diverged(_)
    ));

    assert!(matches!(
        relationships.remove(&tree_id2).unwrap(),
        CommitRelationship::Diverged(_)
    ));

    Ok(())
}
*/

/*
#[test]
fn commit_node_equal() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");
    let hash2 = CommitTree::hash(b"world");

    let node_id1 = Uuid::new_v4();
    let node_id2 = Uuid::new_v4();

    let tree_id1 = Uuid::new_v4();
    let tree_id2 = Uuid::new_v4();

    let mut local_tree1 = CommitTree::new();
    local_tree1.insert(hash1);
    local_tree1.commit();

    let mut local_tree2 = CommitTree::new();
    local_tree2.insert(hash2);
    local_tree2.commit();

    let mut local: MultiTree<Uuid> = Default::default();
    local.insert(tree_id1, &local_tree1);
    local.insert(tree_id2, &local_tree2);

    let mut remote_tree1 = CommitTree::new();
    remote_tree1.insert(hash1);
    remote_tree1.commit();

    let mut remote_tree2 = CommitTree::new();
    remote_tree2.insert(hash2);
    remote_tree2.commit();

    let mut remote: MultiTree<Uuid> = Default::default();
    remote.insert(tree_id1, &remote_tree1);
    remote.insert(tree_id2, &remote_tree2);

    let mut node: NodeTree<Uuid, Uuid> = NodeTree::new(node_id1, &local);

    let local_head = local.head()?;
    node.insert(node_id2, &remote);

    let mut matches = HashMap::new();
    matches.insert(&node_id2, remote.contains(&local_head)?);

    let operations = node.compute(matches)?;
    assert!(operations.is_empty());

    Ok(())
}
*/

/*
#[test]
fn commit_node_push() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");
    let hash2 = CommitTree::hash(b"world");
    let hash3 = CommitTree::hash(b"goodbye");

    let node_id1 = Uuid::new_v4();
    let node_id2 = Uuid::new_v4();

    let tree_id1 = Uuid::new_v4();
    let tree_id2 = Uuid::new_v4();

    let mut local_tree1 = CommitTree::new();
    local_tree1.insert(hash1);
    local_tree1.commit();

    let mut local_tree2 = CommitTree::new();
    local_tree2.insert(hash2);
    local_tree2.insert(hash3); // Puts the local tree ahead of remote
    local_tree2.commit();

    let mut local: MultiTree<Uuid> = Default::default();
    local.insert(tree_id1, &local_tree1);
    local.insert(tree_id2, &local_tree2);

    let mut remote_tree1 = CommitTree::new();
    remote_tree1.insert(hash1);
    remote_tree1.commit();

    let mut remote_tree2 = CommitTree::new();
    remote_tree2.insert(hash2);
    remote_tree2.commit();

    let mut remote: MultiTree<Uuid> = Default::default();
    remote.insert(tree_id1, &remote_tree1);
    remote.insert(tree_id2, &remote_tree2);

    let mut node: NodeTree<Uuid, Uuid> = NodeTree::new(node_id1, &local);

    let mut local_head = local.head()?;
    let mut remote_head = remote.head()?;

    node.insert(node_id2, &remote);

    let mut matches = HashMap::new();
    matches.insert(&node_id2, remote.contains(&local_head)?);

    let operations = node.compute(matches)?;
    assert_eq!(1, operations.len());

    let push = Operation::Push {
        local: node_id1,
        remote: node_id2,
        id: tree_id2,
        difference: 1,
        commit: CommitPair {
            local: local_head.remove(&tree_id2).unwrap(),
            remote: remote_head.remove(&tree_id2).unwrap(),
        },
    };
    assert!(operations.contains(&push));

    Ok(())
}
*/

/*
#[test]
fn commit_node_pull() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");
    let hash2 = CommitTree::hash(b"world");
    let hash3 = CommitTree::hash(b"goodbye");

    let node_id1 = Uuid::new_v4();
    let node_id2 = Uuid::new_v4();

    let tree_id1 = Uuid::new_v4();
    let tree_id2 = Uuid::new_v4();

    let mut local_tree1 = CommitTree::new();
    local_tree1.insert(hash1);
    local_tree1.commit();

    let mut local_tree2 = CommitTree::new();
    local_tree2.insert(hash2);
    local_tree2.commit();

    let mut local: MultiTree<Uuid> = Default::default();
    local.insert(tree_id1, &local_tree1);
    local.insert(tree_id2, &local_tree2);

    let mut remote_tree1 = CommitTree::new();
    remote_tree1.insert(hash1);
    remote_tree1.commit();

    let mut remote_tree2 = CommitTree::new();
    remote_tree2.insert(hash2);
    remote_tree2.insert(hash3); // Puts the remote tree ahead of local
    remote_tree2.commit();

    let mut remote: MultiTree<Uuid> = Default::default();
    remote.insert(tree_id1, &remote_tree1);
    remote.insert(tree_id2, &remote_tree2);

    let mut node: NodeTree<Uuid, Uuid> = NodeTree::new(node_id1, &local);

    let mut local_head = local.head()?;
    let mut remote_head = remote.head()?;

    node.insert(node_id2, &remote);

    let mut matches = HashMap::new();
    matches.insert(&node_id2, remote.contains(&local_head)?);

    let operations = node.compute(matches)?;
    assert_eq!(1, operations.len());

    let pull = Operation::Pull {
        local: node_id1,
        remote: node_id2,
        id: tree_id2,
        difference: 1,
        commit: CommitPair {
            local: local_head.remove(&tree_id2).unwrap(),
            remote: remote_head.remove(&tree_id2).unwrap(),
        },
    };
    assert!(operations.contains(&pull));

    Ok(())
}
*/

/*
#[test]
fn commit_node_conflict() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");
    let hash2 = CommitTree::hash(b"world");
    let hash3 = CommitTree::hash(b"goodbye");

    let node_id1 = Uuid::new_v4();
    let node_id2 = Uuid::new_v4();

    let tree_id1 = Uuid::new_v4();
    let tree_id2 = Uuid::new_v4();

    let mut local_tree1 = CommitTree::new();
    local_tree1.insert(hash1);
    local_tree1.commit();

    let mut local_tree2 = CommitTree::new();
    local_tree2.insert(hash2);
    local_tree2.commit();

    let mut local: MultiTree<Uuid> = Default::default();
    local.insert(tree_id1, &local_tree1);
    local.insert(tree_id2, &local_tree2);

    let mut remote_tree1 = CommitTree::new();
    remote_tree1.insert(hash1);
    remote_tree1.commit();

    let mut remote_tree2 = CommitTree::new();
    remote_tree2.insert(hash3); // Diverges this tree from local
    remote_tree2.commit();

    let mut remote: MultiTree<Uuid> = Default::default();
    remote.insert(tree_id1, &remote_tree1);
    remote.insert(tree_id2, &remote_tree2);

    let mut node: NodeTree<Uuid, Uuid> = NodeTree::new(node_id1, &local);

    let mut local_head = local.head()?;
    let mut remote_head = remote.head()?;

    node.insert(node_id2, &remote);

    let mut matches = HashMap::new();
    matches.insert(&node_id2, remote.contains(&local_head)?);

    let operations = node.compute(matches)?;
    assert_eq!(1, operations.len());

    let conflict = Operation::Conflict {
        local: node_id1,
        remote: node_id2,
        id: tree_id2,
        commit: CommitPair {
            local: local_head.remove(&tree_id2).unwrap(),
            remote: remote_head.remove(&tree_id2).unwrap(),
        },
    };
    assert!(operations.contains(&conflict));

    Ok(())
}
*/

/*
#[test]
fn commit_node_pull_push() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");
    let hash2 = CommitTree::hash(b"world");
    let hash3 = CommitTree::hash(b"goodbye");

    let node_id1 = Uuid::new_v4();
    let node_id2 = Uuid::new_v4();

    let tree_id1 = Uuid::new_v4();
    let tree_id2 = Uuid::new_v4();

    let mut local_tree1 = CommitTree::new();
    local_tree1.insert(hash1);
    local_tree1.commit();

    let mut local_tree2 = CommitTree::new();
    local_tree2.insert(hash2);
    local_tree2.insert(hash3); // Puts the local tree ahead of remote
    local_tree2.commit();

    let mut local: MultiTree<Uuid> = Default::default();
    local.insert(tree_id1, &local_tree1);
    local.insert(tree_id2, &local_tree2);

    let mut remote_tree1 = CommitTree::new();
    remote_tree1.insert(hash1);
    remote_tree1.insert(hash3); // Puts the remote tree ahead of local
    remote_tree1.commit();

    let mut remote_tree2 = CommitTree::new();
    remote_tree2.insert(hash2);
    remote_tree2.commit();

    let mut remote: MultiTree<Uuid> = Default::default();
    remote.insert(tree_id1, &remote_tree1);
    remote.insert(tree_id2, &remote_tree2);

    let mut node: NodeTree<Uuid, Uuid> = NodeTree::new(node_id1, &local);

    let mut local_head = local.head()?;
    let mut remote_head = remote.head()?;

    node.insert(node_id2, &remote);

    let mut matches = HashMap::new();
    matches.insert(&node_id2, remote.contains(&local_head)?);

    let operations = node.compute(matches)?;
    assert_eq!(2, operations.len());

    let push = Operation::Push {
        local: node_id1,
        remote: node_id2,
        id: tree_id2,
        difference: 1,
        commit: CommitPair {
            local: local_head.remove(&tree_id2).unwrap(),
            remote: remote_head.remove(&tree_id2).unwrap(),
        },
    };
    assert!(operations.contains(&push));

    let pull = Operation::Pull {
        local: node_id1,
        remote: node_id2,
        id: tree_id1,
        difference: 1,
        commit: CommitPair {
            local: local_head.remove(&tree_id1).unwrap(),
            remote: remote_head.remove(&tree_id1).unwrap(),
        },
    };
    assert!(operations.contains(&pull));

    Ok(())
}
*/

/*
#[test]
fn commit_node_pull_push_conflict() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");
    let hash2 = CommitTree::hash(b"world");
    let hash3 = CommitTree::hash(b"goodbye");

    let node_id1 = Uuid::new_v4();
    let node_id2 = Uuid::new_v4();

    let tree_id1 = Uuid::new_v4();
    let tree_id2 = Uuid::new_v4();
    let tree_id3 = Uuid::new_v4();

    let mut local_tree1 = CommitTree::new();
    local_tree1.insert(hash1);
    local_tree1.commit();

    let mut local_tree2 = CommitTree::new();
    local_tree2.insert(hash2);
    local_tree2.insert(hash3); // Puts the local tree ahead of remote
    local_tree2.commit();

    let mut local_tree3 = CommitTree::new();
    local_tree3.insert(hash1);
    local_tree3.commit();

    let mut local: MultiTree<Uuid> = Default::default();
    local.insert(tree_id1, &local_tree1);
    local.insert(tree_id2, &local_tree2);
    local.insert(tree_id3, &local_tree3);

    let mut remote_tree1 = CommitTree::new();
    remote_tree1.insert(hash1);
    remote_tree1.insert(hash3); // Puts the remote tree ahead of local
    remote_tree1.commit();

    let mut remote_tree2 = CommitTree::new();
    remote_tree2.insert(hash2);
    remote_tree2.commit();

    let mut remote_tree3 = CommitTree::new();
    remote_tree3.insert(hash2); // Conflict on this tree
    remote_tree3.commit();

    let mut remote: MultiTree<Uuid> = Default::default();
    remote.insert(tree_id1, &remote_tree1);
    remote.insert(tree_id2, &remote_tree2);
    remote.insert(tree_id3, &remote_tree3);

    let mut node: NodeTree<Uuid, Uuid> = NodeTree::new(node_id1, &local);

    let mut local_head = local.head()?;
    let mut remote_head = remote.head()?;

    node.insert(node_id2, &remote);

    let mut matches = HashMap::new();
    matches.insert(&node_id2, remote.contains(&local_head)?);

    let operations = node.compute(matches)?;
    assert_eq!(3, operations.len());

    let push = Operation::Push {
        local: node_id1,
        remote: node_id2,
        id: tree_id2,
        difference: 1,
        commit: CommitPair {
            local: local_head.remove(&tree_id2).unwrap(),
            remote: remote_head.remove(&tree_id2).unwrap(),
        },
    };
    assert!(operations.contains(&push));

    let pull = Operation::Pull {
        local: node_id1,
        remote: node_id2,
        id: tree_id1,
        difference: 1,
        commit: CommitPair {
            local: local_head.remove(&tree_id1).unwrap(),
            remote: remote_head.remove(&tree_id1).unwrap(),
        },
    };
    assert!(operations.contains(&pull));

    let conflict = Operation::Conflict {
        local: node_id1,
        remote: node_id2,
        id: tree_id3,
        commit: CommitPair {
            local: local_head.remove(&tree_id3).unwrap(),
            remote: remote_head.remove(&tree_id3).unwrap(),
        },
    };
    assert!(operations.contains(&conflict));

    Ok(())
}
*/

/*
#[test]
fn commit_multi_node() -> Result<()> {
    let hash1 = CommitTree::hash(b"hello");
    let hash2 = CommitTree::hash(b"world");
    let hash3 = CommitTree::hash(b"goodbye");

    let node_id1 = Uuid::new_v4();
    let node_id2 = Uuid::new_v4();
    let node_id3 = Uuid::new_v4();

    let tree_id1 = Uuid::new_v4();
    let tree_id2 = Uuid::new_v4();
    let tree_id3 = Uuid::new_v4();

    // Node 1 (local)
    let mut local_tree1 = CommitTree::new();
    local_tree1.insert(hash1);
    local_tree1.commit();
    let mut local_tree2 = CommitTree::new();
    local_tree2.insert(hash2);
    // Puts the local tree ahead of remotes (node 2 and node 3)
    local_tree2.insert(hash3);
    local_tree2.commit();
    let mut local_tree3 = CommitTree::new();
    local_tree3.insert(hash3);
    local_tree3.commit();

    let mut local: MultiTree<Uuid> = Default::default();
    local.insert(tree_id1, &local_tree1);
    local.insert(tree_id2, &local_tree2);
    local.insert(tree_id3, &local_tree3);

    // Node 2
    let mut node2_tree1 = CommitTree::new();
    node2_tree1.insert(hash1);
    // Puts the remote tree ahead of local (node 1)
    node2_tree1.insert(hash3);
    node2_tree1.commit();
    let mut node2_tree2 = CommitTree::new();
    node2_tree2.insert(hash2);
    node2_tree2.commit();
    let mut node2_tree3 = CommitTree::new();
    node2_tree3.insert(hash2); // Conflict on this tree
    node2_tree3.commit();

    let mut node2: MultiTree<Uuid> = Default::default();
    node2.insert(tree_id1, &node2_tree1);
    node2.insert(tree_id2, &node2_tree2);
    node2.insert(tree_id3, &node2_tree3);

    // Node 3
    let mut node3_tree1 = CommitTree::new();
    node3_tree1.insert(hash1);
    node3_tree1.commit();
    let mut node3_tree2 = CommitTree::new();
    node3_tree2.insert(hash2);
    node3_tree2.commit();
    let mut node3_tree3 = CommitTree::new();
    node3_tree3.insert(hash3);
    node3_tree3.commit();

    let mut node3: MultiTree<Uuid> = Default::default();
    node3.insert(tree_id1, &node3_tree1);
    node3.insert(tree_id2, &node3_tree2);
    node3.insert(tree_id3, &node3_tree3);

    let mut node: NodeTree<Uuid, Uuid> = NodeTree::new(node_id1, &local);

    let mut local_head = local.head()?;
    let mut node2_head = node2.head()?;
    let mut node3_head = node3.head()?;

    node.insert(node_id2, &node2);
    node.insert(node_id3, &node3);

    let mut matches = HashMap::new();
    matches.insert(&node_id2, node2.contains(&local_head)?);
    matches.insert(&node_id3, node3.contains(&local_head)?);

    let operations = node.compute(matches)?;

    // Expects conflict, pull and two pushes
    let conflict = Operation::Conflict {
        local: node_id1,
        remote: node_id2,
        id: tree_id3,
        commit: CommitPair {
            local: local_head.remove(&tree_id3).unwrap(),
            remote: node2_head.remove(&tree_id3).unwrap(),
        },
    };
    assert!(operations.contains(&conflict));

    let node2_push = Operation::Push {
        local: node_id1,
        remote: node_id2,
        id: tree_id2,
        difference: 1,
        commit: CommitPair {
            local: local_head.get(&tree_id2).cloned().unwrap(),
            remote: node2_head.remove(&tree_id2).unwrap(),
        },
    };
    assert!(operations.contains(&node2_push));

    let node3_push = Operation::Push {
        local: node_id1,
        remote: node_id3,
        id: tree_id2,
        difference: 1,
        commit: CommitPair {
            local: local_head.get(&tree_id2).cloned().unwrap(),
            remote: node3_head.remove(&tree_id2).unwrap(),
        },
    };
    assert!(operations.contains(&node3_push));

    let pull = Operation::Pull {
        local: node_id1,
        remote: node_id2,
        id: tree_id1,
        difference: 1,
        commit: CommitPair {
            local: local_head.get(&tree_id1).cloned().unwrap(),
            remote: node2_head.remove(&tree_id1).unwrap(),
        },
    };
    assert!(operations.contains(&pull));

    Ok(())
}
*/
