//! Type for iterating and managing the commit trees for a vault.
use serde_binary::binary_rw::{BinaryReader, Endian, ReadStream, SeekStream};
use std::ops::Range;

use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};

use crate::{
    vault::{Header, Vault},
    wal::{file::WalFileRow, WalItem},
    Result,
};

pub mod integrity;

/// Compute the Sha256 hash of some data.
pub fn hash(data: &[u8]) -> [u8; 32] {
    Sha256::hash(data)
}

/// Encapsulates the merkle tree for all commits to a vault or WAL.
#[derive(Default)]
pub struct CommitTree {
    tree: MerkleTree<Sha256>,
}

impl CommitTree {
    /// Create a new empty commit tree.
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::<Sha256>::new(),
        }
    }

    /// Create a commit tree from an existing vault.
    pub fn from_vault(vault: &Vault) -> Self {
        let mut commit_tree = Self::new();
        for (_, commit) in vault.commits() {
            commit_tree.tree.insert(commit.to_bytes());
        }
        commit_tree.tree.commit();
        commit_tree
    }

    /// Create a commit tree from a row iterator.
    pub fn from_iterator<'a>(it: &mut RowIterator<'a>) -> Result<Self> {
        let mut commit_tree = Self::new();
        while let Some(row_info) = it.next() {
            let row_info = row_info?;
            commit_tree.tree.insert(row_info.commit);
        }
        commit_tree.tree.commit();
        Ok(commit_tree)
    }

    /// Get the number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.tree.leaves_len()
    }

    /// Insert a commit hash into the tree,
    pub fn insert(&mut self, hash: <Sha256 as Hasher>::Hash) -> &mut Self {
        self.tree.insert(hash);
        self
    }

    /// Commit changes to the tree to compute the root.
    pub fn commit(&mut self) {
        self.tree.commit()
    }

    /// Get the root hash of the underlying merkle tree.
    pub fn root(&self) -> Option<<Sha256 as Hasher>::Hash> {
        self.tree.root()
    }
}

/// Refrerence to the identifier and commit for a row.
#[derive(Debug)]
pub struct RowInfo {
    /// Byte offset of the row.
    pub position: usize,
    /// The length of the row in bytes.
    pub length: u32,
    /// The bytes for the secret identifier.
    pub id: [u8; 16],
    /// The bytes for the commit hash.
    pub commit: [u8; 32],
    /// The byte range for the secret data.
    ///
    /// This is the absolute position in the underlying stream
    /// and gives the caller a chance to read in the secret value
    /// if it needs to.
    pub value: Range<usize>,
}

impl RowInfo {
    /// Read the bytes for the secret value into an owned buffer.
    pub fn read_value<'a>(
        &self,
        reader: &mut BinaryReader<'a>,
    ) -> Result<Vec<u8>> {
        let length = self.value.end - self.value.start;
        reader.seek(self.value.start)?;
        let value = reader.read_bytes(length)?;
        Ok(value)
    }

    /// Get the row identifier.
    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }
}

/// Iterates a stream and yields identifiers and commits.
pub struct RowIterator<'a> {
    reader: BinaryReader<'a>,
    total_rows: u32,
    index: u32,
}

impl<'a> RowIterator<'a> {
    /// Create a new commit iterator that reads from the given stream.
    ///
    /// Expects a valid vault file and will return the vault header along
    /// with the iterator so that callers can access the vault file header information.
    pub fn new(stream: &'a mut impl ReadStream) -> Result<(Self, Header)> {
        let header = Header::read_header_stream(stream)?;
        let mut reader = BinaryReader::new(stream, Endian::Big);
        let total_rows = reader.read_u32()?;
        Ok((
            Self {
                reader,
                total_rows,
                index: 0,
            },
            header,
        ))
    }

    /// Get the expected number of rows in the stream.
    pub fn total_rows(&self) -> &u32 {
        &self.total_rows
    }

    /// Get the current iteration index.
    pub fn index(&self) -> &u32 {
        &self.index
    }

    fn read_row(&mut self) -> Result<RowInfo> {
        let position = self.reader.tell()?;
        let length = self.reader.read_u32()?;
        let id: [u8; 16] =
            self.reader.read_bytes(16)?.as_slice().try_into()?;
        let commit: [u8; 32] =
            self.reader.read_bytes(32)?.as_slice().try_into()?;

        let start = position + 52;
        let end = start + (length as usize - 48);

        let row_info = RowInfo {
            position,
            length,
            id,
            commit,
            value: start..end,
        };
        self.reader.seek(position + 4 + (length as usize))?;
        Ok(row_info)
    }
}

impl<'a> Iterator for RowIterator<'a> {
    type Item = Result<RowInfo>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.total_rows {
            let row = self.read_row();
            self.index += 1;
            Some(row)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        events::SyncEvent,
        test_utils::*,
        vault::{Vault, VaultAccess, VaultEntry},
    };
    use anyhow::Result;

    #[test]
    fn commit_tree_from_vault() -> Result<()> {
        let (encryption_key, _) = mock_encryption_key()?;
        let mut vault = mock_vault();
        let secrets = [
            ("Note one", "First note"),
            ("Note two", "Second note"),
            ("Note three", "Third note"),
        ];

        for (label, note) in secrets {
            let (secret_meta, secret_value, meta_bytes, secret_bytes) =
                mock_secret_note(label, note)?;
            let meta_aead = vault.encrypt(&encryption_key, &meta_bytes)?;
            let secret_aead =
                vault.encrypt(&encryption_key, &secret_bytes)?;
            let (commit, _) = Vault::commit_hash(&meta_aead, &secret_aead)?;
            let secret_id = match vault
                .create(commit, VaultEntry(meta_aead, secret_aead))?
            {
                SyncEvent::CreateSecret(_, secret_id, _) => secret_id,
                _ => unreachable!(),
            };
        }

        let commit_tree = CommitTree::from_vault(&vault);
        assert!(commit_tree.root().is_some());

        Ok(())
    }
}
