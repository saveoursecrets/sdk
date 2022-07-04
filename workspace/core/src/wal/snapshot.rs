//! Types for creating WAL file snapshots.
use crate::{
    constants::SNAPSHOT_IDENTITY,
    encode,
    wal::{file::WalFile, WalProvider},
    Error, Result, Timestamp,
};
use serde_binary::{
    binary_rw::SeekStream, Decode, Deserializer, Encode,
    Result as BinaryResult, Serializer,
};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

/// Directory used to store snapshots.
const SNAPSHOTS_DIR: &str = "snapshots";

/// Name of the snapshots index file.
const SNAPSHOTS_INDEX: &str = "index";

/// Append only index of snapshots that includes timestamp information.
pub struct SnapshotIndex {
    file: File,
}

impl SnapshotIndex {
    /// Manages an index of snapshot references.
    pub fn new<P: AsRef<Path>>(snapshots_dir: P) -> Result<Self> {
        let file_path = snapshots_dir.as_ref().join(SNAPSHOTS_INDEX);
        if !file_path.exists() {
            File::create(&file_path)?;
        }

        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&file_path)?;

        let size = file.metadata()?.len();
        if size == 0 {
            file.write_all(&SNAPSHOT_IDENTITY)?;
        }

        Ok(Self { file })
    }

    fn append(&mut self, snapshot: &SnapshotReference) -> Result<()> {
        let buffer = encode(snapshot)?;
        self.file.write_all(&buffer)?;
        Ok(())
    }
}

/// Reference to a snapshot on disc.
pub struct SnapshotReference {
    timestamp: Timestamp,
    vault_id: Uuid,
    root_hash: [u8; 32],
}

impl Encode for SnapshotReference {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        // Prepare the bytes for the row length
        let size_pos = ser.writer.tell()?;
        ser.writer.write_u32(0)?;

        // Encode the fields
        self.timestamp.encode(&mut *ser)?;
        ser.writer.write_bytes(self.vault_id.as_bytes())?;
        ser.writer.write_bytes(&self.root_hash)?;

        // Backtrack to size_pos and write new length
        let row_pos = ser.writer.tell()?;
        let row_len = row_pos - (size_pos + 4);
        ser.writer.seek(size_pos)?;
        ser.writer.write_u32(row_len as u32)?;
        ser.writer.seek(row_pos)?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        ser.writer.write_u32(row_len as u32)?;

        Ok(())
    }
}

impl Decode for SnapshotReference {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        // Read in the row length
        let _ = de.reader.read_u32()?;

        let mut timestamp: Timestamp = Default::default();
        timestamp.decode(&mut *de)?;
        self.timestamp = timestamp;
        let uuid_bytes: [u8; 16] =
            de.reader.read_bytes(16)?.as_slice().try_into()?;
        self.vault_id = Uuid::from_bytes(uuid_bytes);
        self.root_hash = de.reader.read_bytes(32)?.as_slice().try_into()?;

        // Read in the row length appended to the end of the record
        let _ = de.reader.read_u32()?;

        Ok(())
    }
}

/// Manages a collection of WAL snapshots.
pub struct SnapshotManager {
    snapshots_dir: PathBuf,
    snapshots_index: SnapshotIndex,
}

impl SnapshotManager {
    /// Create a new snapshot manager.
    ///
    /// The `base_dir` must be a directory and already exist; this
    /// function will create a nested directory called `snapshots` used
    /// to store the snapshot index and files.
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self> {
        let snapshots_dir = base_dir.as_ref().join(SNAPSHOTS_DIR);
        if !snapshots_dir.exists() {
            std::fs::create_dir(&snapshots_dir)?;
        }

        if !snapshots_dir.is_dir() {
            return Err(Error::NotDirectory(snapshots_dir));
        }

        let snapshots_index = SnapshotIndex::new(&snapshots_dir)?;
        Ok(Self {
            snapshots_dir,
            snapshots_index,
        })
    }

    /// Create a snapshot from a WAL file.
    pub fn create(
        &mut self,
        vault_id: &Uuid,
        wal: &WalFile,
    ) -> Result<(PathBuf, SnapshotReference)> {
        let root_hash = wal.tree().root().ok_or(Error::NoRootCommit)?;
        let root_id = hex::encode(root_hash);
        let snapshot_parent = self.snapshots_dir.join(vault_id.to_string());

        if !snapshot_parent.exists() {
            std::fs::create_dir(&snapshot_parent)?;
        }

        let snapshot_path = snapshot_parent.join(&root_id);

        tracing::debug!(
            vault_id = %vault_id,
            root_hash = ?root_id,
            "WAL snapshot id");

        // Assuming the integrity of any existing snapshot file
        if !snapshot_path.exists() {
            let mut wal_file = File::open(wal.path())?;
            let mut snapshot_file = File::create(&snapshot_path)?;
            tracing::debug!(
                wal = ?wal.path(),
                snapshot = ?snapshot_path,
                "WAL snapshot path");
            std::io::copy(&mut wal_file, &mut snapshot_file)?;
        }

        // Append to the snapshot index
        let snapshot = SnapshotReference {
            timestamp: Default::default(),
            vault_id: *vault_id,
            root_hash,
        };
        self.snapshots_index.append(&snapshot)?;
        Ok((snapshot_path, snapshot))
    }
}
