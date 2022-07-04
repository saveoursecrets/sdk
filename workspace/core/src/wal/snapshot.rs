//! Snapshot manager for creating WAL file snapshots.
use crate::{
    wal::{file::WalFile, WalProvider},
    CommitHash, Error, Result,
};
use filetime::FileTime;
use std::{
    fs::File,
    path::{Path, PathBuf},
};
use uuid::Uuid;

/// Directory used to store snapshots.
const SNAPSHOTS_DIR: &str = "snapshots";

/// Snapshot represented by it's timestamp derived from
/// the file modification time and the commit hash of the
/// WAL root hash.
pub struct SnapShot(pub PathBuf, pub FileTime, pub CommitHash);

/// Manages a collection of WAL snapshots.
pub struct SnapShotManager {
    snapshots_dir: PathBuf,
}

impl SnapShotManager {
    /// Create a new snapshot manager.
    ///
    /// The `base_dir` must be a directory and already exist; this
    /// function will create a nested directory called `snapshots` used
    /// to store the snapshot files.
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self> {
        let snapshots_dir = base_dir.as_ref().join(SNAPSHOTS_DIR);
        if !snapshots_dir.exists() {
            std::fs::create_dir(&snapshots_dir)?;
        }

        if !snapshots_dir.is_dir() {
            return Err(Error::NotDirectory(snapshots_dir));
        }

        Ok(Self { snapshots_dir })
    }

    /// Create a snapshot from a WAL file.
    ///
    /// If a snapshot already exists with the current root hash
    /// then this will return `false` to indicate no snapshot was
    /// created.
    pub fn create(
        &self,
        vault_id: &Uuid,
        wal: &WalFile,
    ) -> Result<(PathBuf, bool)> {
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
            Ok((snapshot_path, true))
        } else {
            Ok((snapshot_path, false))
        }
    }

    /// List snapshots sorted by file modification time.
    pub fn list(&self, vault_id: &Uuid) -> Result<Vec<SnapShot>> {
        let mut snapshots = Vec::new();
        let snapshot_parent = self.snapshots_dir.join(vault_id.to_string());
        if snapshot_parent.is_dir() {
            for entry in std::fs::read_dir(&snapshot_parent)? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                // 32 byte hash as a hex-encoded string is 64 bytes
                if name.len() == 64 {
                    let root_hash = hex::decode(name.as_bytes())?;
                    let root_hash: [u8; 32] =
                        root_hash.as_slice().try_into()?;
                    let path = entry.path().to_path_buf();
                    let meta = entry.metadata()?;
                    let mtime = FileTime::from_last_modification_time(&meta);
                    snapshots.push(SnapShot(
                        path,
                        mtime,
                        CommitHash(root_hash),
                    ));
                }
            }
        }

        // Sort by file modification time
        snapshots.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        Ok(snapshots)
    }
}
