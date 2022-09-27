use sos_core::{
    wal::WalProvider,
    PatchProvider,
    vault::Summary,
};

use crate::client::{Result, Error, provider::StorageProvider};

/// Compact a WAL file.
pub(crate) async fn compact<W, P>(
    provider: &mut (impl StorageProvider<W, P> + Send + Sync + 'static),
    summary: &Summary) -> Result<(u64, u64)>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    let (wal_file, _) = provider
        .cache_mut()
        .get_mut(summary.id())
        .ok_or(Error::CacheNotAvailable(*summary.id()))?;

    let (compact_wal, old_size, new_size) = wal_file.compact()?;

    // Need to recreate the WAL file and load the updated
    // commit tree
    *wal_file = compact_wal;

    // Refresh in-memory vault and mirrored copy
    provider.refresh_vault(summary, None)?;

    Ok((old_size, new_size))
}
