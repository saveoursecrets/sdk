//! Helper functions shared by the providers.
use secrecy::{ExposeSecret, SecretString};
use sos_core::{
    crypto::secret_key::SecretKey,
    encode,
    vault::{Summary, Vault},
    wal::{reducer::WalReducer, WalProvider},
    PatchProvider,
};

use crate::client::{
    provider::StorageProvider,
    Error, Result,
};

/// Load a vault, unlock it and set it as the current vault.
pub(crate) async fn open_vault<W, P>(
    provider: &mut (impl StorageProvider<W, P> + Send + Sync + 'static),
    summary: &Summary,
    passphrase: &str,
) -> Result<()>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    let vault = reduce_wal(provider, summary).await?;
    let vault_path = provider.vault_path(summary);
    if provider.state().mirror() {
        //let vault_path = provider.vault_path(summary);
        if !vault_path.exists() {
            let buffer = encode(&vault)?;
            write_vault_file(provider, summary, &buffer).await?;
        }
    };

    provider
        .state_mut()
        .open_vault(passphrase, vault, vault_path)?;
    Ok(())
}

/// Refresh the in-memory vault of the current selection
/// from the contents of the current WAL file.
pub(crate) async fn refresh_vault<W, P>(
    provider: &mut (impl StorageProvider<W, P> + Send + Sync + 'static),
    summary: &Summary,
    new_passphrase: Option<&SecretString>,
) -> Result<()>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    let wal = provider
        .cache_mut()
        .get_mut(summary.id())
        .map(|(w, _)| w)
        .ok_or(Error::CacheNotAvailable(*summary.id()))?;
    let vault = WalReducer::new().reduce(wal)?.build()?;

    // Rewrite the on-disc version if we are mirroring
    if provider.state().mirror() {
        let buffer = encode(&vault)?;
        write_vault_file(provider, summary, &buffer).await?;
    }

    if let Some(keeper) = provider.current_mut() {
        if keeper.id() == summary.id() {
            // Update the in-memory version
            let new_key = if let Some(new_passphrase) = new_passphrase {
                if let Some(salt) = vault.salt() {
                    let salt = SecretKey::parse_salt(salt)?;
                    let private_key = SecretKey::derive_32(
                        new_passphrase.expose_secret(),
                        &salt,
                    )?;
                    Some(private_key)
                } else {
                    None
                }
            } else {
                None
            };

            keeper.replace_vault(vault, new_key)?;
        }
    }
    Ok(())
}

/// Compact a WAL file.
pub(crate) async fn compact<W, P>(
    provider: &mut (impl StorageProvider<W, P> + Send + Sync + 'static),
    summary: &Summary,
) -> Result<(u64, u64)>
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
    provider.refresh_vault(summary, None).await?;

    Ok((old_size, new_size))
}

/// Helper to reduce a WAL file to a vault.
pub(crate) async fn reduce_wal<W, P>(
    provider: &mut (impl StorageProvider<W, P> + Send + Sync + 'static),
    summary: &Summary,
) -> Result<Vault>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    // Reduce the WAL to a vault
    let wal_file = provider
        .cache_mut()
        .get_mut(summary.id())
        .map(|(w, _)| w)
        .ok_or(Error::CacheNotAvailable(*summary.id()))?;

    Ok(WalReducer::new().reduce(wal_file)?.build()?)
}

/// Write the buffer for a vault to disc.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn write_vault_file<W, P>(
    provider: &mut (impl StorageProvider<W, P> + Send + Sync + 'static),
    summary: &Summary,
    buffer: &[u8],
) -> Result<()>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    use crate::client::provider::fs_adapter;

    let vault_path = provider.vault_path(&summary);
    fs_adapter::write(vault_path, buffer).await?;
    Ok(())
}

/// Write the buffer for a vault to disc.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn write_vault_file<W, P>(
    _provider: &mut (impl StorageProvider<W, P> + Send + Sync + 'static),
    _summary: &Summary,
    _buffer: &[u8],
) -> Result<()>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    Ok(())
}
