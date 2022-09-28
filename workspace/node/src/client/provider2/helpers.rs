//! Helper functions shared by the providers.
use secrecy::{ExposeSecret, SecretString};
use sos_core::{
    crypto::secret_key::SecretKey,
    encode,
    vault::{Summary, Vault},
    wal::{reducer::WalReducer, WalProvider},
    PatchProvider,
};

use crate::client::{provider2::StorageProvider, Error, Result};

/// Load a vault, unlock it and set it as the current vault.
pub(crate) async fn open_vault(
    provider: &mut (impl StorageProvider + Send + Sync + 'static),
    summary: &Summary,
    passphrase: &str,
) -> Result<()> {
    let vault = provider.reduce_wal(summary)?;
    let vault_path = provider.vault_path(summary);
    if provider.state().mirror() {
        if !vault_path.exists() {
            let buffer = encode(&vault)?;
            write_vault_file(provider, summary, &buffer)?;
        }
    };

    provider
        .state_mut()
        .open_vault(passphrase, vault, vault_path)?;
    Ok(())
}

/// Refresh the in-memory vault of the current selection
/// from the contents of the current WAL file.
pub(crate) async fn refresh_vault(
    provider: &mut (impl StorageProvider + Send + Sync + 'static),
    summary: &Summary,
    new_passphrase: Option<&SecretString>,
) -> Result<()> {
    todo!();
    /*
    let wal = provider
        .cache_mut()
        .get_mut(summary.id())
        .map(|(w, _)| w)
        .ok_or(Error::CacheNotAvailable(*summary.id()))?;
    let vault = WalReducer::new().reduce(wal)?.build()?;

    // Rewrite the on-disc version if we are mirroring
    if provider.state().mirror() {
        let buffer = encode(&vault)?;
        write_vault_file(provider, summary, &buffer)?;
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
    */
}

/// Write the buffer for a vault to disc.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn write_vault_file(
    provider: &mut (impl StorageProvider + Send + Sync + 'static),
    summary: &Summary,
    buffer: &[u8],
) -> Result<()> {
    use crate::client::provider2::fs_adapter;
    let vault_path = provider.vault_path(&summary);
    fs_adapter::write(vault_path, buffer)?;
    Ok(())
}

/// Write the buffer for a vault to disc.
#[cfg(target_arch = "wasm32")]
pub(crate) fn write_vault_file(
    _provider: &mut (impl StorageProvider + Send + Sync + 'static),
    _summary: &Summary,
    _buffer: &[u8],
) -> Result<()> {
    Ok(())
}
