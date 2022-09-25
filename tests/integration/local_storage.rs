use anyhow::Result;

use tempfile::tempdir;

use secrecy::ExposeSecret;
use sos_core::{
    signer::SingleParty, wal::WalProvider,
    PatchProvider,
};
use sos_node::client::local_storage::LocalStorage;

fn run_local_storage_tests<W, P>(
    storage: &mut LocalStorage<W, P>,
) -> Result<()>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    // Create an account with default login vault
    let (passphrase, _) = storage.create_account(None, None)?;

    let mut summaries = storage.vaults().to_vec();
    assert_eq!(1, summaries.len());
    let summary = summaries.remove(0);
    assert_eq!("Login", summary.name());

    // Rename a vault
    storage.set_vault_name(&summary, "MockVault")?;
    let mut summaries = storage.vaults().to_vec();
    let summary = summaries.remove(0);
    assert_eq!("MockVault", summary.name());

    // Open the vault
    storage.open_vault(&summary, passphrase.expose_secret())?;

    // Close the vault
    storage.close_vault();

    Ok(())
}

#[test]
fn integration_local_storage_memory() -> Result<()> {
    let mut storage = LocalStorage::new_memory_storage();
    run_local_storage_tests(&mut storage)?;
    Ok(())
}

#[test]
fn integration_local_storage_file() -> Result<()> {
    let dir = tempdir()?;
    let signer = Box::new(SingleParty::new_random());
    let mut storage = LocalStorage::new_file_storage(signer, dir.path())?;
    run_local_storage_tests(&mut storage)?;
    Ok(())
}
