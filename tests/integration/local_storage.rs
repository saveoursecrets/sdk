use anyhow::Result;

use crate::test_utils::*;

use futures::stream::StreamExt;
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;

use tempfile::tempdir;

use secrecy::ExposeSecret;
use sos_core::{
    commit_tree::CommitProof, signer::SingleParty, wal::WalProvider,
    PatchProvider,
};
use sos_node::client::{
    account::{login, AccountCredentials},
    local_storage::*,
    net::changes::{changes, connect},
};

fn run_local_storage_tests<W, P>(
    storage: &mut LocalStorage<W, P>,
) -> Result<()>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    // Create an account with default login vault
    let default_login_vault = storage.create_account(None, None)?;

    let summaries = storage.vaults();
    assert_eq!(1, summaries.len());
    let login_summary = summaries.get(0).unwrap();
    assert_eq!("Login", login_summary.name());

    println!("Running tests on storage dir {:#?}", summaries);

    Ok(())
}

#[test]
fn integration_local_storage_memory() -> Result<()> {
    let signer = Box::new(SingleParty::new_random());
    let mut storage = LocalStorage::new_memory_storage(signer);
    run_local_storage_tests(&mut storage)?;
    Ok(())
}

#[test]
fn integration_local_storage_file() -> Result<()> {
    let dir = tempdir()?;
    let signer = Box::new(SingleParty::new_random());
    let mut storage =
        LocalStorage::new_file_storage(signer, dir.path(), true)?;
    run_local_storage_tests(&mut storage)?;
    Ok(())
}
