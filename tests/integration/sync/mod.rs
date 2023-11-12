use anyhow::Result;
use sos_net::{
    client::{provider::{new_remote_provider, RemoteProvider, StorageProvider}, user::{Origin, UserStorage}},
    sdk::{
        constants::{EVENT_LOG_EXT, VAULT_EXT},
        signer::ecdsa::BoxedEcdsaSigner,
        vault::Summary,
        vfs, mpc::{Keypair, PATTERN},
    },
};
use std::path::PathBuf;

use crate::test_utils::{
    server, server_public_key,
};

mod create_remote_data;

pub async fn create_remote_provider(
    signer: BoxedEcdsaSigner) -> Result<(Origin, RemoteProvider)> {
    // Setup a remote origin
    let server = server();
    let server_public_key = server_public_key()?;
    let origin = Origin {
        name: "origin".to_owned(),
        url: server,
        public_key: server_public_key,
    };
    
    let keypair = Keypair::new(PATTERN.parse()?)?;

    let mut provider = new_remote_provider(
        &origin,
        signer,
        keypair,
    ).await?;

    // Noise protocol handshake
    provider.handshake().await?;

    Ok((origin, provider))
}

/// Assert that local and remote storage are equal.
pub async fn assert_local_remote_eq(
    expected_summaries: Vec<Summary>,
    server_path: &PathBuf,
    owner: &mut UserStorage,
    provider: &mut RemoteProvider,
) -> Result<()> {
    // Compare vault buffers
    for summary in expected_summaries {
        let local_folder = owner.storage().vault_path(&summary);
        let remote_folder =
            server_path.join(format!("{}.{}", summary.id(), VAULT_EXT));
        let local_buffer = vfs::read(&local_folder).await?;
        let remote_buffer = vfs::read(&remote_folder).await?;
        assert_eq!(local_buffer, remote_buffer);
    }

    // Compare event log status (commit proofs)
    let local_status = owner.storage_mut().account_status().await?;
    let remote_status = provider.account_status().await?;
    assert_eq!(local_status, remote_status);

    Ok(())
}
