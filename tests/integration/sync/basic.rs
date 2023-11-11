use anyhow::Result;
use serial_test::serial;

use sos_net::sdk::storage::AppPaths;

use crate::test_utils::{create_local_account, setup};

#[tokio::test]
#[serial]
async fn integration_sync_basic() -> Result<()> {
    let dirs = setup(1).await?;

    let test_data_dir = dirs.clients.get(0).unwrap();
    AppPaths::set_data_dir(test_data_dir.clone());
    AppPaths::scaffold().await?;

    let (owner, _, _, _) = create_local_account("sync_basic_1").await?;

    Ok(())
}
