use crate::test_utils::{
    assert_local_remote_file_eq, mock::files::create_file_secret,
    simulate_device, spawn, teardown, wait_for_transfers,
};
use anyhow::Result;
use sos_net::client::RemoteSync;

const TEST_ID: &str = "file_transfers_download";

/// Tests downloading an uploaded file on a different device.
#[tokio::test]
async fn file_transfers_download() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut uploader = simulate_device(TEST_ID, &server, 2).await?;
    let default_folder = uploader.owner.default_folder().await.unwrap();

    let mut downloader = uploader.connect(1, None).await?;

    // Create file secret then wait and assert on the upload
    let file = {
        let account = uploader.owner.local_account();
        let mut account = account.lock().await;

        // Create an external file secret
        create_file_secret(&mut *account, &default_folder, None).await?;

        let file = {
            let transfers = account.transfers().await?;
            let transfers = transfers.read().await;
            assert_eq!(1, transfers.len());
            transfers
                .queue()
                .keys()
                .copied()
                .collect::<Vec<_>>()
                .remove(0)
        };
        wait_for_transfers(&account).await?;
        assert_local_remote_file_eq(
            account.paths(),
            &uploader.server_path,
            &file,
        )
        .await?;

        file
    };

    // Sync the uploader so the file events are pushed to the
    // remote server.
    //
    // Note `create_file_secret()` operates on a local account
    // so sync is not automatically performed.
    assert!(uploader.owner.sync().await.is_none());

    {
        // Sync pulls down the file event logs and
        // creates the pending download transfer operation
        assert!(downloader.owner.sync().await.is_none());

        let account = downloader.owner.local_account();
        let mut account = account.lock().await;

        wait_for_transfers(&account).await?;

        assert_local_remote_file_eq(
            account.paths(),
            &downloader.server_path,
            &file,
        )
        .await?;
    }

    teardown(TEST_ID).await;

    Ok(())
}
