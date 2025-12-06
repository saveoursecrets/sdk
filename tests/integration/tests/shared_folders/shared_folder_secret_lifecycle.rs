use anyhow::Result;
use sos_account::{Account, FolderCreate};
use sos_client_storage::NewFolderOptions;
use sos_core::InviteStatus;
use sos_protocol::AccountSync;
use sos_test_utils::{simulate_device, spawn, teardown};

/// Tests creating a shared folder and having the owner
/// perform basic secret lifecycle operations.
#[ignore]
#[tokio::test]
async fn shared_folder_secret_lifecycle() -> Result<()> {
    const TEST_ID: &str = "shared_folder_secret_lifecycle";
    sos_test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;
    let origin = server.origin.clone();

    let test_id_owner: String = format!("{}_owner", TEST_ID);
    let test_id_participant: String = format!("{}_participant", TEST_ID);

    // Prepare mock device(s0)
    let mut account1 =
        simulate_device(&test_id_owner, 1, Some(&server)).await?;
    let account1_password = account1.password.clone();

    let mut account2 =
        simulate_device(&test_id_participant, 1, Some(&server)).await?;
    let account2_password = account2.password.clone();

    // Need both accounts to have set public recipient information
    // for PKI and discovery
    let account1_info = ("name_one", "one@example.com");
    let account2_info = ("name_two", "two@example.com");
    let recipient1 = account1
        .owner
        .set_recipient(
            &origin,
            account1_info.0.to_string(),
            Some(account1_info.1.to_string()),
        )
        .await?;
    let recipient2 = account2
        .owner
        .set_recipient(
            &origin,
            account2_info.0.to_string(),
            Some(account2_info.1.to_string()),
        )
        .await?;

    // Check fetching recipient information from the server.
    let server_recipient1 = account1.owner.find_recipient(&origin).await?;
    let server_recipient2 = account2.owner.find_recipient(&origin).await?;
    assert_eq!(Some(recipient1.clone()), server_recipient1);
    assert_eq!(Some(recipient2.clone()), server_recipient2);

    let recipients = vec![recipient1, recipient2];
    let folder_name = "shared_folder";
    let options = NewFolderOptions::new(folder_name.to_string());
    let FolderCreate {
        folder: shared_folder,
        ..
    } = account1
        .owner
        .create_shared_folder(options, &origin, recipients.as_slice(), None)
        .await?;

    let sent_invites = account1
        .owner
        .sent_folder_invites(&origin, Some(InviteStatus::Pending), None)
        .await?;
    assert!(!sent_invites.is_empty());

    let mut received_invites = account2
        .owner
        .received_folder_invites(&origin, Some(InviteStatus::Pending), None)
        .await?;
    assert!(!received_invites.is_empty());

    let folder_invite = received_invites.remove(0);
    assert_eq!(shared_folder.id(), &folder_invite.folder_id);

    let folders = account1.owner.list_folders().await?;
    assert!(folders.iter().any(|f| f.name() == folder_name));

    println!(
        "-- 1 FOLDER IDS: {:#?} ---",
        folders.iter().map(|f| f.id()).collect::<Vec<_>>()
    );

    // Ensure the owner can manage secrets in the folder
    println!("--- OWNER MUTATE SECRETS ---");
    let secret_ids = super::assert_shared_folder_lifecycle(
        &mut account1.owner,
        shared_folder.id(),
        account1_password,
        &test_id_owner,
    )
    .await?;
    println!("--- OWNER MUTATE SECRETS --- {:?}", secret_ids);

    // Accept the folder invite which will
    // prepare the local copy of the shared
    // folder
    account2
        .owner
        .accept_folder_invite(
            &origin,
            folder_invite.recipient_public_key,
            folder_invite.folder_id,
        )
        .await?;

    let folders = account2.owner.load_folders().await?;
    assert!(folders.iter().any(|f| f.name() == shared_folder.name()));

    println!(
        "-- 1 FOLDER IDS: {:#?} ---",
        folders.iter().map(|f| f.id()).collect::<Vec<_>>()
    );

    // Check the participant in the shared folder
    // can read the existing secrets
    for secret_id in &secret_ids {
        let (row, _) = account2
            .owner
            .read_secret(secret_id, Some(shared_folder.id()))
            .await?;
        println!("{row:?}");
    }

    // Ensure the participant can manage secrets in the folder
    println!("--- PARTICIPANT MUTATE SECRETS ---");
    let new_secret_ids = super::assert_shared_folder_lifecycle(
        &mut account2.owner,
        shared_folder.id(),
        account2_password,
        &test_id_participant,
    )
    .await?;
    println!("--- PARTICIPANT MUTATE SECRETS --- {:?}", new_secret_ids);

    let sync_result = account1.owner.sync().await;
    println!("{sync_result:?}");
    assert!(sync_result.first_error().is_none());

    println!(
        "--- PARTICIPANT SECRET IDS: {:?}",
        account2.owner.list_secret_ids(shared_folder.id()).await?
    );

    println!(
        "--- OWNER SECRET IDS: {:?}",
        account1.owner.list_secret_ids(shared_folder.id()).await?
    );

    for secret_id in &new_secret_ids {
        let (row, _) = account1
            .owner
            .read_secret(secret_id, Some(shared_folder.id()))
            .await?;
        println!("{row:?}");
    }

    account1.owner.sign_out().await?;
    account2.owner.sign_out().await?;

    teardown(TEST_ID).await;
    teardown(&test_id_owner).await;
    teardown(&test_id_participant).await;

    Ok(())
}
