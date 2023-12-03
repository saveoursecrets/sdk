use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::sdk::{
    account::{LocalAccount, UserPaths},
    passwd::diceware::generate_passphrase,
    vfs,
};

const TEST_ID: &str = "contacts";
const CONTACT: &str = include_str!("../../../tests/fixtures/contact.vcf");
const AVATAR: &str = include_str!("../../../tests/fixtures/avatar.vcf");

/// Tests importing and exporting contacts from vCard
/// files.
#[tokio::test]
async fn integration_contacts() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    UserPaths::scaffold(Some(data_dir.clone())).await?;
    UserPaths::new_global(data_dir.clone());

    let (mut account, new_account) = LocalAccount::new_account_with_builder(
        account_name.clone(),
        password.clone(),
        |builder| builder.create_contacts(true).create_file_password(true),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    account.sign_in(password.clone()).await?;

    let contacts = account.contacts_folder().await.unwrap();
    account.open_folder(&contacts).await?;

    let ids = account.import_contacts(CONTACT, |_| {}).await?;
    assert_eq!(1, ids.len());

    let id = ids.get(0).unwrap();
    let contact = data_dir.join("contact.vcf");
    account.export_contact(&contact, id, None).await?;
    assert!(vfs::try_exists(&contact).await?);

    let contact_content = vfs::read_to_string(&contact).await?;
    let contact_content = contact_content.replace('\r', "");
    assert_eq!(CONTACT, &contact_content);

    let contacts = data_dir.join("contacts.vcf");
    account.export_all_contacts(&contacts).await?;
    assert!(vfs::try_exists(&contacts).await?);

    let contacts_content = vfs::read_to_string(&contacts).await?;
    let contacts_content = contacts_content.replace('\r', "");
    assert_eq!(CONTACT, &contacts_content);

    // Try loading bytes for a JPEG avatar
    let ids = account.import_contacts(AVATAR, |_| {}).await?;
    assert_eq!(1, ids.len());
    let id = ids.get(0).unwrap();
    let avatar_bytes = account.load_avatar(id, None).await?;
    assert!(avatar_bytes.is_some());

    teardown(TEST_ID).await;

    Ok(())
}
