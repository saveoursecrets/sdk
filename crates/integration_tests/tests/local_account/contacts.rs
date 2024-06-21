use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

const CONTACT: &str = include_str!("../../tests/fixtures/contact.vcf");
const AVATAR: &str = include_str!("../../tests/fixtures/avatar.vcf");

/// Tests importing and exporting contacts from vCard
/// files.
#[tokio::test]
async fn local_contacts() -> Result<()> {
    const TEST_ID: &str = "contacts";

    //crate::test_utils::init_tracing();

    let expected_contact = CONTACT.replace("\r", "");

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account_with_builder(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        |builder| builder.create_contacts(true).create_file_password(true),
    )
    .await?;

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

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
    assert_eq!(&expected_contact, &contact_content);

    let contacts = data_dir.join("contacts.vcf");
    account.export_all_contacts(&contacts).await?;
    assert!(vfs::try_exists(&contacts).await?);

    let contacts_content = vfs::read_to_string(&contacts).await?;
    let contacts_content = contacts_content.replace('\r', "");
    assert_eq!(&expected_contact, &contacts_content);

    // Try loading bytes for a JPEG avatar
    let ids = account.import_contacts(AVATAR, |_| {}).await?;
    assert_eq!(1, ids.len());
    let id = ids.get(0).unwrap();
    let avatar_bytes = account.load_avatar(id, None).await?;
    assert!(avatar_bytes.is_some());

    teardown(TEST_ID).await;

    Ok(())
}
