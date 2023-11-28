use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::sdk::{
    account::{LocalAccount, UserPaths},
    passwd::diceware::generate_passphrase,
    vfs,
};

const TEST_ID: &str = "contacts";
const VCARD: &str = include_str!("../../../workspace/sdk/fixtures/contact.vcf");

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

    let (mut account, new_account) = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let default_folder = new_account.default_folder();
    account.sign_in(password.clone()).await?;
    account.open_folder(&default_folder).await?;

    account.import_vcard(VCARD, |_| {}).await?; 

    let contacts = data_dir.join("contacts.vcf");
    account.export_all_vcards(&contacts).await?;
    assert!(vfs::try_exists(&contacts).await?);

    teardown(TEST_ID).await;

    Ok(())
}
