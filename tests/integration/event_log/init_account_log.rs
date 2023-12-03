use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::{
    events::Patch,
    sdk::{
        account::{LocalAccount, UserPaths},
        events::{AccountEvent, AccountEventLog},
        passwd::diceware::generate_passphrase,
        vault::secret::{IdentityKind, SecretType},
    },
};

const TEST_ID: &str = "events_init_account_log";

/// Tests lazy initialization of the account events log.
#[tokio::test]
async fn integration_events_init_account_log() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let (mut account, new_account) = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    // Sign in should lazily initialize the account event log
    // from the folders on disc
    account.sign_in(password.clone()).await?;

    let account_events = account.paths().account_events();
    let mut event_log = AccountEventLog::new_account(&account_events).await?;
    let records = event_log.patch_until(None).await?;
    let patch: Patch = records.into();
    let events = patch.into_events::<AccountEvent>().await?;
    assert_eq!(1, events.len());

    assert!(matches!(
        events.get(0),
        Some(AccountEvent::CreateFolder(_, _))
    ));

    /*
    assert!(matches!(
        events.get(1),
        Some(AccountEvent::CreateFolder(_, _))
    ));
    assert!(matches!(
        events.get(2),
        Some(AccountEvent::CreateFolder(_, _))
    ));
    */

    teardown(TEST_ID).await;

    Ok(())
}
