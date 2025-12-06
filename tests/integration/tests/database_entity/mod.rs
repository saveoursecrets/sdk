use anyhow::Result;
use secrecy::SecretString;
use sos_account::Account;
use sos_backend::BackendTarget;
use sos_client_storage::NewFolderOptions;
use sos_core::{
    crypto::AccessKey, AccountId, InviteStatus, Recipient, VaultId,
};
use sos_database::{
    async_sqlite::Client,
    entity::{
        AccountEntity, AccountRecord, RecipientEntity, SharedFolderEntity,
    },
};
use sos_net::{NetworkAccount, NetworkAccountOptions};
use sos_password::diceware::generate_passphrase;
use sos_vault::Summary;

mod shared_folder;

pub const FOLDER_NAME: &str = "shared_folder";

async fn prepare_local_db_account(
    target: &BackendTarget,
    name: &str,
) -> Result<(AccountRecord, NetworkAccount, Summary, SecretString)> {
    assert!(
        matches!(target, BackendTarget::Database(_, _)),
        "must be a database target"
    );
    let account_name = name.to_string();
    let (password, _) = generate_passphrase()?;
    let mut account = NetworkAccount::new_account_with_builder(
        account_name.to_owned(),
        password.clone(),
        target.clone(),
        NetworkAccountOptions::default(),
        |builder| {
            builder
                .save_passphrase(false)
                .create_archive(false)
                .create_authenticator(false)
                .create_contacts(false)
                .create_file_password(true)
        },
    )
    .await?;

    let key: AccessKey = password.clone().into();
    account.sign_in(&key).await?;
    let summary = account.default_folder().await.unwrap();

    let BackendTarget::Database(_, client) = target else {
        unreachable!();
    };
    let account_id = *account.account_id();
    let account_record: AccountRecord = client
        .conn_and_then(move |conn| {
            let entity = AccountEntity::new(&conn);
            let account_row = entity.find_one(&account_id)?;
            Ok::<_, anyhow::Error>(account_row.try_into().unwrap())
        })
        .await?;

    Ok((account_record, account, summary, password))
}

async fn create_recipients_and_shared_folder_with_invite_status(
    server: &mut Client,
    account1: &mut NetworkAccount,
    account2: &mut NetworkAccount,
    invite_status: Option<InviteStatus>,
) -> Result<((AccountId, String), (AccountId, String), VaultId)> {
    // Both accounts must have enabled sharing by
    // creating recipient information
    let recipients = {
        let recipients_info = [
            (
                *account1.account_id(),
                "name_one",
                "one@example.com",
                account1.shared_access_public_key().await?,
            ),
            (
                *account2.account_id(),
                "name_two",
                "two@example.com",
                account2.shared_access_public_key().await?,
            ),
        ];

        let mut recipients = Vec::new();

        // Register each account as a recipient for sharing
        for (account_id, name, email, public_key) in
            recipients_info.into_iter()
        {
            let recipient = Recipient {
                name: name.to_owned(),
                email: Some(email.to_owned()),
                public_key: public_key.clone(),
            };
            server
                .conn_mut_and_then(move |conn| {
                    let mut entity = SharedFolderEntity::new(conn);
                    let recipient_id =
                        entity.upsert_recipient(account_id, recipient)?;
                    Ok::<_, anyhow::Error>(recipient_id)
                })
                .await?;

            recipients.push(Recipient {
                name: name.to_string(),
                email: Some(email.to_string()),
                public_key,
            });
        }
        recipients
    };

    let options = NewFolderOptions::new(FOLDER_NAME.to_string());
    let (vault, _access_key) = account1
        .prepare_shared_folder(options, recipients.as_slice(), None)
        .await?;

    let folder_id = vault.id();

    // Create the shared folder which will also prepare invites and joins
    // for the target recipients.
    SharedFolderEntity::create_shared_folder(
        server,
        account1.account_id(),
        &vault,
        recipients.as_slice(),
    )
    .await?;

    // Search for recipients
    let mut found_recipients = server
        .conn_and_then(move |conn| {
            let mut entity = RecipientEntity::new(&conn);
            Ok::<_, anyhow::Error>(entity.search_recipients("two")?)
        })
        .await?;

    assert_eq!(1, found_recipients.len());

    let from_account_id = *account1.account_id();
    let to_account_id = *account2.account_id();
    let from_recipient_public_key =
        account1.shared_access_public_key().await?.to_string();

    let to_recipient = found_recipients.remove(0);
    let to_recipient_public_key = to_recipient.recipient_public_key.clone();

    // Check the sent invites list for the sender (account1)
    let mut sent_invites = server
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(entity.sent_folder_invites(
                &from_account_id,
                None,
                None,
            )?)
        })
        .await?;
    assert_eq!(1, sent_invites.len());

    // Check the received invites list for the receiver (account2)
    let mut received_invites = server
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(entity.received_folder_invites(
                &to_account_id,
                None,
                None,
            )?)
        })
        .await?;
    assert_eq!(1, received_invites.len());

    let sent_invite = sent_invites.remove(0);
    let received_invite = received_invites.remove(0);

    assert_eq!(sent_invite.row_id, received_invite.row_id);
    assert_eq!(FOLDER_NAME, &sent_invite.folder_name);
    assert_eq!(FOLDER_NAME, &received_invite.folder_name);

    assert_eq!(&to_recipient_public_key, &sent_invite.recipient_public_key);
    assert_eq!(
        &from_recipient_public_key,
        &received_invite.recipient_public_key
    );

    // Name and email should be for the *other* recipient
    assert_eq!("name_two", &sent_invite.recipient_name);
    assert_eq!("name_one", &received_invite.recipient_name);
    assert_eq!(
        Some("two@example.com"),
        sent_invite.recipient_email.as_deref()
    );
    assert_eq!(
        Some("one@example.com"),
        received_invite.recipient_email.as_deref()
    );

    // Check the sent invites list for the sender (account1) that have been accepted (should be empty now)
    let accepted_invites = server
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(entity.sent_folder_invites(
                &from_account_id,
                Some(InviteStatus::Accepted),
                None,
            )?)
        })
        .await?;
    assert!(accepted_invites.is_empty());

    // Accept or decline the invite (account2)
    if let Some(invite_status) = invite_status {
        let from_public_key = from_recipient_public_key.clone();
        let invite_folder_id = *folder_id;
        server
            .conn_mut_and_then(move |conn| {
                let mut entity = SharedFolderEntity::new(conn);
                Ok::<_, anyhow::Error>(entity.update_folder_invite(
                    &to_account_id,
                    invite_status,
                    &from_public_key,
                    &invite_folder_id,
                )?)
            })
            .await?;
    }

    Ok((
        (from_account_id, from_recipient_public_key),
        (to_account_id, to_recipient_public_key),
        *folder_id,
    ))
}
