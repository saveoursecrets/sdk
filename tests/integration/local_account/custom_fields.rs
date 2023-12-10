use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

const TEST_ID: &str = "custom_fields";

/// Tests modifiying custom fields. Custom fields are
/// nested secrets included in a secret's user data.
#[tokio::test]
async fn integration_custom_fields() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;
    let default_folder = account.default_folder().await.unwrap();

    // Create secret
    let (meta, secret) = mock::note("note", TEST_ID);
    let (id, _, _, folder) = account
        .create_secret(meta, secret, Default::default())
        .await?;
    assert_eq!(&default_folder, &folder);

    // Read secret
    let (mut data, _) = account.read_secret(&id, Default::default()).await?;
    assert_eq!(&id, data.id());
    assert_eq!("note", data.meta().label());

    // Create a secret to add as a custom field
    let field_id = SecretId::new_v4();
    let (field_meta, field_secret) =
        mock::password("password_field", generate_passphrase()?.0);

    // Add the custom field
    data.secret_mut().add_field(SecretRow::new(
        field_id.clone(),
        field_meta,
        field_secret,
    ));

    // Update the parent secret to save
    // the custom field
    let (id, meta, secret) = data.into();
    account
        .update_secret(&id, meta, Some(secret), Default::default(), None)
        .await?;

    // Read secret again so we can find and modify the custom field
    let (mut data, _) = account.read_secret(&id, Default::default()).await?;
    let field = data.secret().find_field_by_id(&field_id);
    assert!(field.is_some());

    let field = data.secret().find_field_by_name("password_field");
    assert!(field.is_some());

    let field = data
        .secret()
        .find_field_by_ref(&SecretRef::Name("password_field".to_owned()));
    assert!(field.is_some());

    // Update the field data (need to save the secret to persist)
    let (field_meta, field_secret) =
        mock::password("new_password_field", generate_passphrase()?.0);
    let field = SecretRow::new(field_id, field_meta, field_secret);
    data.secret_mut().update_field(field)?;

    // Old field has gone away
    let field = data.secret().find_field_by_name("password_field");
    assert!(field.is_none());

    // New field can be found
    let field = data.secret().find_field_by_name("new_password_field");
    assert!(field.is_some());

    // Update the secret to persist our changes to the field
    let (id, meta, secret) = data.into();
    account
        .update_secret(&id, meta, Some(secret), Default::default(), None)
        .await?;

    // Read the secret again to prepend another field
    let (mut data, _) = account.read_secret(&id, Default::default()).await?;

    // Insert a link custom field before the password
    let link_field_id = SecretId::new_v4();
    let (link_field_meta, link_field_secret) =
        mock::link("link_field", "https://example.com");
    data.secret_mut().insert_field(
        0,
        SecretRow::new(
            link_field_id.clone(),
            link_field_meta,
            link_field_secret,
        ),
    );
    assert_eq!(2, data.secret().user_data().fields().len());

    // Remove the password custom field
    data.secret_mut().remove_field(&field_id);
    assert_eq!(1, data.secret().user_data().fields().len());

    // Save the changes
    let (id, meta, secret) = data.into();
    account
        .update_secret(&id, meta, Some(secret), Default::default(), None)
        .await?;

    // Check the persisted changes
    let (data, _) = account.read_secret(&id, Default::default()).await?;
    assert_eq!(1, data.secret().user_data().fields().len());
    let field = data.secret().find_field_by_name("new_password_field");
    assert!(field.is_none());
    let field = data.secret().find_field_by_name("link_field");
    assert!(field.is_some());

    teardown(TEST_ID).await;

    Ok(())
}
