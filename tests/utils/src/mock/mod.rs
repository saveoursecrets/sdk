//! Mock data.

use age as age_encryption;
use anyhow::Result;
use argon2::password_hash::SaltString;
use async_sqlite::Client;
use pem as pem_encoding;
use secrecy::SecretBox;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use sos_backend::FolderEventLog;
use sos_core::{
    commit::CommitHash,
    crypto::{KeyDerivation, PrivateKey},
    device::TrustedDevice,
    encode,
    events::{EventLog, EventLogType, EventRecord, WriteEvent},
    AccountId, SecretId, VaultEntry,
};
use sos_database::{
    entity::{
        AccountEntity, AccountRow, EventEntity, EventRecordRow, FolderEntity,
        FolderRow,
    },
    open_file,
};
use sos_password::diceware::generate_passphrase;
use sos_vault::{
    secret::{FileContent, IdentityKind, Secret, SecretMeta},
    BuilderCredentials, EncryptedEntry, Vault, VaultBuilder,
};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;
use url::Url;
use uuid::Uuid;

pub mod files;

const IPHONE: &str = include_str!("../../../fixtures/devices/iphone.json");

/// Generate a mock encyption key.
pub fn encryption_key() -> Result<(PrivateKey, SaltString, SecretString)> {
    let salt = KeyDerivation::generate_salt();
    let (passphrase, _) = generate_passphrase()?;
    let kdf: KeyDerivation = Default::default();
    let deriver = kdf.deriver();
    let derived_key = deriver.derive(&passphrase, &salt, None)?;
    Ok((PrivateKey::Symmetric(derived_key), salt, passphrase))
}

/// Generate a mock secret note.
pub async fn secret_note(
    label: &str,
    text: &str,
) -> Result<(SecretMeta, Secret, Vec<u8>, Vec<u8>)> {
    let secret_value = Secret::Note {
        text: text.to_string().into(),
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    let meta_bytes = encode(&secret_meta).await?;
    let secret_bytes = encode(&secret_value).await?;
    Ok((secret_meta, secret_value, meta_bytes, secret_bytes))
}

/// Generate a mock secret file.
pub async fn secret_file(
    label: &str,
    name: &str,
    mime: &str,
    buffer: Vec<u8>,
) -> Result<(SecretMeta, Secret, Vec<u8>, Vec<u8>)> {
    let checksum = Sha256::digest(&buffer);
    let secret_value = Secret::File {
        content: FileContent::Embedded {
            name: name.to_string(),
            mime: mime.to_string(),
            checksum: checksum.into(),
            buffer: SecretBox::new(buffer.into()),
        },
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    let meta_bytes = encode(&secret_meta).await?;
    let secret_bytes = encode(&secret_value).await?;
    Ok((secret_meta, secret_value, meta_bytes, secret_bytes))
}

/// Generate a mock secret note and add it to a vault.
pub async fn vault_note(
    vault: &mut Vault,
    encryption_key: &PrivateKey,
    label: &str,
    note: &str,
) -> Result<(Uuid, CommitHash, SecretMeta, Secret, WriteEvent)> {
    let (secret_meta, secret_value, meta_bytes, secret_bytes) =
        secret_note(label, note).await?;

    let meta_aead = vault.encrypt(encryption_key, &meta_bytes).await?;
    let secret_aead = vault.encrypt(encryption_key, &secret_bytes).await?;

    let (commit, _) = Vault::commit_hash(&meta_aead, &secret_aead).await?;
    let event = vault
        .create_secret(commit, VaultEntry(meta_aead, secret_aead))
        .await?;
    let secret_id = match &event {
        WriteEvent::CreateSecret(secret_id, _) => *secret_id,
        _ => unreachable!(),
    };

    Ok((secret_id, commit, secret_meta, secret_value, event))
}

/// Generate a mock secret note and update a vault entry.
pub async fn vault_note_update(
    vault: &mut Vault,
    encryption_key: &PrivateKey,
    id: &SecretId,
    label: &str,
    note: &str,
) -> Result<(CommitHash, SecretMeta, Secret, Option<WriteEvent>)> {
    let (secret_meta, secret_value, meta_bytes, secret_bytes) =
        secret_note(label, note).await?;

    let meta_aead = vault.encrypt(encryption_key, &meta_bytes).await?;
    let secret_aead = vault.encrypt(encryption_key, &secret_bytes).await?;

    let (commit, _) = Vault::commit_hash(&meta_aead, &secret_aead).await?;
    let event = vault
        .update_secret(id, commit, VaultEntry(meta_aead, secret_aead))
        .await?;
    Ok((commit, secret_meta, secret_value, event))
}

/// Create a mock vault in a temp file.
pub async fn vault_file() -> Result<(NamedTempFile, Vault, SecretString)> {
    let mut temp = NamedTempFile::new()?;
    let (vault, password) = vault_memory().await?;
    let buffer = encode(&vault).await?;
    temp.write_all(&buffer)?;
    Ok((temp, vault, password))
}

/// Create a mock vault in memory.
pub async fn vault_memory() -> Result<(Vault, SecretString)> {
    let (password, _) = generate_passphrase()?;
    let vault = VaultBuilder::new()
        .build(BuilderCredentials::Password(password.clone(), None))
        .await?;
    Ok((vault, password))
}

/// Create a mock event log in a temp file.
pub async fn event_log_file(
) -> Result<(NamedTempFile, FolderEventLog, PrivateKey)> {
    let (encryption_key, _, _) = encryption_key()?;
    let (_, mut vault, _) = vault_file().await?;

    let temp = NamedTempFile::new()?;
    let mut event_log = FolderEventLog::new_fs_folder(temp.path()).await?;

    // Create the vault
    let event = vault.into_event().await?;
    event_log.apply(&[event]).await?;

    // Create a secret
    let (secret_id, _, _, _, event) = vault_note(
        &mut vault,
        &encryption_key,
        "event log Note",
        "This a event log note secret.",
    )
    .await?;
    event_log.apply(&[event]).await?;

    // Update the secret
    let (_, _, _, event) = vault_note_update(
        &mut vault,
        &encryption_key,
        &secret_id,
        "event log Note Edited",
        "This a event log note secret that was edited.",
    )
    .await?;
    if let Some(event) = event {
        event_log.apply(&[event]).await?;
    }

    Ok((temp, event_log, encryption_key))
}

/// Create a database file and run migrations.
pub async fn file_database() -> Result<(NamedTempFile, Client)> {
    let temp = NamedTempFile::new()?;
    let mut client = open_file(temp.path()).await?;
    sos_database::migrations::migrate_client(&mut client).await?;
    Ok((temp, client))
}

/// Create an in-memory database and run migrations.
pub async fn memory_database() -> Result<Client> {
    Ok(sos_database::open_memory().await?)
}

/// Create a database account.
pub async fn insert_database_account(
    client: &mut Client,
) -> Result<(AccountId, i64)> {
    let account_identifier = AccountId::random();
    let account_row = AccountRow::new_insert(
        &account_identifier,
        "mock-account".to_owned(),
    )?;
    Ok(client
        .conn_mut(move |conn| {
            let account = AccountEntity::new(&conn);
            let account_id = account.insert(&account_row)?;
            Ok((account_identifier, account_id))
        })
        .await?)
}

/// Create a database account and folder for a vault.
pub async fn insert_database_vault(
    client: &mut Client,
    vault: &Vault,
    insert_folder_events: bool,
) -> Result<(AccountId, i64, i64)> {
    let (account_identifier, account_id) =
        insert_database_account(client).await?;

    let folder_row = FolderRow::new_insert(vault).await?;
    let is_identity = vault.summary().flags().is_identity();

    let event = WriteEvent::CreateVault(encode(vault).await?);
    let record = EventRecord::encode_event(&event).await?;
    let event_rows = vec![EventRecordRow::new(&record)?];

    Ok(client
        .conn_mut_and_then(move |conn| {
            let folder = FolderEntity::new(&conn);
            let folder_id = folder.insert_folder(account_id, &folder_row)?;

            // If the vault is an identity vault create
            // the join entry
            if is_identity {
                let account = AccountEntity::new(&conn);
                account.insert_login_folder(account_id, folder_id)?;
            }

            if insert_folder_events {
                let events = EventEntity::new(&conn);
                events.insert_events(
                    EventLogType::Identity,
                    folder_id,
                    event_rows.as_slice(),
                )?;
            }

            Ok::<_, anyhow::Error>((
                account_identifier,
                account_id,
                folder_id,
            ))
        })
        .await?)
}

/// Create a login secret.
pub fn login(
    label: &str,
    account: &str,
    password: SecretString,
) -> (SecretMeta, Secret) {
    let secret_value = Secret::Account {
        account: account.to_owned(),
        password,
        url: Default::default(),
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

/// Create a login secret with website urls.
pub fn login_websites(
    label: &str,
    account: &str,
    password: SecretString,
    url: Vec<Url>,
) -> (SecretMeta, Secret) {
    let secret_value = Secret::Account {
        account: account.to_owned(),
        password,
        url,
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

/// Create a note secret.
pub fn note(label: &str, text: &str) -> (SecretMeta, Secret) {
    let secret_value = Secret::Note {
        text: text.to_string().into(),
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

/// Create a debit/credit card secret.
pub fn card(label: &str, number: &str, cvv: &str) -> (SecretMeta, Secret) {
    let secret_value = Secret::Card {
        number: number.to_string().into(),
        cvv: cvv.to_string().into(),
        expiry: None,
        name: None,
        atm_pin: None,
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

/// Create a bank account secret.
pub fn bank(
    label: &str,
    number: &str,
    routing: &str,
) -> (SecretMeta, Secret) {
    let secret_value = Secret::Bank {
        number: number.to_string().into(),
        routing: routing.to_string().into(),
        iban: None,
        swift: None,
        bic: None,
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

/// Create a list secret.
pub fn list(label: &str, items: HashMap<&str, &str>) -> (SecretMeta, Secret) {
    let secret_value = Secret::List {
        items: items
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned().into()))
            .collect(),
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

/// Create a certificate secret.
pub fn pem(label: &str) -> (SecretMeta, Secret) {
    const CERTIFICATE: &str = include_str!("../../../fixtures/mock-cert.pem");
    let certificates = pem_encoding::parse_many(CERTIFICATE).unwrap();
    let secret_value = Secret::Pem {
        certificates,
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

/// Create an internal file secret.
pub fn internal_file(
    label: &str,
    name: &str,
    mime: &str,
    buffer: impl AsRef<[u8]>,
) -> (SecretMeta, Secret) {
    let checksum = Sha256::digest(&buffer);
    let secret_value = Secret::File {
        content: FileContent::Embedded {
            name: name.to_string(),
            mime: mime.to_string(),
            checksum: checksum.try_into().unwrap(),
            buffer: secrecy::SecretBox::new(
                buffer.as_ref().to_owned().into(),
            ),
        },
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

/// Create a link secret.
pub fn link(label: &str, url: &str) -> (SecretMeta, Secret) {
    let secret_value = Secret::Link {
        url: url.to_string().into(),
        label: None,
        title: None,
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

/// Create a password secret.
pub fn password(label: &str, password: SecretString) -> (SecretMeta, Secret) {
    let secret_value = Secret::Password {
        password,
        name: None,
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

/// Create an AGE secret.
pub fn age(label: &str) -> (SecretMeta, Secret) {
    let secret_value = Secret::Age {
        version: Default::default(),
        key: age_encryption::x25519::Identity::generate().to_string(),
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

/// Create an identity secret.
pub fn identity(
    label: &str,
    id_kind: IdentityKind,
    number: &str,
) -> (SecretMeta, Secret) {
    let secret_value = Secret::Identity {
        id_kind,
        number: number.to_string().into(),
        issue_place: None,
        issue_date: None,
        expiry_date: None,
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

/// Create a TOTP secret.
pub fn totp(label: &str) -> (SecretMeta, Secret) {
    use totp_rs::{Algorithm, TOTP};
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        "MockSecretWhichMustBeAtLeast80Bytes".as_bytes().to_vec(),
        Some("MockIssuer".to_string()),
        "mock@example.com".to_string(),
    )
    .unwrap();

    let secret_value = Secret::Totp {
        totp,
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

/// Create a contact secret.
pub fn contact(label: &str, full_name: &str) -> (SecretMeta, Secret) {
    use vcard4::Vcard;
    let text = format!(
        r#"BEGIN:VCARD
VERSION:4.0
FN:{}
END:VCARD"#,
        full_name
    );
    let vcard: Vcard = text.as_str().try_into().unwrap();
    let secret_value = Secret::Contact {
        vcard: Box::new(vcard),
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

/// Create a page secret.
pub fn page(
    label: &str,
    title: &str,
    document: &str,
) -> (SecretMeta, Secret) {
    let secret_value = Secret::Page {
        title: title.to_string(),
        mime: "text/markdown".to_string(),
        document: document.to_string().into(),
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

/// Create an external file secret (image).
pub fn file_image_secret() -> Result<(SecretMeta, Secret, PathBuf)> {
    let file_path = PathBuf::from("../fixtures/sample.heic");
    let secret: Secret = file_path.clone().try_into()?;
    let meta = SecretMeta::new("image".to_string(), secret.kind());
    Ok((meta, secret, file_path))
}

/// Create an external file secret (text).
pub fn file_text_secret() -> Result<(SecretMeta, Secret, PathBuf)> {
    let file_path = PathBuf::from("../fixtures/test-file.txt");
    let secret: Secret = file_path.clone().try_into()?;
    let meta = SecretMeta::new("text".to_string(), secret.kind());
    Ok((meta, secret, file_path))
}

/// Create a mock trusted device.
pub fn device() -> Result<TrustedDevice> {
    let device: TrustedDevice = serde_json::from_str(IPHONE)?;
    Ok(device)
}
