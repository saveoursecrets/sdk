//! Mock data.

use anyhow::Result;
use secrecy::SecretString;
use sos_net::sdk::{
    age,
    device::TrustedDevice,
    pem,
    sha2::{Digest, Sha256},
    url::Url,
    vault::secret::{FileContent, IdentityKind, Secret, SecretMeta},
};
use std::collections::HashMap;
use std::path::PathBuf;

pub mod files;

const IPHONE: &str = include_str!("../../../../fixtures/devices/iphone.json");

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
    const CERTIFICATE: &str =
        include_str!("../../../../fixtures/mock-cert.pem");
    let certificates = pem::parse_many(CERTIFICATE).unwrap();
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
        key: age::x25519::Identity::generate().to_string(),
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
    use sos_net::sdk::totp::{Algorithm, TOTP};
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
    use sos_net::sdk::vcard4::Vcard;
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
    let file_path = PathBuf::from("../../fixtures/sample.heic");
    let secret: Secret = file_path.clone().try_into()?;
    let meta = SecretMeta::new("image".to_string(), secret.kind());
    Ok((meta, secret, file_path))
}

/// Create an external file secret (text).
pub fn file_text_secret() -> Result<(SecretMeta, Secret, PathBuf)> {
    let file_path = PathBuf::from("../../fixtures/test-file.txt");
    let secret: Secret = file_path.clone().try_into()?;
    let meta = SecretMeta::new("text".to_string(), secret.kind());
    Ok((meta, secret, file_path))
}

/// Create a mock trusted device.
pub fn device() -> Result<TrustedDevice> {
    let device: TrustedDevice = serde_json::from_str(IPHONE)?;
    Ok(device)
}
