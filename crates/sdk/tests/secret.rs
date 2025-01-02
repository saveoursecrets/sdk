use anyhow::Result;
use secrecy::{ExposeSecret, SecretBox};
use sos_sdk::{
    prelude::*,
    signer::{ecdsa::SingleParty, Signer},
};
use sos_test_utils::*;
use std::collections::HashMap;
use vcard4::Vcard;

#[test]
fn secret_serde() -> Result<()> {
    let secret = Secret::Note {
        text: String::from("foo").into(),
        user_data: Default::default(),
    };
    let value = serde_json::to_string_pretty(&secret)?;
    let result: Secret = serde_json::from_str(&value)?;
    assert_eq!(secret, result);
    Ok(())
}

#[tokio::test]
async fn secret_encode_user_data() -> Result<()> {
    let mut user_data: UserData = Default::default();
    user_data.set_comment(Some("Comment".to_string()));
    user_data.set_recovery_note(Some("Recovery".to_string()));

    let card = Secret::Card {
        number: "1234567890123456".to_string().into(),
        expiry: Default::default(),
        cvv: "123".to_string().into(),
        name: Some("Miss Jane Doe".to_string().into()),
        atm_pin: None,
        user_data: Default::default(),
    };
    let card_meta = SecretMeta::new("Embedded card".to_string(), card.kind());

    let bank = Secret::Bank {
        number: "12345678".to_string().into(),
        routing: "00-00-00".to_string().into(),
        iban: None,
        swift: None,
        bic: None,
        user_data: Default::default(),
    };
    let bank_meta = SecretMeta::new("Embedded bank".to_string(), bank.kind());

    user_data.push(SecretRow::new(SecretId::new_v4(), card_meta, card));
    user_data.push(SecretRow::new(SecretId::new_v4(), bank_meta, bank));

    let text = r#"BEGIN:VCARD
VERSION:4.0
FN:Mock Bank
END:VCARD"#;

    let vcard: Vcard = text.try_into()?;
    let secret = Secret::Contact {
        vcard: Box::new(vcard),
        user_data,
    };

    let encoded = encode(&secret).await?;
    let decoded: Secret = decode(&encoded).await?;

    assert_eq!(secret, decoded);
    assert_eq!(2, decoded.user_data().len());

    assert!(matches!(decoded.user_data().comment(), Some("Comment")));
    assert!(matches!(
        decoded.user_data().recovery_note(),
        Some("Recovery")
    ));

    Ok(())
}

#[tokio::test]
async fn secret_encode_note() -> Result<()> {
    let user_data: UserData = Default::default();
    let secret = Secret::Note {
        text: String::from("My Note").into(),
        user_data,
    };
    let encoded = encode(&secret).await?;
    let decoded = decode(&encoded).await?;
    assert_eq!(secret, decoded);
    Ok(())
}

#[tokio::test]
async fn secret_encode_file() -> Result<()> {
    let (_, secret, _, _) = mock_secret_file(
        "Mock file",
        "hello.txt",
        "text/plain",
        "hello".as_bytes().to_vec(),
    )
    .await?;
    let encoded = encode(&secret).await?;
    let decoded = decode(&encoded).await?;
    assert_eq!(secret, decoded);
    Ok(())
}

#[tokio::test]
async fn secret_encode_account() -> Result<()> {
    let secret = Secret::Account {
        account: "Email".to_string(),
        url: vec!["https://webmail.example.com".parse().unwrap()],
        password: "mock-password".to_string().into(),
        user_data: Default::default(),
    };
    let encoded = encode(&secret).await?;
    let decoded = decode(&encoded).await?;
    assert_eq!(secret, decoded);

    let secret_no_url = Secret::Account {
        account: "Email".to_string(),
        url: Default::default(),
        password: "mock-password".to_string().into(),
        user_data: Default::default(),
    };
    let encoded = encode(&secret_no_url).await?;
    let decoded = decode(&encoded).await?;
    assert_eq!(secret_no_url, decoded);
    Ok(())
}

#[tokio::test]
async fn secret_encode_list() -> Result<()> {
    let mut credentials = HashMap::new();
    credentials
        .insert("API_KEY".to_owned(), "mock-access-key".to_owned().into());
    credentials.insert(
        "PROVIDER_KEY".to_owned(),
        "mock-provider-key".to_owned().into(),
    );
    let secret = Secret::List {
        items: credentials,
        user_data: Default::default(),
    };

    let encoded = encode(&secret).await?;
    let decoded = decode(&encoded).await?;

    // To assert consistently we must sort and to sort
    // we need to expose the underlying secret string
    // so we get an Ord implementation
    let (secret_a, secret_b) = if let (
        Secret::List { items: a, .. },
        Secret::List { items: b, .. },
    ) = (secret, decoded)
    {
        let mut a = a
            .into_iter()
            .map(|(k, v)| (k, v.expose_secret().to_owned()))
            .collect::<Vec<_>>();
        a.sort();
        let mut b = b
            .into_iter()
            .map(|(k, v)| (k, v.expose_secret().to_owned()))
            .collect::<Vec<_>>();
        b.sort();
        (a, b)
    } else {
        unreachable!()
    };

    assert_eq!(secret_a, secret_b);
    Ok(())
}

#[tokio::test]
async fn secret_encode_pem() -> Result<()> {
    const CERTIFICATE: &str =
        include_str!("../../../tests/fixtures/mock-cert.pem");
    let certificates = pem::parse_many(CERTIFICATE).unwrap();
    let secret = Secret::Pem {
        certificates,
        user_data: Default::default(),
    };
    let encoded = encode(&secret).await?;
    let decoded = decode(&encoded).await?;
    assert_eq!(secret, decoded);
    Ok(())
}

#[tokio::test]
async fn secret_encode_page() -> Result<()> {
    let secret = Secret::Page {
        title: "Welcome".to_string(),
        mime: "text/markdown".to_string(),
        document: "# Mock Page".to_string().into(),
        user_data: Default::default(),
    };
    let encoded = encode(&secret).await?;
    let decoded = decode(&encoded).await?;
    assert_eq!(secret, decoded);
    Ok(())
}

#[tokio::test]
async fn secret_encode_signer() -> Result<()> {
    let signer = SingleParty::new_random();
    let private_key = SecretSigner::SinglePartyEcdsa(SecretBox::new(
        signer.to_bytes().into(),
    ));
    let secret = Secret::Signer {
        private_key,
        user_data: Default::default(),
    };
    let encoded = encode(&secret).await?;
    let decoded = decode(&encoded).await?;
    assert_eq!(secret, decoded);
    Ok(())
}

#[tokio::test]
async fn secret_encode_contact() -> Result<()> {
    const TEXT: &str = include_str!("../../../tests/fixtures/contact.vcf");
    let vcard: Vcard = TEXT.try_into()?;
    let secret = Secret::Contact {
        vcard: Box::new(vcard),
        user_data: Default::default(),
    };
    let encoded = encode(&secret).await?;
    let decoded = decode(&encoded).await?;

    assert_eq!(secret, decoded);
    Ok(())
}

#[tokio::test]
async fn secret_encode_totp() -> Result<()> {
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

    let secret = Secret::Totp {
        totp,
        user_data: Default::default(),
    };
    let encoded = encode(&secret).await?;
    let decoded = decode(&encoded).await?;

    assert_eq!(secret, decoded);
    Ok(())
}

#[tokio::test]
async fn secret_encode_card() -> Result<()> {
    let secret = Secret::Card {
        number: "1234567890123456".to_string().into(),
        expiry: Default::default(),
        cvv: "123".to_string().into(),
        name: Some("Mock name".to_string().into()),
        atm_pin: Some("123456".to_string().into()),
        user_data: Default::default(),
    };
    let encoded = encode(&secret).await?;
    let decoded = decode(&encoded).await?;

    assert_eq!(secret, decoded);
    Ok(())
}

#[tokio::test]
async fn secret_encode_bank() -> Result<()> {
    let secret = Secret::Bank {
        number: "12345678".to_string().into(),
        routing: "01-02-03".to_string().into(),
        iban: Some("GB 23 01020312345678".to_string().into()),
        swift: Some("XCVDFGB".to_string().into()),
        bic: Some("6789".to_string().into()),
        user_data: Default::default(),
    };
    let encoded = encode(&secret).await?;
    let decoded = decode(&encoded).await?;

    assert_eq!(secret, decoded);
    Ok(())
}

#[tokio::test]
async fn secret_encode_link() -> Result<()> {
    let secret = Secret::Link {
        url: "https://example.com".to_string().into(),
        label: Some("Example".to_string().into()),
        title: Some("Open example website".to_string().into()),
        user_data: Default::default(),
    };
    let encoded = encode(&secret).await?;
    let decoded = decode(&encoded).await?;

    assert_eq!(secret, decoded);
    Ok(())
}

#[tokio::test]
async fn secret_encode_password() -> Result<()> {
    let secret = Secret::Password {
        password: "abracadabra".to_string().into(),
        name: Some("Open the magic cave".to_string().into()),
        user_data: Default::default(),
    };
    let encoded = encode(&secret).await?;
    let decoded = decode(&encoded).await?;

    assert_eq!(secret, decoded);
    Ok(())
}

#[tokio::test]
async fn secret_encode_identification() -> Result<()> {
    let secret = Secret::Identity {
        id_kind: IdentityKind::IdCard,
        number: "12345678".to_string().into(),
        issue_place: Some("Mock city".to_string()),
        issue_date: Some(Default::default()),
        expiry_date: Some(Default::default()),
        user_data: Default::default(),
    };
    let encoded = encode(&secret).await?;
    let decoded = decode(&encoded).await?;
    assert_eq!(secret, decoded);

    Ok(())
}

#[tokio::test]
async fn secret_encode_age() -> Result<()> {
    let secret = Secret::Age {
        version: Default::default(),
        key: age::x25519::Identity::generate().to_string(),
        user_data: Default::default(),
    };
    let encoded = encode(&secret).await?;
    let decoded = decode(&encoded).await?;
    assert_eq!(secret, decoded);

    Ok(())
}
