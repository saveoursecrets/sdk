use std::{borrow::Cow, collections::HashMap, path::PathBuf};

use human_bytes::human_bytes;
use terminal_banner::{Banner, Padding};

use secrecy::{ExposeSecret, SecretString};
use sos_core::{
    search::Document,
    secrecy,
    sha2::{Digest, Sha256},
    url::Url,
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRef},
        Summary,
    },
};

use crate::{
    helpers::readline::{
        read_flag, read_line, read_line_allow_empty, read_multiline,
        read_option, read_password,
    },
    Error, Result, TARGET,
};

use super::account::Owner;

/// Try to resolve a secret.
pub async fn resolve_secret(
    user: Owner,
    summary: &Summary,
    secret: &SecretRef,
) -> Result<Option<(SecretId, SecretMeta)>> {
    let owner = user.read().await;
    let index_reader = owner.index().search().read();
    if let Some(Document {
        secret_id, meta, ..
    }) = index_reader.find_by_uuid_or_label(summary.id(), secret)
    {
        Ok(Some((*secret_id, meta.clone())))
    } else {
        Ok(None)
    }
}

/// Print secret information.
pub fn print_secret(
    secret_meta: &SecretMeta,
    secret_data: &Secret,
) -> Result<()> {
    let heading = format!(
        "[{}] {}",
        secret_meta.short_name(),
        secret_meta.last_updated().to_date_time()?
    );

    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::Owned(heading))
        .text(Cow::Borrowed(secret_meta.label()));

    let banner = match secret_data {
        Secret::Note { text, .. } => {
            banner.text(Cow::Borrowed(text.expose_secret()))
        }
        Secret::Account {
            account,
            url,
            password,
            ..
        } => {
            let mut account = format!("Account:  {}\n", account);
            if let Some(url) = url {
                account.push_str(&format!("Website:  {}\n", url));
            }
            account
                .push_str(&format!("Password: {}", password.expose_secret()));
            banner.text(Cow::Owned(account))
        }
        Secret::List { items, .. } => {
            let mut credentials = String::new();
            for (index, (name, value)) in items.iter().enumerate() {
                credentials.push_str(&format!(
                    "{} = {}",
                    name,
                    value.expose_secret()
                ));
                if index < items.len() - 1 {
                    credentials.push('\n');
                }
            }
            banner.text(Cow::Owned(credentials))
        }
        Secret::File {
            name, buffer, mime, ..
        } => {
            let mut file = format!(
                "{} {}\n",
                name,
                human_bytes(buffer.expose_secret().len() as f64)
            );
            file.push_str(mime);
            banner.text(Cow::Owned(file))
        }
        Secret::Pem { certificates, .. } => {
            banner.text(Cow::Owned(serde_json::to_string(certificates)?))
        }
        Secret::Page {
            title, document, ..
        } => banner
            .text(Cow::Borrowed(title))
            .text(Cow::Borrowed(document.expose_secret())),
        Secret::Password { password, .. } => {
            banner.text(Cow::Borrowed(password.expose_secret()))
        }
        Secret::Link { url, .. } => {
            banner.text(Cow::Borrowed(url.expose_secret()))
        }
        Secret::Signer { .. } | Secret::Age { .. } => {
            banner.text(Cow::Borrowed("[REDACTED PRIVATE SIGNING KEY]"))
        }
        Secret::Contact { vcard, .. } => {
            let vcard = vcard.to_string();
            let vcard = vcard.trim().replace('\r', "");
            banner.text(Cow::Owned(vcard))
        }
        Secret::Totp { totp, .. } => {
            let mut details =
                format!("Account name:  {}\n", totp.account_name);
            if let Some(issuer) = &totp.issuer {
                details.push_str(&format!("Issuer:  {}\n", issuer));
            }
            details.push_str(&format!("Digits: {}", totp.digits));
            banner.text(Cow::Owned(details))
        }
        Secret::Card {
            number,
            expiry,
            cvv,
            name,
            atm_pin,
            ..
        } => {
            let mut value = String::new();
            if let Some(name) = name {
                value.push_str(&format!("Name:  {}\n", name.expose_secret()));
            }
            value.push_str(&format!("Number: {}\n", number.expose_secret()));
            value.push_str(&format!("CVV: {}\n", cvv.expose_secret()));
            if let Some(atm_pin) = atm_pin {
                value.push_str(&format!(
                    "PIN:  {}\n",
                    atm_pin.expose_secret()
                ));
            }
            if let Some(expiry) = expiry {
                value
                    .push_str(&format!("Expiry: {}", expiry.to_date_time()?));
            }
            banner.text(Cow::Owned(value))
        }
        Secret::Bank {
            number,
            routing,
            iban,
            swift,
            bic,
            ..
        } => {
            let mut value = String::new();
            value.push_str(&format!("Number: {}\n", number.expose_secret()));
            value
                .push_str(&format!("Routing: {}\n", routing.expose_secret()));
            if let Some(iban) = iban {
                value.push_str(&format!("IBAN:  {}\n", iban.expose_secret()));
            }
            if let Some(swift) = swift {
                value.push_str(&format!(
                    "SWIFT:  {}\n",
                    swift.expose_secret()
                ));
            }
            if let Some(bic) = bic {
                value.push_str(&format!("BIC:  {}\n", bic.expose_secret()));
            }
            banner.text(Cow::Owned(value))
        }
        Secret::Identity {
            id_kind, number, ..
        } => {
            let mut value = String::new();
            value.push_str(&format!("Kind: {}\n", id_kind));
            value.push_str(&format!("Number: {}\n", number.expose_secret()));
            banner.text(Cow::Owned(value))
        }
    };

    let result = banner.render();
    println!("{}", result);

    Ok(())
}

fn get_label(label: Option<String>) -> Result<String> {
    if let Some(label) = label {
        Ok(label)
    } else {
        Ok(read_line(Some("Label: "))?)
    }
}

fn multiline_banner(kind: &str, label: &str) {
    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::Owned(format!("[{}] {}", kind, label)))
        .text(Cow::Borrowed(
            r#"To abort enter Ctrl+C
To save enter Ctrl+D on a newline"#,
        ))
        .render();
    println!("{}", banner);
}

pub fn add_note(
    label: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let label = get_label(label)?;
    multiline_banner("NOTE", &label);

    if let Some(note) = read_multiline(None)? {
        let note =
            secrecy::Secret::new(note.trim_end_matches('\n').to_string());
        let secret = Secret::Note {
            text: note,
            user_data: Default::default(),
        };
        let secret_meta = SecretMeta::new(label, secret.kind());
        Ok(Some((secret_meta, secret)))
    } else {
        Ok(None)
    }
}

pub fn add_page(
    label: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let label = get_label(label)?;
    let title = read_line(Some("Page title: "))?;
    let mime = "text/markdown".to_string();

    multiline_banner("PAGE", &label);

    if let Some(document) = read_multiline(None)? {
        let document =
            secrecy::Secret::new(document.trim_end_matches('\n').to_string());
        let secret = Secret::Page {
            title,
            mime,
            document,
            user_data: Default::default(),
        };
        let secret_meta = SecretMeta::new(label, secret.kind());
        Ok(Some((secret_meta, secret)))
    } else {
        Ok(None)
    }
}

pub fn add_credentials(
    label: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let label = get_label(label)?;

    let mut credentials: HashMap<String, SecretString> = HashMap::new();
    loop {
        let mut name = read_line(Some("Name: "))?;
        while credentials.get(&name).is_some() {
            tracing::error!(
                target: TARGET,
                "name '{}' already exists",
                &name
            );
            name = read_line(Some("Name: "))?;
        }
        let value = read_password(Some("Value: "))?;
        credentials.insert(name, value);
        let prompt = Some("Add more credentials (y/n)? ");
        if !read_flag(prompt)? {
            break;
        }
    }

    if !credentials.is_empty() {
        let secret = Secret::List {
            items: credentials,
            user_data: Default::default(),
        };
        let secret_meta = SecretMeta::new(label, secret.kind());
        Ok(Some((secret_meta, secret)))
    } else {
        Ok(None)
    }
}

pub fn add_account(
    label: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let label = get_label(label)?;

    let account = read_line(Some("Account name: "))?;
    let url = read_option(Some("Website URL: "))?;
    let password = read_password(Some("Password: "))?;

    let url: Option<Url> = if let Some(url) = url {
        Some(url.parse()?)
    } else {
        None
    };

    let secret = Secret::Account {
        account,
        url,
        password,
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label, secret.kind());
    Ok(Some((secret_meta, secret)))
}

pub fn add_file(
    path: String,
    label: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let file = PathBuf::from(&path);

    let name = if let Some(name) = file.file_name() {
        name.to_string_lossy().into_owned()
    } else {
        return Err(Error::FileName(file));
    };

    let mut label = if let Some(label) = label {
        label
    } else {
        read_line_allow_empty(Some("Label: "))?
    };

    if label.is_empty() {
        label = name;
    }

    let secret = read_file_secret(&path)?;
    let secret_meta = SecretMeta::new(label, secret.kind());
    Ok(Some((secret_meta, secret)))
}

pub fn read_file_secret(path: &str) -> Result<Secret> {
    let file = PathBuf::from(path);

    if !file.is_file() {
        return Err(Error::NotFile(file));
    }

    let name = if let Some(name) = file.file_name() {
        name.to_string_lossy().into_owned()
    } else {
        return Err(Error::FileName(file));
    };

    let mime = mime_guess::from_path(&name)
        .first()
        .map(|m| m.to_string())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let buffer = std::fs::read(file)?;
    let size = buffer.len() as u64;
    let checksum = Sha256::digest(&buffer);
    let buffer = secrecy::Secret::new(buffer);
    Ok(Secret::File {
        name,
        mime,
        buffer,
        checksum: checksum.as_slice().try_into()?,
        external: false,
        size,
        user_data: Default::default(),
    })
}
