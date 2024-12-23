use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use human_bytes::human_bytes;
use terminal_banner::{Banner, Padding};

use secrecy::{ExposeSecret, SecretString};
use sos_net::sdk::{
    account::Account,
    hex, secrecy,
    storage::search::Document,
    url::Url,
    vault::{
        secret::{FileContent, Secret, SecretId, SecretMeta, SecretRef},
        Summary,
    },
    vfs,
};

use crate::{
    helpers::{
        messages::{fail, success},
        readline::{
            read_flag, read_line, read_line_allow_empty, read_multiline,
            read_option, read_password,
        },
    },
    Error, Result,
};

use super::{account::Owner, set_clipboard_text};

/// Resolved secret data.
pub(crate) struct ResolvedSecret {
    pub user: Owner,
    pub secret_id: SecretId,
    pub meta: SecretMeta,
    pub verified: bool,
    pub summary: Summary,
}

/// Try to resolve a secret.
pub async fn resolve_secret(
    user: Owner,
    summary: &Summary,
    secret: &SecretRef,
) -> Result<Option<(SecretId, SecretMeta)>> {
    let owner = user.read().await;
    let owner = owner.selected_account().ok_or(Error::NoSelectedAccount)?;
    let search = owner.index().await?;
    let index_reader = search.read().await;
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
        secret_meta.kind().short_name(),
        secret_meta.last_updated().to_date_time()?
    );

    let banner = Banner::new()
        .padding(Padding::one())
        .text(heading.into())
        .newline()
        .text(secret_meta.label().into());

    let mut banner = match secret_data {
        Secret::Note { text, .. } => banner.text(text.expose_secret().into()),
        Secret::Account {
            account,
            url,
            password,
            ..
        } => {
            let mut account = format!("Account:  {}\n", account);
            for u in url {
                account.push_str(&format!("Website:  {}\n", u));
            }
            account
                .push_str(&format!("Password: {}", password.expose_secret()));
            banner.text(account.into())
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
            banner.text(credentials.into())
        }
        Secret::File { content, .. } => {
            let mut file = format!(
                "{} {}\n",
                content.name(),
                human_bytes(content.size() as f64)
            );
            file.push_str(content.mime());
            banner.text(file.into())
        }
        Secret::Pem { certificates, .. } => {
            banner.text(serde_json::to_string(certificates)?.into())
        }
        Secret::Page {
            title, document, ..
        } => banner
            .text(title.into())
            .text(document.expose_secret().into()),
        Secret::Password { password, .. } => {
            banner.text(password.expose_secret().into())
        }
        Secret::Link { url, .. } => banner.text(url.expose_secret().into()),
        Secret::Signer { .. } | Secret::Age { .. } => {
            banner.text("[REDACTED PRIVATE SIGNING KEY]".into())
        }
        Secret::Contact { vcard, .. } => {
            let vcard = vcard.to_string();
            let vcard = vcard.trim().replace('\r', "");
            banner.text(vcard.into())
        }
        Secret::Totp { totp, .. } => {
            let mut details =
                format!("Account name:  {}\n", totp.account_name);
            if let Some(issuer) = &totp.issuer {
                details.push_str(&format!("Issuer:  {}\n", issuer));
            }
            details.push_str(&format!("Digits: {}", totp.digits));
            banner.text(details.into())
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
            banner.text(value.into())
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
            banner.text(value.into())
        }
        Secret::Identity {
            id_kind, number, ..
        } => {
            let mut value = String::new();
            value.push_str(&format!("Kind: {}\n", id_kind));
            value.push_str(&format!("Number: {}\n", number.expose_secret()));
            banner.text(value.into())
        }
    };

    if let Some(comment) = secret_data.user_data().comment() {
        banner = banner.divider();
        banner = banner.text(comment.trim().into());
    }

    let result = banner.render();
    println!("{}", result);

    Ok(())
}

pub(crate) fn read_name(name: Option<String>) -> Result<String> {
    if let Some(name) = name {
        Ok(name)
    } else {
        Ok(read_line(Some("Name: "))?)
    }
}

pub fn normalize_tags(mut tags: Option<String>) -> Option<HashSet<String>> {
    if let Some(tags) = tags.take() {
        let tags: HashMap<_, _> = tags
            .split(',')
            .map(|s| (s.trim().to_lowercase(), s.trim()))
            .collect();
        let mut set = HashSet::new();
        for (_, v) in tags {
            set.insert(v.to_string());
        }
        Some(set)
    } else {
        None
    }
}

fn multiline_banner(kind: &str, label: &str) {
    let banner = Banner::new()
        .padding(Padding::one())
        .text(format!("[{}] {}", kind, label).into())
        .newline()
        .text(
            r#"To abort enter Ctrl+C
To save enter Ctrl+D on a newline"#
                .into(),
        )
        .render();
    println!("{}", banner);
}

pub fn add_note(
    name: Option<String>,
    tags: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let name = read_name(name)?;
    multiline_banner("NOTE", &name);

    let text = read_multiline(None)?;
    if let Some(note) = text {
        let text = note.trim_end_matches('\n').to_string();
        let secret: Secret = text.into();
        let mut secret_meta = SecretMeta::new(name, secret.kind());
        if let Some(tags) = normalize_tags(tags) {
            secret_meta.set_tags(tags);
        }
        Ok(Some((secret_meta, secret)))
    } else {
        Ok(None)
    }
}

pub fn add_link(
    name: Option<String>,
    tags: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let name = read_name(name)?;
    let link = read_line(Some("URL: "))?;
    let url: Url = link.parse().map_err(|_| Error::InvalidUrl)?;
    let secret: Secret = url.into();
    let mut secret_meta = SecretMeta::new(name, secret.kind());
    if let Some(tags) = normalize_tags(tags) {
        secret_meta.set_tags(tags);
    }
    Ok(Some((secret_meta, secret)))
}

pub fn add_password(
    name: Option<String>,
    tags: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let name = read_name(name)?;

    let password = read_password(None)?;
    let secret: Secret = password.into();
    let mut secret_meta = SecretMeta::new(name, secret.kind());
    if let Some(tags) = normalize_tags(tags) {
        secret_meta.set_tags(tags);
    }
    Ok(Some((secret_meta, secret)))
}

/*
pub fn add_page(
    label: Option<String>,
    tags: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let label = read_name(label)?;
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
        let mut secret_meta = SecretMeta::new(label, secret.kind());
        if let Some(tags) = normalize_tags(tags) {
            secret_meta.set_tags(tags);
        }
        Ok(Some((secret_meta, secret)))
    } else {
        Ok(None)
    }
}
*/

pub fn add_list(
    name: Option<String>,
    tags: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let name = read_name(name)?;

    let mut credentials: HashMap<String, SecretString> = HashMap::new();
    loop {
        let mut name = read_line(Some("Key: "))?;
        while credentials.get(&name).is_some() {
            fail(format!("name '{}' already exists", &name));
            name = read_line(Some("Key: "))?;
        }
        let value = read_password(Some("Value: "))?;
        credentials.insert(name, value);
        let prompt = Some("Add more credentials (y/n)? ");
        if !read_flag(prompt)? {
            break;
        }
    }

    if !credentials.is_empty() {
        let secret: Secret = credentials.into();
        let mut secret_meta = SecretMeta::new(name, secret.kind());
        if let Some(tags) = normalize_tags(tags) {
            secret_meta.set_tags(tags);
        }
        Ok(Some((secret_meta, secret)))
    } else {
        Ok(None)
    }
}

pub fn add_login(
    name: Option<String>,
    tags: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let name = read_name(name)?;

    let account = read_line(Some("Username: "))?;
    let url = read_option(Some("Website: "))?;
    let password = read_password(Some("Password: "))?;

    let url: Vec<Url> = if let Some(url) = url {
        vec![url.parse().map_err(|_| Error::InvalidUrl)?]
    } else {
        vec![]
    };

    let secret = Secret::Account {
        account,
        url,
        password,
        user_data: Default::default(),
    };
    let mut secret_meta = SecretMeta::new(name, secret.kind());
    if let Some(tags) = normalize_tags(tags) {
        secret_meta.set_tags(tags);
    }
    Ok(Some((secret_meta, secret)))
}

pub async fn add_file(
    path: String,
    name: Option<String>,
    tags: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let file = PathBuf::from(&path);

    let file_name = if let Some(name) = file.file_name() {
        name.to_string_lossy().into_owned()
    } else {
        return Err(Error::FileName(file));
    };

    let mut name = if let Some(name) = name {
        name
    } else {
        read_line_allow_empty(Some("Name: "))?
    };

    if name.is_empty() {
        name = file_name;
    }

    let secret = read_file_secret(&path).await?;
    let mut secret_meta = SecretMeta::new(name, secret.kind());
    if let Some(tags) = normalize_tags(tags) {
        secret_meta.set_tags(tags);
    }
    Ok(Some((secret_meta, secret)))
}

pub async fn read_file_secret(path: &str) -> Result<Secret> {
    let file = PathBuf::from(path);

    if !vfs::metadata(&file).await?.is_file() {
        return Err(Error::NotFile(file));
    }

    Ok(file.try_into()?)
}

pub(crate) async fn download_file_secret(
    resolved: &ResolvedSecret,
    file: PathBuf,
    secret: Secret,
) -> Result<()> {
    let owner = resolved.user.read().await;
    let owner = owner.selected_account().ok_or(Error::NoSelectedAccount)?;
    if let Secret::File { content, .. } = secret {
        match content {
            FileContent::External { checksum, .. } => {
                let file_name = hex::encode(checksum);
                let buffer = owner
                    .download_file(
                        resolved.summary.id(),
                        &resolved.secret_id,
                        &file_name,
                    )
                    .await?;
                vfs::write(file, buffer).await?;
            }
            FileContent::Embedded { buffer, .. } => {
                vfs::write(file, buffer.expose_secret()).await?;
            }
        }
        success("Download complete");
        Ok(())
    } else {
        Err(Error::NotFileContent)
    }
}

pub(crate) fn copy_secret_text(secret: &Secret) -> Result<bool> {
    if let Some(text) = secret.display_unsafe() {
        set_clipboard_text(&text)
    } else {
        Ok(false)
    }
}
