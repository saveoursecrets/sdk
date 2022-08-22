//! Functions for printing private data.

use sos_core::{
    secret::{Secret, SecretMeta},
    vault::Summary,
};

use crate::Result;
use std::borrow::Cow;

use human_bytes::human_bytes;
use secrecy::ExposeSecret;
use terminal_banner::{Banner, Padding};

pub(super) fn summaries_list(summaries: &[Summary]) {
    for (index, summary) in summaries.iter().enumerate() {
        println!("{}) {} {}", index + 1, summary.name(), summary.id());
    }
}

pub(super) fn secret(
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
        Secret::Note(text) => {
            banner.text(Cow::Borrowed(text.expose_secret()))
        }
        Secret::Account {
            account,
            url,
            password,
        } => {
            let mut account = format!("Account:  {}\n", account);
            if let Some(url) = url {
                account.push_str(&format!("Website:  {}\n", url));
            }
            account
                .push_str(&format!("Password: {}", password.expose_secret()));
            banner.text(Cow::Owned(account))
        }
        Secret::List(list) => {
            let mut credentials = String::new();
            for (index, (name, value)) in list.iter().enumerate() {
                credentials.push_str(&format!(
                    "{} = {}",
                    name,
                    value.expose_secret()
                ));
                if index < list.len() - 1 {
                    credentials.push('\n');
                }
            }
            banner.text(Cow::Owned(credentials))
        }
        Secret::File { name, buffer, mime } => {
            let mut file = format!(
                "{} {}\n",
                name,
                human_bytes(buffer.expose_secret().len() as f64)
            );
            file.push_str(mime);
            banner.text(Cow::Owned(file))
        }
        Secret::Pem(pem) => {
            banner.text(Cow::Owned(serde_json::to_string(pem)?))
        }
        Secret::Page {
            title, document, ..
        } => banner
            .text(Cow::Borrowed(title))
            .text(Cow::Borrowed(document.expose_secret())),
        Secret::Pin { number } => {
            banner.text(Cow::Borrowed(number.expose_secret()))
        }
    };

    let result = banner.render();
    println!("{}", result);

    Ok(())
}
