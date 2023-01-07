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
        Secret::List { items, user_data } => {
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
        Secret::Pin { number, .. } => {
            banner.text(Cow::Borrowed(number.expose_secret()))
        }
        Secret::Signer(_) => {
            banner.text(Cow::Borrowed("[REDACTED PRIVATE SIGNING KEY]"))
        }
        Secret::Contact(vcard) => banner.text(Cow::Owned(vcard.to_string())),
        Secret::Totp(totp) => {
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
            value.push_str(&format!("Expiry: {}", expiry.expose_secret()));
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
    };

    let result = banner.render();
    println!("{}", result);

    Ok(())
}
