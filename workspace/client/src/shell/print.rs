//! Infallible functions for printing private data.

use sos_core::{
    secret::{Secret, SecretMeta},
    vault::Summary,
};
use std::borrow::Cow;

use human_bytes::human_bytes;
use terminal_banner::{Banner, Padding};

pub(super) fn summaries_list(summaries: &[Summary]) {
    for (index, summary) in summaries.iter().enumerate() {
        println!("{}) {} {}", index + 1, summary.name(), summary.id());
    }
}

pub(super) fn secret(secret_meta: &SecretMeta, secret_data: &Secret) {
    let heading =
        format!("[{}] {}", secret_meta.short_name(), secret_meta.label());

    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::Owned(heading));

    let banner = match secret_data {
        Secret::Note(text) => banner.text(Cow::Borrowed(text)),
        Secret::Account {
            account,
            url,
            password,
        } => {
            let mut account = format!("Account:  {}\n", account);
            if let Some(url) = url {
                account.push_str(&format!("Website:  {}\n", url));
            }
            account.push_str(&format!("Password: {}", password));
            banner.text(Cow::Owned(account))
        }
        Secret::List(list) => {
            let mut credentials = String::new();
            for (index, (name, value)) in list.iter().enumerate() {
                credentials.push_str(&format!("{} = {}", name, value));
                if index < list.len() - 1 {
                    credentials.push('\n');
                }
            }
            banner.text(Cow::Owned(credentials))
        }
        Secret::File { name, buffer, mime } => {
            let mut file =
                format!("{} {}\n", name, human_bytes(buffer.len() as f64));
            file.push_str(mime);
            banner.text(Cow::Owned(file))
        }
    };

    let result = banner.render();
    println!("{}", result);
}
