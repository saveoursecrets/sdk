//! Infallible functions for printing private data.

use sos_core::{
    secret::{Secret, SecretMeta},
    vault::Summary,
};

use human_bytes::human_bytes;

pub(super) fn summaries_list(summaries: &[Summary]) {
    for (index, summary) in summaries.iter().enumerate() {
        println!("{}) {} {}", index + 1, summary.name(), summary.id());
    }
}

pub(super) fn summary(summary: &Summary) {
    println!(
        "Version {} using {} at #{}",
        summary.version(),
        summary.algorithm(),
        summary.change_seq()
    );
    println!("{} {}", summary.name(), summary.id());
}

pub(super) fn secret(secret_meta: &SecretMeta, secret_data: &Secret) {
    println!("[{}] {}", secret_meta.short_name(), secret_meta.label());
    match secret_data {
        Secret::Note(text) => {
            println!("{}", text);
        }
        Secret::Account {
            account,
            url,
            password,
        } => {
            println!("Account: {}", account);
            if let Some(url) = url {
                println!("Website: {}", url);
            }
            println!("Password: {}", password);
        }
        Secret::List(list) => {
            for (name, value) in list {
                println!("{} = {}", name, value);
            }
        }
        Secret::File { name, buffer, mime } => {
            println!(
                "{} {} {}",
                name,
                mime,
                human_bytes(buffer.len() as f64)
            );
        }
    }
}
