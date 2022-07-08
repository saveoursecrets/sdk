use clap::{Args, Parser, Subcommand, Command};
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use sos::Result;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
enum Sos {
    #[clap(external_subcommand)]
    Command(Vec<String>),
}

fn run() -> Result<()> {
    let args = Sos::parse();
    match args {
        Sos::Command(args) => {
            println!("Got sos subcommand args {:#?}", args);
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "sos=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = run() {
        tracing::error!("{}", e);
    }

    Ok(())
}
