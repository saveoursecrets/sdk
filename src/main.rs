use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use sos::{Error, Result};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
enum Sos {
    #[clap(external_subcommand)]
    Command(Vec<String>),
}

// NOTE: Currently help output is not what we would like.
// SEE:  https://github.com/clap-rs/clap/issues/3887

fn run() -> Result<()> {
    let args = Sos::parse();
    match args {
        Sos::Command(mut args) => {
            if let Some(_) = args.get(0) {
                let command = args.remove(0);
                match &command[..] {
                    "agent" | "audit" | "check" | "client" | "server" => {
                        let cmd = format!("sos-{}", command);
                        std::process::Command::new(&cmd)
                            .args(args)
                            .status()?;
                        Ok(())
                    }
                    _ => Err(Error::UnknownCommand(command)),
                }
            } else {
                Err(Error::CommandRequired)
            }
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "sos=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = run() {
        tracing::error!("{}", e);
    }

    Ok(())
}
