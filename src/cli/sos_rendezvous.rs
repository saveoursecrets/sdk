use crate::{commands::rendezvous, Result};
use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct SosRendezvous {
    /// Hex encoded 32 byte Ed25519 secret key.
    #[clap(short, long, env = "SOS_IDENTITY", hide_env_values = true)]
    identity: Option<String>,

    /// Bind address.
    #[clap(short, long, default_value = "0.0.0.0:3505")]
    bind: String,
}

pub async fn run() -> Result<()> {
    let args = SosRendezvous::parse();
    rendezvous::run(args.identity, args.bind).await?;
    Ok(())
}
