//! Generate a new keypair.
//use anyhow::{bail, Result};
use std::path::PathBuf;
//use tokio::{fs, io::AsyncWriteExt};

use crate::{Error, Result};
use sos_net::sdk::{
    hex,
    mpc::{encode_keypair, generate_keypair},
    vfs,
};

/// Generate keypair and write to file.
pub async fn run(
    path: PathBuf,
    force: bool,
    public_key: Option<PathBuf>,
) -> Result<()> {
    if vfs::try_exists(&path).await? && !force {
        return Err(Error::FileExistsUseForce(path));
    }

    let keypair = generate_keypair()?;
    let pem = encode_keypair(&keypair);

    vfs::write(&path, pem.as_bytes()).await?;

    println!("{}", hex::encode(keypair.public_key()));

    if let Some(public_key) = public_key {
        let public_key_hex = hex::encode(keypair.public_key());
        vfs::write(public_key, public_key_hex.as_bytes()).await?;
    }

    Ok(())
}
