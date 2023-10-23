use sos_net::{
    peer::{libp2p::identity::Keypair, rendezvous::Server, Result},
    sdk:hex,
};
use std::{net::SocketAddr, str::FromStr};

pub async fn run(identity: Option<String>, bind: String) -> Result<()> {
    let identity = if let Some(identity) = identity {
        let private_key = hex::decode(identity)?;
        Keypair::ed25519_from_bytes(private_key)?
    } else {
        Keypair::generate_ed25519()
    };

    let addr = SocketAddr::from_str(&bind)?;
    let server = Server::new(identity, addr);
    server.run().await?;
    Ok(())
}
