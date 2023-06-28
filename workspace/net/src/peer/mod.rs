//! Peer to peer networking.

use libp2p::{identity, multiaddr::Protocol, Multiaddr, PeerId};
use sos_sdk::signer::ed25519::BoxedEd25519Signer;

mod behaviour;
pub mod error;
pub mod events;
pub mod network;
pub mod protocol;
pub mod rendezvous;
mod transport;

// Re-exports
pub use error::Error;
pub use libp2p;

/// Result type for the peer module.
pub type Result<T> = std::result::Result<T, error::Error>;

/// Convert from a ed25519-dalek v2.0.0-rc2 secret key to the format
/// that can be interpreted by libp2p (ed25519-dalek v1.0.1).
///
/// We can remove this when `snow` and `libp2p` upgrade to the 2.0.0
/// version of ed25519-dalek.
pub fn convert_libp2p_identity(
    peer_signer: &BoxedEd25519Signer,
) -> Result<identity::Keypair> {
    use identity::ed25519;
    let secret_key_bytes = peer_signer.to_bytes();
    let public_key_bytes = peer_signer.verifying_key().to_bytes();

    let mut encoded = Vec::with_capacity(64);
    encoded.extend_from_slice(secret_key_bytes.as_slice());
    encoded.extend_from_slice(public_key_bytes.as_slice());

    Ok(ed25519::Keypair::try_from_bytes(&mut encoded)?.into())
}

/// Extracts a listen connection from a multiaddr.
pub fn listen_from_multiaddr(addr: &Multiaddr) -> Result<Multiaddr> {
    let mut listen = Multiaddr::empty();
    let protocols = addr.iter().take(2);
    for protocol in protocols {
        listen.push(protocol);
    }
    Ok(listen)
}

/// Extracts a peer identifier from a multiaddr.
pub fn peer_id_from_multihash(addr: &Multiaddr) -> Result<PeerId> {
    match addr.iter().last() {
        Some(Protocol::P2p(hash)) => Ok(PeerId::from_multihash(hash.into())
            .map_err(|_| Error::NoMultiAddrPeerId)?),
        _ => Err(Error::NoMultiAddrPeerId),
    }
}
