//! Standard transport for peer to peer networking.
use super::Result;
use futures::future::Either;
use libp2p::{
    core::{
        muxing::StreamMuxerBox,
        transport::{Boxed, OrTransport},
        upgrade,
    },
    identity, noise, tcp, yamux, PeerId, Transport,
};
use libp2p_quic as quic;

pub(crate) fn build(
    local_key: &identity::Keypair,
) -> Result<Boxed<(PeerId, StreamMuxerBox)>> {
    let tcp_transport =
        tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(local_key)?)
            .multiplex(yamux::Config::default())
            .timeout(std::time::Duration::from_secs(20))
            .boxed();
    let quic_transport =
        quic::tokio::Transport::new(quic::Config::new(local_key));
    let transport = OrTransport::new(quic_transport, tcp_transport)
        .map(|either_output, _| match either_output {
            Either::Left((peer_id, muxer)) => {
                (peer_id, StreamMuxerBox::new(muxer))
            }
            Either::Right((peer_id, muxer)) => {
                (peer_id, StreamMuxerBox::new(muxer))
            }
        })
        .boxed();

    Ok(transport)
}
