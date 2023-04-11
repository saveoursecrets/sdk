//! Rendezvous service for peer discovery.
use futures::StreamExt;
use libp2p::{
    identify, identity, rendezvous,
    swarm::{keep_alive, SwarmBuilder, SwarmEvent},
    PeerId,
};
use std::net::SocketAddr;

use super::{
    Result,
    {
        behaviour::{RendezvousBehaviour, RendezvousBehaviourEvent},
        transport,
    },
};

/// Rendezvous service.
pub struct Server {
    name: String,
    version: String,
    addr: SocketAddr,
    identity: identity::Keypair,
}

impl Server {
    /// Create a new rendezvous server.
    pub fn new(
        name: String,
        version: String,
        identity: identity::Keypair,
        addr: SocketAddr,
    ) -> Self {
        Self {
            name,
            version,
            identity,
            addr,
        }
    }

    /// Start the rendezvous service running.
    pub async fn run(&self) -> Result<()> {
        let mut swarm = SwarmBuilder::with_tokio_executor(
            transport::build(&self.identity)?,
            RendezvousBehaviour {
                identify: identify::Behaviour::new(identify::Config::new(
                    format!("{}/{}", self.name, self.version),
                    self.identity.public(),
                )),
                rendezvous: rendezvous::server::Behaviour::new(
                    rendezvous::server::Config::default(),
                ),
                keep_alive: keep_alive::Behaviour,
            },
            PeerId::from(self.identity.public()),
        )
        .build();

        tracing::info!("{}", swarm.local_peer_id());

        let addr =
            format!("/ip4/{}/tcp/{}", self.addr.ip(), self.addr.port());
        let _ = swarm.listen_on(addr.parse().unwrap());

        while let Some(event) = swarm.next().await {
            match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    tracing::info!("listening {}", address);
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    tracing::info!("connected {}", peer_id);
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    tracing::info!("disconnected {}", peer_id);
                }
                SwarmEvent::Behaviour(
                    RendezvousBehaviourEvent::Rendezvous(
                        rendezvous::server::Event::PeerRegistered {
                            peer,
                            registration,
                        },
                    ),
                ) => {
                    tracing::info!(
                        "peer {} registered for namespace '{}'",
                        peer,
                        registration.namespace
                    );
                }
                SwarmEvent::Behaviour(
                    RendezvousBehaviourEvent::Rendezvous(
                        rendezvous::server::Event::DiscoverServed {
                            enquirer,
                            registrations,
                        },
                    ),
                ) => {
                    tracing::info!(
                        "served peer {} with {} registrations",
                        enquirer,
                        registrations.len()
                    );
                }
                other => {
                    tracing::debug!("unhandled {:?}", other);
                }
            }
        }
        Ok(())
    }
}
