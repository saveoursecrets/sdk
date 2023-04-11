//! Peer to peer network proxy.
use std::{
    collections::{hash_map::Entry, HashMap},
    io, iter,
    time::Duration,
};

use either::Either;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;

use super::{Error, Result};

use libp2p::{
    core::Multiaddr,
    identity,
    kad::{record::store::MemoryStore, Kademlia},
    multiaddr::Protocol,
    rendezvous::{self, Namespace, Cookie},
    request_response::{self, ProtocolSupport, RequestId, ResponseChannel},
    swarm::{
        AddressScore, ConnectionHandlerUpgrErr, Swarm, SwarmBuilder,
        SwarmEvent,
    },
    PeerId,
};

use super::{
    behaviour::*,
    events::{ChangeEvent, MessageEvent, NetworkEvent},
    protocol::{
        PeerRpcRequest, PeerRpcResponse, RpcExchangeCodec,
        RpcExchangeProtocol,
    },
    transport,
};

const NAMESPACE: &str = "rendezvous";

/// Location of a rendezvous server.
#[derive(Clone)]
pub struct RendezvousLocation {
    /// Peer id of the rendezvous server.
    pub id: PeerId,
    /// Dial address for the rendezvous server.
    pub addr: Multiaddr,
}

/// Commands are sent by the client to make changes
/// to the network.
#[derive(Debug)]
pub(crate) enum Command {
    StartListening {
        addr: Multiaddr,
        sender: oneshot::Sender<Result<()>>,
    },
    Dial {
        peer_id: PeerId,
        peer_addr: Multiaddr,
        sender: oneshot::Sender<Result<()>>,
    },
    Request {
        peer_id: PeerId,
        request: PeerRpcRequest,
        sender: oneshot::Sender<Result<RequestId>>,
    },
    Response {
        response: PeerRpcResponse,
        channel: ResponseChannel<PeerRpcResponse>,
    },
    Register {
        namespace: Namespace,
        ttl: Option<u64>,
    },
    Unregister {
        namespace: Namespace,
    },
    Discover {
        namespace: Option<Namespace>,
        limit: Option<u64>,
    }
}

/// Creates a new network.
pub async fn new(
    local_key: identity::Keypair,
    shutdown: oneshot::Receiver<()>,
) -> Result<(Client, impl Stream<Item = NetworkEvent> + Unpin, EventLoop)> {
    let peer_id = local_key.public().to_peer_id();

    let location = RendezvousLocation {
        id: "12D3KooWBL5RkTRJXsSXVUEGfXZuKqdXmWXCfw83QjEv1cjvCGJc".parse()?,
        addr: "/ip4/127.0.0.1/tcp/3505".parse()?,
    };

    let mut swarm = SwarmBuilder::with_tokio_executor(
        transport::build(&local_key)?,
        ComposedBehaviour {
            kademlia: Kademlia::new(
                peer_id.clone(),
                MemoryStore::new(peer_id.clone()),
            ),
            request_response: request_response::Behaviour::new(
                RpcExchangeCodec(),
                iter::once((RpcExchangeProtocol(), ProtocolSupport::Full)),
                Default::default(),
            ),
            rendezvous: rendezvous::client::Behaviour::new(local_key.clone()),
        },
        peer_id,
    )
    .build();

    swarm.add_external_address(location.addr.clone(), AddressScore::Infinite);
    swarm.dial(location.addr.clone())?;

    let (command_sender, command_receiver) = mpsc::channel(0);
    let (event_sender, event_receiver) = mpsc::channel(16);

    Ok((
        Client {
            sender: command_sender,
        },
        Box::pin(event_receiver),
        EventLoop::new(
            peer_id,
            location,
            swarm,
            command_receiver,
            event_sender,
            shutdown,
        ),
    ))
}

/// Client routes incoming commands to the network event loop.
#[derive(Clone)]
pub struct Client {
    sender: mpsc::Sender<Command>,
}

impl Client {
    /// Listen for incoming connections on the given address.
    pub async fn start_listening(&mut self, addr: Multiaddr) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::StartListening { addr, sender })
            .await?;
        receiver.await?
    }

    /// Dial the given peer at the given address.
    pub async fn dial(
        &mut self,
        peer_id: PeerId,
        peer_addr: Multiaddr,
    ) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::Dial {
                peer_id,
                peer_addr,
                sender,
            })
            .await?;
        receiver.await?
    }

    /// Send an RPC request to a peer.
    pub async fn rpc_request(
        &mut self,
        peer_id: PeerId,
        request: PeerRpcRequest,
    ) -> Result<RequestId> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::Request {
                peer_id,
                request,
                sender,
            })
            .await?;
        receiver.await?
    }

    /// Send an RPC response message.
    pub async fn rpc_response(
        &mut self,
        response: PeerRpcResponse,
        channel: ResponseChannel<PeerRpcResponse>,
    ) {
        self.sender
            .send(Command::Response { response, channel })
            .await
            .expect("command receiver not to be dropped.");
    }

    /// Register this peer in a namespace.
    pub async fn register(
        &mut self,
        namespace: Namespace,
        ttl: Option<u64>,
    ) {
        self.sender
            .send(Command::Register { namespace, ttl })
            .await
            .expect("command receiver not to be dropped.");
    }

    /// Unregister this peer from a namespace.
    pub async fn unregister(
        &mut self,
        namespace: Namespace,
    ) {
        self.sender
            .send(Command::Unregister { namespace })
            .await
            .expect("command receiver not to be dropped.");
    }

    /// Discover peers in a namespace.
    pub async fn discover(
        &mut self,
        namespace: Option<Namespace>,
        limit: Option<u64>,
    ) {
        self.sender
            .send(Command::Discover { namespace, limit })
            .await
            .expect("command receiver not to be dropped.");
    }
}

/// Runs the network event loop.
pub struct EventLoop {
    peer_id: PeerId,
    location: RendezvousLocation,
    swarm: Swarm<ComposedBehaviour>,
    command_receiver: mpsc::Receiver<Command>,
    event_sender: mpsc::Sender<NetworkEvent>,
    pending_dial: HashMap<PeerId, oneshot::Sender<Result<()>>>,
    //pending_request: HashMap<RequestId, oneshot::Sender<Result<RequestId>>>,
    //pending_start_providing: HashMap<QueryId, oneshot::Sender<()>>,
    //pending_get_providers: HashMap<QueryId, oneshot::Sender<HashSet<PeerId>>>,
    shutdown: oneshot::Receiver<()>,
    cookie: Option<Cookie>,
}

impl EventLoop {
    fn new(
        peer_id: PeerId,
        location: RendezvousLocation,
        swarm: Swarm<ComposedBehaviour>,
        command_receiver: mpsc::Receiver<Command>,
        event_sender: mpsc::Sender<NetworkEvent>,
        shutdown: oneshot::Receiver<()>,
    ) -> Self {
        Self {
            peer_id,
            location,
            swarm,
            command_receiver,
            event_sender,
            pending_dial: Default::default(),
            //pending_start_providing: Default::default(),
            //pending_get_providers: Default::default(),
            //pending_request: HashMap::new(),
            shutdown,
            cookie: None,
        }
    }

    /// Start the event loop running.
    pub async fn run(mut self) {
        let mut interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            futures::select! {
                _ = &mut self.shutdown => {
                    tracing::info!("peer service shutting down");
                    break;
                }
                event = self.swarm.select_next_some() =>
                    self.handle_event(event).await,
                command = self.command_receiver.next() => match command {
                    Some(c) => self.handle_command(c).await,
                    // Command channel closed, thus shutting down
                    // the network event loop.
                    None =>  return,
                },
                _ = async { interval.tick().await }.fuse() => {
                    if self.cookie.is_some() {
                        self.swarm.behaviour_mut().rendezvous.discover(
                            Some(Namespace::new(NAMESPACE.to_string()).unwrap()),
                            self.cookie.clone(),
                            None,
                            self.location.id,
                        )
                    }
                }
                complete => break,
            }
        }
    }
    
    async fn handle_event(
        &mut self,
        event: SwarmEvent<
            ComposedEvent,
            Either<
                Either<ConnectionHandlerUpgrErr<io::Error>, io::Error>,
                void::Void,
            >,
        >,
    ) {

        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                self.event_sender
                    .send(NetworkEvent::Change(ChangeEvent::NewListenAddr {
                        peer_id: self.peer_id.clone(),
                        address,
                    }))
                    .await
                    .expect("event receiver not to be dropped.");
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {

                /*
                */

                // Must close the dial channel to yield
                if endpoint.is_dialer() {
                    if let Some(sender) = self.pending_dial.remove(&peer_id) {
                        let _ = sender.send(Ok(()));
                    }
                }

                self.event_sender
                    .send(NetworkEvent::Change(
                        ChangeEvent::ConnectionEstablished { peer_id },
                    ))
                    .await
                    .expect("event receiver not to be dropped.");
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.event_sender
                    .send(NetworkEvent::Change(
                        ChangeEvent::ConnectionClosed { peer_id },
                    ))
                    .await
                    .expect("event receiver not to be dropped.");
            }
            // Rendezvous register
            SwarmEvent::Behaviour(ComposedEvent::Rendezvous(
                rendezvous::client::Event::Registered {
                    namespace,
                    ttl,
                    rendezvous_node,
                },
            )) => {
                tracing::info!(
                    "registered for namespace '{}' at rendezvous point {} for the next {} seconds",
                    namespace,
                    rendezvous_node,
                    ttl,
                );
            }
            SwarmEvent::Behaviour(ComposedEvent::Rendezvous(
                rendezvous::client::Event::RegisterFailed(error),
            )) => {
                tracing::error!("failed to register {}", error);
            }
            SwarmEvent::Behaviour(ComposedEvent::Rendezvous(
                rendezvous::client::Event::DiscoverFailed { error, .. },
            )) => {
                tracing::error!("failed to discover peers {:#?}", error);
            }
            // Rendezvous discovery
            SwarmEvent::Behaviour(ComposedEvent::Rendezvous(rendezvous::client::Event::Discovered {
                registrations,
                cookie: new_cookie,
                ..
            })) => {
                self.cookie.replace(new_cookie);

                for registration in registrations {
                    for address in registration.record.addresses() {
                        let peer = registration.record.peer_id();
                        tracing::info!("discovered peer {} at {}",
                            peer, address);

                        let p2p_suffix = Protocol::P2p(*peer.as_ref());
                        let address_with_p2p =
                            if !address.ends_with(&Multiaddr::empty().with(p2p_suffix.clone())) {
                                address.clone().with(p2p_suffix)
                            } else {
                                address.clone()
                            };

                        self.swarm.dial(address_with_p2p).unwrap();
                    }
                }
            }

            /*
            SwarmEvent::Behaviour(ComposedEvent::Kademlia(
                KademliaEvent::OutboundQueryProgressed {
                    id,
                    result: QueryResult::StartProviding(_),
                    ..
                },
            )) => {
                let sender: oneshot::Sender<()> = self
                    .pending_start_providing
                    .remove(&id)
                    .expect("completed query to be previously pending.");
                let _ = sender.send(());
            }
            SwarmEvent::Behaviour(ComposedEvent::Kademlia(
                KademliaEvent::OutboundQueryProgressed {
                    id,
                    result:
                        QueryResult::GetProviders(Ok(
                            GetProvidersOk::FoundProviders {
                                providers, ..
                            },
                        )),
                    ..
                },
            )) => {
                if let Some(sender) = self.pending_get_providers.remove(&id) {
                    sender
                        .send(providers)
                        .expect("receiver not to be dropped");

                    // Finish the query. We are only interested in the
                    // first result.
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .query_mut(&id)
                        .unwrap()
                        .finish();
                }
            }
            SwarmEvent::Behaviour(ComposedEvent::Kademlia(
                KademliaEvent::OutboundQueryProgressed {
                    result:
                        QueryResult::GetProviders(Ok(
                            GetProvidersOk::FinishedWithNoAdditionalRecord {
                                ..
                            },
                        )),
                    ..
                },
            )) => {}
            */
            SwarmEvent::Behaviour(ComposedEvent::Kademlia(_)) => {}
            SwarmEvent::Behaviour(ComposedEvent::RequestResponse(
                request_response::Event::Message { message, .. },
            )) => match message {
                request_response::Message::Request {
                    request,
                    channel,
                    ..
                } => {
                    self.event_sender
                        .send(NetworkEvent::Message(
                            MessageEvent::InboundRequest {
                                request: request.0,
                                channel,
                            },
                        ))
                        .await
                        .expect("event receiver not to be dropped.");
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    self.event_sender
                        .send(NetworkEvent::Message(
                            MessageEvent::OutboundResponse {
                                request_id,
                                response: response.0,
                            },
                        ))
                        .await
                        .expect("event receiver not to be dropped.");
                }
            },
            SwarmEvent::Behaviour(ComposedEvent::RequestResponse(
                request_response::Event::OutboundFailure {
                    //error,
                    ..
                },
            )) => {

            }
            SwarmEvent::Behaviour(ComposedEvent::RequestResponse(
                request_response::Event::ResponseSent { .. },
            )) => {}
            SwarmEvent::IncomingConnection { .. } => {}
            SwarmEvent::OutgoingConnectionError {
                peer_id, error, ..
            } => {
                tracing::error!("{}", error);
                if let Some(peer_id) = peer_id {
                    if let Some(sender) = self.pending_dial.remove(&peer_id) {
                        let _ = sender.send(Err(Error::OutgoingConnection(
                            error.to_string(),
                        )));
                    }
                }
            }
            SwarmEvent::IncomingConnectionError { .. } => {}
            SwarmEvent::Dialing(_peer_id) => {}
            e => tracing::error!("{e:?}"),
        }
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::StartListening { addr, sender } => {
                let _ = match self.swarm.listen_on(addr.clone()) {
                    Ok(_) => sender.send(Ok(())),
                    Err(e) => sender.send(Err(Error::ListenFailed(
                        addr.to_string(),
                        e.to_string(),
                    ))),
                };
            }
            Command::Dial {
                peer_id,
                peer_addr,
                sender,
            } => {
                if let Entry::Vacant(e) = self.pending_dial.entry(peer_id) {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, peer_addr.clone());
                    match self.swarm.dial(
                        peer_addr.clone().with(Protocol::P2p(peer_id.into())),
                    ) {
                        Ok(()) => {
                            e.insert(sender);
                        }
                        Err(e) => {
                            tracing::warn!("error on dial {:#?}", e);
                            let _ = sender.send(Err(Error::DialFailed(
                                peer_addr.to_string(),
                            )));
                        }
                    }
                } else {
                    tracing::warn!("already dialing peer {}", peer_id);
                }
            }
            Command::Request {
                peer_id,
                request,
                sender,
            } => {
                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request);
                sender.send(Ok(request_id)).expect("sender to be open");
            }
            Command::Response { response, channel } => {
                self.swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, response)
                    .expect("connection to peer to be still open.");
            }
            Command::Register { namespace, ttl } => {
                self.swarm.behaviour_mut().rendezvous.register(
                    namespace,
                    self.location.id,
                    ttl,
                );
            }
            Command::Unregister { namespace } => {
                self.swarm.behaviour_mut().rendezvous.unregister(
                    namespace,
                    self.location.id,
                );
            }
            Command::Discover { namespace, limit } => {
                self.swarm.behaviour_mut().rendezvous.discover(
                    namespace,
                    self.cookie.clone(),
                    limit,
                    self.location.id,
                );
            }
        }
    }
}
