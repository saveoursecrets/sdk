//! Peer to peer network event loop.
use std::{
    collections::{hash_map::Entry, HashMap},
    io, iter,
    time::Duration,
};

use either::Either;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;

use sos_core::rpc::{RequestMessage, ResponseMessage};

use super::{Error, Result};

use libp2p::{
    core::Multiaddr,
    identify, identity,
    kad::{record::store::MemoryStore, Kademlia},
    multiaddr::Protocol,
    rendezvous::{
        self, client::RegisterError, Cookie, Namespace, Registration,
    },
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
    protocol::{RpcExchangeCodec, RpcExchangeProtocol},
    transport,
};

/// Location of a rendezvous server.
#[derive(Debug, Clone)]
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
    ConnectedPeers {
        sender: oneshot::Sender<Result<Vec<PeerId>>>,
    },
    Request {
        peer_id: PeerId,
        request: RequestMessage<'static>,
        sender: oneshot::Sender<
            Result<(RequestId, PeerId, ResponseMessage<'static>)>,
        >,
    },
    Response {
        response: ResponseMessage<'static>,
        channel: ResponseChannel<ResponseMessage<'static>>,
    },
    Register {
        namespace: Namespace,
        ttl: Option<u64>,
        sender: oneshot::Sender<Result<()>>,
    },
    Unregister {
        namespace: Namespace,
        sender: oneshot::Sender<Result<()>>,
    },
    Discover {
        namespace: Option<Namespace>,
        limit: Option<u64>,
        sender: oneshot::Sender<Result<Vec<Registration>>>,
    },
}

/// Creates a new network.
pub async fn new(
    local_key: identity::Keypair,
    location: RendezvousLocation,
    shutdown: oneshot::Receiver<()>,
) -> Result<(Client, impl Stream<Item = NetworkEvent> + Unpin, EventLoop)> {
    let peer_id = local_key.public().to_peer_id();

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
            identify: identify::Behaviour::new(identify::Config::new(
                "rendezvous/1.0.0".to_string(),
                //format!("{}/{}", self.name, self.version),
                local_key.public(),
            )),
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

impl Default for Client {
    fn default() -> Self {
        let (sender, _) = mpsc::channel(0);
        Self { sender }
    }
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

    /// Get the list of connected peers from the swarm.
    pub async fn connected_peers(&mut self) -> Result<Vec<PeerId>> {
        let (sender, receiver) = oneshot::channel();
        self.sender.send(Command::ConnectedPeers { sender }).await?;
        receiver.await?
    }

    /// Send an RPC request to a peer.
    pub async fn rpc_request(
        &mut self,
        peer_id: PeerId,
        request: RequestMessage<'static>,
    ) -> Result<(RequestId, PeerId, ResponseMessage<'static>)> {
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
        response: ResponseMessage<'static>,
        channel: ResponseChannel<ResponseMessage<'static>>,
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
    ) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::Register {
                namespace,
                ttl,
                sender,
            })
            .await
            .expect("command receiver not to be dropped.");
        receiver.await?
    }

    /// Unregister this peer from a namespace.
    pub async fn unregister(&mut self, namespace: Namespace) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::Unregister { namespace, sender })
            .await
            .expect("command receiver not to be dropped.");
        receiver.await?
    }

    /// Discover peers in a namespace.
    pub async fn discover(
        &mut self,
        namespace: Option<Namespace>,
        limit: Option<u64>,
    ) -> Result<Vec<Registration>> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::Discover {
                namespace,
                limit,
                sender,
            })
            .await
            .expect("command receiver not to be dropped.");
        receiver.await?
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
    pending_request: HashMap<
        RequestId,
        oneshot::Sender<
            Result<(RequestId, PeerId, ResponseMessage<'static>)>,
        >,
    >,
    pending_register: HashMap<Namespace, oneshot::Sender<Result<()>>>,
    pending_discover: HashMap<
        Option<Namespace>,
        oneshot::Sender<Result<Vec<Registration>>>,
    >,
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
            pending_request: HashMap::new(),
            pending_register: HashMap::new(),
            pending_discover: HashMap::new(),
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
                    /*
                    if self.cookie.is_some() {
                        // FIXME: loop managed list of namespaces
                        self.swarm.behaviour_mut().rendezvous.discover(
                            Some(Namespace::new(NAMESPACE.to_string()).unwrap()),
                            self.cookie.clone(),
                            None,
                            self.location.id,
                        )
                    }
                    */
                }
                complete => break,
            }
        }
    }

    async fn handle_rpc_event(
        &mut self,
        event: request_response::Event<
            RequestMessage<'static>,
            ResponseMessage<'static>,
            ResponseMessage<'static>,
        >,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => {
                match message {
                    request_response::Message::Request {
                        request,
                        channel,
                        ..
                    } => {
                        self.event_sender
                            .send(NetworkEvent::Message(
                                MessageEvent::InboundRequest {
                                    peer,
                                    request,
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
                        if let Some(sender) =
                            self.pending_request.remove(&request_id)
                        {
                            sender
                                .send(Ok((request_id, peer, response)))
                                .expect("sender to not be dropped");
                        }
                    }
                }
            }
            request_response::Event::InboundFailure {
                request_id,
                error,
                ..
            } => {
                if let Some(sender) = self.pending_request.remove(&request_id)
                {
                    sender
                        .send(Err(Error::InboundFailure(error.to_string())))
                        .expect("sender to not be dropped");
                }
            }

            request_response::Event::OutboundFailure {
                request_id,
                error,
                ..
            } => {
                if let Some(sender) = self.pending_request.remove(&request_id)
                {
                    sender
                        .send(Err(Error::OutboundFailure(error.to_string())))
                        .expect("sender to not be dropped");
                }
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rendezvous(&mut self, event: rendezvous::client::Event) {
        match event {
            // Rendezvous register
            rendezvous::client::Event::Registered {
                namespace,
                ttl,
                rendezvous_node,
            } => {
                tracing::info!(
                    "registered for namespace '{}' at rendezvous point {} for the next {} seconds",
                    namespace,
                    rendezvous_node,
                    ttl,
                );

                if let Some(pending) =
                    self.pending_register.remove(&namespace)
                {
                    pending.send(Ok(())).expect("sender channel to be open");
                }
            }
            rendezvous::client::Event::RegisterFailed(error) => {
                tracing::error!("failed to register {}", error);
                if let RegisterError::Remote { namespace, .. } = error {
                    self.pending_register.remove(&namespace);
                }
            }
            rendezvous::client::Event::DiscoverFailed {
                error,
                namespace,
                ..
            } => {
                tracing::error!("failed to discover peers {:#?}", error);
                self.pending_discover.remove(&namespace);
            }
            // Rendezvous discovery
            rendezvous::client::Event::Discovered {
                registrations,
                cookie: new_cookie,
                ..
            } => {
                let namespace = new_cookie.namespace().cloned();
                if let Some(pending) =
                    self.pending_discover.remove(&namespace)
                {
                    self.cookie.replace(new_cookie);

                    for registration in &registrations {
                        for address in registration.record.addresses() {
                            let peer = registration.record.peer_id();
                            tracing::info!(
                                "discovered peer {} at {}",
                                peer,
                                address
                            );

                            let p2p_suffix = Protocol::P2p(*peer.as_ref());
                            let address_with_p2p = if !address.ends_with(
                                &Multiaddr::empty().with(p2p_suffix.clone()),
                            ) {
                                address.clone().with(p2p_suffix)
                            } else {
                                address.clone()
                            };

                            println!("Trying to dial the discovered peer!!!");
                            self.swarm.dial(address_with_p2p).unwrap();
                        }
                    }

                    pending
                        .send(Ok(registrations))
                        .expect("sender channel to be open");
                }
            }
            rendezvous::client::Event::Expired { .. } => {}
        }
    }

    async fn handle_event(
        &mut self,
        event: SwarmEvent<
            ComposedEvent,
            Either<
                Either<
                    Either<ConnectionHandlerUpgrErr<io::Error>, io::Error>,
                    void::Void,
                >,
                io::Error,
            >,
        >,
    ) {
        match event {

            SwarmEvent::Behaviour(ComposedEvent::Identify(identify::Event::Received {
                ..
            })) => {

                println!("GOT IDENTIFY RECEIVED EVENT!!!");

                /*
                swarm.behaviour_mut().rendezvous.register(
                    rendezvous::Namespace::from_static("rendezvous"),
                    rendezvous_point,
                    None,
                );
                */
            }

            SwarmEvent::Behaviour(ComposedEvent::Rendezvous(event)) => {
                self.handle_rendezvous(event).await;
            }
            SwarmEvent::Behaviour(ComposedEvent::RequestResponse(event)) => {
                self.handle_rpc_event(event).await;
            }
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
            Command::ConnectedPeers { sender } => {
                let peers = self.swarm.connected_peers().cloned().collect();
                sender.send(Ok(peers)).expect("sender channel to be open");
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
                self.pending_request.insert(request_id, sender);
            }
            Command::Response { response, channel } => {
                self.swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, response)
                    .expect("connection to peer to be still open.");
            }
            Command::Register {
                namespace,
                ttl,
                sender,
            } => {
                if let Some(pending) =
                    self.pending_register.remove(&namespace)
                {
                    tracing::warn!(
                        "register already running for {:#?}",
                        namespace,
                    );
                    pending
                        .send(Err(Error::RegisterRunning))
                        .expect("sender channel to be open")
                } else {
                    self.swarm.behaviour_mut().rendezvous.register(
                        namespace.clone(),
                        self.location.id,
                        ttl,
                    );

                    self.pending_register.insert(namespace, sender);
                }

                //sender.send(Ok(())).expect("sender channel to be open");
            }
            Command::Unregister { namespace, sender } => {
                self.swarm
                    .behaviour_mut()
                    .rendezvous
                    .unregister(namespace, self.location.id);
                sender.send(Ok(())).expect("sender channel to be open");
            }
            Command::Discover {
                namespace,
                limit,
                sender,
            } => {
                if let Some(pending) =
                    self.pending_discover.remove(&namespace)
                {
                    tracing::warn!(
                        "discover already running for {:#?}",
                        namespace,
                    );
                    pending
                        .send(Err(Error::DiscoverRunning))
                        .expect("sender channel to be open")
                } else {
                    self.swarm.behaviour_mut().rendezvous.discover(
                        namespace.clone(),
                        self.cookie.clone(),
                        limit,
                        self.location.id,
                    );
                    self.pending_discover.insert(namespace, sender);
                }
            }
        }
    }
}
