//! Peer to peer network proxy.
use std::{
    collections::{hash_map::Entry, HashMap},
    io, iter,
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
    request_response::{self, ProtocolSupport, RequestId, ResponseChannel},
    swarm::{ConnectionHandlerUpgrErr, Swarm, SwarmBuilder, SwarmEvent},
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
}

/// Creates a new network.
pub async fn new(
    local_key: identity::Keypair,
    shutdown: oneshot::Receiver<()>,
) -> Result<(Client, impl Stream<Item = NetworkEvent> + Unpin, EventLoop)> {
    let peer_id = local_key.public().to_peer_id();

    let swarm = SwarmBuilder::with_tokio_executor(
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
        },
        peer_id,
    )
    .build();

    let (command_sender, command_receiver) = mpsc::channel(0);
    let (event_sender, event_receiver) = mpsc::channel(16);

    Ok((
        Client {
            sender: command_sender,
        },
        Box::pin(event_receiver),
        EventLoop::new(
            peer_id,
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
            .expect("Command receiver not to be dropped.");
    }
}

/// Runs the network event loop.
pub struct EventLoop {
    peer_id: PeerId,
    swarm: Swarm<ComposedBehaviour>,
    command_receiver: mpsc::Receiver<Command>,
    event_sender: mpsc::Sender<NetworkEvent>,
    pending_dial: HashMap<PeerId, oneshot::Sender<Result<()>>>,
    //pending_request: HashMap<RequestId, oneshot::Sender<Result<RequestId>>>,
    //pending_start_providing: HashMap<QueryId, oneshot::Sender<()>>,
    //pending_get_providers: HashMap<QueryId, oneshot::Sender<HashSet<PeerId>>>,
    shutdown: oneshot::Receiver<()>,
}

impl EventLoop {
    fn new(
        peer_id: PeerId,
        swarm: Swarm<ComposedBehaviour>,
        command_receiver: mpsc::Receiver<Command>,
        event_sender: mpsc::Sender<NetworkEvent>,
        shutdown: oneshot::Receiver<()>,
    ) -> Self {
        Self {
            peer_id,
            swarm,
            command_receiver,
            event_sender,
            pending_dial: Default::default(),
            //pending_start_providing: Default::default(),
            //pending_get_providers: Default::default(),
            //pending_request: HashMap::new(),
            shutdown,
        }
    }

    /// Start the event loop running.
    pub async fn run(mut self) {
        loop {
            futures::select! {
                _ = &mut self.shutdown => {
                    log::info!("peer service shutting down");
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
                complete => break,
            }
        }
    }

    async fn handle_event(
        &mut self,
        event: SwarmEvent<
            ComposedEvent,
            Either<ConnectionHandlerUpgrErr<io::Error>, io::Error>,
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
                log::error!("{}", error);
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
            e => log::error!("{e:?}"),
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
                            log::warn!("error on dial {:#?}", e);
                            let _ = sender.send(Err(Error::DialFailed(
                                peer_addr.to_string(),
                            )));
                        }
                    }
                } else {
                    log::warn!("already dialing peer {}", peer_id);
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
        }
    }
}
