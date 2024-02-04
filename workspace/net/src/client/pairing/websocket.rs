//! Protocol for pairing devices.
use super::{Error, PairingMessage, Result, ServerPairUrl, PATTERN};
use crate::{
    client::NetworkAccount,
    relay::{RelayHeader, RelayPacket, RelayPayload},
};
use crate::{
    client::WebSocketRequest,
    sdk::{decode, device::TrustedDevice, encode, url::Url},
};
use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use serde::{Deserialize, Serialize};
use snow::{Builder, HandshakeState, Keypair, TransportState};
use tokio::{net::TcpStream, sync::mpsc};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{self, protocol::Message},
    MaybeTlsStream, WebSocketStream,
};

const PAIR_PATH: &str = "api/v1/pair";
const TAGLEN: usize = 16;

/// State of the encrypted tunnel.
enum Tunnel {
    /// Handshake state.
    Handshake(HandshakeState),
    /// Transport state.
    Transport(TransportState),
}

type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type WsStream = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

/// Offer to pair.
pub type Offer<'a> = WebSocketPairOffer<'a>;

/// Accept a pairing offer.
pub type Accept<'a> = WebSocketPairAccept<'a>;

/// State machine variants for the offer side.
enum OfferState {
    /// Waiting to start the protocol.
    Pending,
    /// Noise handshake completed.
    Handshake,
}

/// State machine variants for the accept side.
enum AcceptState {
    /// Waiting to start the protocol.
    Pending,
    /// Noise handshake completed.
    Handshake,
}

/// Listen for incoming messages on the stream.
pub async fn listen(mut rx: WsStream, tx: mpsc::Sender<RelayPacket>) {
    while let Some(message) = rx.next().await {
        match message {
            Ok(message) => {
                if let Message::Binary(msg) = message {
                    match decode::<RelayPacket>(&msg).await {
                        Ok(result) => {
                            if let Err(e) = tx.send(result).await {
                                tracing::error!(error = ?e);
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = ?e);
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = ?e);
                break;
            }
        }
    }
}

/// Offer is the device that is authenticated and can
/// authorize the new device.
pub struct WebSocketPairOffer<'a> {
    /// Noise session keypair.
    keypair: Keypair,
    /// Network account.
    account: &'a mut NetworkAccount,
    /// Server URL.
    url: Url,
    /// Pairing URL to share with the other device.
    share_url: ServerPairUrl,
    /// Noise protocol state.
    tunnel: Option<Tunnel>,
    /// Websocket sink.
    tx: WsSink,
    /// Current state of the protocol.
    state: OfferState,
}

impl<'a> WebSocketPairOffer<'a> {
    /// Create a new pairing offer.
    pub async fn new(
        account: &'a mut NetworkAccount,
        url: Url,
    ) -> Result<(Self, WsStream)> {
        let builder = Builder::new(PATTERN.parse()?);
        let keypair = builder.generate_keypair()?;
        let share_url =
            ServerPairUrl::new(url.clone(), keypair.public.clone());
        let responder = builder
            .local_private_key(&keypair.private)
            .build_responder()?;
        let mut request = WebSocketRequest::new(&url, PAIR_PATH)?;
        request
            .uri
            .query_pairs_mut()
            .append_pair("public_key", &hex::encode(&keypair.public));

        let (socket, _) = connect_async(request).await?;
        let (tx, rx) = socket.split();
        Ok((
            Self {
                keypair,
                account,
                url,
                share_url,
                tunnel: Some(Tunnel::Handshake(responder)),
                tx,
                state: OfferState::Pending,
            },
            rx,
        ))
    }

    /// URL that can be shared with the other device.
    pub fn share_url(&self) -> &ServerPairUrl {
        &self.share_url
    }

    /// Process incoming packet.
    pub async fn incoming(&mut self, packet: RelayPacket) -> Result<()> {
        if packet.header.to_public_key != self.keypair.public {
            return Err(Error::NotForMe);
        }

        let result = match (&self.state, &packet.payload) {
            (OfferState::Pending, RelayPayload::Handshake(_, _)) => {
                let reply = self.handshake(&packet).await?;
                Some((OfferState::Handshake, reply))
            }
            (OfferState::Handshake, RelayPayload::Transport(len, buf)) => {
                if let Some(Tunnel::Transport(transport)) = self.tunnel.as_mut() {
                    let message = decrypt(transport, *len, buf.as_slice())?;
                    println!("incoming {:#?}", message);
                    todo!();
                } else {
                    unreachable!();
                }

            }
            _ => todo!("handle other states"),
        };

        if let Some((next_state, reply)) = result {
            self.state = next_state;

            let buffer = encode(&reply).await?;
            self.tx.send(Message::Binary(buffer)).await?;
        }

        Ok(())
    }

    /// Respond to the initiator noise protocol handshake.
    async fn handshake(
        &mut self,
        packet: &RelayPacket,
    ) -> Result<RelayPacket> {
        let packet = if let (
            Some(Tunnel::Handshake(state)),
            RelayPayload::Handshake(len, init_msg),
        ) = (&mut self.tunnel, &packet.payload)
        {
            let mut buf = [0; 1024];
            let mut reply = [0; 1024];
            state.read_message(&init_msg[..*len], &mut buf)?;
            let len = state.write_message(&[], &mut reply)?;
            Some(RelayPacket {
                header: RelayHeader {
                    to_public_key: packet.header.from_public_key.clone(),
                    from_public_key: self.keypair.public.clone(),
                },
                payload: RelayPayload::Handshake(len, reply.to_vec()),
            })
        } else {
            None
        };

        if let Some(packet) = packet {
            let tunnel = self.tunnel.take().unwrap();
            if let Tunnel::Handshake(state) = tunnel {
                self.tunnel =
                    Some(Tunnel::Transport(state.into_transport_mode()?));
            }
            Ok(packet)
        } else {
            todo!("handle bad tunnel state or packet");
        }
    }
}

/// Accept is the device being paired.
pub struct WebSocketPairAccept<'a> {
    /// Noise session keypair.
    keypair: Keypair,
    /// Current device information.
    device: &'a TrustedDevice,
    /// URL shared by the offering device.
    share_url: ServerPairUrl,
    /// Noise protocol state.
    tunnel: Option<Tunnel>,
    /// Sink side of the socket.
    tx: WsSink,
    /// Current state of the protocol.
    state: AcceptState,
}

impl<'a> WebSocketPairAccept<'a> {
    /// Create a new pairing connection.
    pub async fn new(share_url: ServerPairUrl, device: &'a TrustedDevice) -> Result<(Self, WsStream)> {
        let builder = Builder::new(PATTERN.parse()?);
        let keypair = builder.generate_keypair()?;
        let initiator = builder
            .local_private_key(&keypair.private)
            .remote_public_key(share_url.public_key())
            .build_initiator()?;
        let mut request =
            WebSocketRequest::new(share_url.server(), PAIR_PATH)?;
        request
            .uri
            .query_pairs_mut()
            .append_pair("public_key", &hex::encode(&keypair.public));
        let (socket, _) = connect_async(request).await?;
        let (tx, rx) = socket.split();
        Ok((
            Self {
                keypair,
                device,
                share_url,
                tunnel: Some(Tunnel::Handshake(initiator)),
                tx,
                state: AcceptState::Pending,
            },
            rx,
        ))
    }

    /// Process incoming packet.
    pub async fn incoming(&mut self, packet: RelayPacket) -> Result<()> {
        if packet.header.to_public_key != self.keypair.public {
            return Err(Error::NotForMe);
        }

        let result = match (&self.state, &packet.payload) {
            (AcceptState::Pending, RelayPayload::Handshake(_, _)) => {
                let reply = self.into_transport(&packet).await?;
                Some((AcceptState::Handshake, reply))
            }
            _ => todo!("handle other states"),
        };

        if let Some((next_state, reply)) = result {
            self.state = next_state;

            let buffer = encode(&reply).await?;
            self.tx.send(Message::Binary(buffer)).await?;
        }

        Ok(())
    }

    /// Start the pairing protocol.
    pub async fn pair(&mut self) -> Result<()> {
        if let Some(Tunnel::Handshake(state)) = &mut self.tunnel {
            let mut buf = [0u8; 1024];
            let len = state.write_message(&[], &mut buf)?;
            let message = RelayPacket {
                header: RelayHeader {
                    to_public_key: self.share_url.public_key().to_vec(),
                    from_public_key: self.keypair.public.to_vec(),
                },
                payload: RelayPayload::Handshake(len, buf.to_vec()),
            };
            let buffer = encode(&message).await?;
            self.tx.send(Message::Binary(buffer)).await?;
        }
        Ok(())
    }

    /// Complete the noise protocol handshake.
    async fn into_transport(
        &mut self,
        packet: &RelayPacket,
    ) -> Result<RelayPacket> {
        let done = if let (
            Some(Tunnel::Handshake(state)),
            RelayPayload::Handshake(len, reply_msg),
        ) = (&mut self.tunnel, &packet.payload)
        {
            let mut buf = [0; 1024];
            state.read_message(&reply_msg[..*len], &mut buf)?;
            true
        } else {
            false
        };

        if done {
            let tunnel = self.tunnel.take().unwrap();
            if let Tunnel::Handshake(state) = tunnel {
                self.tunnel =
                    Some(Tunnel::Transport(state.into_transport_mode()?));
            }

            if let Some(Tunnel::Transport(transport)) = self.tunnel.as_mut() {
                let private_message = PairingMessage::Request(self.device.clone());
                let (len, buf) = encrypt(transport, &private_message)?;
                let reply = RelayPacket {
                    header: RelayHeader {
                        to_public_key: packet.header.from_public_key.to_vec(),
                        from_public_key: self.keypair.public.to_vec(),
                    },
                    payload: RelayPayload::Transport(len, buf),
                };

                Ok(reply)
            } else {
                unreachable!();
            }
            
        } else {
            todo!("handle bad state/packet");
        }
    }
}

// Encrypt a message.
fn encrypt(
    transport: &mut TransportState,
    message: &PairingMessage) -> Result<(usize, Vec<u8>)> {
    let message = serde_json::to_vec(message)?;
    let mut contents = vec![0; message.len() + TAGLEN];
    let length =
        transport.write_message(&message, &mut contents)?;
    Ok((length, contents))
}

// Decrypt a packet.
fn decrypt(
    transport: &mut TransportState,
    length: usize,
    message: &[u8],
) -> Result<PairingMessage> {
    let mut contents = vec![0; length];
    transport.read_message(
        &message[..length],
        &mut contents,
    )?;
    let new_length = contents.len() - TAGLEN;
    contents.truncate(new_length);
    Ok(serde_json::from_slice(&contents)?)
}
