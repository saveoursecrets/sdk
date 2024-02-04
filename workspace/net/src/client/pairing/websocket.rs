//! Protocol for pairing devices.
use super::{
    packet::{PairingHeader, PairingMessage, PairingPacket, PairingPayload},
    Result, ServerPairUrl, PATTERN,
};
use crate::client::NetworkAccount;
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
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{self, protocol::Message},
    MaybeTlsStream, WebSocketStream,
};

const PAIR_PATH: &str = "api/v1/pair";

/// State of the encrypted tunnel.
enum Tunnel {
    /// Handshake state.
    Handshake(HandshakeState),
    /// Transport state.
    Transport(TransportState),
}

type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type WsStream = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

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
    /// Sink side of the socket.
    tx: WsSink,
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
        let responder = builder.build_responder()?;
        let request = WebSocketRequest::new(&url, PAIR_PATH)?;
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
            },
            rx,
        ))
    }

    /// Start listening for messages on the stream.
    pub async fn listen(mut rx: WsStream) {
        while let Some(message) = rx.next().await {
            match message {
                Ok(message) => {
                    if let Message::Binary(msg) = message {
                        match decode::<PairingPacket>(&msg).await {
                            Ok(result) => {
                                todo!("dispatch packet event");
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

    /// Respond to the initiator noise protocol handshake.
    pub async fn handshake(
        &mut self,
        packet: &PairingPacket,
    ) -> Result<PairingPacket> {
        let packet = if let (
            Some(Tunnel::Handshake(state)),
            PairingPayload::Handshake(len, init_msg),
        ) = (&mut self.tunnel, &packet.payload)
        {
            let mut buf = [0; 1024];
            let mut reply = [0; 1024];
            state.read_message(&init_msg[..*len], &mut buf)?;
            let len = state.write_message(&[], &mut reply)?;
            Some(PairingPacket {
                header: PairingHeader {
                    to_public_key: packet.header.from_public_key.clone(),
                    from_public_key: self.keypair.public.clone(),
                },
                payload: PairingPayload::Handshake(len, reply.to_vec()),
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
pub struct WebSocketPairAccept {
    /// Noise session keypair.
    keypair: Keypair,
    /// URL shared by the offering device.
    share_url: ServerPairUrl,
    /// Noise protocol state.
    tunnel: Option<Tunnel>,
    /// Sink side of the socket.
    tx: WsSink,
}

impl WebSocketPairAccept {
    /// Create a new pairing connection.
    pub async fn new(share_url: ServerPairUrl) -> Result<(Self, WsStream)> {
        let builder = Builder::new(PATTERN.parse()?);
        let keypair = builder.generate_keypair()?;
        let initiator = builder.build_initiator()?;
        let request = WebSocketRequest::new(share_url.server(), PAIR_PATH)?;
        let (socket, _) = connect_async(request).await?;
        let (tx, rx) = socket.split();
        Ok((
            Self {
                keypair,
                share_url,
                tunnel: Some(Tunnel::Handshake(initiator)),
                tx,
            },
            rx,
        ))
    }

    /// Start listening for messages on the stream.
    pub async fn listen(mut rx: WsStream) {
        while let Some(message) = rx.next().await {
            match message {
                Ok(message) => if let Message::Binary(msg) = message {
                    match decode::<PairingPacket>(&msg).await {
                        Ok(result) => {
                            todo!("dispatch packet event");
                        }
                        Err(e) => {
                            tracing::error!(error = ?e);
                            break;
                        }
                    }
                },
                Err(e) => {
                    tracing::error!(error = ?e);
                    break;
                }
            }
        }
    }

    /// Attempt to complete the pairing protocol.
    pub async fn pair(&mut self) -> Result<()> {
        self.handshake().await?;
        Ok(())
    }

    /// Start initiator noise protocol handshake.
    async fn handshake(&mut self) -> Result<()> {
        if let Some(Tunnel::Handshake(state)) = &mut self.tunnel {
            let mut buf = [0u8; 1024];
            let len = state.write_message(&[], &mut buf)?;
            let message = PairingPacket {
                header: PairingHeader {
                    to_public_key: self.share_url.public_key().to_vec(),
                    from_public_key: self.keypair.public.to_vec(),
                },
                payload: PairingPayload::Handshake(len, buf.to_vec()),
            };
            let buffer = encode(&message).await?;
            self.tx.send(Message::Binary(buffer)).await?;
        }
        Ok(())
    }
    
    /// Complete the noise protocol handshake.
    fn into_transport(&mut self, packet: &PairingPacket) -> Result<()> {
        let done = if let (
            Some(Tunnel::Handshake(state)),
            PairingPayload::Handshake(len, reply_msg),
        ) = (&mut self.tunnel, &packet.payload)
        {
            let mut buf = [0; 1024];
            state.read_message(&reply_msg[..*len], &mut buf)?;
            true
        } else { false };

        if done {
            let tunnel = self.tunnel.take().unwrap();
            if let Tunnel::Handshake(state) = tunnel {
                self.tunnel =
                    Some(Tunnel::Transport(state.into_transport_mode()?));
            }
            Ok(())
        } else {
            todo!("handle bad state/packet");
        }
    }
}
