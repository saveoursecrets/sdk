//! Protocol for pairing devices.
use super::{Result, ServerPairUrl, PATTERN, packet::{PairingPacket, PairingPayload, PairingMessage, PairingHeader}};
use crate::client::NetworkAccount;
use crate::{
    client::WebSocketRequest,
    sdk::{device::TrustedDevice, url::Url, encode},
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

                    }
                }
                Err(e) => {
                    tracing::error!(error = ?e);
                    break;
                }
            }
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
                Ok(message) => {
                    if let Message::Binary(msg) = message {

                    }
                }
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

    /// Noise protocol handshake.
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
            //let buffer = serde_json::to_vec(&message)?;
            self.tx.send(Message::Binary(buffer)).await?;
        }
        Ok(())
    }
}
