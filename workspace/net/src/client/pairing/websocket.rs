//! Protocol for pairing devices.
use crate::client::NetworkAccount;
use snow::{Builder, Keypair};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async,
    //MaybeTlsStream, WebSocketStream,
};
use serde::{Serialize, Deserialize};
use super::{Result, ServerPairUrl, PATTERN};
use crate::{
    client::WebSocketRequest,
    sdk::{url::Url, device::TrustedDevice},
};

const PAIR_PATH: &str = "api/v1/pair";

/// Message sent between devices being paired.
struct PairingPacket {
    /// Public key of the recipient.
    pub public_key: Vec<u8>,
    /// Encrypted message payload.
    pub payload: Vec<u8>,
}

/// Pairing message.
#[derive(Serialize, Deserialize)]
enum PairingMessage {
    /// Request sent from the accept side to the 
    /// offering side once the noise protocol handshake 
    /// has completed.
    Request(TrustedDevice),
    /// Confirmation from the offering side to the 
    /// accepting side is the account signing key.
    Confirm([u8; 32]),

    // TODO: error with reason
}

/*
/// Type of stream created for websocket connections.
type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
*/

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
}

impl<'a> WebSocketPairOffer<'a> {
    /// Create a new pairing offer.
    pub fn new(account: &'a mut NetworkAccount, url: Url) -> Result<Self> {
        let keypair = Builder::new(PATTERN.parse()?).generate_keypair()?;
        let share_url =
            ServerPairUrl::new(url.clone(), keypair.public.clone());
        Ok(Self {
            keypair,
            account,
            url,
            share_url,
        })
    }

    /// Connect the websocket transport.
    pub async fn connect(&self) -> Result<()> {
        let request = WebSocketRequest::new(&self.url, PAIR_PATH)?;
        let (ws_stream, _) = connect_async(request).await?;
        todo!();
    }
}

/// Accept is the device being paired.
pub struct WebSocketPairAccept {
    /// Noise session keypair.
    keypair: Keypair,
    /// URL shared by the offering device.
    share_url: ServerPairUrl,
}

impl WebSocketPairAccept {
    /// Create a new pairing connection.
    pub fn new(share_url: ServerPairUrl) -> Result<Self> {
        let keypair = Builder::new(PATTERN.parse()?).generate_keypair()?;
        Ok(Self { keypair, share_url })
    }

    /// Connect the websocket transport.
    pub async fn connect(&self) -> Result<()> {
        let request =
            WebSocketRequest::new(self.share_url.server(), PAIR_PATH)?;
        let (ws_stream, _) = connect_async(request).await?;
        todo!();
    }
}
