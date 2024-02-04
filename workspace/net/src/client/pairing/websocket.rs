//! Protocol for pairing devices.
use super::{Error, PairingMessage, Result, ServerPairUrl, PATTERN};
use crate::{
    client::{
        enrollment::DeviceEnrollment, sync::RemoteSync, NetworkAccount,
        WebSocketRequest,
    },
    relay::{RelayHeader, RelayPacket, RelayPayload},
    sdk::{
        account::Account,
        decode,
        device::{DeviceSigner, TrustedDevice},
        encode,
        events::{DeviceEvent, DeviceEventLog, EventLogExt},
        signer::{ecdsa::SingleParty, Signer},
        sync::Origin,
        url::Url,
    },
};
use futures::{
    select,
    stream::{SplitSink, SplitStream},
    FutureExt, SinkExt, StreamExt,
};
use serde::{Deserialize, Serialize};
use snow::{Builder, HandshakeState, Keypair, TransportState};
use std::{borrow::Cow, path::PathBuf, sync::Arc};
use tokio::{net::TcpStream, sync::mpsc};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        self,
        protocol::{frame::coding::CloseCode, CloseFrame, Message},
    },
    MaybeTlsStream, WebSocketStream,
};

const PAIR_PATH: &str = "api/v1/relay";
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

/// State machine variants for the protocol.
enum PairProtocolState {
    /// Waiting to start the protocol.
    Pending,
    /// Noise handshake completed.
    Handshake,
    /// Protocol completed.
    Done,
}

enum IncomingAction {
    Reply(PairProtocolState, RelayPacket),
    HandleMessage(PairingMessage),
}

/// Listen for incoming messages on the stream.
async fn listen(mut rx: WsStream, tx: mpsc::Sender<RelayPacket>) {
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
pub struct OfferPairing<'a> {
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
    state: PairProtocolState,
}

impl<'a> OfferPairing<'a> {
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
                state: PairProtocolState::Pending,
            },
            rx,
        ))
    }

    /// URL that can be shared with the other device.
    pub fn share_url(&self) -> &ServerPairUrl {
        &self.share_url
    }

    /// Start the event loop.
    pub async fn run(
        &mut self,
        stream: WsStream,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) -> Result<()> {
        let (offer_tx, mut offer_rx) = mpsc::channel::<RelayPacket>(32);
        tokio::task::spawn(listen(stream, offer_tx));
        loop {
            select! {
                event = offer_rx.recv().fuse() => {
                    if let Some(event) = event {
                        self.incoming(event).await?;
                        if matches!(&self.state, PairProtocolState::Done) {
                            break;
                        }
                    }
                }
                event = shutdown_rx.recv().fuse() => {
                    if event.is_some() {
                        let _ = self.tx.send(Message::Close(Some(CloseFrame {
                            code: CloseCode::Normal,
                            reason: Cow::Borrowed("closed"),
                        }))).await;
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Process incoming packet.
    async fn incoming(&mut self, packet: RelayPacket) -> Result<()> {
        if packet.header.to_public_key != self.keypair.public {
            return Err(Error::NotForMe);
        }

        let action = match (&self.state, &packet.payload) {
            (PairProtocolState::Pending, RelayPayload::Handshake(_, _)) => {
                let reply = self.handshake(&packet).await?;
                IncomingAction::Reply(PairProtocolState::Handshake, reply)
            }
            (
                PairProtocolState::Handshake,
                RelayPayload::Transport(len, buf),
            ) => {
                if let Some(Tunnel::Transport(transport)) =
                    self.tunnel.as_mut()
                {
                    let message = decrypt(transport, *len, buf.as_slice())?;
                    IncomingAction::HandleMessage(message)
                } else {
                    unreachable!();
                }
            }
            _ => todo!("handle other states"),
        };

        match action {
            IncomingAction::Reply(next_state, reply) => {
                self.state = next_state;

                let buffer = encode(&reply).await?;
                self.tx.send(Message::Binary(buffer)).await?;
            }
            IncomingAction::HandleMessage(message) => {
                if let PairingMessage::Request(device) = message {
                    self.register_device(device).await?;

                    let account_signer =
                        self.account.account_signer().await?;
                    let account_signing_key = account_signer.to_bytes();
                    let account_signing_key: [u8; 32] =
                        account_signing_key.as_slice().try_into()?;
                    let private_message =
                        PairingMessage::Confirm(account_signing_key);

                    let (len, buf) =
                        if let Some(Tunnel::Transport(transport)) =
                            self.tunnel.as_mut()
                        {
                            encrypt(transport, &private_message)?
                        } else {
                            unreachable!();
                        };

                    let reply = RelayPacket {
                        header: RelayHeader {
                            to_public_key: packet
                                .header
                                .from_public_key
                                .to_vec(),
                            from_public_key: self.keypair.public.to_vec(),
                        },
                        payload: RelayPayload::Transport(len, buf),
                    };

                    self.state = PairProtocolState::Done;
                    let buffer = encode(&reply).await?;
                    self.tx.send(Message::Binary(buffer)).await?;
                } else {
                    todo!("handle wrong pairing message type");
                }
            }
        }

        Ok(())
    }

    async fn register_device(&mut self, device: TrustedDevice) -> Result<()> {
        // Trust the other device in our local event log
        let events: Vec<DeviceEvent> = vec![DeviceEvent::Trust(device)];
        {
            let storage = self.account.storage().await?;
            let mut writer = storage.write().await;
            writer.patch_devices_unchecked(events).await?;
        }

        // Send the patch to remote servers
        if let Some(sync_error) = self.account.patch_devices().await {
            return Err(Error::DevicePatchSync);
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
pub struct AcceptPairing<'a> {
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
    state: PairProtocolState,
    /// Data directory for the device enrollment.
    data_dir: Option<PathBuf>,
    /// Device signing key.
    device_signer: DeviceSigner,
    /// Device enrollment.
    enrollment: Option<DeviceEnrollment>,
}

impl<'a> AcceptPairing<'a> {
    /// Create a new pairing connection.
    pub async fn new(
        share_url: ServerPairUrl,
        device: &'a TrustedDevice,
        device_signer: DeviceSigner,
        data_dir: Option<PathBuf>,
    ) -> Result<(Self, WsStream)> {
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
                state: PairProtocolState::Pending,
                data_dir,
                device_signer,
                enrollment: None,
            },
            rx,
        ))
    }

    /// Start the event loop.
    pub async fn run(
        &mut self,
        stream: WsStream,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) -> Result<()> {
        // Start pairing
        self.pair().await?;

        // Run the event loop
        let (offer_tx, mut offer_rx) = mpsc::channel::<RelayPacket>(32);
        tokio::task::spawn(listen(stream, offer_tx));

        loop {
            select! {
                event = offer_rx.recv().fuse() => {
                    if let Some(event) = event {
                        self.incoming(event).await?;
                        if matches!(&self.state, PairProtocolState::Done) {
                            break;
                        }
                    }
                }
                event = shutdown_rx.recv().fuse() => {
                    if event.is_some() {
                        let _ = self.tx.send(Message::Close(Some(CloseFrame {
                            code: CloseCode::Normal,
                            reason: Cow::Borrowed("closed"),
                        }))).await;
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Take the final device enrollment.
    ///
    /// Errors if the protocol has not reached completion.
    pub fn take_enrollment(self) -> Result<DeviceEnrollment> {
        self.enrollment.ok_or(Error::NoEnrollment)
    }

    /// Start the pairing protocol.
    async fn pair(&mut self) -> Result<()> {
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

    /// Process incoming packet.
    async fn incoming(&mut self, packet: RelayPacket) -> Result<()> {
        if packet.header.to_public_key != self.keypair.public {
            return Err(Error::NotForMe);
        }

        let action = match (&self.state, &packet.payload) {
            (PairProtocolState::Pending, RelayPayload::Handshake(_, _)) => {
                let reply = self.into_transport(&packet).await?;
                IncomingAction::Reply(PairProtocolState::Handshake, reply)
            }
            (
                PairProtocolState::Handshake,
                RelayPayload::Transport(len, buf),
            ) => {
                if let Some(Tunnel::Transport(transport)) =
                    self.tunnel.as_mut()
                {
                    let message = decrypt(transport, *len, buf.as_slice())?;
                    IncomingAction::HandleMessage(message)
                } else {
                    unreachable!();
                }
            }
            _ => todo!("accept incoming handle other states"),
        };

        match action {
            IncomingAction::Reply(next_state, reply) => {
                self.state = next_state;

                let buffer = encode(&reply).await?;
                self.tx.send(Message::Binary(buffer)).await?;
            }
            IncomingAction::HandleMessage(message) => {
                if let PairingMessage::Confirm(signing_key) = message {
                    self.enroll(signing_key).await?;
                    self.state = PairProtocolState::Done;
                } else {
                    todo!("handle wrong pairing message type");
                }
            }
        }

        Ok(())
    }

    /// Enroll this device.
    async fn enroll(&mut self, signing_key: [u8; 32]) -> Result<()> {
        let signer: SingleParty = signing_key.try_into()?;
        let address = signer.address()?;
        let server = self.share_url.server().clone();
        let origin: Origin = server.into();
        let data_dir = self.data_dir.clone();
        let enrollment = NetworkAccount::enroll_device(
            origin,
            Box::new(signer),
            self.device_signer.clone(),
            data_dir,
        )
        .await?;
        self.enrollment = Some(enrollment);
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
                let private_message =
                    PairingMessage::Request(self.device.clone());
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
    message: &PairingMessage,
) -> Result<(usize, Vec<u8>)> {
    let message = serde_json::to_vec(message)?;
    let mut contents = vec![0; message.len() + TAGLEN];
    let length = transport.write_message(&message, &mut contents)?;
    Ok((length, contents))
}

// Decrypt a message.
fn decrypt(
    transport: &mut TransportState,
    length: usize,
    message: &[u8],
) -> Result<PairingMessage> {
    let mut contents = vec![0; length];
    transport.read_message(&message[..length], &mut contents)?;
    let new_length = contents.len() - TAGLEN;
    contents.truncate(new_length);
    Ok(serde_json::from_slice(&contents)?)
}
