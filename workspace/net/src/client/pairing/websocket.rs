//! Protocol for pairing devices.
use super::{DeviceEnrollment, Error, PairingMessage, Result, ServerPairUrl};
use crate::{
    client::{
        pairing::PairingConfirmation, sync::RemoteSync, NetworkAccount,
        SyncOptions, WebSocketRequest,
    },
    relay::{RelayBody, RelayHeader, RelayPacket, RelayPayload},
    sdk::{
        account::Account,
        decode,
        device::{
            DeviceMetaData, DevicePublicKey, DeviceSigner, TrustedDevice,
        },
        encode,
        events::DeviceEvent,
        signer::ecdsa::SingleParty,
        sync::Origin,
        url::Url,
    },
};
use futures::{
    select,
    stream::{SplitSink, SplitStream},
    FutureExt, SinkExt, StreamExt,
};
use serde::{de::DeserializeOwned, Serialize};
use snow::{Builder, HandshakeState, Keypair, TransportState};
use std::{borrow::Cow, path::PathBuf};
use tokio::{net::TcpStream, sync::mpsc};
use tokio_tungstenite::{
    connect_async,
    tungstenite::protocol::{frame::coding::CloseCode, CloseFrame, Message},
    MaybeTlsStream, WebSocketStream,
};
use tracing::{span, Level};

const PATTERN: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";
const RELAY_PATH: &str = "api/v1/relay";
// 16-byte authentication tag appended to the ciphertext
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
#[derive(Debug)]
enum PairProtocolState {
    /// Waiting to start the protocol.
    Pending,
    /// Initial noise handshake completed.
    Handshake,
    /// Pre shared key handshake completed.
    PskHandshake,
    /// Protocol completed.
    Done,
}

#[derive(Debug)]
enum IncomingAction {
    Reply(PairProtocolState, RelayPacket),
    HandleMessage(PairingMessage),
}

/// Listen for incoming messages on the stream.
async fn listen(
    mut rx: WsStream,
    tx: mpsc::Sender<RelayPacket>,
    close_tx: mpsc::Sender<()>,
) {
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
                            let _ = close_tx.send(()).await;
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = ?e);
                let _ = close_tx.send(()).await;
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
    /// Pairing URL to share with the other device.
    share_url: ServerPairUrl,
    /// Noise protocol state.
    tunnel: Option<Tunnel>,
    /// Sink side of the websocket.
    tx: WsSink,
    /// Current state of the protocol.
    state: PairProtocolState,
    /// Determine if the URL sharing is inverted.
    is_inverted: bool,
}

impl<'a> OfferPairing<'a> {
    /// Create a new pairing offer.
    pub async fn new(
        account: &'a mut NetworkAccount,
        url: Url,
    ) -> Result<(OfferPairing<'a>, WsStream)> {
        let builder = Builder::new(PATTERN.parse()?);
        let keypair = builder.generate_keypair()?;
        let share_url =
            ServerPairUrl::new(url.clone(), keypair.public.clone());
        Self::new_connection(account, share_url, keypair, false).await
    }

    /// Create a new pairing offer from a share URL generated
    /// by the accepting device.
    pub async fn new_inverted(
        account: &'a mut NetworkAccount,
        share_url: ServerPairUrl,
    ) -> Result<(OfferPairing<'a>, WsStream)> {
        let builder = Builder::new(PATTERN.parse()?);
        let keypair = builder.generate_keypair()?;
        Self::new_connection(account, share_url, keypair, true).await
    }

    async fn new_connection(
        account: &'a mut NetworkAccount,
        share_url: ServerPairUrl,
        keypair: Keypair,
        is_inverted: bool,
    ) -> Result<(OfferPairing<'a>, WsStream)> {
        let psk = share_url.pre_shared_key().to_vec();
        let tunnel = if is_inverted {
            Builder::new(PATTERN.parse()?)
                .local_private_key(&keypair.private)
                .remote_public_key(share_url.public_key())
                .psk(3, &psk)
                .build_initiator()?
        } else {
            Builder::new(PATTERN.parse()?)
                .local_private_key(&keypair.private)
                .psk(3, &psk)
                .build_responder()?
        };

        let mut request =
            WebSocketRequest::new(share_url.server(), RELAY_PATH)?;
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
                share_url,
                tunnel: Some(Tunnel::Handshake(tunnel)),
                tx,
                state: PairProtocolState::Pending,
                is_inverted,
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
        if self.is_inverted {
            // Start pairing
            self.noise_send_e().await?;
            self.state = PairProtocolState::Handshake;
        }

        let (offer_tx, mut offer_rx) = mpsc::channel::<RelayPacket>(32);
        let (close_tx, mut close_rx) = mpsc::channel::<()>(1);
        tokio::task::spawn(listen(stream, offer_tx, close_tx));
        loop {
            select! {
                event = offer_rx.recv().fuse() => {
                    if let Some(event) = event {
                        self.incoming(event).await?;
                        if self.is_finished() {
                            break;
                        }
                    }
                }
                event = close_rx.recv().fuse() => {
                    if event.is_some() {
                        break;
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

    /// Determine if the protocol has completed.
    pub fn is_finished(&self) -> bool {
        matches!(&self.state, PairProtocolState::Done)
    }

    /// Process incoming packet.
    async fn incoming(&mut self, packet: RelayPacket) -> Result<()> {
        if packet.header.to_public_key != self.keypair.public {
            return Err(Error::NotForMe);
        }

        let span = span!(Level::DEBUG, "pairing_offer");
        let _enter = span.enter();

        let action = if !self.is_inverted {
            match (&self.state, &packet.payload) {
                (
                    PairProtocolState::Pending,
                    RelayPayload::Handshake(_, _),
                ) => {
                    let reply = self.noise_read_e(&packet).await?;
                    IncomingAction::Reply(PairProtocolState::Handshake, reply)
                }
                (
                    PairProtocolState::Handshake,
                    RelayPayload::Handshake(_, _),
                ) => {
                    let reply = self.noise_read_s(&packet).await?;
                    IncomingAction::Reply(
                        PairProtocolState::PskHandshake,
                        reply,
                    )
                }
                (
                    PairProtocolState::PskHandshake,
                    RelayPayload::Transport(len, buf),
                ) => {
                    if let Some(Tunnel::Transport(transport)) =
                        self.tunnel.as_mut()
                    {
                        IncomingAction::HandleMessage(
                            decrypt(transport, *len, buf.as_slice()).await?,
                        )
                    } else {
                        unreachable!();
                    }
                }
                _ => {
                    return Err(Error::BadState);
                }
            }
        } else {
            match (&self.state, &packet.payload) {
                (
                    PairProtocolState::Handshake,
                    RelayPayload::Handshake(_, _),
                ) => {
                    let reply = self.noise_send_s(&packet).await?;
                    IncomingAction::Reply(
                        PairProtocolState::PskHandshake,
                        reply,
                    )
                }
                (
                    PairProtocolState::PskHandshake,
                    RelayPayload::Transport(len, buf),
                ) => {
                    if let Some(Tunnel::Transport(transport)) =
                        self.tunnel.as_mut()
                    {
                        IncomingAction::HandleMessage(
                            decrypt(transport, *len, buf.as_slice()).await?,
                        )
                    } else {
                        unreachable!();
                    }
                }
                _ => {
                    return Err(Error::BadState);
                }
            }
        };

        match action {
            IncomingAction::Reply(next_state, reply) => {
                self.state = next_state;

                let buffer = encode(&reply).await?;
                self.tx.send(Message::Binary(buffer)).await?;
            }
            IncomingAction::HandleMessage(message) => {
                // In inverted mode we can get a ready event
                // so we just reply with another ready event
                // to trigger the usual exchange of information
                if let PairingMessage::Ready = message {
                    let payload = if let Some(Tunnel::Transport(transport)) =
                        self.tunnel_mut()
                    {
                        encrypt(transport, &PairingMessage::Ready).await?
                    } else {
                        unreachable!();
                    };
                    let reply = RelayPacket {
                        header: RelayHeader {
                            to_public_key: packet
                                .header
                                .from_public_key
                                .clone(),
                            from_public_key: self.keypair().public.clone(),
                        },
                        payload,
                    };

                    let buffer = encode(&reply).await?;
                    self.tx.send(Message::Binary(buffer)).await?;
                } else if let PairingMessage::Request(device) = message {
                    tracing::debug!("<- device");

                    let account_signer =
                        self.account.account_signer().await?;
                    let account_signing_key = account_signer.to_bytes();
                    let account_signing_key: [u8; 32] =
                        account_signing_key.as_slice().try_into()?;
                    let (device_signer, manager) =
                        self.account.new_device_vault().await?;
                    let device_key_buffer =
                        manager.into_vault_buffer().await?;

                    self.register_device(device_signer.public_key(), device)
                        .await?;

                    let private_message =
                        PairingMessage::Confirm(PairingConfirmation(
                            account_signing_key,
                            device_signer.to_bytes(),
                            device_key_buffer,
                        ));

                    let payload = if let Some(Tunnel::Transport(transport)) =
                        self.tunnel.as_mut()
                    {
                        encrypt(transport, &private_message).await?
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
                        payload,
                    };

                    tracing::debug!("-> private-key");
                    let buffer = encode(&reply).await?;
                    self.tx.send(Message::Binary(buffer)).await?;
                    self.state = PairProtocolState::Done;
                } else {
                    return Err(Error::BadState);
                }
            }
        }

        Ok(())
    }

    async fn register_device(
        &mut self,
        public_key: DevicePublicKey,
        device: DeviceMetaData,
    ) -> Result<()> {
        let trusted_device =
            TrustedDevice::new(public_key, Some(device), None);
        // Trust the other device in our local event log
        let events: Vec<DeviceEvent> =
            vec![DeviceEvent::Trust(trusted_device)];
        {
            let storage = self.account.storage().await?;
            let mut writer = storage.write().await;
            writer.patch_devices_unchecked(events).await?;
        }

        // Send the patch to remote servers
        if let Some(sync_error) = self.account.patch_devices().await {
            return Err(Error::DevicePatchSync(sync_error));
        }

        // Creating a new device vault saves the folder password
        // and therefore updates the identity folder so we need
        // to sync to ensure the other half of the pairing will
        // fetch data that includes the password for the device
        // vault we will send
        let origins = vec![self.share_url.server().clone().into()];
        let options = SyncOptions { origins };
        if let Some(sync_error) =
            self.account.sync_with_options(&options).await
        {
            return Err(Error::EnrollSync(sync_error));
        }

        Ok(())
    }
}

impl<'a> NoiseTunnel for OfferPairing<'a> {
    async fn send(&mut self, message: Message) -> Result<()> {
        Ok(self.tx.send(message).await?)
    }

    fn pairing_public_key(&self) -> &[u8] {
        self.share_url.public_key()
    }

    fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    fn tunnel_mut(&mut self) -> Option<&mut Tunnel> {
        self.tunnel.as_mut()
    }

    fn into_transport_mode(&mut self) -> Result<()> {
        let tunnel = self.tunnel.take().unwrap();
        if let Tunnel::Handshake(state) = tunnel {
            self.tunnel =
                Some(Tunnel::Transport(state.into_transport_mode()?));
        }
        Ok(())
    }
}

/// Accept is the device being paired.
pub struct AcceptPairing<'a> {
    /// Noise session keypair.
    keypair: Keypair,
    /// Current device information.
    device: &'a DeviceMetaData,
    /// URL shared by the offering device.
    share_url: ServerPairUrl,
    /// Noise protocol state.
    tunnel: Option<Tunnel>,
    /// Sink side of the websocket.
    tx: WsSink,
    /// Current state of the protocol.
    state: PairProtocolState,
    /// Data directory for the device enrollment.
    data_dir: Option<PathBuf>,
    /// Device enrollment.
    enrollment: Option<DeviceEnrollment>,
    /// Whether the pairing is inverted.
    is_inverted: bool,
}

impl<'a> AcceptPairing<'a> {
    /// Create a new pairing connection.
    pub async fn new(
        share_url: ServerPairUrl,
        device: &'a DeviceMetaData,
        data_dir: Option<PathBuf>,
    ) -> Result<(AcceptPairing<'a>, WsStream)> {
        let builder = Builder::new(PATTERN.parse()?);
        let keypair = builder.generate_keypair()?;
        Self::new_connection(share_url, device, data_dir, keypair, false)
            .await
    }

    /// Create a new inverted pairing connection.
    pub async fn new_inverted(
        server: Url,
        device: &'a DeviceMetaData,
        data_dir: Option<PathBuf>,
    ) -> Result<(ServerPairUrl, AcceptPairing<'a>, WsStream)> {
        let builder = Builder::new(PATTERN.parse()?);
        let keypair = builder.generate_keypair()?;
        let share_url = ServerPairUrl::new(server, keypair.public.clone());
        let (pairing, stream) = Self::new_connection(
            share_url.clone(),
            device,
            data_dir,
            keypair,
            true,
        )
        .await?;
        Ok((share_url, pairing, stream))
    }

    async fn new_connection(
        share_url: ServerPairUrl,
        device: &'a DeviceMetaData,
        data_dir: Option<PathBuf>,
        keypair: Keypair,
        is_inverted: bool,
    ) -> Result<(AcceptPairing<'a>, WsStream)> {
        let psk = share_url.pre_shared_key().to_vec();
        let tunnel = if is_inverted {
            Builder::new(PATTERN.parse()?)
                .local_private_key(&keypair.private)
                .psk(3, &psk)
                .build_responder()?
        } else {
            Builder::new(PATTERN.parse()?)
                .local_private_key(&keypair.private)
                .remote_public_key(share_url.public_key())
                .psk(3, &psk)
                .build_initiator()?
        };

        let mut request =
            WebSocketRequest::new(share_url.server(), RELAY_PATH)?;
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
                tunnel: Some(Tunnel::Handshake(tunnel)),
                tx,
                state: PairProtocolState::Pending,
                data_dir,
                enrollment: None,
                is_inverted,
            },
            rx,
        ))
    }

    /// Start the event loop and the pairing protocol.
    pub async fn run(
        &mut self,
        stream: WsStream,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) -> Result<()> {
        if !self.is_inverted {
            // Start pairing
            self.noise_send_e().await?;
            self.state = PairProtocolState::Handshake;
        }

        // Run the event loop
        let (offer_tx, mut offer_rx) = mpsc::channel::<RelayPacket>(32);
        let (close_tx, mut close_rx) = mpsc::channel::<()>(1);
        tokio::task::spawn(listen(stream, offer_tx, close_tx));

        loop {
            select! {
                event = offer_rx.recv().fuse() => {
                    if let Some(event) = event {
                        self.incoming(event).await?;
                        if self.is_finished() {
                            break;
                        }
                    }
                }
                event = close_rx.recv().fuse() => {
                    if event.is_some() {
                        break;
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

    /// Determine if the protocol has completed.
    pub fn is_finished(&self) -> bool {
        matches!(&self.state, PairProtocolState::Done)
    }

    /// Take the final device enrollment.
    ///
    /// Errors if the protocol has not reached completion.
    pub fn take_enrollment(self) -> Result<DeviceEnrollment> {
        self.enrollment.ok_or(Error::NoEnrollment)
    }

    /// Process incoming packet.
    async fn incoming(&mut self, packet: RelayPacket) -> Result<()> {
        if packet.header.to_public_key != self.keypair.public {
            return Err(Error::NotForMe);
        }

        let span = span!(Level::DEBUG, "pairing_accept");
        let _enter = span.enter();

        let action = if !self.is_inverted {
            match (&self.state, &packet.payload) {
                (
                    PairProtocolState::Handshake,
                    RelayPayload::Handshake(_, _),
                ) => {
                    let reply = self.noise_send_s(&packet).await?;
                    IncomingAction::Reply(
                        PairProtocolState::PskHandshake,
                        reply,
                    )
                }
                (
                    PairProtocolState::PskHandshake,
                    RelayPayload::Transport(len, buf),
                ) => {
                    if let Some(Tunnel::Transport(transport)) =
                        self.tunnel.as_mut()
                    {
                        IncomingAction::HandleMessage(
                            decrypt(transport, *len, buf.as_slice()).await?,
                        )
                    } else {
                        unreachable!();
                    }
                }
                _ => {
                    return Err(Error::BadState);
                }
            }
        } else {
            match (&self.state, &packet.payload) {
                (
                    PairProtocolState::Pending,
                    RelayPayload::Handshake(_, _),
                ) => {
                    let reply = self.noise_read_e(&packet).await?;
                    IncomingAction::Reply(PairProtocolState::Handshake, reply)
                }
                (
                    PairProtocolState::Handshake,
                    RelayPayload::Handshake(_, _),
                ) => {
                    let reply = self.noise_read_s(&packet).await?;
                    IncomingAction::Reply(
                        PairProtocolState::PskHandshake,
                        reply,
                    )
                }
                (
                    PairProtocolState::PskHandshake,
                    RelayPayload::Transport(len, buf),
                ) => {
                    if let Some(Tunnel::Transport(transport)) =
                        self.tunnel.as_mut()
                    {
                        IncomingAction::HandleMessage(
                            decrypt(transport, *len, buf.as_slice()).await?,
                        )
                    } else {
                        unreachable!();
                    }
                }
                _ => {
                    return Err(Error::BadState);
                }
            }
        };

        match action {
            IncomingAction::Reply(next_state, reply) => {
                self.state = next_state;

                let buffer = encode(&reply).await?;
                self.tx.send(Message::Binary(buffer)).await?;
            }
            IncomingAction::HandleMessage(message) => {
                // When the noise handshake is complete start
                // pairing by sending the trusted device information
                if let PairingMessage::Ready = message {
                    tracing::debug!("<- ready");
                    if let Some(Tunnel::Transport(transport)) =
                        self.tunnel.as_mut()
                    {
                        let private_message =
                            PairingMessage::Request(self.device.clone());
                        let payload =
                            encrypt(transport, &private_message).await?;
                        let reply = RelayPacket {
                            header: RelayHeader {
                                to_public_key: packet
                                    .header
                                    .from_public_key
                                    .to_vec(),
                                from_public_key: self.keypair.public.to_vec(),
                            },
                            payload,
                        };
                        tracing::debug!("-> device");
                        let buffer = encode(&reply).await?;
                        self.tx.send(Message::Binary(buffer)).await?;
                    } else {
                        unreachable!();
                    }
                } else if let PairingMessage::Confirm(confirmation) = message
                {
                    self.create_enrollment(confirmation).await?;
                    self.state = PairProtocolState::Done;
                } else {
                    return Err(Error::BadState);
                }
            }
        }

        Ok(())
    }

    /// Create the device enrollment once pairing is complete.
    ///
    /// Callers can now access the device enrollment using
    /// [AcceptPairing::take_enrollment] and then call
    /// [DeviceEnrollment::fetch_account] to retrieve the
    /// account data.
    async fn create_enrollment(
        &mut self,
        confirmation: PairingConfirmation,
    ) -> Result<()> {
        let PairingConfirmation(
            signing_key,
            device_signing_key_buf,
            device_vault_buffer,
        ) = confirmation;
        let signer: SingleParty = signing_key.try_into()?;
        let server = self.share_url.server().clone();
        let origin: Origin = server.into();
        let data_dir = self.data_dir.clone();
        let enrollment = DeviceEnrollment::new(
            Box::new(signer),
            origin,
            device_signing_key_buf.try_into()?,
            device_vault_buffer,
            data_dir,
        )
        .await?;
        self.enrollment = Some(enrollment);
        Ok(())
    }
}

/// Serialize and encrypt a message.
async fn encrypt<T: Serialize>(
    transport: &mut TransportState,
    message: &T,
) -> crate::client::pairing::Result<RelayPayload> {
    let message = serde_json::to_vec(message)?;
    let body: RelayBody = message.into();
    let body = encode(&body).await?;
    let mut contents = vec![0u8; body.len() + TAGLEN];
    let length = transport.write_message(&body, &mut contents)?;
    Ok(RelayPayload::Transport(length, contents))
}

/// Decrypt a message and deserialize the content.
async fn decrypt<T: DeserializeOwned>(
    transport: &mut TransportState,
    length: usize,
    message: &[u8],
) -> crate::client::pairing::Result<T> {
    let mut contents = vec![0; length];
    transport.read_message(&message[..length], &mut contents)?;
    let body: RelayBody = decode(&contents).await?;
    let message = serde_json::from_slice(body.as_ref())?;
    Ok(message)
}

impl<'a> NoiseTunnel for AcceptPairing<'a> {
    async fn send(&mut self, message: Message) -> Result<()> {
        Ok(self.tx.send(message).await?)
    }

    fn pairing_public_key(&self) -> &[u8] {
        self.share_url.public_key()
    }

    fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    fn tunnel_mut(&mut self) -> Option<&mut Tunnel> {
        self.tunnel.as_mut()
    }

    fn into_transport_mode(&mut self) -> Result<()> {
        let tunnel = self.tunnel.take().unwrap();
        if let Tunnel::Handshake(state) = tunnel {
            self.tunnel =
                Some(Tunnel::Transport(state.into_transport_mode()?));
        }
        Ok(())
    }
}

trait NoiseTunnel {
    /// Send a message.
    async fn send(&mut self, message: Message) -> Result<()>;

    /// Public key of the party that created the pairing URL.
    fn pairing_public_key(&self) -> &[u8];

    /// Noise keypair.
    fn keypair(&self) -> &Keypair;

    /// Noise tunnel state.
    fn tunnel_mut(&mut self) -> Option<&mut Tunnel>;

    /// Update the noise tunnel state.
    fn into_transport_mode(&mut self) -> Result<()>;

    /// Send the first packet of the initial noise handshake.
    async fn noise_send_e(&mut self) -> Result<()> {
        let span = span!(Level::DEBUG, "pairing");
        let _enter = span.enter();

        let buffer = if let Some(Tunnel::Handshake(state)) = self.tunnel_mut()
        {
            let mut buf = [0u8; 1024];
            // -> e
            tracing::debug!("-> e");
            let len = state.write_message(&[], &mut buf)?;
            let message = RelayPacket {
                header: RelayHeader {
                    to_public_key: self.pairing_public_key().to_vec(),
                    from_public_key: self.keypair().public.to_vec(),
                },
                payload: RelayPayload::Handshake(len, buf.to_vec()),
            };
            encode(&message).await?
        } else {
            unreachable!();
        };
        self.send(Message::Binary(buffer)).await?;
        Ok(())
    }

    /// Respond to the first packet of the noise protocol handshake.
    async fn noise_read_e(
        &mut self,
        packet: &RelayPacket,
    ) -> Result<RelayPacket> {
        if let (
            Some(Tunnel::Handshake(state)),
            RelayPayload::Handshake(len, init_msg),
        ) = (self.tunnel_mut(), &packet.payload)
        {
            let mut buf = [0; 1024];
            let mut reply = [0; 1024];
            // <- e
            tracing::debug!("<- e");
            state.read_message(&init_msg[..*len], &mut buf)?;
            // -> e, ee, s, es
            tracing::debug!("-> e, ee, s, es");
            let len = state.write_message(&[], &mut reply)?;
            Ok(RelayPacket {
                header: RelayHeader {
                    to_public_key: packet.header.from_public_key.clone(),
                    from_public_key: self.keypair().public.clone(),
                },
                payload: RelayPayload::Handshake(len, reply.to_vec()),
            })
        } else {
            Err(Error::BadState)
        }
    }

    /// Handle the second packet of the noise protocol handshake
    /// and transition into transport mode.
    async fn noise_send_s(
        &mut self,
        packet: &RelayPacket,
    ) -> Result<RelayPacket> {
        let packet = if let (
            Some(Tunnel::Handshake(state)),
            RelayPayload::Handshake(len, init_msg),
        ) = (self.tunnel_mut(), &packet.payload)
        {
            let mut buf = [0; 1024];
            let mut reply = [0; 1024];
            // <- e, ee, s, es
            tracing::debug!("<- e, ee, s, es");
            state.read_message(&init_msg[..*len], &mut buf)?;
            // -> s, se
            tracing::debug!("-> s, se");
            let len = state.write_message(&[], &mut reply)?;
            Some(RelayPacket {
                header: RelayHeader {
                    to_public_key: packet.header.from_public_key.clone(),
                    from_public_key: self.keypair().public.clone(),
                },
                payload: RelayPayload::Handshake(len, reply.to_vec()),
            })
        } else {
            None
        };

        if let Some(packet) = packet {
            self.into_transport_mode()?;
            Ok(packet)
        } else {
            return Err(Error::BadState);
        }
    }

    /// Handle the final packet of the noise protocol handshake
    /// and transition into transport mode.
    async fn noise_read_s(
        &mut self,
        packet: &RelayPacket,
    ) -> Result<RelayPacket> {
        if let (
            Some(Tunnel::Handshake(state)),
            RelayPayload::Handshake(len, init_msg),
        ) = (self.tunnel_mut(), &packet.payload)
        {
            let mut buf = [0; 1024];
            // <- s, se
            tracing::debug!("<- s, se");
            state.read_message(&init_msg[..*len], &mut buf)?;

            self.into_transport_mode()?;

            let payload = if let Some(Tunnel::Transport(transport)) =
                self.tunnel_mut()
            {
                encrypt(transport, &PairingMessage::Ready).await?
            } else {
                unreachable!();
            };
            Ok(RelayPacket {
                header: RelayHeader {
                    to_public_key: packet.header.from_public_key.clone(),
                    from_public_key: self.keypair().public.clone(),
                },
                payload,
            })
        } else {
            Err(Error::BadState)
        }
    }
}
