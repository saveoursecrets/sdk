//! Provides an encrypted channel using ECDSA and ECDH.
use super::{csprng, AeadPack, Cipher, DerivedPrivateKey, Nonce, PrivateKey};
use crate::{
    mpc::ProtocolState,
    signer::ecdsa::{verify_signature_address, BoxedEcdsaSigner},
    Error, Result,
};
use async_trait::async_trait;
use crypto_bigint::{CheckedAdd, Encoding, U192};
use k256::{
    ecdh::EphemeralSecret, elliptic_curve::ecdh::SharedSecret, EncodedPoint,
    PublicKey, Secp256k1,
};
use rand::Rng;
use sha3::{Digest, Keccak256};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use uuid::Uuid;
use web3_address::ethereum::Address;
use web3_signature::Signature;

/// Generate a secret key suitable for symmetric encryption.
fn derive_secret_key(
    shared: &SharedSecret<Secp256k1>,
    salt: &[u8],
) -> Result<DerivedPrivateKey> {
    let hkdf = shared.extract::<Keccak256>(Some(salt));
    let mut okm = [0u8; 32];
    hkdf.expand(&[], &mut okm).expect("HKDF length is invalid");
    Ok(DerivedPrivateKey::new(secrecy::Secret::new(okm.to_vec())))
}

/// Manages a collection of sessions.
pub struct SessionManager {
    sessions: HashMap<Uuid, ServerSession>,
    duration_secs: u64,
}

impl SessionManager {
    /// Create a session manager using the given session duration.
    pub fn new(duration_secs: u64) -> Self {
        Self {
            sessions: Default::default(),
            duration_secs,
        }
    }

    /// Get the keys of sessions that have expired.
    ///
    /// Sessions that have been marked with the keep alive
    /// flag are not included.
    pub fn expired_keys(&self) -> Vec<Uuid> {
        self.sessions
            .iter()
            .filter(|(_, v)| v.expired() && !v.keep_alive())
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
    }

    /// Remove the given session.
    pub fn remove_session(&mut self, key: &Uuid) -> Option<ServerSession> {
        self.sessions.remove(key)
    }

    /// Attempt to get a mutable reference to a session.
    pub fn get_mut(&mut self, id: &Uuid) -> Option<&mut ServerSession> {
        self.sessions.get_mut(id)
    }

    /// Offer a new session to a client announcing it has the given
    /// identity.
    ///
    /// Callers can ensure the identity is known to the service before
    /// offering a session.
    pub fn offer(&mut self, identity: Address) -> (Uuid, &ServerSession) {
        let id = Uuid::new_v4();
        let session = ServerSession::new(identity, self.duration_secs);
        let session = self.sessions.entry(id).or_insert(session);
        (id, session)
    }

    /// Verify the identity for a session.
    pub fn verify_identity(
        &mut self,
        id: &Uuid,
        signature: Signature,
    ) -> Result<&mut ServerSession> {
        let session = self.get_mut(id).ok_or(Error::NoSession)?;
        let message = session.challenge();

        let (valid, recovered_key) = verify_signature_address(
            &session.identity,
            signature,
            message.as_slice(),
        )?;

        let public_key = recovered_key.to_encoded_point(true);
        if valid {
            session.identity_proof = Some(signature.to_bytes());
        } else {
            return Err(Error::BadSessionIdentity);
        }

        session.compute_ecdh(public_key.as_bytes())?;

        Ok(session)
    }
}

/// Represents a session.
pub struct ServerSession {
    /// Client identity.
    identity: Address,
    /// Expiry time.
    expires: Instant,
    /// Duration for this session.
    duration_secs: u64,
    /// Random challenge that the client must sign to
    /// prove their identity.
    ///
    /// This is also used as the salt for key derivation.
    challenge: [u8; 16],
    /// Signature that proves the client's identity.
    identity_proof: Option<[u8; 65]>,
    /// Session secret.
    secret: EphemeralSecret,
    /// Derived private key for symmetric encryption.
    private: Option<PrivateKey>,
    /// Number once for session messages.
    nonce: U192,
    /// Determines if this session is allowed to expire.
    keep_alive: bool,
}

impl ServerSession {
    /// Create a new server session.
    pub fn new(identity: Address, duration_secs: u64) -> Self {
        let rng = &mut csprng();
        let challenge: [u8; 16] = rng.gen();

        Self {
            identity,
            challenge,
            duration_secs,
            identity_proof: None,
            expires: Instant::now() + Duration::from_secs(duration_secs),
            secret: EphemeralSecret::random(&mut csprng()),
            private: None,
            nonce: U192::ZERO,
            keep_alive: false,
        }
    }

    /// Get the client identity.
    pub fn identity(&self) -> &Address {
        &self.identity
    }

    /// Get the challenge bytes.
    pub fn challenge(&self) -> [u8; 16] {
        self.challenge
    }

    /// Set the keep alive flag for this session.
    pub fn set_keep_alive(&mut self, keep_alive: bool) {
        self.keep_alive = keep_alive;
    }

    /// Get the keep alive flag for this session.
    pub fn keep_alive(&self) -> bool {
        self.keep_alive
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> Vec<u8> {
        let public_key_bytes = EncodedPoint::from(self.secret.public_key());
        public_key_bytes.as_ref().to_vec()
    }

    /// Compute the shared diffie hellman secret.
    pub fn compute_ecdh<B: AsRef<[u8]>>(
        &mut self,
        public_key_bytes: B,
    ) -> Result<()> {
        if self.identity_proof.is_none() {
            return Err(Error::NoSessionIdentity);
        }

        let client_public =
            PublicKey::from_sec1_bytes(public_key_bytes.as_ref())?;
        let shared = self.secret.diffie_hellman(&client_public);
        let key = derive_secret_key(&shared, self.challenge.as_ref())?;
        self.private = Some(PrivateKey::Symmetric(key));
        Ok(())
    }

    /// Update this session to have the given nonce.
    pub fn set_nonce(&mut self, nonce: &Nonce) {
        let bytes = match nonce {
            Nonce::Nonce24(bytes) => *bytes,
            _ => unreachable!("session got invalid nonce kind"),
        };

        let nonce = U192::from_be_bytes(bytes);
        self.nonce = nonce;
    }

    /// Verify an incoming nonce is greater than the nonce
    /// assigned to this session.
    pub fn verify_nonce(&self, other_nonce: &Nonce) -> Result<()> {
        let bytes = match other_nonce {
            Nonce::Nonce24(bytes) => *bytes,
            _ => unreachable!("session got invalid nonce kind"),
        };

        let other_nonce = U192::from_be_bytes(bytes);
        if other_nonce <= self.nonce {
            Err(Error::BadNonce)
        } else {
            Ok(())
        }
    }

    /// Refresh this session.
    ///
    /// Extends the expiry time for this session from now by the session
    /// duration given when the session was created.
    pub fn refresh(&mut self) {
        self.expires =
            Instant::now() + Duration::from_secs(self.duration_secs);
    }

    /// Determine if this session has expired.
    pub fn expired(&self) -> bool {
        Instant::now() >= self.expires
    }

    /// Determine if this session is still valid.
    pub fn valid(&self) -> bool {
        self.ready() && (Instant::now() < self.expires)
    }
}

impl EncryptedChannel for ServerSession {
    fn private_key(&self) -> Result<&PrivateKey> {
        self.private.as_ref().ok_or(Error::NoSessionKey)
    }

    fn next_nonce(&mut self) -> Result<Nonce> {
        let one = U192::from(1u8);
        self.nonce = self.nonce.checked_add(&one).unwrap();
        let nonce = Nonce::Nonce24(self.nonce.to_be_bytes());
        Ok(nonce)
    }

    fn salt(&self) -> Result<&[u8; 16]> {
        Ok(&self.challenge)
    }
}

/// Client side session implementation.
pub struct ClientSession {
    signer: BoxedEcdsaSigner,
    /// Session identifier.
    id: Uuid,
    /// Challenge created when a session was offered.
    ///
    /// Used as the salt for key derivation.
    challenge: Option<[u8; 16]>,
    /// Session secret.
    secret: EphemeralSecret,
    /// Private key for symmetric encryption.
    private: Option<PrivateKey>,
    /// Number once for session messages.
    nonce: U192,
}

impl ClientSession {
    /// Create a new client session.
    pub fn new(signer: BoxedEcdsaSigner, id: Uuid) -> Result<Self> {
        let secret = EphemeralSecret::random(&mut csprng());
        Ok(Self {
            signer,
            id,
            challenge: None,
            secret,
            private: None,
            nonce: U192::ZERO,
        })
    }

    /// Get the session identifier.
    pub fn id(&self) -> &Uuid {
        &self.id
    }

    /// Sign the server challenge to prove our identity
    /// and generate the private key for symmetric encryption.
    pub async fn sign(
        &mut self,
        public_key_bytes: &[u8],
        challenge: [u8; 16],
    ) -> Result<(Signature, PrivateKey)> {
        let server_public = PublicKey::from_sec1_bytes(public_key_bytes)?;
        let shared = self.secret.diffie_hellman(&server_public);
        let signature = self.signer.sign(&challenge).await?;
        let derived_key = derive_secret_key(&shared, challenge.as_ref())?;
        self.challenge = Some(challenge);
        Ok((signature, PrivateKey::Symmetric(derived_key)))
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> Vec<u8> {
        let public_key_bytes = EncodedPoint::from(self.secret.public_key());
        public_key_bytes.as_ref().to_vec()
    }

    /// Update this session to have the given nonce.
    pub fn set_nonce(&mut self, nonce: &Nonce) {
        let bytes = match nonce {
            Nonce::Nonce24(bytes) => *bytes,
            _ => unreachable!("session got invalid nonce kind"),
        };
        let nonce = U192::from_be_bytes(bytes);
        self.nonce = nonce;
    }

    /// Complete the session negotiation.
    pub fn finish(&mut self, key: PrivateKey) {
        self.private = Some(key);
    }
}

impl EncryptedChannel for ClientSession {
    fn private_key(&self) -> Result<&PrivateKey> {
        self.private.as_ref().ok_or(Error::NoSessionKey)
    }

    fn next_nonce(&mut self) -> Result<Nonce> {
        let one = U192::from(1u8);
        self.nonce = self.nonce.checked_add(&one).unwrap();
        let nonce = Nonce::Nonce24(self.nonce.to_be_bytes());
        Ok(nonce)
    }

    fn salt(&self) -> Result<&[u8; 16]> {
        self.challenge.as_ref().ok_or(Error::NoSessionSalt)
    }
}

/// Cryptographic operations for both sides of session communication.
#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait EncryptedChannel {
    /// Get the private key for the session.
    fn private_key(&self) -> Result<&PrivateKey>;

    /// Increment and return the next sequential nonce.
    fn next_nonce(&mut self) -> Result<Nonce>;

    /// Get the challenge/salt for the session.
    fn salt(&self) -> Result<&[u8; 16]>;

    /// Get the bytes used to create a signature for the message.
    ///
    /// This is the challenge (or salt) concatenated with the
    /// nonce for the message.
    fn sign_bytes<H: Digest>(&self, nonce: &Nonce) -> Result<[u8; 32]> {
        let nonce_bytes = match nonce {
            Nonce::Nonce24(bytes) => bytes,
            _ => unreachable!("session got invalid nonce kind"),
        };

        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(self.salt()?);
        bytes.extend_from_slice(nonce_bytes);

        let digest: [u8; 32] = H::digest(&bytes).as_slice().try_into()?;
        Ok(digest)
    }

    /// Encrypt a message.
    async fn encrypt(&mut self, message: &[u8]) -> Result<AeadPack> {
        let nonce = self.next_nonce()?;
        let key = self.private_key()?;
        Cipher::XChaCha20Poly1305
            .encrypt_symmetric(key, message, Some(nonce))
            .await
    }

    /// Decrypt a message.
    async fn decrypt(&self, aead: &AeadPack) -> Result<Vec<u8>> {
        let key = self.private_key()?;
        Cipher::XChaCha20Poly1305.decrypt_symmetric(key, aead).await
    }

    /// Determine if this session is ready.
    fn ready(&self) -> bool {
        self.private_key().ok().is_some()
    }
}

/// Represents a server transport.
pub struct ServerTransport {
    /// Expiry time.
    expires: Instant,
    /// Duration for this session.
    duration_secs: u64,
    /// Determines if this session is allowed to expire.
    keep_alive: bool,
    /// Noise transport.
    protocol: ProtocolState,
}

impl ServerTransport {
    /// Create a new server session.
    pub fn new(duration_secs: u64, protocol: ProtocolState) -> Self {
        Self {
            duration_secs,
            expires: Instant::now() + Duration::from_secs(duration_secs),
            keep_alive: false,
            protocol,
        }
    }

    /// Set the keep alive flag for this session.
    pub fn set_keep_alive(&mut self, keep_alive: bool) {
        self.keep_alive = keep_alive;
    }

    /// Get the keep alive flag for this session.
    pub fn keep_alive(&self) -> bool {
        self.keep_alive
    }

    /// Refresh this session.
    ///
    /// Extends the expiry time for this session from now by the session
    /// duration given when the session was created.
    pub fn refresh(&mut self) {
        self.expires =
            Instant::now() + Duration::from_secs(self.duration_secs);
    }

    /// Determine if this session has expired.
    pub fn expired(&self) -> bool {
        Instant::now() >= self.expires
    }

    /// Determine if this session is still valid.
    pub fn valid(&self) -> bool {
        Instant::now() < self.expires
    }

    /// Mutable reference to the transport protocol.
    pub fn protocol_mut(&mut self) -> &mut ProtocolState {
        &mut self.protocol
    }
}

/// Manages a collection of noise protocol sessions.
pub struct ServerTransportManager {
    sessions: HashMap<Vec<u8>, ServerTransport>,
    duration_secs: u64,
}

impl ServerTransportManager {
    /// Create a session manager using the given session duration.
    pub fn new(duration_secs: u64) -> Self {
        Self {
            sessions: Default::default(),
            duration_secs,
        }
    }

    /// Get the keys of transports that have expired.
    ///
    /// Transports that have been marked with the keep alive
    /// flag are not included.
    pub fn expired_keys(&self) -> Vec<Vec<u8>> {
        self.sessions
            .iter()
            .filter(|(_, v)| v.expired() && !v.keep_alive())
            .map(|(k, _)| k.to_vec())
            .collect::<Vec<_>>()
    }

    /// Add a session.
    pub fn add_session(
        &mut self,
        public_key: Vec<u8>,
        transport: ServerTransport,
    ) {
        self.sessions.insert(public_key, transport);
    }

    /// Remove the given session.
    pub fn remove_session(
        &mut self,
        public_key: &[u8],
    ) -> Option<ServerTransport> {
        self.sessions.remove(public_key)
    }

    /// Attempt to get a mutable reference to a session.
    pub fn get_mut(
        &mut self,
        public_key: &[u8],
    ) -> Option<&mut ServerTransport> {
        self.sessions.get_mut(public_key)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::signer::ecdsa::{BoxedEcdsaSigner, SingleParty};
    use anyhow::Result;
    use k256::ecdsa::SigningKey;
    use std::time::Duration;

    fn new_signer() -> BoxedEcdsaSigner {
        let client_identity = SigningKey::random(&mut csprng());
        Box::new(SingleParty(client_identity))
    }

    #[tokio::test]
    async fn session_negotiate() -> Result<()> {
        let mut manager = SessionManager::new(60);

        // Client sends a request to generate an authenticated
        // session by sending it's signing address
        // ...
        let signer = new_signer();
        let address = signer.address()?;

        let (session_id, server_session) = manager.offer(address);
        let server_public_key = server_session.public_key();

        // Send the session id, challenge and server public key
        // bytes to the client which will create it's session state
        // ...
        let mut client_session = ClientSession::new(signer, session_id)?;
        let (signature, client_key) = client_session
            .sign(&server_public_key, server_session.challenge())
            .await?;

        assert_eq!(U192::from(0u8), client_session.nonce);

        // Send the session id, signature and client public key
        // bytes to the server which computes it's shared secret
        // ...
        let server_session =
            manager.verify_identity(&session_id, signature)?;
        server_session.compute_ecdh(client_session.public_key())?;

        client_session.finish(client_key);

        assert_eq!(U192::from(0u8), server_session.nonce);

        // Encrypt on the client, send to the server and
        // decrypt on the server
        let message = b"client sent message";
        let aead = client_session.encrypt(message).await?;
        server_session.set_nonce(&aead.nonce);
        let bytes = server_session.decrypt(&aead).await?;

        assert_eq!(message.as_ref(), &bytes);
        assert_eq!(U192::from(1u8), client_session.nonce);
        assert_eq!(U192::from(1u8), server_session.nonce);

        // Encrypt on the server, send to the client and
        // decrypt on the client
        let message = b"server sent message";
        let aead = server_session.encrypt(message).await?;
        client_session.set_nonce(&aead.nonce);
        let bytes = client_session.decrypt(&aead).await?;

        assert_eq!(message.as_ref(), &bytes);
        assert_eq!(U192::from(2u8), client_session.nonce);
        assert_eq!(U192::from(2u8), server_session.nonce);

        // Encrypt on the client, send to the server and
        // decrypt on the server
        let message = b"client sent message with another nonce";
        let aead = client_session.encrypt(message).await?;
        server_session.set_nonce(&aead.nonce);
        let bytes = server_session.decrypt(&aead).await?;

        assert_eq!(message.as_ref(), &bytes);
        assert_eq!(U192::from(3u8), client_session.nonce);
        assert_eq!(U192::from(3u8), server_session.nonce);

        // Encrypt on the server, send to the client and
        // decrypt on the client
        let message = b"server sent message with another nonce";
        let aead = server_session.encrypt(message).await?;
        client_session.set_nonce(&aead.nonce);
        let bytes = client_session.decrypt(&aead).await?;

        assert_eq!(message.as_ref(), &bytes);
        assert_eq!(U192::from(4u8), client_session.nonce);
        assert_eq!(U192::from(4u8), server_session.nonce);

        Ok(())
    }

    #[tokio::test]
    async fn session_expired() -> Result<()> {
        // Create a manager that will expire sessions after a second.
        let mut manager = SessionManager::new(1);

        let signer = new_signer();
        let address = signer.address()?;

        // Generate a session
        let (_session_id, server_session) = manager.offer(address);

        assert!(!server_session.ready());

        // Wait for the session to expire
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify expiry
        assert!(server_session.expired());

        Ok(())
    }
}
