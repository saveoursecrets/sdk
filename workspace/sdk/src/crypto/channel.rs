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
