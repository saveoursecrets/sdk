//! Manages network sessions.
use crypto_bigint::{CheckedAdd, Encoding, U192};
use k256::{
    ecdh::EphemeralSecret, ecdsa::recoverable,
    elliptic_curve::ecdh::SharedSecret, EncodedPoint, PublicKey, Secp256k1,
};
use rand::Rng;
use sha3::Keccak256;
use sos_core::{
    address::AddressStr,
    crypto::{secret_key::SecretKey, xchacha20poly1305, AeadPack, Nonce},
    signer::BoxedSigner,
};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use uuid::Uuid;
use web3_signature::Signature;

use crate::{Error, Result};

/// Default session length in seconds.
const SESSION_LENGTH: u64 = 900;

/// Generate a secret key suitable for symmetric encryption.
fn derive_secret_key(
    shared: &SharedSecret<Secp256k1>,
    salt: &[u8],
) -> Result<SecretKey> {
    let hkdf = shared.extract::<Keccak256>(Some(salt));
    let mut okm = [0u8; 32];
    hkdf.expand(&[], &mut okm).expect("HKDF length is invalid");
    Ok(SecretKey::Key32(secrecy::Secret::new(okm)))
}

/// Manages a collection of sessions.
#[derive(Default)]
pub struct SessionManager {
    sessions: HashMap<Uuid, ServerSession>,
}

impl SessionManager {
    /// Attempt to get a session.
    pub fn get(&self, id: &Uuid) -> Option<&ServerSession> {
        self.sessions.get(id)
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
    pub fn offer(&mut self, identity: AddressStr) -> (Uuid, &ServerSession) {
        let id = Uuid::new_v4();
        let session = ServerSession::new(identity);
        let session = self.sessions.entry(id.clone()).or_insert(session);
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
        let recoverable: recoverable::Signature = signature.try_into()?;
        let public_key = recoverable.recover_verifying_key(&message)?;
        let public_key: [u8; 33] =
            public_key.to_bytes().as_slice().try_into()?;
        let address: AddressStr = (&public_key).try_into()?;
        if address == session.identity {
            session.identity_proof = Some(signature.to_bytes());
        } else {
            return Err(Error::BadSessionIdentity);
        }

        session.compute_ecdh(public_key)?;

        Ok(session)
    }
}

/// Represents a session.
pub struct ServerSession {
    /// Client identity.
    identity: AddressStr,
    /// Expiry time.
    expires: Instant,
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
    private: Option<SecretKey>,
    /// Number once for session messages.
    nonce: U192,
}

impl ServerSession {
    /// Create a new server session.
    pub fn new(identity: AddressStr) -> Self {
        let rng = &mut rand::thread_rng();
        let challenge: [u8; 16] = rng.gen();

        Self {
            identity,
            challenge,
            identity_proof: None,
            expires: Instant::now() + Duration::from_secs(SESSION_LENGTH),
            secret: EphemeralSecret::random(&mut rand::thread_rng()),
            private: None,
            nonce: U192::ZERO,
        }
    }

    /// Get the client identity.
    pub fn identity(&self) -> &AddressStr {
        &self.identity
    }

    /// Get the challenge bytes.
    pub fn challenge(&self) -> [u8; 16] {
        self.challenge
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
        self.private = Some(key);
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

    /// Determine if this session is still valid.
    pub fn valid(&self) -> bool {
        self.ready() && (Instant::now() < self.expires)
    }
}

impl EncryptedChannel for ServerSession {
    fn private_key(&self) -> Result<&SecretKey> {
        Ok(self.private.as_ref().ok_or(Error::NoSessionKey)?)
    }

    fn next_nonce(&mut self) -> Result<Nonce> {
        let one = U192::from(1u8);
        self.nonce = self.nonce.checked_add(&one).unwrap();
        let nonce = Nonce::Nonce24(self.nonce.to_be_bytes());
        Ok(nonce)
    }
}

/// Client side session implementation.
pub struct ClientSession {
    signer: BoxedSigner,
    /// Session identifier.
    id: Uuid,
    /// Session secret.
    secret: EphemeralSecret,
    /// Derived private key for symmetric encryption.
    private: Option<SecretKey>,
    /// Number once for session messages.
    nonce: U192,
}

impl ClientSession {
    /// Create a new client session.
    pub fn new(signer: BoxedSigner, id: Uuid) -> Result<Self> {
        let secret = EphemeralSecret::random(&mut rand::thread_rng());
        Ok(Self {
            signer,
            id,
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
    ) -> Result<(Signature, SecretKey)> {
        let server_public =
            PublicKey::from_sec1_bytes(public_key_bytes.as_ref())?;
        let shared = self.secret.diffie_hellman(&server_public);
        let signature = self.signer.sign(&challenge).await?;
        let key = derive_secret_key(&shared, challenge.as_ref())?;
        Ok((signature, key))
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
    pub fn finish(&mut self, key: SecretKey) {
        self.private = Some(key);
    }
}

impl EncryptedChannel for ClientSession {
    fn private_key(&self) -> Result<&SecretKey> {
        Ok(self.private.as_ref().ok_or(Error::NoSessionKey)?)
    }

    fn next_nonce(&mut self) -> Result<Nonce> {
        let one = U192::from(1u8);
        self.nonce = self.nonce.checked_add(&one).unwrap();
        let nonce = Nonce::Nonce24(self.nonce.to_be_bytes());
        Ok(nonce)
    }
}

/// Cryptographic operations for both sides of session communication.
pub trait EncryptedChannel {
    /// Get the private key for the session.
    fn private_key(&self) -> Result<&SecretKey>;

    /// Increment and return the next sequential nonce.
    fn next_nonce(&mut self) -> Result<Nonce>;

    /// Encrypt a message.
    fn encrypt(&mut self, message: &[u8]) -> Result<AeadPack> {
        let nonce = self.next_nonce()?;
        let key = self.private_key()?;
        Ok(xchacha20poly1305::encrypt(key, message, Some(nonce))?)
    }

    /// Decrypt a message.
    fn decrypt(&self, aead: &AeadPack) -> Result<Vec<u8>> {
        let key = self.private_key()?;
        Ok(xchacha20poly1305::decrypt(key, aead)?)
    }

    /// Determine if this session is ready.
    fn ready(&self) -> bool {
        self.private_key().ok().is_some()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;
    use k256::ecdsa::SigningKey;
    use sos_core::signer::{Signer, SingleParty};

    #[tokio::test]
    async fn session_negotiate() -> Result<()> {
        let mut manager: SessionManager = Default::default();

        // Client sends a request to generate an authenticated
        // session by sending it's signing address
        // ...
        let client_identity = SigningKey::random(&mut rand::thread_rng());
        let signer = Box::new(SingleParty(client_identity));
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
        let aead = client_session.encrypt(message)?;
        server_session.set_nonce(&aead.nonce);
        let bytes = server_session.decrypt(&aead)?;

        assert_eq!(message.as_ref(), &bytes);
        assert_eq!(U192::from(1u8), client_session.nonce);
        assert_eq!(U192::from(1u8), server_session.nonce);

        // Encrypt on the server, send to the client and
        // decrypt on the client
        let message = b"server sent message";
        let aead = server_session.encrypt(message)?;
        client_session.set_nonce(&aead.nonce);
        let bytes = client_session.decrypt(&aead)?;

        assert_eq!(message.as_ref(), &bytes);
        assert_eq!(U192::from(2u8), client_session.nonce);
        assert_eq!(U192::from(2u8), server_session.nonce);

        // Encrypt on the client, send to the server and
        // decrypt on the server
        let message = b"client sent message with another nonce";
        let aead = client_session.encrypt(message)?;
        server_session.set_nonce(&aead.nonce);
        let bytes = server_session.decrypt(&aead)?;

        assert_eq!(message.as_ref(), &bytes);
        assert_eq!(U192::from(3u8), client_session.nonce);
        assert_eq!(U192::from(3u8), server_session.nonce);

        // Encrypt on the server, send to the client and
        // decrypt on the client
        let message = b"server sent message with another nonce";
        let aead = server_session.encrypt(message)?;
        client_session.set_nonce(&aead.nonce);
        let bytes = client_session.decrypt(&aead)?;

        assert_eq!(message.as_ref(), &bytes);
        assert_eq!(U192::from(4u8), client_session.nonce);
        assert_eq!(U192::from(4u8), server_session.nonce);

        Ok(())
    }
}
