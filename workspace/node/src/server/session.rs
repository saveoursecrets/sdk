//! Manages network sessions.
//!
//! To create a session a client makes a request and the server
//! will issue a session offer with the server's public key bytes.
use k256::{
    ecdh::{EphemeralSecret, SharedSecret},
    ecdsa::recoverable,
    EncodedPoint, PublicKey,
};
use rand::Rng;
use sos_core::{address::AddressStr, signer::BoxedSigner};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use uuid::Uuid;
use web3_signature::Signature;

use crate::server::{Error, Result};

/// Default session length in seconds.
const SESSION_LENGTH: u64 = 900;

/// Manages a collection of sessions.
pub struct SessionManager {
    sessions: HashMap<Uuid, Session>,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new() -> Self {
        Self {
            sessions: Default::default(),
        }
    }

    /// Attempt to get a mutable reference to a session.
    pub fn get_mut(&mut self, id: &Uuid) -> Option<&mut Session> {
        self.sessions.get_mut(id)
    }

    /// Offer a new session to a client announcing it has the given
    /// identity.
    ///
    /// Callers can ensure the identity is known to the service before
    /// offering a session.
    pub fn offer(&mut self, identity: AddressStr) -> (Uuid, &Session) {
        let id = Uuid::new_v4();
        let session = Session::new(identity);
        let session = self.sessions.entry(id.clone()).or_insert(session);
        (id, session)
    }

    /// Verify the identity for a session.
    pub fn verify_identity(
        &mut self,
        id: &Uuid,
        signature: Signature,
    ) -> Result<()> {
        let session = self.get_mut(id).ok_or(Error::NoSession)?;
        let message = session.challenge();
        let recoverable: recoverable::Signature = signature.try_into()?;
        let public_key = recoverable.recover_verify_key(message)?;
        let public_key: [u8; 33] =
            public_key.to_bytes().as_slice().try_into()?;
        let address: AddressStr = (&public_key).try_into()?;
        if address == session.identity {
            session.identity_proof = Some(signature);
        } else {
            return Err(Error::BadSessionIdentity)
        }
        Ok(())
    }
}

/// Represents a session.
pub struct Session {
    /// Client identity.
    identity: AddressStr,
    /// Expiry time.
    expires: Instant,
    /// Challenge that the client must sign to prove their identity.
    challenge: [u8; 16],
    /// Signature that proves the client's identity.
    identity_proof: Option<Signature>,
    /// Session secret.
    secret: EphemeralSecret,
    /// Shared session secret.
    shared: Option<SharedSecret>,
}

impl Session {
    /// Create a new server session.
    pub fn new(identity: AddressStr) -> Self {
        let mut rng = &mut rand::thread_rng();
        let challenge: [u8; 16] = rng.gen();
        Self {
            identity,
            challenge,
            identity_proof: None,
            expires: Instant::now() + Duration::from_secs(SESSION_LENGTH),
            secret: EphemeralSecret::random(&mut rand::thread_rng()),
            shared: None,
        }
    }

    /// Get the challenge bytes.
    pub fn challenge(&self) -> &[u8] {
        &self.challenge
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
            return Err(Error::NoSessionIdentity)
        }

        let client_public =
            PublicKey::from_sec1_bytes(public_key_bytes.as_ref())?;
        let shared = self.secret.diffie_hellman(&client_public);
        self.shared = Some(shared);
        Ok(())
    }
}

/// Client side session implementation.
pub struct ClientSession {
    signer: BoxedSigner,
    /// Session identifier.
    id: Uuid,
    /// Session secret.
    secret: EphemeralSecret,
    /// Shared session secret.
    shared: SharedSecret,
}

impl ClientSession {
    /// Create a new client session.
    pub fn new<B: AsRef<[u8]>>(
        signer: BoxedSigner,
        id: Uuid,
        public_key_bytes: B,
    ) -> Result<Self> {
        let secret = EphemeralSecret::random(&mut rand::thread_rng());
        let server_public =
            PublicKey::from_sec1_bytes(public_key_bytes.as_ref())?;
        let shared = secret.diffie_hellman(&server_public);
        Ok(Self {
            signer,
            id,
            secret,
            shared,
        })
    }

    /// Sign the server challenge to prove our identity.
    pub async fn sign<B: AsRef<[u8]>>(
        &self,
        challenge: B,
    ) -> Result<Signature> {
        let signature = self.signer.sign(challenge.as_ref()).await?;
        Ok(signature)
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> Vec<u8> {
        let public_key_bytes = EncodedPoint::from(self.secret.public_key());
        public_key_bytes.as_ref().to_vec()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;
    use k256::ecdsa::SigningKey;
    use sos_core::{
        address::AddressStr,
        signer::{Signer, SingleParty},
    };

    #[tokio::test]
    async fn session_negotiate() -> Result<()> {
        let mut manager = SessionManager::new();

        let client_identity = SigningKey::random(&mut rand::thread_rng());
        let signer = Box::new(SingleParty(client_identity));
        let address = signer.address()?;

        let (session_id, server_session) = manager.offer(address);
        let server_public_key = server_session.public_key();

        // Send the session id, challenge and server public key bytes to the client
        // which will create it's session state
        // ...
        let mut client_session =
            ClientSession::new(signer, session_id, &server_public_key)?;

        let signature =
            client_session.sign(server_session.challenge()).await?;

        // Send the signature to the server to prove our identity
        manager.verify_identity(&session_id, signature)?;

        // Send the session id and client public key bytes to the server
        // which computes it's shared secret
        let server_session = manager.get_mut(&session_id).unwrap();
        server_session.compute_ecdh(client_session.public_key())?;

        assert_eq!(
            server_session.shared.as_ref().unwrap().as_bytes(),
            client_session.shared.as_bytes()
        );

        Ok(())
    }
}
