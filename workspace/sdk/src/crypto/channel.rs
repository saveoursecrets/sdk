//! Provides an encrypted channel using ECDSA and ECDH.
use super::{csprng, AeadPack, Cipher, DerivedPrivateKey, Nonce, PrivateKey};
use crate::{
    mpc::ProtocolState,
    signer::ecdsa::{verify_signature_address, BoxedEcdsaSigner},
    Error, Result,
};
use async_trait::async_trait;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

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
