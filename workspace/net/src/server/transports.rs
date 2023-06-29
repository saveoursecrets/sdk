//! Manages noise protocol transports with client connections.
use sos_sdk::mpc::ProtocolState;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// Noise transport channel for a client.
pub struct TransportChannel {
    /// Expiry time.
    expires: Instant,
    /// Duration for this session.
    duration_secs: u64,
    /// Determines if this session is allowed to expire.
    keep_alive: bool,
    /// Noise transport.
    protocol: ProtocolState,
}

impl TransportChannel {
    /// Create a new transport channel.
    pub fn new(duration_secs: u64, protocol: ProtocolState) -> Self {
        Self {
            duration_secs,
            expires: Instant::now() + Duration::from_secs(duration_secs),
            keep_alive: false,
            protocol,
        }
    }

    /// Set the keep alive flag for this channel.
    pub fn set_keep_alive(&mut self, keep_alive: bool) {
        self.keep_alive = keep_alive;
    }

    /// Get the keep alive flag for this channel.
    pub fn keep_alive(&self) -> bool {
        self.keep_alive
    }

    /// Refresh this channel.
    ///
    /// Extends the expiry time for this channel from now by the channel
    /// duration given when the channel was created.
    pub fn refresh(&mut self) {
        self.expires =
            Instant::now() + Duration::from_secs(self.duration_secs);
    }

    /// Determine if this channel has expired.
    pub fn expired(&self) -> bool {
        Instant::now() >= self.expires
    }

    /// Determine if this channel is still valid.
    pub fn valid(&self) -> bool {
        Instant::now() < self.expires
    }

    /// Mutable reference to the noise transport protocol state.
    pub fn protocol_mut(&mut self) -> &mut ProtocolState {
        &mut self.protocol
    }
}

/// Manages a collection of noise protocol channels.
pub struct TransportManager {
    channels: HashMap<Vec<u8>, TransportChannel>,
    duration_secs: u64,
}

impl TransportManager {
    /// Create a transport manager using the given duration.
    pub fn new(duration_secs: u64) -> Self {
        Self {
            channels: Default::default(),
            duration_secs,
        }
    }
    
    /// Create a new channel.
    pub fn new_channel(&self, protocol: ProtocolState) -> TransportChannel {
        TransportChannel::new(
            self.duration_secs,
            protocol,
        )
    }

    /// Get the keys of transports that have expired.
    ///
    /// Transports that have been marked with the keep alive
    /// flag are not included.
    pub fn expired_keys(&self) -> Vec<Vec<u8>> {
        self.channels
            .iter()
            .filter(|(_, v)| v.expired() && !v.keep_alive())
            .map(|(k, _)| k.to_vec())
            .collect::<Vec<_>>()
    }

    /// Add a transport channel.
    pub fn add_channel(
        &mut self,
        public_key: Vec<u8>,
        transport: TransportChannel,
    ) {
        self.channels.insert(public_key, transport);
    }

    /// Remove the given channel.
    pub fn remove_channel(
        &mut self,
        public_key: &[u8],
    ) -> Option<TransportChannel> {
        self.channels.remove(public_key)
    }

    /// Attempt to get a mutable reference to a channel.
    pub fn get_mut(
        &mut self,
        public_key: &[u8],
    ) -> Option<&mut TransportChannel> {
        self.channels.get_mut(public_key)
    }
}
