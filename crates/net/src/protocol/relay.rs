include!(concat!(env!("OUT_DIR"), "/relay.rs"));

// Must match the protobuf enum variants
const HANDSHAKE: &str = "Handshake";
const TRANSPORT: &str = "Transport";

impl RelayPacket {
    /// Determine if this packet is in a handshake state.
    pub fn is_handshake(&self) -> bool {
        self.payload.as_ref().unwrap().is_handshake()
    }
}

impl RelayPayload {
    /// Create a new handshake payload.
    pub fn new_handshake(length: usize, contents: Vec<u8>) -> Self {
        Self {
            kind: RelayType::from_str_name(HANDSHAKE).unwrap() as i32,
            body: Some(RelayBody {
                length: length as u32,
                contents,
            }),
        }
    }

    /// Create a new transport payload.
    pub fn new_transport(length: usize, contents: Vec<u8>) -> Self {
        Self {
            kind: RelayType::from_str_name(TRANSPORT).unwrap() as i32,
            body: Some(RelayBody {
                length: length as u32,
                contents,
            }),
        }
    }

    /// Determine if this payload is in a handshake state.
    pub fn is_handshake(&self) -> bool {
        let kind: RelayType = self.kind.try_into().unwrap();
        kind.as_str_name() == HANDSHAKE
    }
}
