include!(concat!(env!("OUT_DIR"), "/relay.rs"));

use crate::protocol::{ProtoMessage, Result};

// Must match the protobuf enum variants
const HANDSHAKE: &str = "Handshake";
const TRANSPORT: &str = "Transport";

impl RelayPacket {
    /// Determine if this packet is in a handshake state.
    pub fn is_handshake(&self) -> bool {
        self.payload.as_ref().unwrap().is_handshake()
    }

    /// Encode a packet prefixed with the target public key.
    #[cfg(feature = "client")]
    pub(crate) async fn encode_prefixed(self) -> Result<Vec<u8>> {
        let mut recipient =
            self.header.as_ref().unwrap().to_public_key.clone();
        let key_length = recipient.len() as u16;
        let length_bytes = key_length.to_le_bytes();
        let mut message = self.encode_proto().await?;

        let mut encoded = Vec::new();
        encoded.extend_from_slice(&length_bytes);
        encoded.append(&mut recipient);
        encoded.append(&mut message);

        Ok(encoded)
    }

    /// Decode an encoded packet into a public key and
    /// protobuf packet bytes.
    #[cfg(feature = "server")]
    pub(crate) fn decode_split(
        packet: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        use crate::protocol::Error;
        let amount = std::mem::size_of::<u16>();
        if packet.len() > amount {
            let key_length = &packet[0..amount];
            let key_length: [u8; 2] = key_length.try_into().unwrap();
            let key_length = u16::from_le_bytes(key_length);
            if packet.len() > key_length as usize + amount {
                let boundary = key_length as usize + amount;
                let public_key = &packet[amount..boundary];
                let public_key = public_key.to_vec();
                let message_len = packet.len() - boundary;

                let mut message = Vec::new();
                message.reserve(message_len);
                message.extend_from_slice(&packet[boundary..]);

                Ok((public_key, message))
            } else {
                Err(Error::EndOfFile)
            }
        } else {
            Err(Error::EndOfFile)
        }
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
