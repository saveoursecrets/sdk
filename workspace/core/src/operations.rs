//! Encoding of the vault operations so that local changes 
//! to an in-memory representation of a vault can be sent 
//! to a remote server.

use serde::{Deserialize, Serialize};
use serde_binary::{
    Decode, Deserializer, Encode, Error as BinaryError, Result as BinaryResult,
    Serializer,
};
use k256::{
    ecdsa::signature::Signature,
};
use uuid::Uuid;

use crate::{
    Error, Result,
    crypto::AeadPack,
    vault::encode,
    signer::Signer,
};

/// Payload sent to a remote server.
pub enum Payload {
    /// Update the vault meta data.
    UpdateMeta(AeadPack),

    /// Create a secret.
    CreateSecret(Uuid, (AeadPack, AeadPack)),

    /// Read a secret.
    ReadSecret(Uuid),

    /// Update a secret.
    UpdateSecret(Uuid, (AeadPack, AeadPack)),

    /// Delete a secret.
    DeleteSecret(Uuid),
}

impl Payload {
    /// Append a signature to a payload.
    pub async fn sign(&self, signer: impl Signer) -> Result<SignedPayload> {
        let encoded = encode(self)?;
        let signature = signer.sign(&encoded).await?;
        let signature_bytes: [u8; 65] = signature.as_bytes().try_into()?;
        Ok(SignedPayload(signature_bytes, encoded))
    }
}

/// Payload with an attached signature.
pub struct SignedPayload([u8; 65], Vec<u8>);

impl Encode for SignedPayload {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        ser.writer.write_bytes(&self.0)?;
        ser.writer.write_u32(self.1.len() as u32)?;
        ser.writer.write_bytes(&self.1)?;
        Ok(())
    }
}

impl Decode for SignedPayload {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let signature = de.reader.read_bytes(65)?;
        let length = de.reader.read_u32()?;
        let payload = de.reader.read_bytes(length as usize)?;
        let signature: [u8; 65] = signature.as_slice().try_into()?;
        *self = SignedPayload(signature, payload);
        Ok(())
    }
}

/// Constants for the types of payload.
pub mod types {
    /// Type identifier for the update meta operation.
    pub const UPDATE_META: u8 = 0x1;

    /// Type identifier for the create secret operation.
    pub const CREATE_SECRET: u8 = 0x2;

    /// Type identifier for the read secret operation.
    pub const READ_SECRET: u8 = 0x3;

    /// Type identifier for the update secret operation.
    pub const UPDATE_SECRET: u8 = 0x4;

    /// Type identifier for the delete secret operation.
    pub const DELETE_SECRET: u8 = 0x5;
}

impl Encode for Payload {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        match self {
            Payload::UpdateMeta(meta) => {
                ser.writer.write_u8(types::UPDATE_META)?;
                meta.encode(&mut *ser)?;
            }
            Payload::CreateSecret(uuid, (meta_aead, secret_aead)) => {
                ser.writer.write_u8(types::CREATE_SECRET)?;
                uuid.serialize(&mut *ser)?;
                meta_aead.encode(&mut *ser)?;
                secret_aead.encode(&mut *ser)?;
            }
            Payload::ReadSecret(uuid) => {
                ser.writer.write_u8(types::READ_SECRET)?;
                uuid.serialize(&mut *ser)?;
            }
            Payload::UpdateSecret(uuid, (meta_aead, secret_aead)) => {
                ser.writer.write_u8(types::UPDATE_SECRET)?;
                uuid.serialize(&mut *ser)?;
                meta_aead.encode(&mut *ser)?;
                secret_aead.encode(&mut *ser)?;
            }
            Payload::DeleteSecret(uuid) => {
                ser.writer.write_u8(types::DELETE_SECRET)?;
                uuid.serialize(&mut *ser)?;
            }
        }
        Ok(())
    }
}

impl Decode for Payload {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let kind = de.reader.read_u8()?;
        match kind {
            types::UPDATE_META => {
                let mut aead_pack: AeadPack = Default::default();
                aead_pack.decode(&mut *de)?;
                *self = Payload::UpdateMeta(aead_pack);
            }
            types::CREATE_SECRET => {
                let uuid: Uuid = Deserialize::deserialize(&mut *de)?;
                let mut meta_aead: AeadPack = Default::default();
                meta_aead.decode(&mut *de)?;
                let mut secret_aead: AeadPack = Default::default();
                secret_aead.decode(&mut *de)?;
                *self = Payload::CreateSecret(uuid, (meta_aead, secret_aead));
            }
            types::READ_SECRET => {
                let uuid: Uuid = Deserialize::deserialize(&mut *de)?;
                *self = Payload::ReadSecret(uuid);
            }
            types::UPDATE_SECRET => {
                let uuid: Uuid = Deserialize::deserialize(&mut *de)?;
                let mut meta_aead: AeadPack = Default::default();
                meta_aead.decode(&mut *de)?;
                let mut secret_aead: AeadPack = Default::default();
                secret_aead.decode(&mut *de)?;
                *self = Payload::CreateSecret(uuid, (meta_aead, secret_aead));
            }
            types::DELETE_SECRET => {
                let uuid: Uuid = Deserialize::deserialize(&mut *de)?;
                *self = Payload::ReadSecret(uuid);
            }
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownPayloadKind(kind),
                )))
            }
        }
        Ok(())
    }
}
