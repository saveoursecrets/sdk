//! Encoding of the vault operations so that local changes
//! to an in-memory representation of a vault can be sent
//! to a remote server.

use serde::{Deserialize, Serialize};
use serde_binary::{
    Decode, Deserializer, Encode, Error as BinaryError, Result as BinaryResult,
    Serializer,
};
use std::borrow::Cow;
use uuid::Uuid;

use crate::{crypto::AeadPack, signer::Signer, vault::encode, Error, Result};

/// Payload sent to a remote server.
#[derive(Serialize, Deserialize)]
pub enum Payload<'a> {
    /// Update the vault meta data.
    UpdateVault(Cow<'a, Option<AeadPack>>),

    /// Create a secret.
    CreateSecret(Uuid, Cow<'a, (AeadPack, AeadPack)>),

    /// Read a secret.
    ReadSecret(Uuid),

    /// Update a secret.
    UpdateSecret(Uuid, Cow<'a, (AeadPack, AeadPack)>),

    /// Delete a secret.
    DeleteSecret(Uuid),
}

/// Payload with an attached signature.
pub struct SignedPayload([u8; 65], Vec<u8>);

impl<'a> Payload<'a> {
    /// Append a signature to a payload.
    pub async fn sign(&self, signer: impl Signer) -> Result<SignedPayload> {
        let encoded = encode(self)?;
        let signature = signer.sign(&encoded).await?;
        let signature_bytes: [u8; 65] = signature.to_bytes();
        Ok(SignedPayload(signature_bytes, encoded))
    }
}

/// Constants for the types of operations.
pub mod types {
    /// Type identifier for the create account operation.
    pub const CREATE_ACCOUNT: u8 = 0x01;

    /// Type identifier for the delete account operation.
    pub const DELETE_ACCOUNT: u8 = 0x02;

    /// Type identifier for the create vault operation.
    pub const CREATE_VAULT: u8 = 0x03;

    /// Type identifier for the create vault operation.
    pub const READ_VAULT: u8 = 0x04;

    /// Type identifier for the update vault operation.
    pub const UPDATE_VAULT: u8 = 0x05;

    /// Type identifier for the delete vault operation.
    pub const DELETE_VAULT: u8 = 0x06;

    /// Type identifier for the create secret operation.
    pub const CREATE_SECRET: u8 = 0x07;

    /// Type identifier for the read secret operation.
    pub const READ_SECRET: u8 = 0x08;

    /// Type identifier for the update secret operation.
    pub const UPDATE_SECRET: u8 = 0x09;

    /// Type identifier for the delete secret operation.
    pub const DELETE_SECRET: u8 = 0x0A;
}

impl<'a> Encode for Payload<'a> {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        match self {
            Payload::UpdateVault(meta) => {
                ser.writer.write_u8(types::UPDATE_VAULT)?;
                ser.writer.write_bool(meta.is_some())?;
                if let Cow::Borrowed(Some(meta)) = meta {
                    meta.encode(&mut *ser)?;
                }
            }
            Payload::CreateSecret(
                uuid,
                Cow::Borrowed((meta_aead, secret_aead)),
            ) => {
                ser.writer.write_u8(types::CREATE_SECRET)?;
                uuid.serialize(&mut *ser)?;
                meta_aead.encode(&mut *ser)?;
                secret_aead.encode(&mut *ser)?;
            }

            Payload::CreateSecret(_uuid, Cow::Owned(_)) => {
                unreachable!("cannot encode owned payload")
            }
            Payload::ReadSecret(uuid) => {
                ser.writer.write_u8(types::READ_SECRET)?;
                uuid.serialize(&mut *ser)?;
            }
            Payload::UpdateSecret(
                uuid,
                Cow::Borrowed((meta_aead, secret_aead)),
            ) => {
                ser.writer.write_u8(types::UPDATE_SECRET)?;
                uuid.serialize(&mut *ser)?;
                meta_aead.encode(&mut *ser)?;
                secret_aead.encode(&mut *ser)?;
            }
            Payload::UpdateSecret(_uuid, Cow::Owned(_)) => {
                unreachable!("cannot encode owned payload")
            }
            Payload::DeleteSecret(uuid) => {
                ser.writer.write_u8(types::DELETE_SECRET)?;
                uuid.serialize(&mut *ser)?;
            }
        }
        Ok(())
    }
}

impl<'a> Decode for Payload<'a> {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let kind = de.reader.read_u8()?;
        match kind {
            types::UPDATE_VAULT => {
                let has_meta = de.reader.read_bool()?;
                let aead_pack = if has_meta {
                    let mut aead_pack: AeadPack = Default::default();
                    aead_pack.decode(&mut *de)?;
                    Some(aead_pack)
                } else {
                    None
                };
                *self = Payload::UpdateVault(Cow::Owned(aead_pack));
            }
            types::CREATE_SECRET => {
                let uuid: Uuid = Deserialize::deserialize(&mut *de)?;
                let mut meta_aead: AeadPack = Default::default();
                meta_aead.decode(&mut *de)?;
                let mut secret_aead: AeadPack = Default::default();
                secret_aead.decode(&mut *de)?;
                *self = Payload::CreateSecret(
                    uuid,
                    Cow::Owned((meta_aead, secret_aead)),
                );
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
                *self = Payload::UpdateSecret(
                    uuid,
                    Cow::Owned((meta_aead, secret_aead)),
                );
            }
            types::DELETE_SECRET => {
                let uuid: Uuid = Deserialize::deserialize(&mut *de)?;
                *self = Payload::DeleteSecret(uuid);
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
