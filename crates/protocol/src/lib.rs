#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Networking and sync protocol types for [Save Our Secrets](https://saveoursecrets.com).
//!
//! When the `account` feature is enabled [SyncStorage] will be
//! implemented for `LocalAccount`.

// There are two layers to the types in this module; the wire
// types which are defined in the protobuf files are prefixed
// with `Wire` and then there are the binding types.
//
// Each binding type wraps an inner wire type and converts
// infallibly to the inner wire type and fallibly from
// the inner wire type which allows us to convert between
// the limited protobuf types and the enforced optionality
// of protobufs.
//
// Encoding and decoding is provided by a blanket implementation
// so that we can provide `encode()` and `decode()` functions for
// types declared in the SDK library.
//
// A 64-bit machine is assumed as we cast between `u64` and `usize`
// for convenience, the code may panic on 32-bit machines.

mod bindings;
mod error;
#[cfg(feature = "integration")]
pub mod integration;
pub mod local_transport;
mod sync;
mod traits;

#[cfg(any(feature = "files", feature = "listen"))]
pub mod transfer;

pub use bindings::*;
pub use error::{AsConflict, ConflictError, Error};
use sos_sdk::{
    events::{EventLogExt, EventRecord, FolderReducer},
    prelude::Account,
    storage::ClientStorage,
};
pub use sync::*;
pub use traits::*;

use prost::{bytes::Buf, Message};

#[cfg(test)]
mod tests;

pub use sos_sdk as sdk;

use std::sync::Arc;
use tokio::sync::RwLock;

/// Result type for the wire protocol.
pub type Result<T> = std::result::Result<T, Error>;

/*
#[doc(hidden)]
pub(crate) async fn import_account<E>(
    account: &mut (impl Account<Error = E> + Send + Sync + 'static),
    create_set: CreateSet,
) -> std::result::Result<(), E>
where
    E: From<sos_sdk::Error>,
{
    let address = *account.address();
    let paths = account.paths();
    let mut storage = ClientStorage::empty(address, paths).await?;

    {
        let mut identity_log = storage.identity_log.write().await;
        let records: Vec<EventRecord> = create_set.identity.into();
        identity_log.apply_records(records).await?;
        let vault = FolderReducer::new()
            .reduce(&*identity_log)
            .await?
            .build(true)
            .await?;
        let buffer = encode(&vault).await?;
        let identity_vault = paths.identity_vault();
        vfs::write(identity_vault, &buffer).await?;
    }

    {
        let mut account_log = storage.account_log.write().await;
        let records: Vec<EventRecord> = create_set.account.into();
        account_log.apply_records(records).await?;
    }

    {
        let mut device_log = storage.device_log.write().await;
        let records: Vec<EventRecord> = create_set.device.into();
        device_log.apply_records(records).await?;
    }

    #[cfg(feature = "files")]
    {
        let mut file_log = storage.file_log.write().await;
        let records: Vec<EventRecord> = create_set.files.into();
        file_log.apply_records(records).await?;
    }

    storage.import_folder_patches(create_set.folders).await?;

    account
        .set_storage(Some(Arc::new(RwLock::new(storage))))
        .await;

    Ok(())
}
*/

/// Trait for encoding and decoding protobuf generated types.
///
/// A blanket implementation adds this to any [prost::Message]
/// and runs the encoding and decoding using `spawn_blocking`.
#[doc(hidden)]
pub trait ProtoMessage {
    /// Encode this message.
    #[allow(async_fn_in_trait)]
    async fn encode_proto(self) -> Result<Vec<u8>>;

    /// Decode a message.
    #[allow(async_fn_in_trait)]
    async fn decode_proto<B>(buffer: B) -> Result<Self>
    where
        B: Buf + Send + 'static,
        Self: Sized;
}

impl<T> ProtoMessage for T
where
    T: Message + Default + 'static,
{
    async fn encode_proto(self) -> Result<Vec<u8>> {
        tokio::task::spawn_blocking(move || {
            let mut buf = Vec::new();
            buf.reserve(self.encoded_len());
            self.encode(&mut buf)?;
            Ok(buf)
        })
        .await?
    }

    async fn decode_proto<B>(buffer: B) -> Result<Self>
    where
        B: Buf + Send + 'static,
        Self: Sized,
    {
        tokio::task::spawn_blocking(move || Ok(Self::decode(buffer)?)).await?
    }
}

/// Marker trait to indicate a binding type that
/// converts to a protobuf type.
trait ProtoBinding {
    type Inner: Message + Default;
}

/// Trait for wire protocol encoding and decoding.
#[doc(hidden)]
pub trait WireEncodeDecode {
    /// Encode this request.
    #[allow(async_fn_in_trait)]
    async fn encode(self) -> Result<Vec<u8>>;

    /// Decode this request.
    #[allow(async_fn_in_trait)]
    async fn decode<B>(buffer: B) -> Result<Self>
    where
        B: Buf + Send + 'static,
        Self: Sized;
}

impl<T> WireEncodeDecode for T
where
    T: ProtoBinding + Send + 'static,
    <T as ProtoBinding>::Inner: From<T> + 'static,
    T: TryFrom<<T as ProtoBinding>::Inner, Error = Error>,
{
    async fn encode(self) -> Result<Vec<u8>> {
        tokio::task::spawn_blocking(move || {
            let value: <Self as ProtoBinding>::Inner = self.into();
            let mut buf = Vec::new();
            buf.reserve(value.encoded_len());
            value.encode(&mut buf)?;
            Ok(buf)
        })
        .await?
    }

    async fn decode<B>(buffer: B) -> Result<Self>
    where
        B: Buf + Send + 'static,
        Self: Sized,
    {
        tokio::task::spawn_blocking(move || {
            let result = <<Self as ProtoBinding>::Inner>::decode(buffer)?;
            Ok(result.try_into()?)
        })
        .await?
    }
}

fn decode_uuid(id: &[u8]) -> Result<uuid::Uuid> {
    let id: [u8; 16] = id.try_into()?;
    Ok(uuid::Uuid::from_bytes(id))
}

fn encode_uuid(id: &uuid::Uuid) -> Vec<u8> {
    id.as_bytes().to_vec()
}
