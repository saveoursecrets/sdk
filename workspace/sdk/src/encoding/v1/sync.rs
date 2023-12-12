use crate::{
    commit::CommitProof,
    decode, encode,
    encoding::{decode_uuid, encoding_error},
    prelude::{FileIdentity, PATCH_IDENTITY},
};

use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::{Error, ErrorKind, Result};

use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};

use crate::sync::{
    AccountDiff, ChangeSet, Diff, FolderDiff, FolderPatch, Patch, SyncDiff,
};

#[async_trait]
impl<T> Encodable for Patch<T>
where
    T: Default + Encodable + Decodable + Send + Sync,
{
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(PATCH_IDENTITY).await?;
        for event in self.iter() {
            event.encode(writer).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl<T> Decodable for Patch<T>
where
    T: Default + Encodable + Decodable + Send + Sync,
{
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        FileIdentity::read_identity(reader, &PATCH_IDENTITY)
            .await
            .map_err(encoding_error)?;
        let mut pos = reader.stream_position().await?;
        let len = reader.len().await?;
        while pos < len {
            let mut event: T = Default::default();
            event.decode(reader).await?;
            self.append(event);
            pos = reader.stream_position().await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Encodable for ChangeSet {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        // Identity patch
        let buffer = encode(&self.identity).await.map_err(encoding_error)?;
        let length = buffer.len();
        writer.write_u32(length as u32).await?;
        writer.write_bytes(&buffer).await?;

        // Account patch
        let buffer = encode(&self.account).await.map_err(encoding_error)?;
        let length = buffer.len();
        writer.write_u32(length as u32).await?;
        writer.write_bytes(&buffer).await?;

        // Folder patches
        writer.write_u16(self.folders.len() as u16).await?;
        for (id, folder) in &self.folders {
            writer.write_bytes(id.as_ref()).await?;
            let buffer = encode(folder).await.map_err(encoding_error)?;
            let length = buffer.len();
            writer.write_u32(length as u32).await?;
            writer.write_bytes(&buffer).await?;
        }

        Ok(())
    }
}

#[async_trait]
impl Decodable for ChangeSet {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        // Identity patch
        let length = reader.read_u32().await?;
        let buffer = reader.read_bytes(length as usize).await?;
        self.identity = decode(&buffer).await.map_err(encoding_error)?;

        // Account patch
        let length = reader.read_u32().await?;
        let buffer = reader.read_bytes(length as usize).await?;
        self.account = decode(&buffer).await.map_err(encoding_error)?;

        // Folder patches
        let num_folders = reader.read_u16().await?;
        for _ in 0..(num_folders as usize) {
            let id = decode_uuid(&mut *reader).await?;
            let length = reader.read_u32().await?;
            let buffer = reader.read_bytes(length as usize).await?;
            let folder: FolderPatch =
                decode(&buffer).await.map_err(encoding_error)?;
            self.folders.insert(id, folder);
        }

        Ok(())
    }
}

#[async_trait]
impl Encodable for SyncDiff {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.identity.encode(&mut *writer).await?;
        self.account.encode(&mut *writer).await?;
        writer.write_u16(self.folders.len() as u16).await?;
        for (id, diff) in &self.folders {
            writer.write_bytes(id.as_ref()).await?;
            diff.encode(&mut *writer).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for SyncDiff {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let mut identity: FolderDiff = Default::default();
        identity.decode(&mut *reader).await?;
        self.identity = identity;

        let mut account: AccountDiff = Default::default();
        account.decode(&mut *reader).await?;
        self.account = account;

        let num_folders = reader.read_u16().await?;
        for _ in 0..num_folders {
            let id = decode_uuid(&mut *reader).await?;
            let mut folder: FolderDiff = Default::default();
            folder.decode(&mut *reader).await?;
            self.folders.insert(id, folder);
        }
        Ok(())
    }
}

const DIFF_EVEN: u8 = 1;
const DIFF_PATCH: u8 = 2;

#[async_trait]
impl<T> Encodable for Diff<T>
where
    T: Default + Encodable + Decodable + Send + Sync,
{
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        match self {
            Self::Even => {
                writer.write_u8(DIFF_EVEN).await?;
            }
            Self::Patch { head, patch } => {
                writer.write_u8(DIFF_PATCH).await?;
                head.encode(&mut *writer).await?;
                patch.encode(&mut *writer).await?;
            }
            Self::Noop => panic!("attempt to encode a noop"),
        }
        Ok(())
    }
}

#[async_trait]
impl<T> Decodable for Diff<T>
where
    T: Default + Encodable + Decodable + Send + Sync,
{
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let op = reader.read_u8().await?;
        match op {
            DIFF_EVEN => *self = Self::Even,
            DIFF_PATCH => {
                let mut head: CommitProof = Default::default();
                head.decode(&mut *reader).await?;
                let mut patch: Patch<T> = Default::default();
                patch.decode(&mut *reader).await?;
                *self = Self::Patch { head, patch }
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unknown diff variant kind {}", op),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        decode, encode,
        events::{AccountEvent, WriteEvent},
        sync::ChangeSet,
        sync::{AccountPatch, FolderPatch},
        vault::Vault,
    };
    use anyhow::Result;
    use std::collections::HashMap;

    #[tokio::test]
    async fn encode_decode_change_set() -> Result<()> {
        let vault: Vault = Default::default();
        let buf = encode(&vault).await?;
        let identity: FolderPatch = vec![WriteEvent::CreateVault(buf)].into();

        let folder_vault: Vault = Default::default();
        let folder_id = *folder_vault.id();

        let account: AccountPatch =
            vec![AccountEvent::CreateFolder(*folder_vault.id())].into();

        let mut folders = HashMap::new();
        let buf = encode(&folder_vault).await?;
        let folder: FolderPatch = vec![WriteEvent::CreateVault(buf)].into();
        folders.insert(folder_id, folder);

        let account_data = ChangeSet {
            identity,
            account,
            folders,
        };

        let buffer = encode(&account_data).await?;
        let _: ChangeSet = decode(&buffer).await?;
        Ok(())
    }
}
