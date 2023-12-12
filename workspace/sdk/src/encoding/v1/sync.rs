use crate::{
    decode, encode,
    encoding::{decode_uuid, encoding_error},
    prelude::{EventRecord, FileIdentity, PATCH_IDENTITY},
};

use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::Result;

use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};

use crate::sync::{ChangeSet, FolderPatch, Patch};

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

#[cfg(test)]
mod test {
    use crate::{
        decode, encode,
        events::{AccountEvent, WriteEvent},
        signer::ecdsa::Address,
        sync::ChangeSet,
        sync::{AccountPatch, FolderPatch},
        vault::Vault,
    };
    use anyhow::Result;
    use std::collections::HashMap;

    #[tokio::test]
    async fn encode_decode_change_set() -> Result<()> {
        let address: Address = Default::default();

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
