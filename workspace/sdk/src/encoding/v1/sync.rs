use crate::{
    decode, encode,
    encoding::{decode_uuid, encoding_error},
    prelude::{FileIdentity, PATCH_IDENTITY},
};
use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::Result;

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
        writer.write_u32(self.len() as u32).await?;
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
        let num_events = reader.read_u32().await?;
        for _ in 0..num_events {
            let mut event: T = Default::default();
            event.decode(reader).await?;
            self.append(event);
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

        // Device patch
        #[cfg(feature = "device")]
        {
            let buffer =
                encode(&self.device).await.map_err(encoding_error)?;
            let length = buffer.len();
            writer.write_u32(length as u32).await?;
            writer.write_bytes(&buffer).await?;
        }

        // Files patch
        #[cfg(feature = "files")]
        {
            let buffer =
                encode(&self.files).await.map_err(encoding_error)?;
            let length = buffer.len();
            writer.write_u32(length as u32).await?;
            writer.write_bytes(&buffer).await?;
        }

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

        // Device patch
        #[cfg(feature = "device")]
        {
            let length = reader.read_u32().await?;
            let buffer = reader.read_bytes(length as usize).await?;
            self.device = decode(&buffer).await.map_err(encoding_error)?;
        }

        // Files patch
        #[cfg(feature = "files")]
        {
            let length = reader.read_u32().await?;
            let buffer = reader.read_bytes(length as usize).await?;
            self.files = decode(&buffer).await.map_err(encoding_error)?;
        }

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
        writer.write_bool(self.identity.is_some()).await?;
        if let Some(identity) = &self.identity {
            identity.encode(&mut *writer).await?;
        }

        writer.write_bool(self.account.is_some()).await?;
        if let Some(account) = &self.account {
            account.encode(&mut *writer).await?;
        }

        #[cfg(feature = "device")]
        {
            writer.write_bool(self.device.is_some()).await?;
            if let Some(device) = &self.device {
                device.encode(&mut *writer).await?;
            }
        }

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
        let has_identity = reader.read_bool().await?;
        if has_identity {
            let mut identity: FolderDiff = Default::default();
            identity.decode(&mut *reader).await?;
            self.identity = Some(identity);
        }

        let has_account = reader.read_bool().await?;
        if has_account {
            let mut account: AccountDiff = Default::default();
            account.decode(&mut *reader).await?;
            self.account = Some(account);
        }

        #[cfg(feature = "device")]
        {
            use crate::sync::DeviceDiff;
            let has_device = reader.read_bool().await?;
            if has_device {
                let mut device: DeviceDiff = Default::default();
                device.decode(&mut *reader).await?;
                self.device = Some(device);
            }
        }

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

#[async_trait]
impl<T> Encodable for Diff<T>
where
    T: Default + Encodable + Decodable + Send + Sync,
{
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.before.encode(&mut *writer).await?;
        self.after.encode(&mut *writer).await?;
        self.patch.encode(&mut *writer).await?;
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
        self.before.decode(&mut *reader).await?;
        self.after.decode(&mut *reader).await?;
        self.patch.decode(&mut *reader).await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        decode, encode,
        events::{AccountEvent, WriteEvent},
        sync::{AccountPatch, ChangeSet, FolderPatch},
        vault::Vault,
    };
    use anyhow::Result;
    use std::collections::HashMap;

    #[cfg(feature = "device")]
    use crate::{
        device::{DeviceSigner, TrustedDevice},
        events::DeviceEvent,
        sync::DevicePatch,
    };

    #[cfg(feature = "files")]
    use crate::{
        events::FileEvent,
        storage::files::ExternalFileName,
        vault::{VaultId, secret::SecretId},
        sync::FilePatch,
    };

    #[tokio::test]
    async fn encode_decode_change_set() -> Result<()> {
        let vault: Vault = Default::default();
        let buf = encode(&vault).await?;
        let identity: FolderPatch = vec![WriteEvent::CreateVault(buf)].into();

        let folder_vault: Vault = Default::default();
        let folder_id = *folder_vault.id();

        let account: AccountPatch =
            vec![AccountEvent::CreateFolder(*folder_vault.id(), vec![])]
                .into();

        let mut folders = HashMap::new();
        let buf = encode(&folder_vault).await?;
        let folder: FolderPatch = vec![WriteEvent::CreateVault(buf)].into();
        folders.insert(folder_id, folder);

        #[cfg(feature = "device")]
        let device = {
            let device_signer = DeviceSigner::new_random();
            let mock_device =
                TrustedDevice::new(device_signer.public_key(), None, None);
            let device: DevicePatch =
                vec![DeviceEvent::Trust(mock_device)].into();
            device
        };

        #[cfg(feature = "files")]
        let files = {
            let checksum: [u8; 32] = [0; 32];
            let files: FilePatch =
                vec![FileEvent::CreateFile(
                    VaultId::new_v4(),
                    SecretId::new_v4(),
                    checksum.into(),
                )].into();
            files
        };

        let account_data = ChangeSet {
            identity,
            account,
            #[cfg(feature = "device")]
            device,
            #[cfg(feature = "files")]
            files,
            folders,
        };

        let buffer = encode(&account_data).await?;
        let result: ChangeSet = decode(&buffer).await?;

        assert_eq!(1, result.identity.len());
        assert_eq!(1, result.account.len());
        assert_eq!(1, result.device.len());
        assert_eq!(1, result.files.len());

        let folder = result.folders.get(&folder_id).unwrap();
        assert_eq!(1, folder.len());

        Ok(())
    }
}
