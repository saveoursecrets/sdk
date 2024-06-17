use crate::{
    commit::{CommitProof, CommitState, Comparison},
    decode, encode,
    encoding::{decode_uuid, encoding_error},
    events::EventRecord,
    sync::CheckedPatch,
};
use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::{Error, ErrorKind, Result};

use crate::sync::{
    ChangeSet, Diff, FolderDiff, FolderPatch, MaybeDiff, Patch, SyncCompare,
    SyncDiff, SyncPacket, SyncStatus, UpdateSet,
};

#[cfg(feature = "files")]
use crate::storage::files::{ExternalFile, FileSet, FileTransfersSet};

#[cfg(test)]
mod test {
    use crate::{
        decode, encode,
        events::{AccountEvent, IntoRecord},
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
        sync::FilePatch,
        vault::{secret::SecretId, VaultId},
    };

    /*
    #[tokio::test]
    async fn encode_decode_change_set() -> Result<()> {
        let vault: Vault = Default::default();
        let event = vault.into_event().await?;
        let identity =
            FolderPatch::new(vec![(&event).default_record().await?]);

        let folder_vault: Vault = Default::default();
        let folder_id = *folder_vault.id();

        let event = AccountEvent::CreateFolder(*folder_vault.id(), vec![]);
        let account =
            AccountPatch::new(vec![(&event).default_record().await?]);

        let mut folders = HashMap::new();
        let event = folder_vault.into_event().await?;
        let folder = FolderPatch::new(vec![(&event).default_record().await?]);
        folders.insert(folder_id, folder);

        #[cfg(feature = "device")]
        let device = {
            let device_signer = DeviceSigner::new_random();
            let mock_device =
                TrustedDevice::new(device_signer.public_key(), None, None);
            let event = DeviceEvent::Trust(mock_device);
            let device =
                DevicePatch::new(vec![(&event).default_record().await?]);
            device
        };

        #[cfg(feature = "files")]
        let files = {
            let checksum: [u8; 32] = [0; 32];
            let event = FileEvent::CreateFile(
                VaultId::new_v4(),
                SecretId::new_v4(),
                checksum.into(),
            );
            let files =
                FilePatch::new(vec![(&event).default_record().await?]);
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

        let buffer = account_data.encode()?;
        let result = ChangeSet::decode(&buffer).await?;

        assert_eq!(1, result.identity.len());
        assert_eq!(1, result.account.len());
        assert_eq!(1, result.device.len());
        assert_eq!(1, result.files.len());

        let folder = result.folders.get(&folder_id).unwrap();
        assert_eq!(1, folder.len());

        Ok(())
    }
    */
}

#[cfg(feature = "files")]
#[async_trait]
impl Encodable for ExternalFile {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(self.vault_id().as_bytes()).await?;
        writer.write_bytes(self.secret_id().as_bytes()).await?;
        writer.write_bytes(self.file_name().as_ref()).await?;
        Ok(())
    }
}

#[cfg(feature = "files")]
#[async_trait]
impl Decodable for ExternalFile {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let vault_id = decode_uuid(&mut *reader).await?;
        let secret_id = decode_uuid(&mut *reader).await?;
        let file_name: [u8; 32] = reader
            .read_bytes(32)
            .await?
            .as_slice()
            .try_into()
            .map_err(encoding_error)?;
        *self = ExternalFile::new(vault_id, secret_id, file_name.into());
        Ok(())
    }
}

#[cfg(feature = "files")]
#[async_trait]
impl Encodable for FileSet {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let num_files = self.0.len();
        writer.write_u32(num_files as u32).await?;
        for file in &self.0 {
            file.encode(&mut *writer).await?;
        }
        Ok(())
    }
}

#[cfg(feature = "files")]
#[async_trait]
impl Decodable for FileSet {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let num_files = reader.read_u32().await? as usize;
        for _ in 0..num_files {
            let mut file: ExternalFile = Default::default();
            file.decode(&mut *reader).await?;
            self.0.insert(file);
        }
        Ok(())
    }
}

#[cfg(feature = "files")]
#[async_trait]
impl Encodable for FileTransfersSet {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.uploads.encode(&mut *writer).await?;
        self.downloads.encode(&mut *writer).await?;
        Ok(())
    }
}

#[cfg(feature = "files")]
#[async_trait]
impl Decodable for FileTransfersSet {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.uploads.decode(&mut *reader).await?;
        self.downloads.decode(&mut *reader).await?;
        Ok(())
    }
}
