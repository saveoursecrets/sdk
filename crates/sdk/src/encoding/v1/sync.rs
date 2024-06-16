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

#[async_trait]
impl<T> Encodable for Patch<T>
where
    T: Default + Encodable + Decodable + Send + Sync,
{
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_u32(self.len() as u32).await?;
        for event in self.iter() {
            event.encode(&mut *writer).await?;
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
        let num_events = reader.read_u32().await?;
        for _ in 0..num_events {
            let mut event = EventRecord::default();
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
        self.identity.encode(&mut *writer).await?;
        self.account.encode(&mut *writer).await?;
        #[cfg(feature = "device")]
        self.device.encode(&mut *writer).await?;
        #[cfg(feature = "files")]
        self.files.encode(&mut *writer).await?;

        // Folder patches
        writer.write_u16(self.folders.len() as u16).await?;
        for (id, folder) in &self.folders {
            writer.write_bytes::<&[u8]>(id.as_ref()).await?;
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
        self.identity.decode(&mut *reader).await?;
        self.account.decode(&mut *reader).await?;
        #[cfg(feature = "device")]
        self.device.decode(&mut *reader).await?;
        #[cfg(feature = "files")]
        self.files.decode(&mut *reader).await?;

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
impl Encodable for UpdateSet {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.identity.encode(&mut *writer).await?;
        self.account.encode(&mut *writer).await?;

        #[cfg(feature = "device")]
        self.device.encode(&mut *writer).await?;

        #[cfg(feature = "files")]
        self.files.encode(&mut *writer).await?;

        // Folder patches
        writer.write_u16(self.folders.len() as u16).await?;
        for (id, folder) in &self.folders {
            writer.write_bytes::<&[u8]>(id.as_ref()).await?;
            let buffer = encode(folder).await.map_err(encoding_error)?;
            let length = buffer.len();
            writer.write_u32(length as u32).await?;
            writer.write_bytes(&buffer).await?;
        }

        Ok(())
    }
}

#[async_trait]
impl Decodable for UpdateSet {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.identity.decode(&mut *reader).await?;
        self.account.decode(&mut *reader).await?;

        #[cfg(feature = "device")]
        self.device.decode(&mut *reader).await?;

        #[cfg(feature = "files")]
        self.files.decode(&mut *reader).await?;

        // Folder patches
        let num_folders = reader.read_u16().await?;
        for _ in 0..(num_folders as usize) {
            let id = decode_uuid(&mut *reader).await?;
            let length = reader.read_u32().await?;
            let buffer = reader.read_bytes(length as usize).await?;
            let folder: FolderDiff =
                decode(&buffer).await.map_err(encoding_error)?;
            self.folders.insert(id, folder);
        }

        Ok(())
    }
}

#[async_trait]
impl Encodable for SyncPacket {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.status.encode(&mut *writer).await?;
        self.diff.encode(&mut *writer).await?;
        self.compare.encode(&mut *writer).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for SyncPacket {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.status.decode(&mut *reader).await?;
        self.diff.decode(&mut *reader).await?;
        self.compare.decode(&mut *reader).await?;
        Ok(())
    }
}

#[async_trait]
impl Encodable for SyncCompare {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.identity.encode(&mut *writer).await?;
        self.account.encode(&mut *writer).await?;
        #[cfg(feature = "device")]
        self.device.encode(&mut *writer).await?;
        #[cfg(feature = "files")]
        self.files.encode(&mut *writer).await?;

        writer.write_u16(self.folders.len() as u16).await?;
        for (id, comparison) in &self.folders {
            writer.write_bytes(id.as_bytes()).await?;
            comparison.encode(&mut *writer).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for SyncCompare {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.identity.decode(&mut *reader).await?;
        self.account.decode(&mut *reader).await?;
        #[cfg(feature = "device")]
        self.device.decode(&mut *reader).await?;
        #[cfg(feature = "files")]
        self.files.decode(&mut *reader).await?;

        let num_folders = reader.read_u16().await?;
        for _ in 0..num_folders {
            let id = decode_uuid(&mut *reader).await?;
            let mut comparison: Comparison = Default::default();
            comparison.decode(&mut *reader).await?;
            self.folders.insert(id, comparison);
        }

        Ok(())
    }
}

#[async_trait]
impl Encodable for SyncStatus {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.root.encode(&mut *writer).await?;
        self.identity.encode(&mut *writer).await?;
        self.account.encode(&mut *writer).await?;
        #[cfg(feature = "device")]
        self.device.encode(&mut *writer).await?;
        #[cfg(feature = "files")]
        self.files.encode(&mut *writer).await?;

        writer.write_u16(self.folders.len() as u16).await?;
        for (id, commit_state) in &self.folders {
            writer.write_bytes(id.as_bytes()).await?;
            commit_state.encode(&mut *writer).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for SyncStatus {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.root.decode(&mut *reader).await?;
        self.identity.decode(&mut *reader).await?;
        self.account.decode(&mut *reader).await?;
        #[cfg(feature = "device")]
        self.device.decode(&mut *reader).await?;
        #[cfg(feature = "files")]
        self.files.decode(&mut *reader).await?;

        let num_folders = reader.read_u16().await?;
        for _ in 0..num_folders {
            let id = decode_uuid(&mut *reader).await?;
            let mut commit_state: CommitState = Default::default();
            commit_state.decode(&mut *reader).await?;
            self.folders.insert(id, commit_state);
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
        #[cfg(feature = "device")]
        self.device.encode(&mut *writer).await?;
        #[cfg(feature = "files")]
        self.files.encode(&mut *writer).await?;

        writer.write_u16(self.folders.len() as u16).await?;
        for (id, diff) in &self.folders {
            writer.write_bytes::<&[u8]>(id.as_ref()).await?;
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
        self.identity.decode(&mut *reader).await?;
        self.account.decode(&mut *reader).await?;
        #[cfg(feature = "device")]
        self.device.decode(&mut *reader).await?;
        #[cfg(feature = "files")]
        self.files.decode(&mut *reader).await?;

        let num_folders = reader.read_u16().await?;
        for _ in 0..num_folders {
            let id = decode_uuid(&mut *reader).await?;
            let mut folder: MaybeDiff<FolderDiff> = Default::default();
            folder.decode(&mut *reader).await?;
            self.folders.insert(id, folder);
        }
        Ok(())
    }
}

#[async_trait]
impl Encodable for CheckedPatch {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        match self {
            CheckedPatch::Noop => panic!("attempt to encode a noop"),
            CheckedPatch::Success(proof) => {
                writer.write_u8(1).await?;
                proof.encode(&mut *writer).await?;
            }
            CheckedPatch::Conflict { head, contains } => {
                writer.write_u8(2).await?;
                head.encode(&mut *writer).await?;
                contains.encode(&mut *writer).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for CheckedPatch {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let kind = reader.read_u8().await?;
        match kind {
            1 => {
                let mut proof = CommitProof::default();
                proof.decode(&mut *reader).await?;
                *self = CheckedPatch::Success(proof);
            }
            2 => {
                let mut head = CommitProof::default();
                head.decode(&mut *reader).await?;
                let mut contains: Option<CommitProof> = None;
                contains.decode(&mut *reader).await?;
                *self = CheckedPatch::Conflict { head, contains };
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unknown checked patch variant kind {}", kind),
                ));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl<T> Encodable for MaybeDiff<T>
where
    T: Default + Encodable + Decodable + Send + Sync,
{
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        match self {
            MaybeDiff::Noop => panic!("attempt to encode a noop"),
            MaybeDiff::Diff(diff) => {
                writer.write_u8(1).await?;
                diff.encode(&mut *writer).await?;
            }
            MaybeDiff::Compare(state) => {
                writer.write_u8(2).await?;
                state.encode(&mut *writer).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl<T> Decodable for MaybeDiff<T>
where
    T: Default + Encodable + Decodable + Send + Sync,
{
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let kind = reader.read_u8().await?;
        match kind {
            1 => {
                let mut diff = T::default();
                diff.decode(&mut *reader).await?;
                *self = MaybeDiff::Diff(diff);
            }
            2 => {
                let mut state = Option::<CommitState>::default();
                state.decode(&mut *reader).await?;
                *self = MaybeDiff::Compare(state);
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unknown diff variant kind {}", kind),
                ));
            }
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
        self.last_commit.encode(&mut *writer).await?;
        self.checkpoint.encode(&mut *writer).await?;
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
        self.last_commit.decode(&mut *reader).await?;
        self.checkpoint.decode(&mut *reader).await?;
        self.patch.decode(&mut *reader).await?;
        Ok(())
    }
}

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
