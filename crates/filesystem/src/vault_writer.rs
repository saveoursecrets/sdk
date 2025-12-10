//! Write vault changes to a file on disc.
use async_fd_lock::{LockRead, LockWrite};
use async_trait::async_trait;
use binary_stream::futures::{BinaryReader, BinaryWriter};
use sos_core::{
    SecretId, VaultCommit, VaultEntry, VaultFlags,
    commit::CommitHash,
    crypto::AeadPack,
    encode,
    encoding::encoding_options,
    events::{ReadEvent, WriteEvent},
};
use sos_vault::{Contents, EncryptedEntry, Header, Summary, Vault};
use sos_vfs::{self as vfs, OpenOptions};
use std::io::Cursor;
use std::{borrow::Cow, io::SeekFrom, ops::Range, path::Path, path::PathBuf};
use tokio::io::BufWriter;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// Write changes to a vault file on disc.
pub struct VaultFileWriter<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_core::Error>
        + From<sos_vault::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    pub(crate) file_path: PathBuf,
    marker: std::marker::PhantomData<E>,
}

impl<E> VaultFileWriter<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_core::Error>
        + From<sos_vault::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    /// Create a new vault file writer.
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let file_path = path.as_ref().to_path_buf();
        Self {
            file_path,
            marker: std::marker::PhantomData,
        }
    }

    /// Check the identity bytes and return the byte offset of the
    /// beginning of the vault content area.
    async fn check_identity(&self) -> Result<u64, E> {
        Ok(Header::read_content_offset(&self.file_path).await?)
    }

    /// Write out the header preserving the existing content bytes.
    async fn write_header(
        &self,
        content_offset: u64,
        header: &Header,
    ) -> Result<(), E> {
        let head = encode(header).await?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.file_path)
            .await?;

        // Read the content into memory
        file.seek(SeekFrom::Start(content_offset)).await?;
        let mut content = Vec::new();
        file.read_to_end(&mut content).await?;

        // Rewind and truncate the file
        file.rewind().await?;
        file.set_len(0).await?;

        let mut guard = file.lock_write().await.map_err(|e| e.error)?;

        // Write out the header
        guard.write_all(&head).await?;

        // Write out the content
        guard.write_all(&content).await?;
        guard.flush().await?;

        Ok(())
    }

    /// Splice a file preserving the head and tail and
    /// optionally inserting content in between.
    async fn splice(
        &self,
        head: Range<u64>,
        tail: Range<u64>,
        content: Option<&[u8]>,
    ) -> Result<(), E> {
        let end = {
            let file =
                OpenOptions::new().read(true).open(&self.file_path).await?;
            let mut guard = file.lock_read().await.map_err(|e| e.error)?;

            // Read the tail into memory
            guard.seek(SeekFrom::Start(tail.start)).await?;
            let mut end = Vec::new();
            guard.read_to_end(&mut end).await?;

            end
        };

        let file =
            OpenOptions::new().write(true).open(&self.file_path).await?;

        let mut guard = file.lock_write().await.map_err(|e| e.error)?;

        if head.start == 0 {
            // Rewind and truncate the file to the head
            guard.rewind().await?;
            guard.inner_mut().set_len(head.end).await?;
        } else {
            unreachable!("file splice head range always starts at zero");
        }

        // Must seek to the end before writing out the content or tail
        guard.seek(SeekFrom::End(0)).await?;

        // Inject the content if necessary
        if let Some(content) = content {
            guard.write_all(content).await?;
        }

        // Write out the end portion
        guard.write_all(&end).await?;
        guard.flush().await?;

        Ok(())
    }

    /// Find the byte offset of a row.
    ///
    /// Returns the content offset and the byte
    /// offset and row length of the row if it exists.
    async fn find_row(
        &self,
        id: &SecretId,
    ) -> Result<(u64, Option<(u64, u32)>), E> {
        let content_offset = self.check_identity().await?;

        let file =
            OpenOptions::new().read(true).open(&self.file_path).await?;
        let mut guard = file.lock_read().await.map_err(|e| e.error)?;

        let mut reader = BinaryReader::new(&mut guard, encoding_options());
        reader.seek(SeekFrom::Start(content_offset)).await?;

        // Scan all the rows
        let mut current_pos = reader.stream_position().await?;
        while let Ok(row_len) = reader.read_u32().await {
            let row_id: [u8; 16] = reader
                .read_bytes(16)
                .await?
                .as_slice()
                .try_into()
                .map_err(sos_core::Error::from)?;
            let row_id = SecretId::from_bytes(row_id);
            if id == &row_id {
                // Need to backtrack as we just read the row length and UUID;
                // calling decode_row() will try to read the length and UUID.
                reader.seek(SeekFrom::Start(current_pos)).await?;
                return Ok((content_offset, Some((current_pos, row_len))));
            }

            // Move on to the next row
            reader
                .seek(SeekFrom::Start(current_pos + 8 + row_len as u64))
                .await?;
            current_pos = reader.stream_position().await?;
        }

        Ok((content_offset, None))
    }
}

#[async_trait]
impl<E> EncryptedEntry for VaultFileWriter<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_vault::Error>
        + From<sos_core::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    type Error = E;

    async fn summary(&self) -> Result<Summary, Self::Error> {
        Ok(Header::read_summary_file(&self.file_path).await?)
    }

    async fn vault_name(&self) -> Result<Cow<'_, str>, Self::Error> {
        let header = Header::read_header_file(&self.file_path).await?;
        let name = header.name().to_string();
        Ok(Cow::Owned(name))
    }

    async fn set_vault_name(
        &mut self,
        name: String,
    ) -> Result<WriteEvent, Self::Error> {
        let content_offset = self.check_identity().await?;
        let mut header = Header::read_header_file(&self.file_path).await?;
        header.set_name(name.clone());
        self.write_header(content_offset, &header).await?;
        Ok(WriteEvent::SetVaultName(name))
    }

    async fn set_vault_flags(
        &mut self,
        flags: VaultFlags,
    ) -> Result<WriteEvent, Self::Error> {
        let content_offset = self.check_identity().await?;
        let mut header = Header::read_header_file(&self.file_path).await?;
        *header.flags_mut() = flags.clone();
        self.write_header(content_offset, &header).await?;
        Ok(WriteEvent::SetVaultFlags(flags))
    }

    async fn set_vault_meta(
        &mut self,
        meta_data: AeadPack,
    ) -> Result<WriteEvent, Self::Error> {
        let content_offset = self.check_identity().await?;
        let mut header = Header::read_header_file(&self.file_path).await?;
        header.set_meta(Some(meta_data.clone()));
        self.write_header(content_offset, &header).await?;
        Ok(WriteEvent::SetVaultMeta(meta_data))
    }

    async fn create_secret(
        &mut self,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent, Self::Error> {
        let id = SecretId::new_v4();
        self.insert_secret(id, commit, secret).await
    }

    async fn insert_secret(
        &mut self,
        id: SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent, Self::Error> {
        let _summary = self.summary().await?;

        // Encode the row into a buffer
        let mut buffer = Vec::new();
        let mut writer =
            BinaryWriter::new(Cursor::new(&mut buffer), encoding_options());
        let row = VaultCommit(commit, secret);
        Contents::encode_row(&mut writer, &id, &row).await?;
        writer.flush().await?;

        // Append to the file
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .open(&self.file_path)
            .await?;
        let mut guard = file.lock_write().await.map_err(|e| e.error)?;
        guard.write_all(&buffer).await?;
        guard.flush().await?;

        Ok(WriteEvent::CreateSecret(id, row))
    }

    async fn read_secret<'a>(
        &'a self,
        id: &SecretId,
    ) -> Result<Option<(Cow<'a, VaultCommit>, ReadEvent)>, Self::Error> {
        let _summary = self.summary().await?;
        let event = ReadEvent::ReadSecret(*id);
        let (_, row) = self.find_row(id).await?;
        if let Some((row_offset, _)) = row {
            let file =
                OpenOptions::new().read(true).open(&self.file_path).await?;
            let mut guard = file.lock_read().await.map_err(|e| e.error)?;

            let mut reader =
                BinaryReader::new(&mut guard, encoding_options());
            reader.seek(SeekFrom::Start(row_offset)).await?;
            let (_, value) = Contents::decode_row(&mut reader).await?;
            Ok(Some((Cow::Owned(value), event)))
        } else {
            Ok(None)
        }
    }

    async fn update_secret(
        &mut self,
        id: &SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<Option<WriteEvent>, Self::Error> {
        let _summary = self.summary().await?;
        let (_content_offset, row) = self.find_row(id).await?;
        if let Some((row_offset, row_len)) = row {
            // Prepare the row
            let mut buffer = Vec::new();
            let mut stream = BufWriter::new(Cursor::new(&mut buffer));
            let mut writer =
                BinaryWriter::new(&mut stream, encoding_options());

            let row = VaultCommit(commit, secret);
            Contents::encode_row(&mut writer, id, &row).await?;
            writer.flush().await?;

            // Splice the row into the file
            let length = writer.len().await?;

            let head = 0..row_offset;
            // Row offset is before the row length u32 so we
            // need to account for that too
            let tail = (row_offset + 8 + row_len as u64)..length;

            self.splice(head, tail, Some(&buffer)).await?;

            Ok(Some(WriteEvent::UpdateSecret(*id, row)))
        } else {
            Ok(None)
        }
    }

    async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>, Self::Error> {
        let _summary = self.summary().await?;
        let (_content_offset, row) = self.find_row(id).await?;
        if let Some((row_offset, row_len)) = row {
            let length = vfs::metadata(&self.file_path).await?.len();

            let head = 0..row_offset;
            // Row offset is before the row length u32 so we
            // need to account for that too
            let tail = (row_offset + 8 + row_len as u64)..length;

            self.splice(head, tail, None).await?;

            Ok(Some(WriteEvent::DeleteSecret(*id)))
        } else {
            Ok(None)
        }
    }

    async fn replace_vault(
        &mut self,
        vault: &Vault,
    ) -> Result<(), Self::Error> {
        let buffer = encode(vault).await?;

        let file =
            OpenOptions::new().write(true).open(&self.file_path).await?;
        let mut guard = file.lock_write().await.map_err(|e| e.error)?;
        guard.write_all(&buffer).await?;
        guard.flush().await?;

        Ok(())
    }
}
