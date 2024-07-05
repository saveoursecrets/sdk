//! Implements random access to a single vault file on disc.
use std::{
    borrow::Cow,
    io::SeekFrom,
    ops::{DerefMut, Range},
    path::Path,
    path::PathBuf,
};

use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite,
        AsyncWriteExt,
    },
    sync::Mutex,
};

use futures::io::{BufWriter, Cursor};
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

use async_trait::async_trait;
use binary_stream::futures::{stream_length, BinaryReader, BinaryWriter};

use uuid::Uuid;

use crate::{
    commit::CommitHash,
    crypto::AeadPack,
    encode,
    encoding::encoding_options,
    events::{ReadEvent, WriteEvent},
    vault::{
        secret::SecretId, Contents, Header, Summary, VaultAccess,
        VaultCommit, VaultEntry, VaultFlags,
    },
    vfs::{File, OpenOptions},
    Result,
};

/// Mutates a vault file in-place.
pub struct VaultWriter<F>
where
    F: AsyncRead + AsyncWrite + AsyncSeek + Unpin + Send,
{
    pub(crate) file_path: PathBuf,
    stream: Mutex<Compat<F>>,
}

impl VaultWriter<File> {
    /// Open a file in read and write mode suitable for passing
    /// to the new constructor.
    pub async fn open<P: AsRef<Path>>(path: P) -> Result<File> {
        Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.as_ref())
            .await?)
    }
}

impl<F: AsyncRead + AsyncWrite + AsyncSeek + Unpin + Send> VaultWriter<F> {
    /// Create a new vault access.
    ///
    /// The underlying file should already exist and be a valid vault.
    pub fn new<P: AsRef<Path>>(path: P, file: F) -> Result<Self> {
        let file_path = path.as_ref().to_path_buf();
        let stream = Mutex::new(file.compat_write());
        Ok(Self { file_path, stream })
    }

    /// Check the identity bytes and return the byte offset of the
    /// beginning of the vault content area.
    async fn check_identity(&self) -> Result<u64> {
        Header::read_content_offset(&self.file_path).await
    }

    /// Write out the header preserving the existing content bytes.
    async fn write_header(
        &self,
        content_offset: u64,
        header: &Header,
    ) -> Result<()> {
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

        // Write out the header
        file.write_all(&head).await?;

        // Write out the content
        file.write_all(&content).await?;

        file.flush().await?;

        Ok(())
    }

    /// Splice a file preserving the head and tail and
    /// optionally inserting content in between.
    async fn splice(
        &self,
        head: Range<u64>,
        tail: Range<u64>,
        content: Option<&[u8]>,
    ) -> Result<()> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.file_path)
            .await?;

        // Read the tail into memory
        file.seek(SeekFrom::Start(tail.start)).await?;
        let mut end = Vec::new();
        file.read_to_end(&mut end).await?;

        if head.start == 0 {
            // Rewind and truncate the file to the head
            file.rewind().await?;
            file.set_len(head.end).await?;
        } else {
            unreachable!("file splice head range always starts at zero");
        }

        // Must seek to the end before writing out the content or tail
        file.seek(SeekFrom::End(0)).await?;

        // Inject the content if necessary
        if let Some(content) = content {
            file.write_all(content).await?;
        }

        // Write out the end portion
        file.write_all(&end).await?;

        file.flush().await?;

        Ok(())
    }

    /// Find the byte offset of a row.
    ///
    /// Returns the content offset and the byte
    /// offset and row length of the row if it exists.
    async fn find_row(
        &self,
        id: &SecretId,
    ) -> Result<(u64, Option<(u64, u32)>)> {
        let content_offset = self.check_identity().await?;

        let mut stream = self.stream.lock().await;
        let mut reader = BinaryReader::new(&mut *stream, encoding_options());
        reader.seek(SeekFrom::Start(content_offset)).await?;

        // Scan all the rows
        let mut current_pos = reader.stream_position().await?;
        while let Ok(row_len) = reader.read_u32().await {
            let row_id: [u8; 16] =
                reader.read_bytes(16).await?.as_slice().try_into()?;
            let row_id = Uuid::from_bytes(row_id);
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
impl<F: AsyncRead + AsyncWrite + AsyncSeek + Send + Unpin> VaultAccess
    for VaultWriter<F>
{
    async fn summary(&self) -> Result<Summary> {
        Header::read_summary_file(&self.file_path).await
    }

    async fn vault_name(&self) -> Result<Cow<'_, str>> {
        let header = Header::read_header_file(&self.file_path).await?;
        let name = header.name().to_string();
        Ok(Cow::Owned(name))
    }

    async fn set_vault_name(&mut self, name: String) -> Result<WriteEvent> {
        let content_offset = self.check_identity().await?;
        let mut header = Header::read_header_file(&self.file_path).await?;
        header.set_name(name.clone());
        self.write_header(content_offset, &header).await?;
        Ok(WriteEvent::SetVaultName(name))
    }

    async fn set_vault_flags(
        &mut self,
        flags: VaultFlags,
    ) -> Result<WriteEvent> {
        let content_offset = self.check_identity().await?;
        let mut header = Header::read_header_file(&self.file_path).await?;
        *header.flags_mut() = flags.clone();
        self.write_header(content_offset, &header).await?;
        Ok(WriteEvent::SetVaultFlags(flags))
    }

    async fn set_vault_meta(
        &mut self,
        meta_data: AeadPack,
    ) -> Result<WriteEvent> {
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
    ) -> Result<WriteEvent> {
        let id = Uuid::new_v4();
        self.insert_secret(id, commit, secret).await
    }

    async fn insert_secret(
        &mut self,
        id: SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent> {
        let _summary = self.summary().await?;
        let mut stream = self.stream.lock().await;

        let mut writer = BinaryWriter::new(&mut *stream, encoding_options());
        let row = VaultCommit(commit, secret);

        // Seek to the end of the file and append the row
        writer.seek(SeekFrom::End(0)).await?;

        Contents::encode_row(&mut writer, &id, &row).await?;

        writer.flush().await?;

        Ok(WriteEvent::CreateSecret(id, row))
    }

    async fn read_secret<'a>(
        &'a self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'a, VaultCommit>>, ReadEvent)> {
        let _summary = self.summary().await?;
        let event = ReadEvent::ReadSecret(*id);
        let (_, row) = self.find_row(id).await?;
        if let Some((row_offset, _)) = row {
            let mut stream = self.stream.lock().await;
            let mut reader =
                BinaryReader::new(&mut *stream, encoding_options());
            reader.seek(SeekFrom::Start(row_offset)).await?;
            let (_, value) = Contents::decode_row(&mut reader).await?;
            Ok((Some(Cow::Owned(value)), event))
        } else {
            Ok((None, event))
        }
    }

    async fn update_secret(
        &mut self,
        id: &SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<Option<WriteEvent>> {
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
    ) -> Result<Option<WriteEvent>> {
        let _summary = self.summary().await?;
        let (_content_offset, row) = self.find_row(id).await?;
        if let Some((row_offset, row_len)) = row {
            let length = {
                let mut stream = self.stream.lock().await;
                stream_length(stream.deref_mut()).await?
            };

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
}
