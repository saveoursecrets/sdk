//! Implements random access to a single vault file on disc.
use std::{
    borrow::Cow,
    io::{Cursor, SeekFrom},
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

use async_trait::async_trait;
use binary_stream::{
    tokio::{BinaryReader, BinaryWriter},
    Endian,
};

use uuid::Uuid;

use crate::{
    commit::CommitHash,
    crypto::AeadPack,
    encode,
    encoding::stream_len,
    events::{ReadEvent, WriteEvent},
    vault::{
        secret::SecretId, Contents, Header, Summary, VaultAccess,
        VaultCommit, VaultEntry,
    },
    vfs::{File, OpenOptions},
    Result,
};

/// Mutates a vault file in-place.
pub struct VaultWriter<F>
where
    F: AsyncRead + AsyncWrite + AsyncSeek + Unpin + Send,
{
    file_path: PathBuf,
    stream: Mutex<F>,
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
        let stream = Mutex::new(file);
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
            //file.seek(SeekFrom::End(0))?;
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
        let mut reader = BinaryReader::new(&mut *stream, Endian::Little);

        reader.seek(content_offset).await?;

        // Scan all the rows
        let mut current_pos = reader.tell().await?;
        while let Ok(row_len) = reader.read_u32().await {
            let row_id: [u8; 16] =
                reader.read_bytes(16).await?.as_slice().try_into()?;
            let row_id = Uuid::from_bytes(row_id);
            if id == &row_id {
                // Need to backtrack as we just read the row length and UUID;
                // calling decode_row() will try to read the length and UUID.
                reader.seek(current_pos).await?;
                return Ok((content_offset, Some((current_pos, row_len))));
            }

            // Move on to the next row
            reader.seek(current_pos + 8 + row_len as u64).await?;
            current_pos = reader.tell().await?;
        }

        Ok((content_offset, None))
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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

    async fn set_vault_name(
        &mut self,
        name: String,
    ) -> Result<WriteEvent<'_>> {
        let content_offset = self.check_identity().await?;
        let mut header = Header::read_header_file(&self.file_path).await?;
        header.set_name(name.clone());
        self.write_header(content_offset, &header).await?;
        Ok(WriteEvent::SetVaultName(Cow::Owned(name)))
    }

    async fn set_vault_meta(
        &mut self,
        meta_data: Option<AeadPack>,
    ) -> Result<WriteEvent<'_>> {
        let content_offset = self.check_identity().await?;
        let mut header = Header::read_header_file(&self.file_path).await?;
        header.set_meta(meta_data.clone());
        self.write_header(content_offset, &header).await?;
        Ok(WriteEvent::SetVaultMeta(Cow::Owned(meta_data)))
    }

    async fn create(
        &mut self,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent<'_>> {
        let id = Uuid::new_v4();
        self.insert(id, commit, secret).await
    }

    async fn insert(
        &mut self,
        id: SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent<'_>> {
        let _summary = self.summary().await?;
        let mut stream = self.stream.lock().await;
        let length = stream_len(stream.deref_mut()).await?;
        let mut writer = BinaryWriter::new(&mut *stream, Endian::Little);
        let row = VaultCommit(commit, secret);

        // Seek to the end of the file and append the row
        writer.seek(length).await?;
        Contents::encode_row(&mut writer, &id, &row).await?;

        drop(stream);

        Ok(WriteEvent::CreateSecret(id, Cow::Owned(row)))
    }

    async fn read<'a>(
        &'a self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'a, VaultCommit>>, ReadEvent)> {
        let _summary = self.summary().await?;
        let event = ReadEvent::ReadSecret(*id);
        let (_, row) = self.find_row(id).await?;
        if let Some((row_offset, _)) = row {
            let mut stream = self.stream.lock().await;
            let mut reader = BinaryReader::new(&mut *stream, Endian::Little);
            reader.seek(row_offset).await?;
            let (_, value) = Contents::decode_row(&mut reader).await?;
            Ok((Some(Cow::Owned(value)), event))
        } else {
            Ok((None, event))
        }
    }

    async fn update(
        &mut self,
        id: &SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<Option<WriteEvent<'_>>> {
        let _summary = self.summary().await?;
        let (_content_offset, row) = self.find_row(id).await?;
        if let Some((row_offset, row_len)) = row {
            // Prepare the row
            let mut buffer = Vec::new();
            let mut stream = Cursor::new(&mut buffer);
            let mut writer = BinaryWriter::new(&mut stream, Endian::Little);

            let row = VaultCommit(commit, secret);
            Contents::encode_row(&mut writer, id, &row).await?;

            // Splice the row into the file
            let length = {
                let mut stream = self.stream.lock().await;
                stream_len(stream.deref_mut()).await?
            };

            let head = 0..row_offset;
            // Row offset is before the row length u32 so we
            // need to account for that too
            let tail = (row_offset + 8 + row_len as u64)..length;

            self.splice(head, tail, Some(&buffer)).await?;

            Ok(Some(WriteEvent::UpdateSecret(*id, Cow::Owned(row))))
        } else {
            Ok(None)
        }
    }

    async fn delete(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent<'_>>> {
        let _summary = self.summary().await?;
        let (_content_offset, row) = self.find_row(id).await?;
        if let Some((row_offset, row_len)) = row {
            let length = {
                let mut stream = self.stream.lock().await;
                stream_len(stream.deref_mut()).await?
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::VaultWriter;
    use crate::test_utils::*;
    use crate::{
        constants::DEFAULT_VAULT_NAME,
        crypto::secret_key::SecretKey,
        events::WriteEvent,
        vault::{secret::*, Header, Vault, VaultAccess, VaultEntry},
    };
    use anyhow::Result;
    use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};

    use uuid::Uuid;

    type SecureNoteResult = (SecretId, SecretMeta, Secret, Vec<u8>, Vec<u8>);

    async fn create_secure_note<
        F: AsyncRead + AsyncWrite + AsyncSeek + Unpin + Send,
    >(
        vault_access: &mut VaultWriter<F>,
        vault: &Vault,
        encryption_key: &SecretKey,
        secret_label: &str,
        secret_note: &str,
    ) -> Result<SecureNoteResult> {
        let (secret_meta, secret_value, meta_bytes, secret_bytes) =
            mock_secret_note(secret_label, secret_note).await?;

        let meta_aead = vault.encrypt(encryption_key, &meta_bytes)?;
        let secret_aead = vault.encrypt(encryption_key, &secret_bytes)?;

        let (commit, _) =
            Vault::commit_hash(&meta_aead, &secret_aead).await?;

        if let WriteEvent::CreateSecret(secret_id, _) = vault_access
            .create(commit, VaultEntry(meta_aead, secret_aead))
            .await?
        {
            Ok((
                secret_id,
                secret_meta,
                secret_value,
                meta_bytes,
                secret_bytes,
            ))
        } else {
            panic!("expecting create secret payload");
        }
    }

    #[tokio::test]
    async fn vault_file_access() -> Result<()> {
        let (encryption_key, _, _) = mock_encryption_key()?;
        let (temp, vault, _) = mock_vault_file().await?;

        let vault_file = VaultWriter::open(temp.path()).await?;
        let mut vault_access = VaultWriter::new(temp.path(), vault_file)?;

        // Missing row should not exist
        let missing_id = Uuid::new_v4();
        let (row, _) = vault_access.read(&missing_id).await?;
        assert!(row.is_none());

        // Create a secret note
        let secret_label = "Test note";
        let secret_note = "Super secret note for you to read.";
        let (
            secret_id,
            _secret_meta,
            _secret_value,
            _meta_bytes,
            _secret_bytes,
        ) = create_secure_note(
            &mut vault_access,
            &vault,
            &encryption_key,
            secret_label,
            secret_note,
        )
        .await?;

        // Verify the secret exists
        let (row, _) = vault_access.read(&secret_id).await?;
        assert!(row.is_some());

        // Delete the secret
        let _ = vault_access.delete(&secret_id).await?;

        // Verify it does not exist after deletion
        let (row, _) = vault_access.read(&secret_id).await?;
        assert!(row.is_none());

        // Create a new secure note so we can update it
        let (
            secret_id,
            _secret_meta,
            _secret_value,
            _meta_bytes,
            _secret_bytes,
        ) = create_secure_note(
            &mut vault_access,
            &vault,
            &encryption_key,
            secret_label,
            secret_note,
        )
        .await?;

        // Update the secret with new values
        let updated_label = "Updated test note";
        let updated_note = "Updated note text.";
        let (_, _, meta_bytes, secret_bytes) =
            mock_secret_note(updated_label, updated_note).await?;

        let updated_meta = vault.encrypt(&encryption_key, &meta_bytes)?;
        let updated_secret = vault.encrypt(&encryption_key, &secret_bytes)?;
        let (commit, _) =
            Vault::commit_hash(&updated_meta, &updated_secret).await?;
        let _ = vault_access
            .update(
                &secret_id,
                commit,
                VaultEntry(updated_meta, updated_secret),
            )
            .await?;

        // Clean up the secret for next test execution
        let _ = vault_access.delete(&secret_id).await?;

        let vault_name = vault_access.vault_name().await?;
        assert_eq!(DEFAULT_VAULT_NAME, &vault_name);

        let new_name = String::from("New vault name");
        let _ = vault_access.set_vault_name(new_name.clone()).await;

        let vault_name = vault_access.vault_name().await?;
        assert_eq!(&new_name, &vault_name);

        // Reset the fixture vault name
        let _ = vault_access.set_vault_name(DEFAULT_VAULT_NAME.to_string());

        temp.close()?;

        Ok(())
    }

    #[tokio::test]
    async fn vault_file_del_splice() -> Result<()> {
        let (encryption_key, _, _) = mock_encryption_key()?;
        let (temp, vault, _) = mock_vault_file().await?;

        let vault_file = VaultWriter::open(temp.path()).await?;
        let mut vault_access = VaultWriter::new(temp.path(), vault_file)?;

        let secrets = [
            ("Note one", "First note"),
            ("Note two", "Second note"),
            ("Note three", "Third note"),
        ];

        let mut secret_ids = Vec::new();
        for note_data in secrets {
            let (
                secret_id,
                _secret_meta,
                _secret_value,
                _meta_bytes,
                _secret_bytes,
            ) = create_secure_note(
                &mut vault_access,
                &vault,
                &encryption_key,
                note_data.0,
                note_data.1,
            )
            .await?;
            secret_ids.push(secret_id);
        }

        let del_secret_id = secret_ids.get(1).unwrap();
        let _ = vault_access.delete(del_secret_id).await?;

        // Check the file identity is good after the deletion splice
        assert!(Header::read_header_file(temp.path()).await.is_ok());

        // Clean up other secrets
        for secret_id in secret_ids {
            let _ = vault_access.delete(&secret_id).await?;
        }

        // Verify again to finish up
        assert!(Header::read_header_file(temp.path()).await.is_ok());

        temp.close()?;

        Ok(())
    }
}
