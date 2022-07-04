//! Manages access to a single vault file on disc.
use std::{
    borrow::Cow,
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    ops::Range,
    path::Path,
    path::PathBuf,
    sync::Mutex,
};

use serde_binary::{
    binary_rw::{
        BinaryReader, BinaryWriter, Endian, FileStream, MemoryStream,
        OpenType, SeekStream,
    },
    Deserializer, Serializer,
};
use uuid::Uuid;

use crate::{
    constants::VAULT_IDENTITY,
    crypto::AeadPack,
    events::SyncEvent,
    secret::SecretId,
    vault::{
        encode, Contents, Header, Summary, VaultAccess, VaultCommit,
        VaultEntry,
    },
    CommitHash, FileIdentity, Result,
};

/// Implements access to an encrypted vault backed by a file on disc.
pub struct VaultFileAccess {
    file_path: PathBuf,
    stream: Mutex<FileStream>,
}

impl VaultFileAccess {
    /// Create a new vault access.
    ///
    /// The underlying file should already exist and be a valid vault.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file_path = path.as_ref().to_path_buf();
        let file = std::fs::File::open(path.as_ref())?;
        let _metadata = file.metadata()?;
        let stream = Mutex::new(FileStream::new(path, OpenType::ReadWrite)?);
        Ok(Self { file_path, stream })
    }

    /// Check the identity bytes and return the byte offset of the
    /// beginning of the vault content area.
    fn check_identity(&self) -> Result<usize> {
        let mut stream = self.stream.lock().unwrap();
        let reader = BinaryReader::new(&mut *stream, Endian::Big);
        let mut de = Deserializer { reader };
        // Must reset to beginning of the file
        de.reader.seek(0)?;
        FileIdentity::read_identity(&mut de, &VAULT_IDENTITY)?;
        let header_len = de.reader.read_u32()? as usize;
        Ok(VAULT_IDENTITY.len() + 4 + header_len)
    }

    /// Seek to the content offset and read the sequence number and
    /// total number of rows.
    fn rows(&self, content_offset: usize) -> Result<u32> {
        let mut stream = self.stream.lock().unwrap();
        let reader = BinaryReader::new(&mut *stream, Endian::Big);
        let mut de = Deserializer { reader };
        de.reader.seek(content_offset)?;
        Ok(de.reader.read_u32()?)
    }

    /// Seek to the content offset and write the total number of rows.
    fn set_rows(&self, content_offset: usize, rows: u32) -> Result<()> {
        let mut stream = self.stream.lock().unwrap();
        let writer = BinaryWriter::new(&mut *stream, Endian::Big);
        let mut ser = Serializer { writer };
        ser.writer.seek(content_offset)?;
        ser.writer.write_u32(rows)?;
        Ok(())
    }

    /// Write out the header preserving the existing content bytes.
    fn write_header(
        &self,
        content_offset: usize,
        header: &Header,
    ) -> Result<()> {
        let head = encode(header)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.file_path)?;

        // Read the content into memory
        file.seek(SeekFrom::Start(content_offset as u64))?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;

        // Rewind and truncate the file
        file.rewind()?;
        file.set_len(0)?;

        // Write out the header
        file.write_all(&head)?;

        // Write out the content
        file.write_all(&content)?;

        Ok(())
    }

    /// Splice a file preserving the head and tail and optionally inserting
    /// content in between.
    fn splice(
        &self,
        head: Range<usize>,
        tail: Range<usize>,
        content: Option<&[u8]>,
    ) -> Result<()> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.file_path)?;

        // Read the tail into memory
        file.seek(SeekFrom::Start(tail.start as u64))?;
        let mut end = Vec::new();
        file.read_to_end(&mut end)?;

        if head.start == 0 {
            // Rewind and truncate the file to the head
            file.rewind()?;
            file.set_len(head.end as u64)?;
        } else {
            unreachable!("file splice head range always starts at zero");
        }

        // Must seek to the end before writing out the content or tail
        file.seek(SeekFrom::End(0))?;

        // Inject the content if necessary
        if let Some(content) = content {
            //file.seek(SeekFrom::End(0))?;
            file.write_all(content)?;
        }

        // Write out the end portion
        file.write_all(&end)?;

        Ok(())
    }

    /// Find the byte offset of a row.
    ///
    /// Returns the content offset, total rows and the byte offset and row length of the row if it exists.
    fn find_row(
        &self,
        id: &SecretId,
    ) -> Result<(usize, u32, Option<(usize, u32)>)> {
        let content_offset = self.check_identity()?;

        let mut stream = self.stream.lock().unwrap();
        let reader = BinaryReader::new(&mut *stream, Endian::Big);
        let mut de = Deserializer { reader };

        de.reader.seek(content_offset)?;

        let total_rows = de.reader.read_u32()?;
        // Scan all the rows
        let mut current_pos = de.reader.tell()?;
        while let Ok(row_len) = de.reader.read_u32() {
            let row_id: [u8; 16] =
                de.reader.read_bytes(16)?.as_slice().try_into()?;
            let row_id = Uuid::from_bytes(row_id);
            if id == &row_id {
                // Need to backtrack as we just read the row length and UUID;
                // calling decode_row() will try to read the length and UUID.
                de.reader.seek(current_pos)?;
                return Ok((
                    content_offset,
                    total_rows,
                    Some((current_pos, row_len)),
                ));
            }

            // Move on to the next row
            de.reader.seek(current_pos + 4 + (row_len as usize))?;
            current_pos = de.reader.tell()?;
        }

        Ok((content_offset, total_rows, None))
    }
}

impl VaultAccess for VaultFileAccess {
    fn summary(&self) -> Result<Summary> {
        Header::read_summary_file(&self.file_path)
    }

    fn vault_name(&self) -> Result<(String, SyncEvent<'_>)> {
        let header = Header::read_header_file(&self.file_path)?;
        let name = header.name().to_string();
        Ok((name, SyncEvent::GetVaultName))
    }

    fn set_vault_name(&mut self, name: String) -> Result<SyncEvent<'_>> {
        let content_offset = self.check_identity()?;
        let mut header = Header::read_header_file(&self.file_path)?;
        header.set_name(name.clone());
        self.write_header(content_offset, &header)?;
        Ok(SyncEvent::SetVaultName(Cow::Owned(name)))
    }

    fn set_vault_meta(
        &mut self,
        meta_data: Option<AeadPack>,
    ) -> Result<SyncEvent<'_>> {
        let content_offset = self.check_identity()?;
        let mut header = Header::read_header_file(&self.file_path)?;
        header.set_meta(meta_data.clone());
        self.write_header(content_offset, &header)?;
        Ok(SyncEvent::SetVaultMeta(Cow::Owned(meta_data)))
    }

    fn create(
        &mut self,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<SyncEvent<'_>> {
        let id = Uuid::new_v4();
        self.insert(id, commit, secret)
    }

    fn insert(
        &mut self,
        id: SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<SyncEvent<'_>> {
        let content_offset = self.check_identity()?;
        let total_rows = self.rows(content_offset)?;

        let mut stream = self.stream.lock().unwrap();
        let length = stream.len()?;
        let writer = BinaryWriter::new(&mut *stream, Endian::Big);
        let mut ser = Serializer { writer };

        let row = VaultCommit(commit, secret);

        // Seek to the end of the file and append the row
        ser.writer.seek(length)?;
        Contents::encode_row(&mut ser, &id, &row)?;

        drop(stream);

        // Update the total rows count
        self.set_rows(content_offset, total_rows + 1)?;

        // Update the change sequence number
        Ok(SyncEvent::CreateSecret(id, Cow::Owned(row)))
    }

    fn read<'a>(
        &'a self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'a, VaultCommit>>, SyncEvent<'_>)> {
        let (_, _, row) = self.find_row(id)?;
        if let Some((row_offset, _)) = row {
            let mut stream = self.stream.lock().unwrap();
            let reader = BinaryReader::new(&mut *stream, Endian::Big);
            let mut de = Deserializer { reader };
            de.reader.seek(row_offset)?;
            let (_, value) = Contents::decode_row(&mut de)?;
            Ok((Some(Cow::Owned(value)), SyncEvent::ReadSecret(*id)))
        } else {
            Ok((None, SyncEvent::ReadSecret(*id)))
        }
    }

    fn update(
        &mut self,
        id: &SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<Option<SyncEvent<'_>>> {
        let (_content_offset, _total_rows, row) = self.find_row(id)?;
        if let Some((row_offset, row_len)) = row {
            // Prepare the row
            let mut stream = MemoryStream::new();
            let writer = BinaryWriter::new(&mut stream, Endian::Big);
            let mut ser = Serializer { writer };

            let row = VaultCommit(commit, secret);
            Contents::encode_row(&mut ser, id, &row)?;
            let encoded: Vec<u8> = stream.into();

            // Splice the row into the file
            let stream = self.stream.lock().unwrap();
            let length = stream.len()?;
            drop(stream);

            let head = 0..row_offset;
            // Row offset is before the row length u32 so we
            // need to account for that too
            let tail = (row_offset + 4 + (row_len as usize))..length;

            self.splice(head, tail, Some(&encoded))?;

            Ok(Some(SyncEvent::UpdateSecret(*id, Cow::Owned(row))))
        } else {
            Ok(None)
        }
    }

    fn delete(&mut self, id: &SecretId) -> Result<Option<SyncEvent<'_>>> {
        let (content_offset, total_rows, row) = self.find_row(id)?;
        if let Some((row_offset, row_len)) = row {
            let stream = self.stream.lock().unwrap();
            let length = stream.len()?;
            drop(stream);

            let head = 0..row_offset;
            // Row offset is before the row length u32 so we
            // need to account for that too
            let tail = (row_offset + 4 + (row_len as usize))..length;

            self.splice(head, tail, None)?;

            // Update the total rows count
            self.set_rows(content_offset, total_rows - 1)?;

            // Update the change sequence number
            Ok(Some(SyncEvent::DeleteSecret(*id)))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::VaultFileAccess;
    use crate::test_utils::*;
    use crate::{
        crypto::secret_key::SecretKey,
        events::SyncEvent,
        secret::*,
        vault::{Header, Vault, VaultAccess, VaultEntry, DEFAULT_VAULT_NAME},
    };
    use anyhow::Result;

    use uuid::Uuid;

    fn create_secure_note(
        vault_access: &mut VaultFileAccess,
        vault: &Vault,
        encryption_key: &SecretKey,
        secret_label: &str,
        secret_note: &str,
    ) -> Result<(SecretId, SecretMeta, Secret, Vec<u8>, Vec<u8>)> {
        let (secret_meta, secret_value, meta_bytes, secret_bytes) =
            mock_secret_note(secret_label, secret_note)?;

        let meta_aead = vault.encrypt(encryption_key, &meta_bytes)?;
        let secret_aead = vault.encrypt(encryption_key, &secret_bytes)?;

        let (commit, _) = Vault::commit_hash(&meta_aead, &secret_aead)?;

        if let SyncEvent::CreateSecret(secret_id, _) =
            vault_access.create(commit, VaultEntry(meta_aead, secret_aead))?
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

    #[test]
    fn vault_file_access() -> Result<()> {
        let (encryption_key, _) = mock_encryption_key()?;
        let (temp, vault, _) = mock_vault_file()?;

        let mut vault_access = VaultFileAccess::new(temp.path())?;
        let total_rows = vault_access.rows(vault_access.check_identity()?)?;
        assert_eq!(0, total_rows);

        // Missing row should not exist
        let missing_id = Uuid::new_v4();
        let (row, _) = vault_access.read(&missing_id)?;
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
        )?;

        let total_rows = vault_access.rows(vault_access.check_identity()?)?;
        assert_eq!(1, total_rows);

        // Verify the secret exists
        let (row, _) = vault_access.read(&secret_id)?;
        assert!(row.is_some());

        // Delete the secret
        let _ = vault_access.delete(&secret_id)?;
        let total_rows = vault_access.rows(vault_access.check_identity()?)?;
        assert_eq!(0, total_rows);

        // Verify it does not exist after deletion
        let (row, _) = vault_access.read(&secret_id)?;
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
        )?;
        let total_rows = vault_access.rows(vault_access.check_identity()?)?;
        assert_eq!(1, total_rows);

        // Update the secret with new values
        let updated_label = "Updated test note";
        let updated_note = "Updated note text.";
        let (_, _, meta_bytes, secret_bytes) =
            mock_secret_note(updated_label, updated_note)?;

        let updated_meta = vault.encrypt(&encryption_key, &meta_bytes)?;
        let updated_secret = vault.encrypt(&encryption_key, &secret_bytes)?;
        let (commit, _) = Vault::commit_hash(&updated_meta, &updated_secret)?;
        let _ = vault_access.update(
            &secret_id,
            commit,
            VaultEntry(updated_meta, updated_secret),
        )?;
        let total_rows = vault_access.rows(vault_access.check_identity()?)?;
        assert_eq!(1, total_rows);

        // Clean up the secret for next test execution
        let _ = vault_access.delete(&secret_id)?;
        let total_rows = vault_access.rows(vault_access.check_identity()?)?;
        assert_eq!(0, total_rows);

        let (vault_name, _) = vault_access.vault_name()?;
        assert_eq!(DEFAULT_VAULT_NAME, vault_name);

        let new_name = String::from("New vault name");
        let _ = vault_access.set_vault_name(new_name.clone());

        let (vault_name, _) = vault_access.vault_name()?;
        assert_eq!(&new_name, &vault_name);

        // Reset the fixture vault name
        let _ = vault_access.set_vault_name(DEFAULT_VAULT_NAME.to_string());

        temp.close()?;

        Ok(())
    }

    #[test]
    fn vault_file_del_splice() -> Result<()> {
        let (encryption_key, _) = mock_encryption_key()?;
        let (temp, vault, _) = mock_vault_file()?;

        let mut vault_access = VaultFileAccess::new(temp.path())?;

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
            )?;
            secret_ids.push(secret_id);
        }

        let total_rows = vault_access.rows(vault_access.check_identity()?)?;
        assert_eq!(3, total_rows);

        let del_secret_id = secret_ids.get(1).unwrap();
        let _ = vault_access.delete(del_secret_id)?;

        let total_rows = vault_access.rows(vault_access.check_identity()?)?;
        assert_eq!(2, total_rows);

        // Check the file identity is good after the deletion splice
        assert!(Header::read_header_file(temp.path()).is_ok());

        // Clean up other secrets
        for secret_id in secret_ids {
            let _ = vault_access.delete(&secret_id)?;
        }

        let total_rows = vault_access.rows(vault_access.check_identity()?)?;
        assert_eq!(0, total_rows);

        // Verify again to finish up
        assert!(Header::read_header_file(temp.path()).is_ok());

        temp.close()?;

        Ok(())
    }
}
