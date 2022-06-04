//! Manages access to a single vault file on disc.
use std::{
    borrow::Cow,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    ops::Range,
    path::Path,
    path::PathBuf,
    sync::Mutex,
};

use serde_binary::{
    binary_rw::{
        BinaryReader, BinaryWriter, Endian, FileStream, MemoryStream, OpenType,
        Stream,
    },
    Decode, Deserializer, Serializer,
};
use uuid::Uuid;

use crate::{
    crypto::AeadPack,
    file_identity::FileIdentity,
    operations::{Payload, VaultAccess},
    vault::{Contents, IDENTITY},
    Error, Result,
};

// 4 identity bytes, 4 bytes for the header length (u32) and
// 2 bytes for the version identifier (u16)
const CHANGE_SEQ_OFFSET: usize = 10;

/// Wrapper type for accessing a vault file that manages
/// an underlying file stream.
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
        let metadata = file.metadata()?;
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
        FileIdentity::read_identity(&mut de, &IDENTITY)?;
        let header_len = de.reader.read_u32()? as usize;
        Ok(IDENTITY.len() + 4 + header_len)
    }

    /// Set the current sequence number.
    fn set_change_seq(&self, change_seq: u32) -> Result<()> {
        let mut stream = self.stream.lock().unwrap();
        let writer = BinaryWriter::new(&mut *stream, Endian::Big);
        let mut ser = Serializer { writer };
        ser.writer.seek(CHANGE_SEQ_OFFSET)?;
        ser.writer.write_u32(change_seq)?;
        Ok(())
    }

    /// Increment the current sequence number by one.
    fn inc_change_seq(&self, change_seq: u32) -> Result<u32> {
        if let Some(next_change_seq) = change_seq.checked_add(1) {
            self.set_change_seq(next_change_seq)?;
            Ok(next_change_seq)
        } else {
            Err(Error::TooManyChanges)
        }
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

        // Inject the content if necessary
        if let Some(content) = content {
            file.seek(SeekFrom::End(0))?;
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
        uuid: &Uuid,
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
            if uuid == &row_id {
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

        return Ok((content_offset, total_rows, None));
    }
}

impl VaultAccess for VaultFileAccess {
    fn change_seq(&self) -> Result<u32> {
        let mut stream = self.stream.lock().unwrap();
        let reader = BinaryReader::new(&mut *stream, Endian::Big);
        let mut de = Deserializer { reader };
        de.reader.seek(CHANGE_SEQ_OFFSET)?;
        Ok(de.reader.read_u32()?)
    }

    fn save(&mut self, buffer: &[u8]) -> Result<Payload> {
        let mut file = File::options()
            .read(true)
            .write(true)
            .open(&self.file_path)?;
        file.write_all(buffer)?;

        let change_seq = self.change_seq()?;
        Ok(Payload::SaveVault(change_seq))
    }

    fn create(
        &mut self,
        uuid: Uuid,
        secret: (AeadPack, AeadPack),
    ) -> Result<Payload> {
        let content_offset = self.check_identity()?;
        let total_rows = self.rows(content_offset)?;
        let change_seq = self.change_seq()?;

        let mut stream = self.stream.lock().unwrap();
        let length = stream.len()?;
        let writer = BinaryWriter::new(&mut *stream, Endian::Big);
        let mut ser = Serializer { writer };

        // Seek to the end of the file and append the row
        ser.writer.seek(length)?;
        Contents::encode_row(&mut ser, &uuid, &secret)?;

        drop(stream);

        // Update the total rows count
        self.set_rows(content_offset, total_rows + 1)?;

        // Update the change sequence number
        let change_seq = self.inc_change_seq(change_seq)?;
        Ok(Payload::CreateSecret(change_seq, uuid, Cow::Owned(secret)))
    }

    fn read<'a>(
        &'a self,
        uuid: &Uuid,
    ) -> Result<(Option<Cow<'a, (AeadPack, AeadPack)>>, Payload)> {
        let (_, _, row) = self.find_row(uuid)?;
        let change_seq = self.change_seq()?;
        if let Some((row_offset, _)) = row {
            let mut stream = self.stream.lock().unwrap();
            let reader = BinaryReader::new(&mut *stream, Endian::Big);
            let mut de = Deserializer { reader };
            de.reader.seek(row_offset)?;
            let (_, (meta, secret)) = Contents::decode_row(&mut de)?;
            Ok((
                Some(Cow::Owned((meta, secret))),
                Payload::ReadSecret(change_seq, *uuid),
            ))
        } else {
            Ok((None, Payload::ReadSecret(change_seq, *uuid)))
        }
    }

    fn update(
        &mut self,
        uuid: &Uuid,
        secret: (AeadPack, AeadPack),
    ) -> Result<Option<Payload>> {
        let (content_offset, total_rows, row) = self.find_row(uuid)?;
        if let Some((row_offset, row_len)) = row {
            let change_seq = self.change_seq()?;

            // Prepare the row
            let mut stream = MemoryStream::new();
            let writer = BinaryWriter::new(&mut stream, Endian::Big);
            let mut ser = Serializer { writer };
            Contents::encode_row(&mut ser, uuid, &secret)?;
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

            // Update the change sequence number
            let change_seq = self.inc_change_seq(change_seq)?;

            Ok(Some(Payload::UpdateSecret(
                change_seq,
                *uuid,
                Cow::Owned(secret),
            )))
        } else {
            Ok(None)
        }
    }

    fn delete(&mut self, uuid: &Uuid) -> Result<Option<Payload>> {
        let id = *uuid;
        let (content_offset, total_rows, row) = self.find_row(uuid)?;
        if let Some((row_offset, row_len)) = row {
            let change_seq = self.change_seq()?;

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
            let change_seq = self.inc_change_seq(change_seq)?;
            Ok(Some(Payload::DeleteSecret(change_seq, id)))
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
        crypto::{secret_key::SecretKey, AeadPack},
        operations::VaultAccess,
        secret::*,
        vault::Vault,
        Result,
    };

    use uuid::Uuid;

    fn create_secure_note(
        vault_access: &mut VaultFileAccess,
        vault: &Vault,
        encryption_key: &SecretKey,
        secret_label: &str,
        secret_note: &str,
    ) -> Result<(Uuid, SecretMeta, Secret, Vec<u8>, Vec<u8>)> {
        let (secret_id, secret_meta, secret_value, meta_bytes, secret_bytes) =
            mock_secret_note(secret_label, secret_note)?;

        let meta_aead = vault.encrypt(encryption_key, &meta_bytes)?;
        let secret_aead = vault.encrypt(encryption_key, &secret_bytes)?;

        let _ = vault_access.create(secret_id, (meta_aead, secret_aead))?;
        Ok((
            secret_id,
            secret_meta,
            secret_value,
            meta_bytes,
            secret_bytes,
        ))
    }

    #[test]
    fn vault_file_access() -> Result<()> {
        let (encryption_key, _) = mock_encryption_key()?;
        let vault = mock_vault();

        let mut vault_access = VaultFileAccess::new(
            "./fixtures/6691de55-f499-4ed9-b72d-5631dbf1815c.vault",
        )?;
        let total_rows = vault_access.rows(vault_access.check_identity()?)?;
        assert_eq!(0, total_rows);

        let initial_change_seq = vault_access.change_seq()?;

        // Missing row should not exist
        let missing_id = Uuid::new_v4();
        let (row, _) = vault_access.read(&missing_id)?;
        assert!(row.is_none());

        // Create a secret note
        let secret_label = "Test note";
        let secret_note = "Super secret note for you to read.";
        let (secret_id, _secret_meta, _secret_value, meta_bytes, secret_bytes) =
            create_secure_note(
                &mut vault_access,
                &vault,
                &encryption_key,
                secret_label,
                secret_note,
            )?;

        let total_rows = vault_access.rows(vault_access.check_identity()?)?;
        assert_eq!(1, total_rows);

        assert_eq!(initial_change_seq + 1, vault_access.change_seq()?);

        // Verify the secret exists
        let (row, _) = vault_access.read(&secret_id)?;
        assert!(row.is_some());

        // Delete the secret
        let _ = vault_access.delete(&secret_id)?;
        let total_rows = vault_access.rows(vault_access.check_identity()?)?;
        assert_eq!(0, total_rows);

        assert_eq!(initial_change_seq + 2, vault_access.change_seq()?);

        // Verify it does not exist after deletion
        let (row, _) = vault_access.read(&secret_id)?;
        assert!(row.is_none());

        // Create a new secure note so we can update it
        let (secret_id, _secret_meta, _secret_value, meta_bytes, secret_bytes) =
            create_secure_note(
                &mut vault_access,
                &vault,
                &encryption_key,
                secret_label,
                secret_note,
            )?;
        let total_rows = vault_access.rows(vault_access.check_identity()?)?;
        assert_eq!(1, total_rows);

        assert_eq!(initial_change_seq + 3, vault_access.change_seq()?);

        // Update the secret with new values
        let updated_label = "Updated test note";
        let updated_note = "Updated note text.";
        let (_, _, _, meta_bytes, secret_bytes) =
            mock_secret_note(updated_label, updated_note)?;

        let updated_meta = vault.encrypt(&encryption_key, &meta_bytes)?;
        let updated_secret = vault.encrypt(&encryption_key, &secret_bytes)?;
        let _ =
            vault_access.update(&secret_id, (updated_meta, updated_secret))?;
        let total_rows = vault_access.rows(vault_access.check_identity()?)?;
        assert_eq!(1, total_rows);

        assert_eq!(initial_change_seq + 4, vault_access.change_seq()?);

        // Clean up the secret for next test execution
        let _ = vault_access.delete(&secret_id)?;
        let total_rows = vault_access.rows(vault_access.check_identity()?)?;
        assert_eq!(0, total_rows);

        assert_eq!(initial_change_seq + 5, vault_access.change_seq()?);

        Ok(())
    }
}
