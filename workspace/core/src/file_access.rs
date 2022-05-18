//! Manages access to a single vault file on disc.
use std::{borrow::Cow, path::Path, sync::Mutex};

use serde_binary::{
    binary_rw::{
        BinaryReader, BinaryWriter, Endian, FileStream, OpenType, Stream,
    },
    Decode, Deserializer, Serializer,
};
use uuid::Uuid;

use crate::{
    crypto::AeadPack,
    file_identity::FileIdentity,
    operations::{Payload, VaultAccess},
    vault::{Contents, IDENTITY},
    Result,
};

/// Wrapper type for accessing a vault file that manages
/// an underlying file stream.
pub struct VaultFileAccess {
    stream: Mutex<FileStream>,
}

impl VaultFileAccess {
    /// Create a new vault access.
    ///
    /// The underlying file should already exist and be a valid vault.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = std::fs::File::open(path.as_ref())?;
        let metadata = file.metadata()?;
        let stream = Mutex::new(FileStream::new(path, OpenType::ReadWrite)?);
        Ok(Self { stream })
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

    /// Seek to the content offset and read the total number of rows.
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
}

impl VaultAccess for VaultFileAccess {
    fn create(
        &mut self,
        uuid: Uuid,
        secret: (AeadPack, AeadPack),
    ) -> Result<Payload> {
        let content_offset = self.check_identity()?;
        let total_rows = self.rows(content_offset)?;

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

        Ok(Payload::CreateSecret(uuid, Cow::Owned(secret)))
    }

    fn read(
        &self,
        uuid: &Uuid,
    ) -> Result<(Option<&(AeadPack, AeadPack)>, Payload)> {
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
                // calling decode_row() will try to read the length and UUID
                // as well.
                de.reader.seek(current_pos)?;
                let (_, (meta, secret)) = Contents::decode_row(&mut de)?;
                // TODO: returned owned AeadPack tuple
                return Ok((None, Payload::ReadSecret(row_id)));
            }

            // Move on to the next row
            de.reader.seek(current_pos + 4 + (row_len as usize))?;
            current_pos = de.reader.tell()?;
        }

        Ok((None, Payload::ReadSecret(*uuid)))
    }

    fn update(
        &mut self,
        uuid: &Uuid,
        secret: (AeadPack, AeadPack),
    ) -> Result<Option<Payload>> {
        todo!("Update a secret in vault file");
    }

    fn delete(&mut self, uuid: &Uuid) -> Result<Payload> {
        todo!("Delete a secret in vault file");
    }
}

#[cfg(test)]
mod tests {
    use super::VaultFileAccess;
    use crate::{crypto::AeadPack, operations::VaultAccess, Result};
    use crate::test_utils::*;

    use uuid::Uuid;

    #[test]
    fn vault_file_access() -> Result<()> {
        let (encryption_key, _) = mock_encryption_key()?;
        let vault = mock_vault();

        let mut vault_access = VaultFileAccess::new(
            "./fixtures/fba77e3b-edd0-4849-a05f-dded6df31d22.vault",
        )?;

        let missing_id = Uuid::new_v4();
        let (row, _) = vault_access.read(&missing_id)?;
        assert!(row.is_none());

        let secret_label = "Test note";
        let secret_note = "Super secret note for you to read.";
        let (secret_id, _secret_meta, _secret_value, meta_bytes, secret_bytes) =
            mock_secret_note(secret_label, secret_note)?;

        let meta_aead = vault.encrypt(&encryption_key, &meta_bytes)?;
        let secret_aead = vault.encrypt(&encryption_key, &secret_bytes)?;

        let _ = vault_access.create(secret_id, (meta_aead, secret_aead))?;

        let (row, _) = vault_access.read(&secret_id)?;
        assert!(row.is_some());

        Ok(())
    }
}
