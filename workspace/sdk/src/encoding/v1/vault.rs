use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};

use std::io::{Read, Seek, Write};

use uuid::Uuid;

use crate::{
    commit::CommitHash,
    constants::VAULT_IDENTITY,
    crypto::{secret_key::SEED_SIZE, AeadPack, ALGORITHMS},
    formats::FileIdentity,
    vault::{
        secret::SecretId, Auth, Contents, Header, Summary, Vault,
        VaultCommit, VaultEntry, VaultFlags, VaultMeta,
    },
    Error, Timestamp,
};

impl Encode for VaultMeta {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        self.date_created.encode(&mut *writer)?;
        writer.write_string(&self.label)?;
        Ok(())
    }
}

impl Decode for VaultMeta {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let mut date_created: Timestamp = Default::default();
        date_created.decode(&mut *reader)?;
        self.label = reader.read_string()?;
        Ok(())
    }
}

impl Encode for VaultEntry {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        self.0.encode(&mut *writer)?;
        self.1.encode(&mut *writer)?;
        Ok(())
    }
}

impl Decode for VaultEntry {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let mut meta: AeadPack = Default::default();
        meta.decode(&mut *reader)?;
        let mut secret: AeadPack = Default::default();
        secret.decode(&mut *reader)?;
        *self = VaultEntry(meta, secret);
        Ok(())
    }
}

impl Encode for VaultCommit {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        writer.write_bytes(self.0.as_ref())?;

        let size_pos = writer.tell()?;
        writer.write_u32(0)?;

        self.1.encode(&mut *writer)?;

        // Encode the data length for lazy iteration
        let row_pos = writer.tell()?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(size_pos)?;
        writer.write_u32(row_len as u32)?;
        writer.seek(row_pos)?;

        Ok(())
    }
}

impl Decode for VaultCommit {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let commit: [u8; 32] =
            reader.read_bytes(32)?.as_slice().try_into()?;
        let commit = CommitHash(commit);

        // Read in the length of the data blob
        let _ = reader.read_u32()?;

        let mut group: VaultEntry = Default::default();
        group.decode(&mut *reader)?;
        self.0 = commit;
        self.1 = group;
        Ok(())
    }
}

impl Encode for Auth {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        writer.write_bool(self.salt.is_some())?;
        if let Some(salt) = &self.salt {
            writer.write_string(salt)?;
        }
        writer.write_bool(self.seed.is_some())?;
        if let Some(seed) = &self.seed {
            writer.write_bytes(seed)?;
        }
        Ok(())
    }
}

impl Decode for Auth {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let has_salt = reader.read_bool()?;
        if has_salt {
            self.salt = Some(reader.read_string()?);
        }
        let has_seed = reader.read_bool()?;
        if has_seed {
            self.seed =
                Some(reader.read_bytes(SEED_SIZE)?.as_slice().try_into()?);
        }
        Ok(())
    }
}

impl Encode for Summary {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        writer.write_u16(self.version)?;
        self.algorithm.encode(&mut *writer)?;
        writer.write_bytes(self.id.as_bytes())?;
        writer.write_string(&self.name)?;
        writer.write_u64(self.flags.bits())?;
        Ok(())
    }
}

impl Decode for Summary {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        self.version = reader.read_u16()?;
        self.algorithm.decode(&mut *reader)?;

        if !ALGORITHMS.contains(self.algorithm.as_ref()) {
            return Err(BinaryError::Boxed(Box::from(
                Error::UnknownAlgorithm(self.algorithm.into()),
            )));
        }

        let uuid: [u8; 16] = reader.read_bytes(16)?.as_slice().try_into()?;
        self.id = Uuid::from_bytes(uuid);
        self.name = reader.read_string()?;
        self.flags = VaultFlags::from_bits(reader.read_u64()?)
            .ok_or(Error::InvalidVaultFlags)
            .map_err(Box::from)?;
        Ok(())
    }
}

impl Encode for Header {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        FileIdentity::write_identity(&mut *writer, &VAULT_IDENTITY)
            .map_err(Box::from)?;

        let size_pos = writer.tell()?;
        writer.write_u32(0)?;

        self.summary.encode(&mut *writer)?;

        writer.write_bool(self.meta.is_some())?;
        if let Some(meta) = &self.meta {
            meta.encode(&mut *writer)?;
        }

        self.auth.encode(&mut *writer)?;

        // Backtrack to size_pos and write new length
        let header_pos = writer.tell()?;
        let header_len = header_pos - (size_pos + 4);

        writer.seek(size_pos)?;
        writer.write_u32(header_len as u32)?;
        writer.seek(header_pos)?;

        Ok(())
    }
}

impl Decode for Header {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        FileIdentity::read_identity(&mut *reader, &VAULT_IDENTITY)
            .map_err(Box::from)?;

        // Read in the header length
        let _ = reader.read_u32()?;

        self.summary.decode(&mut *reader)?;

        let has_meta = reader.read_bool()?;
        if has_meta {
            self.meta = Some(Default::default());
            if let Some(meta) = self.meta.as_mut() {
                meta.decode(&mut *reader)?;
            }
        }

        self.auth.decode(&mut *reader)?;
        Ok(())
    }
}

impl Contents {
    /// Encode a single row into a serializer.
    pub fn encode_row<W: Write + Seek>(
        writer: &mut BinaryWriter<W>,
        key: &SecretId,
        row: &VaultCommit,
    ) -> BinaryResult<()> {
        let size_pos = writer.tell()?;
        writer.write_u32(0)?;

        writer.write_bytes(key.as_bytes())?;
        row.encode(&mut *writer)?;

        // Backtrack to size_pos and write new length
        let row_pos = writer.tell()?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(size_pos)?;
        writer.write_u32(row_len as u32)?;
        writer.seek(row_pos)?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        writer.write_u32(row_len as u32)?;

        Ok(())
    }

    /// Decode a single row from a deserializer.
    pub fn decode_row<R: Read + Seek>(
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<(SecretId, VaultCommit)> {
        // Read in the row length
        let _ = reader.read_u32()?;

        let uuid: [u8; 16] = reader.read_bytes(16)?.as_slice().try_into()?;
        let uuid = Uuid::from_bytes(uuid);

        let mut row: VaultCommit = Default::default();
        row.decode(&mut *reader)?;

        // Read in the row length suffix
        let _ = reader.read_u32()?;

        Ok((uuid, row))
    }
}

impl Encode for Contents {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        //ser.writer.write_u32(self.data.len() as u32)?;
        for (key, row) in &self.data {
            Contents::encode_row(writer, key, row)?;
        }
        Ok(())
    }
}

impl Decode for Contents {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        //let length = de.reader.read_u32()?;

        /*
        for _ in 0..length {
            let (uuid, value) = Contents::decode_row(de)?;
            self.data.insert(uuid, value);
        }
        */

        let mut pos = reader.tell()?;
        let len = reader.len()?;
        while pos < len {
            let (uuid, value) = Contents::decode_row(reader)?;
            self.data.insert(uuid, value);
            pos = reader.tell()?;
        }

        Ok(())
    }
}

impl Encode for Vault {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        self.header.encode(writer)?;
        self.contents.encode(writer)?;
        Ok(())
    }
}

impl Decode for Vault {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        self.header.decode(reader)?;
        self.contents.decode(reader)?;
        Ok(())
    }
}
