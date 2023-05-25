use crate::Error;

use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};

use std::{
    borrow::Cow,
    io::{Read, Seek, Write},
};

use crate::{
    commit::CommitHash,
    crypto::AeadPack,
    events::{
        AuditData, AuditEvent, EventKind, EventRecord, LogFlags, ReadEvent,
        WriteEvent,
    },
    vault::{secret::SecretId, VaultCommit},
    Timestamp,
};

use uuid::Uuid;

impl Encode for EventKind {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        let value: u16 = self.into();
        writer.write_u16(value)?;
        Ok(())
    }
}

impl Decode for EventKind {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let op = reader.read_u16()?;
        *self = op.try_into().map_err(|_| {
            BinaryError::Boxed(Box::from(Error::UnknownEventKind(op)))
        })?;
        Ok(())
    }
}

impl Encode for EventRecord {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        // Prepare the bytes for the row length
        let size_pos = writer.tell()?;
        writer.write_u32(0)?;

        // Encode the time component
        self.0.encode(&mut *writer)?;

        // Write the previous commit hash bytes
        writer.write_bytes(self.1.as_ref())?;

        // Write the commit hash bytes
        writer.write_bytes(self.2.as_ref())?;

        // FIXME: ensure the buffer size does not exceed u32

        // Write the data bytes
        writer.write_u32(self.3.len() as u32)?;
        writer.write_bytes(&self.3)?;

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
}

impl Decode for EventRecord {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        // Read in the row length
        let _ = reader.read_u32()?;

        // Decode the time component
        let mut time: Timestamp = Default::default();
        time.decode(&mut *reader)?;

        // Read the hash bytes
        let previous: [u8; 32] =
            reader.read_bytes(32)?.as_slice().try_into()?;
        let commit: [u8; 32] =
            reader.read_bytes(32)?.as_slice().try_into()?;

        // Read the data bytes
        let length = reader.read_u32()?;
        let buffer = reader.read_bytes(length as usize)?;

        self.0 = time;
        self.1 = CommitHash(previous);
        self.2 = CommitHash(commit);
        self.3 = buffer;

        // Read in the row length appended to the end of the record
        let _ = reader.read_u32()?;

        Ok(())
    }
}

impl Encode for AuditEvent {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        // Context bit flags
        let flags = self.log_flags();
        writer.write_u16(flags.bits())?;
        // Time - the when
        self.time.encode(&mut *writer)?;
        // EventKind - the what
        self.event_kind.encode(&mut *writer)?;
        // Address - by whom
        writer.write_bytes(self.address.as_ref())?;
        // Data - context
        if flags.contains(LogFlags::DATA) {
            let data = self.data.as_ref().unwrap();
            data.encode(&mut *writer)?;
        }
        Ok(())
    }
}

impl Decode for AuditEvent {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        // Context bit flags
        let bits = reader.read_u16()?;
        // Time - the when
        let mut timestamp: Timestamp = Default::default();
        timestamp.decode(&mut *reader)?;
        // EventKind - the what
        self.event_kind.decode(&mut *reader)?;
        // Address - by whom
        let address = reader.read_bytes(20)?;
        let address: [u8; 20] = address.as_slice().try_into()?;
        self.address = address.into();
        // Data - context
        if let Some(flags) = LogFlags::from_bits(bits) {
            if flags.contains(LogFlags::DATA)
                && flags.contains(LogFlags::DATA_VAULT)
            {
                let vault_id: [u8; 16] =
                    reader.read_bytes(16)?.as_slice().try_into()?;
                if !flags.contains(LogFlags::DATA_SECRET) {
                    self.data =
                        Some(AuditData::Vault(Uuid::from_bytes(vault_id)));
                } else {
                    let secret_id: [u8; 16] =
                        reader.read_bytes(16)?.as_slice().try_into()?;
                    self.data = Some(AuditData::Secret(
                        Uuid::from_bytes(vault_id),
                        Uuid::from_bytes(secret_id),
                    ));
                }
            }
        } else {
            return Err(BinaryError::Custom(
                "log data flags has bad bits".to_string(),
            ));
        }
        Ok(())
    }
}

impl Encode for AuditData {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        match self {
            AuditData::Vault(vault_id) => {
                writer.write_bytes(vault_id.as_bytes())?;
            }
            AuditData::Secret(vault_id, secret_id) => {
                writer.write_bytes(vault_id.as_bytes())?;
                writer.write_bytes(secret_id.as_bytes())?;
            }
        }
        Ok(())
    }
}

impl Encode for ReadEvent {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        let op = self.event_kind();
        op.encode(&mut *writer)?;

        match self {
            ReadEvent::Noop => panic!("attempt to encode a noop"),
            ReadEvent::ReadVault => {}
            ReadEvent::ReadSecret(uuid) => {
                writer.write_bytes(uuid.as_bytes())?;
            }
        }
        Ok(())
    }
}

impl Decode for ReadEvent {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let mut op: EventKind = Default::default();
        op.decode(&mut *reader)?;
        match op {
            EventKind::Noop => panic!("attempt to decode a noop"),
            EventKind::ReadVault => {
                *self = ReadEvent::ReadVault;
            }
            EventKind::ReadSecret => {
                let id = SecretId::from_bytes(
                    reader.read_bytes(16)?.as_slice().try_into()?,
                );
                *self = ReadEvent::ReadSecret(id);
            }
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownEventKind((&op).into()),
                )))
            }
        }
        Ok(())
    }
}

impl<'a> Encode for WriteEvent<'a> {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        let op = self.event_kind();
        op.encode(&mut *writer)?;

        match self {
            WriteEvent::Noop => {
                panic!("WriteEvent: attempt to encode a noop")
            }
            WriteEvent::CreateVault(vault)
            | WriteEvent::UpdateVault(vault) => {
                writer.write_u32(vault.as_ref().len() as u32)?;
                writer.write_bytes(vault.as_ref())?;
            }
            WriteEvent::DeleteVault => {}
            WriteEvent::SetVaultName(name) => {
                writer.write_string(name)?;
            }
            WriteEvent::SetVaultMeta(meta) => {
                writer.write_bool(meta.is_some())?;
                if let Some(meta) = meta.as_ref() {
                    meta.encode(&mut *writer)?;
                }
            }
            WriteEvent::CreateSecret(uuid, value) => {
                writer.write_bytes(uuid.as_bytes())?;
                value.as_ref().encode(&mut *writer)?;
            }
            WriteEvent::UpdateSecret(uuid, value) => {
                writer.write_bytes(uuid.as_bytes())?;
                value.as_ref().encode(&mut *writer)?;
            }
            WriteEvent::DeleteSecret(uuid) => {
                writer.write_bytes(uuid.as_bytes())?;
            }
        }
        Ok(())
    }
}

impl<'a> Decode for WriteEvent<'a> {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let mut op: EventKind = Default::default();
        op.decode(&mut *reader)?;
        match op {
            EventKind::Noop => panic!("WriteEvent: attempt to decode a noop"),
            EventKind::CreateVault => {
                let length = reader.read_u32()?;
                let buffer = reader.read_bytes(length as usize)?;
                *self = WriteEvent::CreateVault(Cow::Owned(buffer))
            }
            EventKind::UpdateVault => {
                let length = reader.read_u32()?;
                let buffer = reader.read_bytes(length as usize)?;
                *self = WriteEvent::UpdateVault(Cow::Owned(buffer))
            }
            EventKind::DeleteVault => {
                *self = WriteEvent::DeleteVault;
            }
            EventKind::SetVaultName => {
                let name = reader.read_string()?;
                *self = WriteEvent::SetVaultName(Cow::Owned(name));
            }
            EventKind::SetVaultMeta => {
                let has_meta = reader.read_bool()?;
                let aead_pack = if has_meta {
                    let mut aead_pack: AeadPack = Default::default();
                    aead_pack.decode(&mut *reader)?;
                    Some(aead_pack)
                } else {
                    None
                };
                *self = WriteEvent::SetVaultMeta(Cow::Owned(aead_pack));
            }
            EventKind::CreateSecret => {
                let id = SecretId::from_bytes(
                    reader.read_bytes(16)?.as_slice().try_into()?,
                );
                let mut commit: VaultCommit = Default::default();
                commit.decode(&mut *reader)?;
                *self = WriteEvent::CreateSecret(id, Cow::Owned(commit));
            }
            EventKind::UpdateSecret => {
                let id = SecretId::from_bytes(
                    reader.read_bytes(16)?.as_slice().try_into()?,
                );
                let mut commit: VaultCommit = Default::default();
                commit.decode(&mut *reader)?;
                *self = WriteEvent::UpdateSecret(id, Cow::Owned(commit));
            }
            EventKind::DeleteSecret => {
                let id = SecretId::from_bytes(
                    reader.read_bytes(16)?.as_slice().try_into()?,
                );
                *self = WriteEvent::DeleteSecret(id);
            }
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownEventKind((&op).into()),
                )))
            }
        }
        Ok(())
    }
}
