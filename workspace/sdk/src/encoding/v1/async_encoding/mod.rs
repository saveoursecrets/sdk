use std::io::Seek;

use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite,
    AsyncWriteExt,
};

use binary_stream::{
    tokio::{BinaryReader, BinaryWriter},
    BinaryError, BinaryResult,
};

use uuid::Uuid;

use crate::{
    commit::CommitHash,
    crypto::{AeadPack, Nonce},
    vault::{secret::SecretId, Contents, VaultCommit, VaultEntry},
    Error,
};

/// Temporary hack during migration to all async
impl Contents {
    /// Encode a single row into a serializer.
    pub async fn encode_row_async<W: AsyncWrite + AsyncSeek + Unpin>(
        writer: &mut BinaryWriter<W>,
        key: &SecretId,
        row: &VaultCommit,
    ) -> BinaryResult<()> {
        let size_pos = writer.tell().await?;
        writer.write_u32(0).await?;

        writer.write_bytes(key.as_bytes()).await?;
        encode_row_async(row, &mut *writer).await?;

        // Backtrack to size_pos and write new length
        let row_pos = writer.tell().await?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(size_pos).await?;
        writer.write_u32(row_len as u32).await?;
        writer.seek(row_pos).await?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        writer.write_u32(row_len as u32).await?;

        Ok(())
    }

    /// Decode a single row from a deserializer.
    pub async fn decode_row_async<R: AsyncRead + AsyncSeek + Unpin>(
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<(SecretId, VaultCommit)> {
        // Read in the row length
        let _ = reader.read_u32().await?;

        let uuid: [u8; 16] =
            reader.read_bytes(16).await?.as_slice().try_into()?;
        let uuid = Uuid::from_bytes(uuid);

        let mut row: VaultCommit = Default::default();
        decode_row_async(&mut row, &mut *reader).await?;

        // Read in the row length suffix
        let _ = reader.read_u32().await?;

        Ok((uuid, row))
    }
}

async fn encode_row_async<W: AsyncWrite + AsyncSeek + Unpin>(
    row: &VaultCommit,
    writer: &mut BinaryWriter<W>,
) -> BinaryResult<()> {
    writer.write_bytes(row.0.as_ref()).await?;

    let size_pos = writer.tell().await?;
    writer.write_u32(0).await?;

    encode_vault_entry(&row.1, &mut *writer).await?;

    // Encode the data length for lazy iteration
    let row_pos = writer.tell().await?;
    let row_len = row_pos - (size_pos + 4);
    writer.seek(size_pos).await?;
    writer.write_u32(row_len as u32).await?;
    writer.seek(row_pos).await?;

    Ok(())
}

async fn decode_row_async<R: AsyncRead + AsyncSeek + Unpin>(
    row: &mut VaultCommit,
    reader: &mut BinaryReader<R>,
) -> BinaryResult<()> {
    let commit: [u8; 32] =
        reader.read_bytes(32).await?.as_slice().try_into()?;
    let commit = CommitHash(commit);

    // Read in the length of the data blob
    let _ = reader.read_u32().await?;

    let mut group: VaultEntry = Default::default();
    decode_vault_entry(&mut group, reader).await?;
    row.0 = commit;
    row.1 = group;
    Ok(())
}

async fn encode_vault_entry<W: AsyncWrite + AsyncSeek + Unpin>(
    entry: &VaultEntry,
    writer: &mut BinaryWriter<W>,
) -> BinaryResult<()> {
    encode_aead_pack(&entry.0, &mut *writer).await?;
    encode_aead_pack(&entry.1, &mut *writer).await?;
    Ok(())
}

async fn decode_vault_entry<R: AsyncRead + AsyncSeek + Unpin>(
    _entry: &mut VaultEntry,
    _reader: &mut BinaryReader<R>,
) -> BinaryResult<()> {
    let _meta: AeadPack = Default::default();
    //meta.decode(&mut *reader)?;
    let _secret: AeadPack = Default::default();
    //secret.decode(&mut *reader)?;
    //*entry = VaultEntry(meta, secret);
    Ok(())
}

async fn encode_aead_pack<W: AsyncWrite + AsyncSeek + Unpin>(
    aead: &AeadPack,
    writer: &mut BinaryWriter<W>,
) -> BinaryResult<()> {
    match &aead.nonce {
        Nonce::Nonce12(ref bytes) => {
            writer.write_u8(12).await?;
            writer.write_bytes(bytes).await?;
        }
        Nonce::Nonce24(ref bytes) => {
            writer.write_u8(24).await?;
            writer.write_bytes(bytes).await?;
        }
    }
    writer.write_u32(aead.ciphertext.len() as u32).await?;
    writer.write_bytes(&aead.ciphertext).await?;
    Ok(())
}

async fn decode_aead_pack<R: AsyncRead + AsyncSeek + Unpin>(
    aead: &mut AeadPack,
    reader: &mut BinaryReader<R>,
) -> BinaryResult<()> {
    let nonce_size = reader.read_u8().await?;
    let nonce_buffer = reader.read_bytes(nonce_size as usize).await?;
    match nonce_size {
        12 => {
            aead.nonce = Nonce::Nonce12(nonce_buffer.as_slice().try_into()?)
        }
        24 => {
            aead.nonce = Nonce::Nonce24(nonce_buffer.as_slice().try_into()?)
        }
        _ => {
            return Err(BinaryError::Boxed(Box::from(
                Error::UnknownNonceSize(nonce_size),
            )));
        }
    }
    let len = reader.read_u32().await?;
    aead.ciphertext = reader.read_bytes(len as usize).await?;
    Ok(())
}
