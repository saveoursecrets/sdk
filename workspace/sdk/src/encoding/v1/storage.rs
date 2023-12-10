use crate::{
    decode, encode, encoding::encoding_error, storage::AccountPack,
    vault::Vault,
};

use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::{Error, ErrorKind, Result};

#[async_trait]
impl Encodable for AccountPack {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        // Address
        writer.write_bytes(self.address.as_ref()).await?;

        // Identity vault
        let buffer =
            encode(&self.identity_vault).await.map_err(encoding_error)?;
        let length = buffer.len();
        writer.write_u32(length as u32).await?;
        writer.write_bytes(&buffer).await?;

        // Folders
        writer.write_u8(self.folders.len() as u8).await?;
        for folder in &self.folders {
            let buffer = encode(folder).await.map_err(encoding_error)?;
            let length = buffer.len();
            writer.write_u32(length as u32).await?;
            writer.write_bytes(&buffer).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for AccountPack {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        // Address
        let address = reader.read_bytes(20).await?;
        let address: [u8; 20] =
            address.as_slice().try_into().map_err(encoding_error)?;
        self.address = address.into();

        // Identity vault
        let length = reader.read_u32().await?;
        let buffer = reader.read_bytes(length as usize).await?;
        self.identity_vault =
            decode(&buffer).await.map_err(encoding_error)?;

        // Folders
        let num_folders = reader.read_u8().await?;
        for _ in 0..(num_folders as usize) {
            let length = reader.read_u32().await?;
            let buffer = reader.read_bytes(length as usize).await?;
            let folder: Vault =
                decode(&buffer).await.map_err(encoding_error)?;
            self.folders.push(folder);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{decode, encode, storage::AccountPack};
    use anyhow::Result;

    #[tokio::test]
    async fn encode_decode_account_pack() -> Result<()> {
        let account_data: AccountPack = Default::default();
        let buffer = encode(&account_data).await?;
        let _: AccountPack = decode(&buffer).await?;
        Ok(())
    }
}
