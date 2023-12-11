use crate::{
    encoding::encoding_error,
    prelude::{EventRecord, FileIdentity, PATCH_IDENTITY},
};

use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::Result;

use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};

use crate::sync::{Patch, ChangeSet};

#[async_trait]
impl<T> Encodable for Patch<T>
where
    T: Default + Encodable + Decodable + Send + Sync,
{
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(PATCH_IDENTITY).await?;
        for event in self.iter() {
            event.encode(writer).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl<T> Decodable for Patch<T>
where
    T: Default + Encodable + Decodable + Send + Sync,
{
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        FileIdentity::read_identity(reader, &PATCH_IDENTITY)
            .await
            .map_err(encoding_error)?;
        let mut pos = reader.stream_position().await?;
        let len = reader.len().await?;
        while pos < len {
            let mut event: T = Default::default();
            event.decode(reader).await?;
            self.append(event);
            pos = reader.stream_position().await?;
        }
        Ok(())
    }
}


#[async_trait]
impl Encodable for ChangeSet {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        todo!("encode change set");
        Ok(())
    }
}

#[async_trait]
impl Decodable for ChangeSet
{
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        todo!("decode change set");
        Ok(())
    }
}
