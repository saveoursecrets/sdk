use crate::{
    encoding::encoding_error,
    Timestamp,
};
use async_trait::async_trait;
use binary_stream::futures::{BinaryReader, BinaryWriter, Decode, Encode};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::Result;
use time::{Duration, OffsetDateTime};

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for Timestamp {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let seconds = self.0.unix_timestamp();
        let nanos = self.0.nanosecond();
        writer.write_i64(seconds).await?;
        writer.write_u32(nanos).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for Timestamp {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let seconds = reader.read_i64().await?;
        let nanos = reader.read_u32().await?;

        self.0 = OffsetDateTime::from_unix_timestamp(seconds)
            .map_err(encoding_error)?
            + Duration::nanoseconds(nanos as i64);
        Ok(())
    }
}
