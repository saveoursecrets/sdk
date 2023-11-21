//! Binary RPC protocol for peer to peer message exchange.
use async_trait::async_trait;
use futures::prelude::*;
use libp2p::{
    core::upgrade::{read_length_prefixed, write_length_prefixed},
    request_response::Codec,
};
use std::{
    convert::AsRef,
    io::{self, ErrorKind},
};

use sos_sdk::{decode, encode};

use crate::rpc::{RequestMessage, ResponseMessage};

const MAX_BUFFER_READ: usize = 16_777_216;

/// Protocol for RPC messages.
#[derive(Debug, Clone)]
pub struct RpcExchangeProtocol {
    name: String,
}

impl Default for RpcExchangeProtocol {
    fn default() -> Self {
        Self {
            name: "/sos-rpc/1.0.0".to_owned(),
        }
    }
}

impl AsRef<str> for RpcExchangeProtocol {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

/// Codec for RPC messages.
#[derive(Default, Clone)]
pub struct RpcExchangeCodec;

/*
impl ProtocolName for RpcExchangeProtocol {
    fn protocol_name(&self) -> &[u8] {
        "/sos-rpc/1.0.0".as_bytes()
    }
}
*/

#[async_trait]
impl Codec for RpcExchangeCodec {
    type Protocol = RpcExchangeProtocol;
    type Request = RequestMessage<'static>;
    type Response = ResponseMessage<'static>;

    async fn read_request<T>(
        &mut self,
        _: &RpcExchangeProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, MAX_BUFFER_READ).await?;
        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        let request: RequestMessage<'static> =
            decode(vec.as_slice())
                .await
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        Ok(request)
    }

    async fn read_response<T>(
        &mut self,
        _: &RpcExchangeProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, MAX_BUFFER_READ).await?;
        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        let response: ResponseMessage<'static> = decode(vec.as_slice())
            .await
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        Ok(response)
    }

    async fn write_request<T>(
        &mut self,
        _: &RpcExchangeProtocol,
        io: &mut T,
        data: RequestMessage<'static>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = encode(&data)
            .await
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        write_length_prefixed(io, data).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &RpcExchangeProtocol,
        io: &mut T,
        data: ResponseMessage<'static>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = encode(&data)
            .await
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        write_length_prefixed(io, data).await?;
        io.close().await?;
        Ok(())
    }
}
