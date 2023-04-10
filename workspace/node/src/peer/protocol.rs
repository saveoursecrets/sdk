//! Binary RPC protocol for peer to peer message exchange.
use async_trait::async_trait;
use futures::prelude::*;
use libp2p::{
    core::upgrade::{
        read_length_prefixed, write_length_prefixed, ProtocolName,
    },
    request_response::Codec,
};
use std::io::{self, ErrorKind};

use sos_core::{
    decode, encode,
    rpc::{RequestMessage, ResponseMessage},
};

const MAX_BUFFER_READ: usize = 16_777_216;

/// Protocol for RPC messages.
#[derive(Debug, Clone)]
pub struct RpcExchangeProtocol();

/// Codec for RPC messages.
#[derive(Clone)]
pub struct RpcExchangeCodec();

/// RPC request message.
#[derive(Debug)]
pub struct PeerRpcRequest(pub RequestMessage<'static>);

/// RPC response message.
#[derive(Debug)]
pub struct PeerRpcResponse(pub ResponseMessage<'static>);

impl ProtocolName for RpcExchangeProtocol {
    fn protocol_name(&self) -> &[u8] {
        "/sos-rpc/1".as_bytes()
    }
}

#[async_trait]
impl Codec for RpcExchangeCodec {
    type Protocol = RpcExchangeProtocol;
    type Request = PeerRpcRequest;
    type Response = PeerRpcResponse;

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

        let request: RequestMessage<'static> = decode(vec.as_slice())
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        Ok(PeerRpcRequest(request))
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

        let request: ResponseMessage<'static> = decode(vec.as_slice())
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        Ok(PeerRpcResponse(request))
    }

    async fn write_request<T>(
        &mut self,
        _: &RpcExchangeProtocol,
        io: &mut T,
        PeerRpcRequest(ref data): PeerRpcRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data =
            encode(data).map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        write_length_prefixed(io, data).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &RpcExchangeProtocol,
        io: &mut T,
        PeerRpcResponse(ref data): PeerRpcResponse,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data =
            encode(data).map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        write_length_prefixed(io, data).await?;
        io.close().await?;
        Ok(())
    }
}
