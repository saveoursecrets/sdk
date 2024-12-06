use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Standard framed codec used by the native bridge.
pub(crate) fn framed<T: AsyncRead + AsyncWrite>(
    io: T,
) -> Framed<T, LengthDelimitedCodec> {
    LengthDelimitedCodec::builder()
        .native_endian()
        .new_framed(io)
}
