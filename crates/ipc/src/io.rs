use pin_project_lite::pin_project;
use std::io::{Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

pin_project! {
    #[derive(Debug)]
    pub struct TokioIo<T> {
        #[pin]
        inner: T,
    }
}

impl<T> TokioIo<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    pub fn inner(self) -> T {
        self.inner
    }
}

impl<T> hyper::rt::Read for TokioIo<T>
where
    T: Read,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        /*
        let n = unsafe {
            let mut tbuf = tokio::io::ReadBuf::uninit(buf.as_mut());
            match tokio::io::AsyncRead::poll_read(
                self.project().inner,
                cx,
                &mut tbuf,
            ) {
                Poll::Ready(Ok(())) => tbuf.filled().len(),
                other => return other,
            }
        };

        unsafe {
            buf.advance(n);
        }
        Poll::Ready(Ok(()))
        */
        todo!();
    }
}

impl<T> hyper::rt::Write for TokioIo<T>
where
    T: Write,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        // tokio::io::AsyncWrite::poll_write(self.project().inner, cx, buf)
        todo!();
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        // tokio::io::AsyncWrite::poll_flush(self.project().inner, cx)
        todo!();
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        // tokio::io::AsyncWrite::poll_shutdown(self.project().inner, cx)
        todo!();
    }

    fn is_write_vectored(&self) -> bool {
        // tokio::io::AsyncWrite::is_write_vectored(&self.inner)
        todo!();
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        /*
        tokio::io::AsyncWrite::poll_write_vectored(
            self.project().inner,
            cx,
            bufs,
        )
        */
        todo!();
    }
}
