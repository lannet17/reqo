//! TLS stream returned by a [`TlsConnector`](crate::tls::TlsConnector).

use crate::tls::TlsIo;
#[cfg(feature = "aync")]
use crate::tls::AsyncTlsIo;
use crate::{Timeout, ALPN};
use std::io;
use std::io::{Read, Write};
#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
#[cfg(feature = "aync")]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// TLS stream over `S`: sync when `S` is `Read + Write`, async when it is
/// `AsyncRead + AsyncWrite`.
pub struct TlsStream<S> {
    inner: S,
    alpn: ALPN,
    #[cfg(feature = "aync")]
    pub(super) timeout: Timeout,
}

impl<S> TlsStream<S> {
    fn with_alpn(inner: S, alpn: ALPN, _timeout: Timeout) -> TlsStream<S> {
        TlsStream {
            inner,
            alpn,
            #[cfg(feature = "aync")]
            timeout: _timeout,
        }
    }

    /// Negotiated ALPN.
    pub fn alpn(&self) -> &ALPN { &self.alpn }
}

impl TlsStream<Box<dyn TlsIo>> {
    pub(crate) fn new(inner: Box<dyn TlsIo>, timeout: Timeout) -> Self {
        let alpn = inner.alpn();
        TlsStream::with_alpn(inner, alpn, timeout)
    }

    /// Send close_notify.
    pub fn shutdown(&mut self) -> io::Result<()> { self.inner.shutdown() }
}

#[cfg(feature = "aync")]
impl TlsStream<Box<dyn AsyncTlsIo>> {
    pub(crate) fn new_async(inner: Box<dyn AsyncTlsIo>, timeout: Timeout) -> Self {
        let alpn = inner.alpn();
        TlsStream::with_alpn(inner, alpn, timeout)
    }
}

impl<S: Read> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.inner.read(buf) }
}

impl<S: Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.inner.write(buf) }

    fn flush(&mut self) -> io::Result<()> { self.inner.flush() }
}

#[cfg(feature = "aync")]
impl<S: AsyncRead + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().inner).poll_read(cx, buf) {
            // many servers close without close_notify; treat it as EOF
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Poll::Ready(Ok(())),
            res => res,
        }
    }
}

#[cfg(feature = "aync")]
impl<S: AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
