//! Thin wrappers around a backend's TLS stream (see [`crate::tls`]).

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

/// Synchronous TLS stream produced by a [`TlsConnector`](crate::tls::TlsConnector).
pub struct TlsStream {
    inner: Box<dyn TlsIo>,
    alpn: ALPN,
    #[cfg(feature = "aync")]
    pub(super) timeout: Timeout,
}

impl TlsStream {
    pub(crate) fn new(inner: Box<dyn TlsIo>, _timeout: Timeout) -> TlsStream {
        TlsStream {
            alpn: inner.alpn(),
            inner,
            #[cfg(feature = "aync")]
            timeout: _timeout,
        }
    }

    pub fn alpn(&self) -> &ALPN { &self.alpn }

    pub fn shutdown(&mut self) -> io::Result<()> { self.inner.shutdown() }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.inner.read(buf) }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.inner.write(buf) }

    fn flush(&mut self) -> io::Result<()> { self.inner.flush() }
}

/// Asynchronous TLS stream produced by a [`TlsConnector`](crate::tls::TlsConnector).
#[cfg(feature = "aync")]
pub struct AsyncTlsStream {
    inner: Box<dyn AsyncTlsIo>,
    alpn: ALPN,
    pub(super) timeout: Timeout,
}

#[cfg(feature = "aync")]
impl AsyncTlsStream {
    pub(crate) fn new(inner: Box<dyn AsyncTlsIo>, timeout: Timeout) -> AsyncTlsStream {
        AsyncTlsStream { alpn: inner.alpn(), inner, timeout }
    }

    pub fn alpn(&self) -> &ALPN { &self.alpn }
}

#[cfg(feature = "aync")]
impl AsyncRead for AsyncTlsStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().inner).poll_read(cx, buf) {
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Poll::Ready(Ok(())),
            res => res,
        }
    }
}

#[cfg(feature = "aync")]
impl AsyncWrite for AsyncTlsStream {
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
