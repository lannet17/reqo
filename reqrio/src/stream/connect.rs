use crate::error::HlsResult;
#[cfg(feature = "quic")]
use crate::fingerprint::H3Finger;
use crate::stream::http1::*;
use crate::stream::http2::*;
#[cfg(feature = "quic")]
use crate::stream::http3::HTTP3Stream;
#[cfg(feature = "quic")]
use crate::stream::quic::QUICConnect;
use crate::stream::write::BufWriting;
use crate::stream::{ConnParam, HTTPStream, ProxyStream, Stream, TlsStream};
#[cfg(feature = "aync")]
use crate::stream::AsyncTlsStream;
use crate::tls::{TlsConnector, TlsOptions};
use crate::*;
#[cfg(feature = "aync")]
use std::future::Future;
use std::io::Write;
use std::mem;
#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
#[cfg(feature = "aync")]
use tokio::io::AsyncWrite;

pub enum ProxyState<S> {
    Connecting {
        stream: S,
        timeout: Timeout,
        buffer: Writer,
    },
    Finish,
}

pub struct ProxyConnecting<'a, S> {
    pub(crate) state: ProxyState<S>,
    pub(crate) proxy: &'a Proxy,
    pub(crate) dst_addr: &'a Addr,
    #[cfg(feature = "aync")]
    pub(crate) index: usize,
    #[cfg(feature = "aync")]
    pub(crate) finish: bool,
    #[cfg(feature = "aync")]
    pub(crate) timeout_reset: bool,
}

impl<'a, S: Write> ProxyConnecting<'a, S> {
    pub fn wait(mut self) -> HlsResult<ProxyStream<S>> {
        #[allow(unused)]
        let (mut stream, mut buffer, mut timeout) = match mem::replace(&mut self.state, ProxyState::Finish) {
            ProxyState::Connecting { stream, buffer, timeout } => (stream, buffer, timeout),
            ProxyState::Finish => unreachable!(),
        };
        for i in 0..4 {
            let finish = self.proxy.write_context(self.dst_addr, &mut buffer, i)?;
            BufWriting {
                stream: &mut stream,
                buf: &mut buffer,
                #[cfg(feature = "aync")]
                timeout: &mut timeout,
                #[cfg(feature = "aync")]
                timeout_reset: false,
            }.wait()?;
            if finish { break; }
        }
        Ok(ProxyStream {
            stream,
            handle_proxy: matches!(self.proxy,  Proxy::Null),
            http_proxy: matches!(self.proxy, Proxy::HttpPlain(_)),
            buffer,
            resp: StreamMessage::default(),
            #[cfg(feature = "aync")]
            timeout,
        })
    }
}

#[cfg(feature = "aync")]
impl<'a, S: AsyncWrite + Unpin> Future for ProxyConnecting<'a, S> {
    type Output = HlsResult<ProxyStream<S>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let connector = self.get_mut();
        let (stream, buffer, timeout) = match &mut connector.state {
            ProxyState::Connecting { stream, buffer, timeout } => (stream, buffer, timeout),
            ProxyState::Finish => unreachable!(),
        };
        if !connector.timeout_reset {
            timeout.reset_connect();
            connector.timeout_reset = true;
        }
        for i in 0..4 {
            if i < connector.index { continue; }
            let finish = if buffer.is_empty() {
                connector.proxy.write_context(connector.dst_addr, buffer, i)?
            } else { connector.finish };
            let mut writing = BufWriting {
                stream,
                buf: buffer,
                timeout,
                timeout_reset: false,
            };
            match Pin::new(&mut writing).poll(cx)? {
                Poll::Ready(_) => if finish { break; },
                Poll::Pending => {
                    timeout.connect_timeout(cx)?;
                    return Poll::Pending;
                }
            }
        }
        let (stream, buffer, timeout) = match mem::replace(&mut connector.state, ProxyState::Finish) {
            ProxyState::Connecting { stream, buffer, timeout } => (stream, buffer, timeout),
            ProxyState::Finish => unreachable!(),
        };
        Poll::Ready(Ok(ProxyStream {
            stream,
            handle_proxy: matches!(connector.proxy,  Proxy::Null),
            http_proxy: matches!(connector.proxy, Proxy::HttpPlain(_)),
            buffer,
            resp: StreamMessage::default(),
            timeout,
        }))
    }
}

/// Plain TCP → (optional proxy) → (optional TLS via the configured backend) → HTTP stream.
impl HTTPStream {
    pub(crate) fn connect_tcp_sync(tcp: std::net::TcpStream, tls: &TlsOptions<'_>, connector: &dyn TlsConnector, param: &ConnParam<'_>, finger: &Fingerprint) -> HlsResult<(ALPN, HTTPStream)> {
        let proxy_stream = ProxyStream::connect(tcp, param.url.addr(), param.proxy, param.timeout.clone()).wait()?;
        match param.url.scheme() {
            Scheme::Http | Scheme::Ws => Ok((ALPN::HTTP11, HTTPStream::SyncH1(HTTP1Stream::new(Stream::SyncHttp(proxy_stream))))),
            Scheme::Https | Scheme::Wss => {
                let io = connector.connect(Box::new(proxy_stream), tls)?;
                let mut tls_stream = TlsStream::new(io, param.timeout.clone());
                if *tls_stream.alpn() != ALPN::HTTP20 {
                    return Ok((ALPN::HTTP11, HTTPStream::SyncH1(HTTP1Stream::new(Stream::SyncHttps(tls_stream)))));
                }
                let buffer = Self::h2_preface(finger)?;
                tls_stream.write_all(buffer.filled())?;
                let mut buffer = buffer;
                buffer.reset();
                Ok((ALPN::HTTP20, HTTPStream::SyncH2(HTTP2Stream::new(buffer, Stream::SyncHttps(tls_stream)))))
            }
            _ => Err("stream not supported".into())
        }
    }

    #[cfg(feature = "aync")]
    pub(crate) async fn connect_tcp_async(tcp: tokio::net::TcpStream, tls: TlsOptions<'_>, connector: &dyn TlsConnector, param: &ConnParam<'_>, finger: &Fingerprint) -> HlsResult<(ALPN, HTTPStream)> {
        let proxy_stream = ProxyStream::connect(tcp, param.url.addr(), param.proxy, param.timeout.clone()).await?;
        match param.url.scheme() {
            Scheme::Http | Scheme::Ws => Ok((ALPN::HTTP11, HTTPStream::AsyncH1(HTTP1Stream::new(Stream::AsyncHttp(proxy_stream))))),
            Scheme::Https | Scheme::Wss => {
                let handshake = connector.connect_async(Box::new(proxy_stream), tls);
                let io = tokio::time::timeout(param.timeout.connect(), handshake).await
                    .or(Err(TimeError::ConnectTimeout))??;
                let tls_stream = AsyncTlsStream::new(io, param.timeout.clone());
                if *tls_stream.alpn() != ALPN::HTTP20 {
                    return Ok((ALPN::HTTP11, HTTPStream::AsyncH1(HTTP1Stream::new(Stream::AsyncHttps(tls_stream)))));
                }
                let mut buffer = Self::h2_preface(finger)?;
                let mut stream = Stream::AsyncHttps(tls_stream);
                stream.write(&mut buffer).await?;
                Ok((ALPN::HTTP20, HTTPStream::AsyncH2(HTTP2Stream::new(buffer, stream))))
            }
            _ => Err("stream not supported".into())
        }
    }

    fn h2_preface(finger: &Fingerprint) -> HlsResult<Writer> {
        let mut buffer = Writer::with_capacity(32876);
        buffer.write_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")?;
        finger.h2().build_settings(&mut buffer)?;
        Ok(buffer)
    }
}

#[cfg(feature = "quic")]
#[must_use = "streams do nothing unless `.wait()/.await`"]
pub struct QUICStreamConnect<'a, S> {
    pub(crate) conn: Option<QUICConnect<'a, S>>,
    pub(crate) h3_finger: &'a H3Finger,
    #[cfg(feature = "aync")]
    pub(crate) stream: Option<QUICStream<S>>,
    #[cfg(feature = "aync")]
    pub(crate) offset: usize,
    #[cfg(feature = "aync")]
    pub(crate) connected: bool,
}

#[cfg(feature = "quic")]
impl<'a, S> QUICStreamConnect<'a, S> {
    fn build_settings(&self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.reset_offset(100..100);
        writer.write_u8(0)?;
        self.h3_finger.build_settings(writer)?;
        quic::write_variant_front(writer.len() as u64, writer)?;
        quic::write_variant_front(2, writer)?;
        let flag = QUICFrameFlag::new(0);
        quic::write_variant_front(flag.encode(), writer)?;
        Ok(())
    }
}

#[cfg(feature = "quic")]
impl<'a> QUICStreamConnect<'a, std::net::UdpSocket> {
    pub fn wait(mut self) -> HlsResult<HTTPStream> {
        let mut stream = self.conn.take().ok_or("invalid connection")?.wait()?;
        let mut writer = stream.alloc_buffer();
        self.build_settings(&mut writer)?;
        let offset = writer.len();
        stream.write_packet(writer, QUICFlag::new(PacketType::ShortHeader)).wait()?;
        Ok(HTTPStream::SyncH3(HTTP3Stream::new(stream, offset)))
    }
}

#[cfg(all(feature = "quic", feature = "aync"))]
impl<'a> Future for QUICStreamConnect<'a, tokio::net::UdpSocket> {
    type Output = HlsResult<HTTPStream>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let connector = self.get_mut();
        if !connector.connected {
            let stream = connector.conn.as_mut().ok_or("invalid connection")?;
            match Pin::new(stream).poll(cx)? {
                Poll::Ready(mut stream) => {
                    let mut writer = stream.alloc_buffer();
                    connector.build_settings(&mut writer)?;
                    connector.offset = writer.len();
                    stream.make_message(writer, QUICFlag::new(PacketType::ShortHeader))?;
                    if stream.poll_send(cx)?.is_pending() {
                        connector.stream = Some(stream);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(HTTPStream::AsyncH3(HTTP3Stream::new(stream, connector.offset))))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            let stream = connector.stream.as_mut().ok_or("invalid connection")?;
            if stream.poll_send(cx)?.is_pending() { return Poll::Pending; };
            let stream = connector.stream.take().ok_or("invalid connection")?;
            Poll::Ready(Ok(HTTPStream::AsyncH3(HTTP3Stream::new(stream, connector.offset))))
        }
    }
}