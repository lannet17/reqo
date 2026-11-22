//! reqtls as a TLS backend for [`reqo`](https://crates.io/crates/reqo).
//!
//! ```toml
//! # Same git source for both, so only one `reqo` crate (and `TlsConnector` trait) exists.
//! reqo = { git = "https://github.com/lannet17/reqo", default-features = false }   # drop rustls
//! reqtls = { git = "https://github.com/lannet17/reqo", features = ["reqo"] }      # add "reqo-async" for AcReq
//! ```
//! ```ignore
//! use reqo::*;
//! let req = ScReq::new()
//!     .with_tls_connector(std::sync::Arc::new(reqtls::ReqtlsConnector::new(reqtls::TlsFinger::from_ja3(ja3)?)));
//! ```

use crate::*;
use reqo::tls::{SyncIo, TlsConnector, TlsIo, TlsOptions, TlsVersion};
use reqo::{HlsError, HlsResult};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

#[cfg(feature = "reqo-async")]
use reqo::tls::{AsyncIo, AsyncTlsIo, BoxFuture};

const RECORD_CAP: usize = 16469;
const PLAIN_CAP: usize = 16384 + 2048;

/// [`TlsConnector`] backed by reqtls: full ClientHello fingerprint control
/// (ja3 / ja4 / raw ClientHello / built-in profiles), TLCP / SM ciphers, etc.
pub struct ReqtlsConnector {
    fingerprint: TlsFinger<'static>,
    /// Last session per server name, for resumption.
    sessions: Mutex<HashMap<String, TlsSession>>,
}

impl ReqtlsConnector {
    pub fn new(fingerprint: TlsFinger<'static>) -> Self {
        ReqtlsConnector { fingerprint, sessions: Mutex::new(HashMap::new()) }
    }

    pub fn fingerprint(&self) -> &TlsFinger<'static> { &self.fingerprint }

    fn take_session(&self, name: &str) -> Option<TlsSession> {
        self.sessions.lock().ok()?.remove(name)
    }

    fn store_session(&self, name: &str, session: &TlsSession) {
        if let Ok(mut s) = self.sessions.lock() { s.insert(name.to_string(), session.clone()); }
    }
}

impl Default for ReqtlsConnector {
    fn default() -> Self { ReqtlsConnector::new(TlsFinger::Default) }
}

fn err(e: impl std::fmt::Display) -> HlsError { HlsError::Tls(e.to_string()) }

fn io_err(e: RlsError) -> io::Error { io::Error::other(e.to_string()) }

/// Owned copies of everything a reqtls `ClientConfig` borrows.
struct ConfigParts {
    alpn: ALPN,
    certs: Vec<Certificate>,
    key: RsaKey,
    ca: Vec<Certificate>,
    key_log: Option<Arc<String>>,
    version: Version,
    verify: bool,
}

impl ConfigParts {
    fn new(opts: &TlsOptions<'_>) -> HlsResult<Self> {
        // reqtls takes the *preferred* ALPN and offers it plus lower versions.
        let alpn = opts.alpn.first().map(|a| ALPN::from_slice(a.value().as_bytes())).unwrap_or_default();
        let (certs, key) = match opts.identity {
            Some(id) => (Certificate::from_pem(&id.cert_chain_pem).map_err(err)?, RsaKey::from_pri_pem(&id.key_pem).map_err(err)?),
            None => (vec![], RsaKey::none()),
        };
        let ca = match opts.ca_pem {
            Some(pem) => Certificate::from_pem(pem).map_err(err)?,
            None => vec![],
        };
        Ok(ConfigParts {
            alpn,
            certs,
            key,
            ca,
            key_log: opts.key_log.map(|p| Arc::new(p.to_string())),
            version: match opts.max_version { TlsVersion::Tls12 => Version::TLS_1_2, TlsVersion::Tls13 => Version::TLS_1_3 },
            verify: opts.verify,
        })
    }

    fn client_config<'a>(&'a mut self, sni: &'a str, finger: &'a TlsFinger<'a>, session: Option<TlsSession>) -> ClientConfig<'a> {
        ClientConfig {
            sni,
            alpn: &self.alpn,
            fingerprint: finger,
            client_cert: &mut self.certs,
            cert_key: &self.key,
            verify: self.verify,
            ca_certs: &self.ca,
            key_log: self.key_log.clone(),
            session,
            version: self.version,
        }
    }
}

/// TLS record state shared by the sync and async streams.
struct Engine {
    conn: Connection,
    encrypted_channel: bool,
    handshake_finished: bool,
    hello_retrying: bool,
    read_buffer: Writer,
    write_buffer: Writer,
    /// Decrypted application data not yet handed to the caller.
    plain: Vec<u8>,
    plain_pos: usize,
}

impl StreamHandle for Engine {
    fn stream_param(&mut self) -> (&Writer, StreamParam<'_>) {
        (&self.read_buffer, StreamParam {
            handshake_finish: &mut self.handshake_finished,
            encrypted_channel: &mut self.encrypted_channel,
            hello_retrying: &mut self.hello_retrying,
            write_buffer: &mut self.write_buffer,
            conn: &mut self.conn,
        })
    }
}

impl Engine {
    fn new(parts: &ConfigParts, session: TlsSession) -> Engine {
        let conn = Connection::new_client(session, parts.key_log.clone(), false)
            .with_verify(parts.verify)
            .with_mtls(!parts.certs.is_empty());
        Engine {
            conn,
            encrypted_channel: false,
            handshake_finished: false,
            hello_retrying: false,
            read_buffer: Writer::with_capacity(RECORD_CAP),
            write_buffer: Writer::with_capacity(RECORD_CAP),
            plain: vec![0; PLAIN_CAP],
            plain_pos: 0,
        }
    }

    /// Length of the complete record at the head of `read_buffer`, if any.
    fn complete_record(&self) -> Option<usize> {
        let f = self.read_buffer.filled();
        if f.len() < 5 { return None; }
        let len = u16::from_be_bytes([f[3], f[4]]) as usize + 5;
        (f.len() >= len).then_some(len)
    }

    fn prepare_read(&mut self) -> io::Result<()> {
        self.read_buffer.check_move(5.max(self.complete_record().unwrap_or(0))).map_err(io::Error::other)?;
        if self.read_buffer.unfilled().is_empty() {
            return Err(io::Error::other("TLS record larger than buffer"));
        }
        Ok(())
    }

    /// Process one complete record of length `len`; returns plaintext bytes now available.
    fn process(&mut self, len: usize, config: Option<&mut Config<'_>>) -> io::Result<usize> {
        let mut plain = std::mem::take(&mut self.plain);
        let res = self.handle_record(len, config, &mut plain);
        self.plain = plain;
        self.read_buffer.used_empty(len);
        self.plain_pos = 0;
        res.map_err(io_err)
    }

    fn encrypt(&mut self, data: &[u8]) -> io::Result<()> {
        for chunk in data.chunks(16384) {
            let len = self.conn.make_message(RecordType::ApplicationData, chunk, self.write_buffer.unfilled()).map_err(io_err)?;
            self.write_buffer.add_len(len);
        }
        Ok(())
    }

    fn close_notify(&mut self) -> io::Result<()> {
        let len = self.conn.make_message(RecordType::Alert, &Alert::close_notify().to_bytes(), self.write_buffer.unfilled()).map_err(io_err)?;
        self.write_buffer.add_len(len);
        Ok(())
    }

    fn alpn(&self) -> reqo::ALPN {
        reqo::ALPN::from_slice(self.conn.alpn().value().as_bytes())
    }
}

// ---------------------------------------------------------------- sync ----

struct SyncStream {
    engine: Engine,
    io: Box<dyn SyncIo>,
    /// Plaintext bytes in `engine.plain[plain_pos..plain_end]`.
    plain_end: usize,
}

impl SyncStream {
    fn flush_out(&mut self) -> io::Result<()> {
        if !self.engine.write_buffer.is_empty() {
            self.io.write_all(self.engine.write_buffer.filled())?;
            self.engine.write_buffer.reset();
        }
        self.io.flush()
    }

    /// Read until one complete record sits at the head of the read buffer.
    fn read_record(&mut self) -> io::Result<usize> {
        loop {
            if let Some(len) = self.engine.complete_record() { return Ok(len); }
            self.engine.prepare_read()?;
            let n = self.io.read(self.engine.read_buffer.unfilled())?;
            if n == 0 { return Err(io::ErrorKind::UnexpectedEof.into()); }
            self.engine.read_buffer.add_len(n);
        }
    }

    fn handshake(&mut self, config: &mut Config<'_>) -> HlsResult<()> {
        let client = config.client_mut().ok_or("missing client config")?;
        self.engine.build_client_hello(client).map_err(err)?;
        loop {
            self.flush_out()?;
            if self.engine.handshake_finished { break; }
            let len = self.read_record()?;
            self.engine.process(len, Some(config))?;
        }
        if self.engine.conn.version() == Version::TLS_1_3 { self.engine.conn.make_cipher(false).map_err(err)?; }
        Ok(())
    }
}

impl Read for SyncStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.engine.plain_pos == self.plain_end {
            let len = match self.read_record() {
                Ok(len) => len,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            };
            self.plain_end = self.engine.process(len, None)?;
            self.flush_out()?; // e.g. key updates
        }
        let n = buf.len().min(self.plain_end - self.engine.plain_pos);
        buf[..n].copy_from_slice(&self.engine.plain[self.engine.plain_pos..self.engine.plain_pos + n]);
        self.engine.plain_pos += n;
        Ok(n)
    }
}

impl Write for SyncStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for chunk in buf.chunks(16384) {
            self.engine.encrypt(chunk)?;
            self.flush_out()?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> { self.flush_out() }
}

impl TlsIo for SyncStream {
    fn alpn(&self) -> reqo::ALPN { self.engine.alpn() }

    fn shutdown(&mut self) -> io::Result<()> {
        self.engine.close_notify()?;
        self.flush_out()
    }
}

impl TlsConnector for ReqtlsConnector {
    fn connect(&self, io: Box<dyn SyncIo>, opts: &TlsOptions<'_>) -> HlsResult<Box<dyn TlsIo>> {
        let mut parts = ConfigParts::new(opts)?;
        let session = self.take_session(opts.server_name);
        let mut stream = SyncStream {
            engine: Engine::new(&parts, session.clone().unwrap_or_default()),
            io,
            plain_end: 0,
        };
        let mut config = Config::Client(parts.client_config(opts.server_name, &self.fingerprint, session));
        stream.handshake(&mut config)?;
        self.store_session(opts.server_name, stream.engine.conn.session());
        Ok(Box::new(stream))
    }

    #[cfg(feature = "reqo-async")]
    fn connect_async<'a>(&'a self, io: Box<dyn AsyncIo>, opts: TlsOptions<'a>) -> BoxFuture<'a, HlsResult<Box<dyn AsyncTlsIo>>> {
        Box::pin(async move {
            let mut parts = ConfigParts::new(&opts)?;
            let session = self.take_session(opts.server_name);
            let mut stream = async_stream::AsyncStream::new(Engine::new(&parts, session.clone().unwrap_or_default()), io);
            let mut config = Config::Client(parts.client_config(opts.server_name, &self.fingerprint, session));
            stream.handshake(&mut config).await?;
            self.store_session(opts.server_name, stream.engine.conn.session());
            Ok(Box::new(stream) as Box<dyn AsyncTlsIo>)
        })
    }
}

// --------------------------------------------------------------- async ----

#[cfg(feature = "reqo-async")]
mod async_stream {
    use super::*;
    use reqo::tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use std::pin::Pin;
    use std::task::{ready, Context, Poll};

    pub(super) struct AsyncStream {
        pub(super) engine: Engine,
        io: Box<dyn AsyncIo>,
        plain_end: usize,
        /// Plaintext length accepted by the in-flight `poll_write`.
        pending_write: usize,
        close_sent: bool,
    }

    // `Connection` holds raw pointers; it is only ever used through `&mut self`.
    unsafe impl Send for AsyncStream {}
    unsafe impl Sync for AsyncStream {}

    impl AsyncStream {
        pub(super) fn new(engine: Engine, io: Box<dyn AsyncIo>) -> Self {
            AsyncStream { engine, io, plain_end: 0, pending_write: 0, close_sent: false }
        }

        pub(super) async fn handshake(&mut self, config: &mut Config<'_>) -> HlsResult<()> {
            let client = config.client_mut().ok_or("missing client config")?;
            self.engine.build_client_hello(client).map_err(err)?;
            loop {
                if !self.engine.write_buffer.is_empty() {
                    self.io.write_all(self.engine.write_buffer.filled()).await?;
                    self.engine.write_buffer.reset();
                    self.io.flush().await?;
                }
                if self.engine.handshake_finished { break; }
                let len = loop {
                    if let Some(len) = self.engine.complete_record() { break len; }
                    self.engine.prepare_read()?;
                    let n = self.io.read(self.engine.read_buffer.unfilled()).await?;
                    if n == 0 { return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()); }
                    self.engine.read_buffer.add_len(n);
                };
                self.engine.process(len, Some(config))?;
            }
            if self.engine.conn.version() == Version::TLS_1_3 { self.engine.conn.make_cipher(false).map_err(err)?; }
            Ok(())
        }

        fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            while !self.engine.write_buffer.is_empty() {
                let n = ready!(Pin::new(&mut self.io).poll_write(cx, self.engine.write_buffer.filled()))?;
                if n == 0 { return Poll::Ready(Err(io::ErrorKind::WriteZero.into())); }
                self.engine.write_buffer.used_empty(n);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for AsyncStream {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            while this.engine.plain_pos == this.plain_end {
                ready!(this.poll_flush_out(cx))?;
                let len = match this.engine.complete_record() {
                    Some(len) => len,
                    None => {
                        this.engine.prepare_read()?;
                        let mut rb = ReadBuf::new(this.engine.read_buffer.unfilled());
                        ready!(Pin::new(&mut this.io).poll_read(cx, &mut rb))?;
                        let n = rb.filled().len();
                        if n == 0 { return Poll::Ready(Ok(())); } // EOF
                        this.engine.read_buffer.add_len(n);
                        continue;
                    }
                };
                this.plain_end = this.engine.process(len, None)?;
            }
            let n = buf.remaining().min(this.plain_end - this.engine.plain_pos);
            buf.put_slice(&this.engine.plain[this.engine.plain_pos..this.engine.plain_pos + n]);
            this.engine.plain_pos += n;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for AsyncStream {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.pending_write == 0 {
                // Encrypt at most one record at a time so the buffer never overflows.
                ready!(this.poll_flush_out(cx))?;
                let n = buf.len().min(16384);
                this.engine.encrypt(&buf[..n])?;
                this.pending_write = n;
            }
            ready!(this.poll_flush_out(cx))?;
            let n = std::mem::take(&mut this.pending_write);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            ready!(this.poll_flush_out(cx))?;
            Pin::new(&mut this.io).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if !this.close_sent {
                ready!(this.poll_flush_out(cx))?;
                this.engine.close_notify()?;
                this.close_sent = true;
            }
            ready!(this.poll_flush_out(cx))?;
            Pin::new(&mut this.io).poll_shutdown(cx)
        }
    }

    impl AsyncTlsIo for AsyncStream {
        fn alpn(&self) -> reqo::ALPN { self.engine.alpn() }
    }
}
