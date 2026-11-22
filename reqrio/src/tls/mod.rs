//! Pluggable TLS layer.
//!
//! reqrio itself never performs a TLS handshake. It hands an already-connected
//! (and, if configured, proxied) byte stream to a [`TlsConnector`], and gets back
//! an encrypted stream plus the negotiated ALPN.
//!
//! * With the default `rustls` feature, [`RustlsConnector`] is used automatically.
//! * Any other backend (e.g. a private fingerprinting implementation) only needs
//!   to implement [`TlsConnector`] and be installed with
//!   [`ReqExt::set_tls_connector`](crate::ReqExt::set_tls_connector).
//!
//! ```ignore
//! struct MyConnector;
//! impl reqo::tls::TlsConnector for MyConnector {
//!     fn connect(&self, io: Box<dyn SyncIo>, opts: &TlsOptions<'_>) -> HlsResult<Box<dyn TlsIo>> { ... }
//! }
//! let req = Session::new().with_tls_connector(Arc::new(MyConnector));
//! ```

#[cfg(feature = "rustls")]
mod rustls_backend;

use crate::error::HlsResult;
use crate::ALPN;
use std::io::{self, Read, Write};
use std::sync::Arc;
#[cfg(feature = "rustls")]
pub use rustls_backend::RustlsConnector;
#[cfg(feature = "aync")]
use std::{future::Future, pin::Pin};
#[cfg(feature = "aync")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Highest TLS version the client should offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TlsVersion {
    Tls12,
    #[default]
    Tls13,
}

/// Client certificate chain + private key for mutual TLS, PEM encoded.
#[derive(Clone)]
pub struct ClientIdentity {
    pub cert_chain_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

impl ClientIdentity {
    pub fn from_pem(cert_chain_pem: impl Into<Vec<u8>>, key_pem: impl Into<Vec<u8>>) -> Self {
        ClientIdentity { cert_chain_pem: cert_chain_pem.into(), key_pem: key_pem.into() }
    }

    pub fn from_pem_files(cert_path: impl AsRef<std::path::Path>, key_path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        Ok(ClientIdentity::from_pem(std::fs::read(cert_path)?, std::fs::read(key_path)?))
    }
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity").finish_non_exhaustive()
    }
}

/// Backend-agnostic parameters for one client handshake.
#[derive(Debug, Clone)]
pub struct TlsOptions<'a> {
    /// SNI / certificate name.
    pub server_name: &'a str,
    /// ALPN protocols to offer, most preferred first.
    pub alpn: &'a [ALPN],
    /// Verify the server certificate chain and hostname.
    pub verify: bool,
    pub max_version: TlsVersion,
    pub identity: Option<&'a ClientIdentity>,
    /// Extra trusted roots (PEM). When set, *only* these roots are trusted.
    pub ca_pem: Option<&'a [u8]>,
    /// Path to append NSS key-log lines to (debugging only).
    pub key_log: Option<&'a str>,
    /// Request Encrypted Client Hello where the backend supports it.
    pub ech: bool,
}

/// Plain (possibly proxied) transport handed to a backend for synchronous use.
pub trait SyncIo: Read + Write + Send + Sync {}
impl<T: Read + Write + Send + Sync> SyncIo for T {}

/// An established synchronous TLS stream.
pub trait TlsIo: Read + Write + Send + Sync {
    /// The negotiated ALPN protocol, or [`ALPN::nullptr`] if none was negotiated.
    fn alpn(&self) -> ALPN;
    /// Send close_notify and flush.
    fn shutdown(&mut self) -> io::Result<()>;
}

#[cfg(feature = "aync")]
pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
#[cfg(feature = "aync")]
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncIo for T {}

/// An established asynchronous TLS stream. `poll_shutdown` should send close_notify.
#[cfg(feature = "aync")]
pub trait AsyncTlsIo: AsyncRead + AsyncWrite + Unpin + Send + Sync {
    fn alpn(&self) -> ALPN;
}

#[cfg(feature = "aync")]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A TLS client implementation.
pub trait TlsConnector: Send + Sync {
    /// Perform a blocking handshake over `io`.
    fn connect(&self, io: Box<dyn SyncIo>, opts: &TlsOptions<'_>) -> HlsResult<Box<dyn TlsIo>>;

    /// Perform a non-blocking handshake over `io`.
    #[cfg(feature = "aync")]
    fn connect_async<'a>(&'a self, io: Box<dyn AsyncIo>, opts: TlsOptions<'a>) -> BoxFuture<'a, HlsResult<Box<dyn AsyncTlsIo>>> {
        let _ = (io, opts);
        Box::pin(async { Err("this TLS backend does not support async connections".into()) })
    }
}

/// The connector used when none was set explicitly.
pub fn default_connector() -> HlsResult<Arc<dyn TlsConnector>> {
    #[cfg(feature = "rustls")]
    {
        use std::sync::OnceLock;
        static DEFAULT: OnceLock<Arc<RustlsConnector>> = OnceLock::new();
        Ok(DEFAULT.get_or_init(|| Arc::new(RustlsConnector::new())).clone())
    }
    #[cfg(not(feature = "rustls"))]
    Err("no TLS backend: enable the `rustls` feature or call `set_tls_connector`".into())
}

/// ALPN list to offer for a preferred protocol.
pub(crate) fn alpn_offer(preferred: &ALPN) -> &'static [ALPN] {
    const H2: &[ALPN] = &[ALPN::HTTP20, ALPN::HTTP11];
    const H1: &[ALPN] = &[ALPN::HTTP11];
    if *preferred == ALPN::HTTP20 { H2 } else { H1 }
}

/// Per-session TLS settings (shared by `Session` / `aio::Session`).
#[derive(Clone)]
pub(crate) struct TlsSettings {
    pub(crate) verify: bool,
    pub(crate) version: TlsVersion,
    pub(crate) identity: Option<ClientIdentity>,
    pub(crate) ca_pem: Option<Vec<u8>>,
    pub(crate) key_log: Option<Arc<String>>,
    pub(crate) connector: Option<Arc<dyn TlsConnector>>,
}

impl Default for TlsSettings {
    fn default() -> Self {
        TlsSettings { verify: true, version: TlsVersion::default(), identity: None, ca_pem: None, key_log: None, connector: None }
    }
}

impl TlsSettings {
    pub(crate) fn connector(&self) -> HlsResult<Arc<dyn TlsConnector>> {
        match &self.connector {
            Some(c) => Ok(c.clone()),
            None => default_connector(),
        }
    }

    pub(crate) fn options<'a>(&'a self, server_name: &'a str, alpn: &ALPN) -> TlsOptions<'a> {
        TlsOptions {
            server_name,
            alpn: alpn_offer(alpn),
            verify: self.verify,
            max_version: self.version,
            identity: self.identity.as_ref(),
            ca_pem: self.ca_pem.as_deref(),
            key_log: self.key_log.as_deref().map(String::as_str),
            ech: false,
        }
    }
}
