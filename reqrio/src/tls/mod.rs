//! TLS connectors.
//!
//! After TCP (and the proxy, if any) is set up, the session passes the stream to
//! [`TlsConnector::connect`] (or `connect_async`). If the returned stream reports
//! `h2` as ALPN the session uses HTTP/2, otherwise HTTP/1.1.
//!
//! Without a connector set, `RustlsConnector` is used (`rustls` feature).
//! Change it with [`ReqExt::set_tls_connector`](crate::ReqExt::set_tls_connector).

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

/// Highest TLS version to offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TlsVersion {
    Tls12,
    #[default]
    Tls13,
}

/// Client certificate chain and private key (PEM) for mTLS.
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

/// Settings for one handshake, taken from the session.
#[derive(Debug, Clone)]
pub struct TlsOptions<'a> {
    /// SNI, and the name the certificate is checked against.
    pub server_name: &'a str,
    /// Protocols to offer, in order of preference.
    pub alpn: &'a [ALPN],
    /// Check the certificate chain and host name.
    pub verify: bool,
    pub max_version: TlsVersion,
    pub identity: Option<&'a ClientIdentity>,
    /// CA certificates (PEM). If set, only these are trusted.
    pub ca_pem: Option<&'a [u8]>,
    /// File to append NSS key-log lines to.
    pub key_log: Option<&'a str>,
    /// Use ECH if the connector supports it.
    pub ech: bool,
}

/// The TCP stream (after the proxy, if any) given to [`TlsConnector::connect`].
pub trait SyncIo: Read + Write + Send + Sync {}
impl<T: Read + Write + Send + Sync> SyncIo for T {}

/// Stream returned by [`TlsConnector::connect`].
pub trait TlsIo: Read + Write + Send + Sync {
    /// Negotiated ALPN; [`ALPN::nullptr`] if none.
    fn alpn(&self) -> ALPN;
    /// Send close_notify.
    fn shutdown(&mut self) -> io::Result<()>;
}

#[cfg(feature = "aync")]
pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
#[cfg(feature = "aync")]
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncIo for T {}

/// Stream returned by `connect_async`. `poll_shutdown` should send close_notify.
#[cfg(feature = "aync")]
pub trait AsyncTlsIo: AsyncRead + AsyncWrite + Unpin + Send + Sync {
    fn alpn(&self) -> ALPN;
}

#[cfg(feature = "aync")]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Does the TLS handshake for a session.
pub trait TlsConnector: Send + Sync {
    /// Handshake on `io` and return the encrypted stream.
    fn connect(&self, io: Box<dyn SyncIo>, opts: &TlsOptions<'_>) -> HlsResult<Box<dyn TlsIo>>;

    /// Async version of [`connect`](Self::connect). The default returns an error.
    #[cfg(feature = "aync")]
    fn connect_async<'a>(&'a self, io: Box<dyn AsyncIo>, opts: TlsOptions<'a>) -> BoxFuture<'a, HlsResult<Box<dyn AsyncTlsIo>>> {
        let _ = (io, opts);
        Box::pin(async { Err("this TLS backend does not support async connections".into()) })
    }
}

static DEFAULT: std::sync::RwLock<Option<Arc<dyn TlsConnector>>> = std::sync::RwLock::new(None);

/// Set the connector for sessions that don't have one, including the ones
/// created by `reqo::get` / `post` / `put`.
pub fn set_default_connector(connector: Arc<dyn TlsConnector>) {
    *DEFAULT.write().unwrap_or_else(|e| e.into_inner()) = Some(connector);
}

/// Connector for sessions that don't have one: the one passed to
/// [`set_default_connector`], else `RustlsConnector` (`rustls` feature), else an error.
pub fn default_connector() -> HlsResult<Arc<dyn TlsConnector>> {
    if let Some(c) = DEFAULT.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        return Ok(c.clone());
    }
    #[cfg(feature = "rustls")]
    {
        use std::sync::OnceLock;
        static DEFAULT: OnceLock<Arc<RustlsConnector>> = OnceLock::new();
        Ok(DEFAULT.get_or_init(|| Arc::new(RustlsConnector::new())).clone())
    }
    #[cfg(not(feature = "rustls"))]
    Err("no TLS backend: enable the `rustls` feature or call `set_tls_connector`".into())
}

/// `h2` → `[h2, http/1.1]`, anything else → `[http/1.1]`.
pub(crate) fn alpn_offer(preferred: &ALPN) -> &'static [ALPN] {
    const H2: &[ALPN] = &[ALPN::HTTP20, ALPN::HTTP11];
    const H1: &[ALPN] = &[ALPN::HTTP11];
    if *preferred == ALPN::HTTP20 { H2 } else { H1 }
}

/// TLS settings stored in a session.
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
