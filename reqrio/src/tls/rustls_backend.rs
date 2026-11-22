//! rustls connector (ring, webpki-roots).

use super::{SyncIo, TlsConnector, TlsIo, TlsOptions, TlsVersion};
use crate::error::{HlsError, HlsResult};
use crate::{hex, ALPN};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme, StreamOwned};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

#[cfg(feature = "aync")]
use super::{AsyncIo, AsyncTlsIo, BoxFuture};

/// [`TlsConnector`] using rustls.
///
/// Trusted roots are `webpki-roots`, the certificates in `SSL_CERT_FILE` (read
/// once, in [`new`](Self::new)) and any added with
/// [`with_extra_roots_pem`](Self::with_extra_roots_pem).
///
/// The rustls config is kept per (verify, version, ALPN), so later connections
/// can resume the TLS session. Configs with mTLS, a CA bundle or a key log are
/// built for each connection.
pub struct RustlsConnector {
    provider: Arc<CryptoProvider>,
    custom: Option<Arc<ClientConfig>>,
    extra_roots: Vec<CertificateDer<'static>>,
    cache: Mutex<HashMap<CacheKey, Arc<ClientConfig>>>,
}

#[derive(Hash, PartialEq, Eq)]
struct CacheKey {
    verify: bool,
    version: TlsVersion,
    alpn: Vec<Vec<u8>>,
}

impl Default for RustlsConnector {
    fn default() -> Self { RustlsConnector::new() }
}

impl RustlsConnector {
    pub fn new() -> Self {
        let mut extra_roots = vec![];
        if let Some(path) = std::env::var_os("SSL_CERT_FILE") {
            match std::fs::read(&path) {
                Ok(pem) => extra_roots.extend(CertificateDer::pem_slice_iter(&pem).filter_map(Result::ok)),
                Err(_e) => {
                    #[cfg(feature = "log")]
                    log::warn!("[rustls] cannot read SSL_CERT_FILE {:?}: {}", path, _e);
                }
            }
        }
        RustlsConnector {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            custom: None,
            extra_roots,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Also trust the certificates in `pem`. Adding an intermediate certificate
    /// works for servers that don't send their full chain.
    pub fn with_extra_roots_pem(mut self, pem: &[u8]) -> HlsResult<Self> {
        for cert in CertificateDer::pem_slice_iter(pem) {
            self.extra_roots.push(cert.map_err(tls_err)?);
        }
        Ok(self)
    }

    /// Use this rustls config as is. Only `alpn_protocols` is set per connection;
    /// the session's verify, mTLS, CA and key-log settings are ignored.
    pub fn with_config(config: Arc<ClientConfig>) -> Self {
        RustlsConnector { custom: Some(config), ..RustlsConnector::new() }
    }

    fn config(&self, opts: &TlsOptions<'_>) -> HlsResult<Arc<ClientConfig>> {
        let alpn: Vec<Vec<u8>> = opts.alpn.iter().map(|a| a.value().as_bytes().to_vec()).collect();
        if let Some(custom) = &self.custom {
            if custom.alpn_protocols == alpn { return Ok(custom.clone()); }
            let mut cfg = (**custom).clone();
            cfg.alpn_protocols = alpn;
            return Ok(Arc::new(cfg));
        }
        // configs with mTLS, a CA bundle or a key log are not cached
        let cacheable = opts.identity.is_none() && opts.ca_pem.is_none() && opts.key_log.is_none();
        let key = CacheKey { verify: opts.verify, version: opts.max_version, alpn };
        if cacheable {
            if let Some(cfg) = self.cache.lock().map_err(tls_err)?.get(&key) { return Ok(cfg.clone()); }
        }
        let cfg = Arc::new(self.build(opts, key.alpn.clone())?);
        if cacheable { self.cache.lock().map_err(tls_err)?.insert(key, cfg.clone()); }
        Ok(cfg)
    }

    fn build(&self, opts: &TlsOptions<'_>, alpn: Vec<Vec<u8>>) -> HlsResult<ClientConfig> {
        let versions: &[&rustls::SupportedProtocolVersion] = match opts.max_version {
            TlsVersion::Tls12 => &[&rustls::version::TLS12],
            TlsVersion::Tls13 => &[&rustls::version::TLS13, &rustls::version::TLS12],
        };
        let builder = ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(versions)
            .map_err(tls_err)?;
        let builder = if opts.verify {
            let mut roots = RootCertStore::empty();
            match opts.ca_pem {
                Some(pem) => {
                    for cert in CertificateDer::pem_slice_iter(pem) {
                        roots.add(cert.map_err(tls_err)?).map_err(tls_err)?;
                    }
                }
                None => {
                    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                    roots.add_parsable_certificates(self.extra_roots.iter().cloned());
                }
            }
            builder.with_root_certificates(roots)
        } else {
            builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(
                self.provider.signature_verification_algorithms,
            )))
        };
        let mut cfg = match opts.identity {
            Some(id) => {
                let certs = CertificateDer::pem_slice_iter(&id.cert_chain_pem)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(tls_err)?;
                let key = PrivateKeyDer::from_pem_slice(&id.key_pem).map_err(tls_err)?;
                builder.with_client_auth_cert(certs, key).map_err(tls_err)?
            }
            None => builder.with_no_client_auth(),
        };
        cfg.alpn_protocols = alpn;
        if let Some(path) = opts.key_log {
            cfg.key_log = Arc::new(FileKeyLog(path.to_string()));
        }
        Ok(cfg)
    }

    fn server_name(opts: &TlsOptions<'_>) -> HlsResult<ServerName<'static>> {
        ServerName::try_from(opts.server_name.to_string()).map_err(tls_err)
    }
}

fn tls_err(e: impl std::fmt::Display) -> HlsError {
    HlsError::Tls(e.to_string())
}

fn alpn_of(proto: Option<&[u8]>) -> ALPN {
    proto.map(ALPN::from_slice).unwrap_or_else(ALPN::nullptr)
}

impl TlsConnector for RustlsConnector {
    fn connect(&self, mut io: Box<dyn SyncIo>, opts: &TlsOptions<'_>) -> HlsResult<Box<dyn TlsIo>> {
        let mut conn = ClientConnection::new(self.config(opts)?, Self::server_name(opts)?).map_err(tls_err)?;
        while conn.is_handshaking() {
            conn.complete_io(&mut io)?;
        }
        Ok(Box::new(RustlsStream(StreamOwned::new(conn, io))))
    }

    #[cfg(feature = "aync")]
    fn connect_async<'a>(&'a self, io: Box<dyn AsyncIo>, opts: TlsOptions<'a>) -> BoxFuture<'a, HlsResult<Box<dyn AsyncTlsIo>>> {
        Box::pin(async move {
            let connector = tokio_rustls::TlsConnector::from(self.config(&opts)?);
            let stream = connector.connect(Self::server_name(&opts)?, io).await?;
            Ok(Box::new(stream) as Box<dyn AsyncTlsIo>)
        })
    }
}

struct RustlsStream(StreamOwned<ClientConnection, Box<dyn SyncIo>>);

impl Read for RustlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0.read(buf) {
            // many servers close without close_notify; treat it as EOF
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
            res => res,
        }
    }
}

impl Write for RustlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.0.write(buf) }

    fn flush(&mut self) -> io::Result<()> { self.0.flush() }
}

impl TlsIo for RustlsStream {
    fn alpn(&self) -> ALPN { alpn_of(self.0.conn.alpn_protocol()) }

    fn shutdown(&mut self) -> io::Result<()> {
        self.0.conn.send_close_notify();
        self.0.flush()
    }
}

#[cfg(feature = "aync")]
impl AsyncTlsIo for tokio_rustls::client::TlsStream<Box<dyn AsyncIo>> {
    fn alpn(&self) -> ALPN { alpn_of(self.get_ref().1.alpn_protocol()) }
}

/// Writes NSS key-log lines to a file.
#[derive(Debug)]
struct FileKeyLog(String);

impl rustls::KeyLog for FileKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let line = format!("{} {} {}\n", label, hex::encode(client_random), hex::encode(secret));
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&self.0) {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// For `verify = false`: any certificate is accepted, but handshake signatures
/// are still checked against it.
#[derive(Debug)]
struct NoVerify(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}
