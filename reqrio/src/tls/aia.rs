//! Fetching missing intermediate certificates through AIA (RFC 5280 4.2.2.1).
//!
//! Many servers don't send their full chain. When verification fails with
//! `UnknownIssuer`, take the caIssuers URL from the last certificate of the
//! chain, download the issuer and try again, like browsers do.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How many missing certificates are fetched at most for one chain.
const MAX_FETCH: usize = 4;
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Certificates are a few KB; anything much larger isn't one.
const MAX_BODY: usize = 256 * 1024;

/// Downloaded certificates by URL.
pub(super) type AiaCache = Arc<Mutex<HashMap<String, Vec<CertificateDer<'static>>>>>;

/// webpki verification, plus AIA fetching on `UnknownIssuer`.
#[derive(Debug)]
pub(super) struct AiaVerifier {
    inner: Arc<WebPkiServerVerifier>,
    cache: AiaCache,
}

impl AiaVerifier {
    pub(super) fn new(inner: Arc<WebPkiServerVerifier>, cache: AiaCache) -> Self {
        AiaVerifier { inner, cache }
    }

    fn issuers(&self, cert: &CertificateDer<'_>) -> Vec<CertificateDer<'static>> {
        for url in ca_issuers(cert) {
            if let Some(certs) = self.cache.lock().ok().and_then(|c| c.get(&url).cloned()) {
                return certs;
            }
            let certs = match blocking(|| fetch(&url)) {
                Ok(body) => parse_certs(&body),
                Err(_) => continue,
            };
            if certs.is_empty() { continue; }
            if let Ok(mut c) = self.cache.lock() { c.insert(url, certs.clone()); }
            return certs;
        }
        vec![]
    }
}

impl ServerCertVerifier for AiaVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let unknown_issuer = rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer);
        let res = self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now);
        if !matches!(&res, Err(e) if *e == unknown_issuer) { return res; }

        let mut chain: Vec<CertificateDer<'_>> = intermediates.to_vec();
        for _ in 0..MAX_FETCH {
            let last = chain.last().unwrap_or(end_entity).clone();
            let fetched: Vec<_> = self.issuers(&last).into_iter().filter(|c| !chain.contains(c) && c != end_entity).collect();
            if fetched.is_empty() { break; }
            chain.extend(fetched);
            match self.inner.verify_server_cert(end_entity, &chain, server_name, ocsp_response, now) {
                Err(e) if e == unknown_issuer => continue,
                other => return other,
            }
        }
        res
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The verifier runs inside the handshake; in a multi-threaded tokio runtime,
/// tell tokio this thread is going to block.
fn blocking<T>(f: impl FnOnce() -> T) -> T {
    #[cfg(feature = "aync")]
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(f);
        }
    }
    f()
}

/// GET over plain HTTP (AIA URLs are http; https would need TLS to get TLS working).
fn fetch(url: &str) -> io::Result<Vec<u8>> {
    let rest = url.strip_prefix("http://").ok_or_else(|| io::Error::other("only http AIA URLs are fetched"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let addr = if authority.contains(':') { authority.to_string() } else { format!("{authority}:80") };
    let host = authority.split(':').next().unwrap_or(authority);
    let sock = addr.to_socket_addrs()?.next().ok_or_else(|| io::Error::other("no address"))?;
    let mut stream = TcpStream::connect_timeout(&sock, FETCH_TIMEOUT)?;
    stream.set_read_timeout(Some(FETCH_TIMEOUT))?;
    stream.set_write_timeout(Some(FETCH_TIMEOUT))?;
    write!(stream, "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: reqo/{}\r\nAccept: */*\r\n\r\n", env!("CARGO_PKG_VERSION"))?;

    let mut resp = Vec::new();
    stream.take(MAX_BODY as u64 + 16 * 1024).read_to_end(&mut resp)?;
    let end = resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| io::Error::other("bad response"))?;
    let head = std::str::from_utf8(&resp[..end]).map_err(io::Error::other)?;
    let status = head.split_whitespace().nth(1).unwrap_or("");
    if status != "200" { return Err(io::Error::other(format!("AIA fetch: status {status}"))); }
    Ok(resp[end + 4..].to_vec())
}

/// DER certificate, PEM certificate(s), or a PKCS#7 bundle (`.p7c`, DER or PEM).
pub(super) fn parse_certs(body: &[u8]) -> Vec<CertificateDer<'static>> {
    if body.starts_with(b"-----BEGIN") {
        let certs: Vec<_> = CertificateDer::pem_slice_iter(body).filter_map(Result::ok).collect();
        if !certs.is_empty() { return certs; }
        // "-----BEGIN PKCS7-----"
        let b64: String = std::str::from_utf8(body).unwrap_or("").lines().filter(|l| !l.starts_with("-----")).collect();
        return match crate::base64::b64decode(b64) {
            Ok(der) => pkcs7_certs(&der),
            Err(_) => vec![],
        };
    }
    if is_certificate(body) { return vec![CertificateDer::from(body.to_vec())]; }
    pkcs7_certs(body)
}

// ---- minimal DER reading -------------------------------------------------

/// One TLV: tag, contents, and the whole encoding.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    raw: &'a [u8],
}

fn read_tlv(data: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *data.first()?;
    let first = *data.get(1)? as usize;
    let (len, hdr) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 { return None; }
        let len = data.get(2..2 + n)?.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
        (len, 2 + n)
    };
    let total = hdr.checked_add(len)?;
    let raw = data.get(..total)?;
    Some((Tlv { tag, value: &raw[hdr..], raw }, &data[total..]))
}

fn children(data: &[u8]) -> Vec<Tlv<'_>> {
    let mut out = vec![];
    let mut rest = data;
    while !rest.is_empty() {
        match read_tlv(rest) {
            Some((t, r)) => { out.push(t); rest = r; }
            None => break,
        }
    }
    out
}

const SEQUENCE: u8 = 0x30;
/// 1.3.6.1.5.5.7.1.1 authorityInfoAccess
const OID_AIA: &[u8] = &[0x2b, 6, 1, 5, 5, 7, 1, 1];
/// 1.3.6.1.5.5.7.48.2 caIssuers
const OID_CA_ISSUERS: &[u8] = &[0x2b, 6, 1, 5, 5, 7, 48, 2];
/// 1.2.840.113549.1.7.2 signedData
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 2];

fn is_certificate(der: &[u8]) -> bool {
    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm SEQUENCE, signature BIT STRING }
    match read_tlv(der) {
        Some((cert, rest)) if cert.tag == SEQUENCE && rest.is_empty() => {
            let c = children(cert.value);
            c.len() == 3 && c[0].tag == SEQUENCE && c[1].tag == SEQUENCE && c[2].tag == 0x03
        }
        _ => false,
    }
}

/// caIssuers URLs of a certificate.
pub(super) fn ca_issuers(cert: &[u8]) -> Vec<String> {
    let Some((cert, _)) = read_tlv(cert) else { return vec![] };
    let Some(tbs) = children(cert.value).into_iter().next() else { return vec![] };
    // extensions: [3] EXPLICIT SEQUENCE OF Extension
    let Some(exts) = children(tbs.value).into_iter().find(|t| t.tag == 0xa3) else { return vec![] };
    let Some((exts, _)) = read_tlv(exts.value) else { return vec![] };
    for ext in children(exts.value) {
        let parts = children(ext.value);
        let (Some(oid), Some(value)) = (parts.first(), parts.last()) else { continue };
        if oid.tag != 0x06 || oid.value != OID_AIA || value.tag != 0x04 { continue; }
        // OCTET STRING { SEQUENCE OF AccessDescription { accessMethod OID, accessLocation GeneralName } }
        let Some((list, _)) = read_tlv(value.value) else { return vec![] };
        return children(list.value)
            .into_iter()
            .filter_map(|desc| {
                let d = children(desc.value);
                let (method, location) = (d.first()?, d.get(1)?);
                // uniformResourceIdentifier [6] IA5String
                (method.value == OID_CA_ISSUERS && location.tag == 0x86)
                    .then(|| String::from_utf8(location.value.to_vec()).ok())
                    .flatten()
            })
            .collect();
    }
    vec![]
}

/// Certificates in a degenerate PKCS#7 SignedData.
fn pkcs7_certs(der: &[u8]) -> Vec<CertificateDer<'static>> {
    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
    let Some((info, _)) = read_tlv(der) else { return vec![] };
    let info = children(info.value);
    let (Some(oid), Some(content)) = (info.first(), info.get(1)) else { return vec![] };
    if oid.value != OID_SIGNED_DATA || content.tag != 0xa0 { return vec![]; }
    // SignedData ::= SEQUENCE { version, digestAlgorithms, contentInfo, certificates [0] IMPLICIT ..., ... }
    let Some((signed, _)) = read_tlv(content.value) else { return vec![] };
    children(signed.value)
        .into_iter()
        .find(|t| t.tag == 0xa0)
        .map(|certs| {
            children(certs.value)
                .into_iter()
                .filter(|c| is_certificate(c.raw))
                .map(|c| CertificateDer::from(c.raw.to_vec()))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Let's Encrypt "YR2" intermediate; its issuer is at http://yr.i.lencr.org/
    const YR2: &[u8] = include_bytes!("testdata/lets-encrypt-yr2.pem");

    #[test]
    fn aia_url() {
        let cert = CertificateDer::from_pem_slice(YR2).unwrap();
        assert!(is_certificate(&cert));
        assert_eq!(ca_issuers(&cert), vec!["http://yr.i.lencr.org/".to_string()]);
    }

    #[test]
    fn parse_formats() {
        let cert = CertificateDer::from_pem_slice(YR2).unwrap();
        assert_eq!(parse_certs(YR2), vec![cert.clone()]);
        assert_eq!(parse_certs(&cert), vec![cert.clone()]);

        // degenerate PKCS#7 SignedData holding the certificate
        fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            match value.len() {
                n if n < 0x80 => out.push(n as u8),
                n => { out.push(0x82); out.extend_from_slice(&(n as u16).to_be_bytes()); }
            }
            out.extend_from_slice(value);
            out
        }
        let signed_data = tlv(SEQUENCE, &[
            tlv(0x02, &[1]),                     // version
            tlv(0x31, &[]),                      // digestAlgorithms
            tlv(SEQUENCE, &tlv(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 1])), // data
            tlv(0xa0, &cert),                    // certificates
            tlv(0x31, &[]),                      // signerInfos
        ].concat());
        let p7 = tlv(SEQUENCE, &[tlv(0x06, OID_SIGNED_DATA), tlv(0xa0, &signed_data)].concat());
        assert_eq!(parse_certs(&p7), vec![cert]);
        assert!(parse_certs(b"not a certificate").is_empty());
    }
}
