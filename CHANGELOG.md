# reqo-v0.5.0

Forked from reqrio 0.4.2.

TLS
* TLS goes through `reqo::tls::TlsConnector`. `RustlsConnector` (feature `rustls`, default) is used unless
  another connector is set with `set_tls_connector`.
* `RustlsConnector` trusts webpki-roots, `SSL_CERT_FILE` and `with_extra_roots_pem`.
* `reqo::tls::set_default_connector` changes the connector used by sessions without one.
* `set_mtls` takes a `ClientIdentity` (PEM) and an optional CA bundle; `set_version` takes a `TlsVersion`.
* Removed `set_tls_session` / `tls_session` (rustls resumes sessions itself) and the TLS fields of `Fingerprint`.
* HTTP/3 (`quic`) doesn't build for now.

API
* `ScReq` → `reqo::Session`, `AcReq` → `reqo::aio::Session`.
* `reqrio-json` is gone. Use `body!{..}` (JSON; `.form()` for a form) and `header!{..}`.
* `Response::json::<T>()` and `Body::json(&T)` need the `serde` feature.
* `params()` and multipart data take key/value pairs. `set_headers_json` → `merge_headers`.
* `HlsError::Rls` → `HlsError::Base`, plus `HlsError::Tls`.
* New crate `reqo-base`: buffers, URL, ALPN, gzip/deflate/brotli/zstd, written in Rust (no FFI).

Fixes
* HTTP/1.1 pipelining hung when the next response was already in the buffer.
* A compressed body could be decoded past its `Content-Length`.

Removed
* C bindings (`bindings`, `EXPORT.md`) and the old release workflow.

Earlier history: see [reqrio](https://github.com/xllgl2017/reqrio/blob/main/CHANGELOG.md).
