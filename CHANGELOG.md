# reqo-v0.5.0

First release as `reqo`, forked from reqrio 0.4.2. TLS is now pluggable and rustls is the default backend.

* New crate `reqo-base`: pure-Rust buffers (`Writer` / `Reader`), URL types, ALPN and content coding
  (gzip / deflate / zlib / brotli / zstd). No FFI or native downloads needed.
* New `reqo::tls` module: `TlsConnector` / `TlsIo` / `AsyncTlsIo` traits; `RustlsConnector` (feature `rustls`, on by default).
  `RustlsConnector` also trusts certificates from `SSL_CERT_FILE` and `with_extra_roots_pem`.
* Other TLS stacks (e.g. ones with ClientHello fingerprinting) plug in by implementing `TlsConnector`.
* Breaking: `set_mtls(ClientIdentity, Option<ca_pem>)`, `set_version(TlsVersion)`, new `set_tls_connector`;
  removed `set_tls_session` / `tls_session` (rustls resumes sessions itself), the TLS parts of `Fingerprint`,
  and the old TLS re-exports. `HlsError::Rls` was replaced by `HlsError::Base` / `HlsError::Tls`.
* Fix: HTTP/1.1 pipelining stalled when the next response was already buffered, and a compressed body
  could be decoded past its `Content-Length`.
* `ScReq` is now `reqo::Session` and `AcReq` is now `reqo::aio::Session` (same API, selected by import path).
* Removed the `reqrio-json` crate. New macros instead:
  `body!{..}` builds a JSON body (`body!{..}.form()` for urlencoded), `header!{..}` builds a `Header`.
  Values are plain std types (`ToJson`); there is no JSON value type in reqo anymore.
* `Response::json::<T>()` / `Body::json(&T)` (serde) live behind the optional `serde` feature.
* `params()` and multipart data take key/value pairs; `set_headers_json` became `merge_headers(Header)`.
* `quic` (HTTP/3) is not available with the pluggable TLS layer yet.
* Removed the C FFI bindings (`bindings` submodule, `EXPORT.md`) and the old release workflow.

Earlier history: see [reqrio](https://github.com/xllgl2017/reqrio/blob/main/CHANGELOG.md).
