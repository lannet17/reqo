//!# reqrio - High-Performance HTTP Request Engine
//!
//! A modern Rust HTTP request library optimized for low latency, high concurrency, and minimal memory overhead.
//! Designed to mimic browser behavior for advanced web automation, API integration, and reverse proxy development.
//!
//! ## Why reqrio?
//!
//! - **Browser-like Requests**: Browser-identical header ordering and HTTP/2 settings; TLS fingerprinting via a pluggable backend
//! - **Enterprise-Grade Performance**: Handle thousands of concurrent requests with minimal overhead using async/sync dual-mode
//! - **Pluggable TLS**: rustls by default (mTLS, session resumption); swap in any [`tls::TlsConnector`]
//! - **Efficient Memory Usage**: Intelligent use of Rust's lifetime system and `Cow` to eliminate unnecessary copies
//!
//! ## Core Features
//!
//! - **Efficient Reference-Based Architecture**: Leverages Rust's ownership model with `Cow` and lifetime borrowing to minimize allocations
//! - **Dual Concurrency Models**: Sync (`ScReq`) and Async (`AcReq`) engines for flexible deployment
//! - **TLS Fingerprinting**: available through the optional reqtls backend (hex / Ja3 / Ja4)
//! - **Strict Header Ordering**: Enforces HTTP/2.0 and HTTP/1.1 header sequences consistent with real browser requests
//! - **Complete Protocol Support**: HTTP/1.1, HTTP/2.0, and full-duplex WebSocket with connection pooling
//!
//! ## Architecture: Efficient Data Pipeline
//!
//! `reqrio` uses a layered architecture that optimizes memory usage through intelligent borrowing and streaming:
//!```text
//! ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ Write ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
//! │        Form  ┌─────────┐           ┌───────────────┐           ┌─────────────┐           ┌──────┐ │
//! │ User ───────►│  Req    │  Body     │ RequestBuf    │  Buffer   │             │ Encrypted │      │ │
//! │        Json  │ Engine  ├─ Cow<T> ──┤ Header + Body │──────────►│  TlsStream  │──────────►│ TCP  │ │
//! │        Files │ (Sync)  │ Lifetime  │    Readers    │           │   Encrypt   │           │ Send │ │
//! │ User ───────►│ (Async) │           │ (borrowed)    │           │             │           │      │ │
//! │              └─────────┘           └───────────────┘           └─────────────┘           └──────┘ │
//! └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
//! ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  Read ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  ─ ─ ─ ─ ┐
//! │                 ┌──────────┐            ┌────────┐                 │
//! │ ┌───────┐ read  │   TLS    │ decrypt to │ ScReq  │  return         │
//! │ │  TCP  │──────►│ Fragment │───────────►│ AcReq  │─────────► User  │
//! │ └───────┘       │ Decrypt  │            │(Engine)│ Response        │
//! │                 └──────────┘            └────────┘                 │
//! └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘
//!
//! ```
//! **Key Design Principles:**
//! - **Lifetime-Based Borrowing**: Data is borrowed via lifetime parameters during header and body processing, avoiding unnecessary copies
//! - **Copy-on-Write (Cow)**: Form data and JSON payloads use `Cow<T>` to support both borrowed and owned data without overhead
//! - **Streaming Body Readers**: Support for HTTP/1.1 and HTTP/2.0 with separate body readers for efficient chunking
//! - **Single Data Copy at Encryption**: Data flows into TLS encryption layer where it is copied once for cryptographic operations
//! - **Zero-Copy for Files**: Large file uploads are read on-demand through `BodyReader` interface, avoiding full buffering
//!
//!
//! ## Quick Start Guide
//!
//! ### Simple GET Request
//! The simplest way to send a GET request:
//!
//! ```rust
//! # use reqo::*;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut res = reqo::get("https://api.example.com/users", None)?;
//! println!("{}", res.as_text()?);
//! # Ok(())
//! # }
//! ```
//!
//! ### GET Request with Query Parameters
//! Add query parameters using the `.params()` method:
//! ```rust
//! # use reqo::*;
//! # fn ff() {
//! // Send GET request with query parameters
//! let res = reqo::get("https://www.baidu.com".params([("p1", "1"), ("p2", "??34//11<<><")]), None).unwrap();
//!
//! // Access response headers and body
//! let header = res.header();
//! let text = res.text().unwrap();
//!
//! // With the `serde` feature: `let v: serde_json::Value = res.json().unwrap();`
//! # }
//! ```
//!
//! ### POST with Form Data
//! ```rust
//! # use reqo::*;
//! # fn ff() {
//! let url = "https://www.baidu.com/api";
//! let data = body! {
//!     "field1": "value1",
//!     "field2": 2
//! };
//!
//! let resp = reqo::post(url, data.form()).unwrap();
//! # }
//! ```
//!
//! ### POST with JSON Data
//! ```rust
//! # use reqo::*;
//! # fn ff() {
//! let url = "https://www.baidu.com/api";
//! let data = body! {
//!     "field1": "value1",
//!     "field2": { "nested": [1, 2, 3] }
//! };
//!
//! let resp = reqo::post(url, data).unwrap();
//! # }
//! ```
//!
//! ### POST with Serializable Struct
//! ```rust,ignore
//! // requires the `serde` feature
//! # use reqo::*;
//! # use serde::Serialize;
//! # fn ff() {
//! #[derive(Serialize)]
//! struct Data {
//!     field1: String,
//!     field2: bool,
//! }
//!
//! let url = "https://www.baidu.com/api";
//! let resp = reqo::post(
//!     url,
//!     Body::json(&Data {
//!         field1: "value".to_string(),
//!         field2: false,
//!     }).unwrap()
//! ).unwrap();
//! # }
//! ```
//!
//! ### Advanced: Custom Session with Fingerprinting
//! For authentic browser emulation, configure a session with custom headers and TLS settings:
//!
//! ```rust
//! # use reqo::*;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let headers = header! {
//!     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
//!     "Accept-Encoding": "gzip, deflate, br, zstd",
//!     "Accept-Language": "en-US,en;q=0.9",
//!     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
//! };
//!
//! let mut session = ScReq::new()
//!     .with_alpn(ALPN::HTTP20)                    // Use HTTP/2.0 for modern sites
//!     .with_header(headers)                      // Set browser-compatible headers
//!     .with_timeout(Timeout::new_same(5000, 3)); // 5s timeout with 3 retries
//!
//! // Make requests with persistent session state
//! let resp = session.post("https://api.example.com/data", body! {"key": "value"})?;
//! # Ok(())
//! # }
//! ```
//!
//! ### WebSocket Connection (Sync)
//! Real-time communication with WebSocket protocol:
//! ```rust
//! # use reqo::*;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let url = "wss://stream.example.com/events";
//!
//! let mut ws = WebSocket::open_sync(url)?;
//!
//! // Read frames in a loop
//! loop {
//!     let frame = ws.read_frame().wait()?;
//!     match frame.frame_type().op_code() {
//!         WsOpcode::TEXT => {
//!             let text = String::from_utf8(frame.payload().as_bytes().to_vec())?;
//!             println!("Received: {}", text);
//!         }
//!         WsOpcode::BINARY => println!("Binary data received"),
//!         WsOpcode::PING => {
//!             ws.send_pong(frame.payload().as_bytes()).wait()?;
//!         }
//!         WsOpcode::CLOSE => break,
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Performance Characteristics
//!
//! - **Request Latency**: ~1-5ms per request (varies by network/server)
//! - **Concurrent Throughput**: 10K+ requests/sec on standard hardware
//! - **Memory Efficiency**: ~50-100KB per idle connection
//! - **Zero Allocation**: Header processing uses stack when possible
//!
//! ## Use Cases
//!
//! - **Web Scraping**: Authentic browser behavior bypass advanced detection
//! - **API Testing**: Precise control over HTTP semantics and TLS configuration
//! - **Real-Time Systems**: WebSocket support for live data streaming
//! - **Reverse Proxies**: Direct TLS record layer access for protocol development
//! - **Performance Tools**: Connection pooling and efficient concurrent requests
//!
//! ## Thread Safety & Concurrency
//!
//! - `ScReq` (Sync): Single-threaded, `Send + Sync` for thread pools
//! - `AcReq` (Async): Tokio-based, designed for `async/await` workloads
//! - Connection pooling and session reuse recommended for production
//!
//! ## Feature Flags
//!
//! - `aync`: Enable async runtime with Tokio support (required for `AcReq`)
//! - `export`: Enable C FFI bindings for cross-language integration
//! - `serde`: Enable serde serialization/deserialization support
//! - `log`: Enable internal debug logging (requires Rust nightly)
//!
//! ## Security Considerations
//!
//! - **Certificate Verification**: Enabled by default; disable only for testing with `verify(false)`
//! - **TLS Session Caching**: Automatic session resumption for performance; explicitly managed
//! - **Memory Safety**: Rust type system prevents buffer overflows and use-after-free bugs
//! - **Constant-Time Operations**: Critical cryptographic operations use constant-time implementations
//!
//! ## Advanced Topics
//!
//! ### Custom TLS Configuration
//! For advanced TLS scenarios like mTLS or custom certificate chains:
//!
//! ```rust,no_run
//! # use reqo::*;
//! // Client certificate chain + key (PEM), and an optional private CA bundle (PEM).
//! let identity = ClientIdentity::from_pem_files("client.pem", "client.key")?;
//! let ca = std::fs::read("ca-bundle.pem")?;
//! let req = ScReq::new().with_mtls(identity, Some(ca));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### TLS backends
//! TLS is pluggable through [`tls::TlsConnector`]. The default `rustls` feature
//! uses rustls; to use another backend (e.g. reqtls for ClientHello
//! fingerprinting), disable default features and install its connector:
//!
//! ```toml
//! # take both from the same git source, so there is only one `reqo` (and one `TlsConnector` trait)
//! reqo = { git = "https://github.com/lannet17/reqo", default-features = false }
//! reqtls = { git = "https://github.com/lannet17/reqo", features = ["reqo"] }
//! ```
//! ```rust,ignore
//! let req = ScReq::new().with_tls_connector(std::sync::Arc::new(reqtls::ReqtlsConnector::default()));
//! ```
//!
//! ### Proxy Configuration
//! Route requests through HTTP/SOCKS proxies:
//!
//! ```rust,no_run
//! # use reqo::*;
//! // let proxy = Proxy::http("http://proxy.example.com:8080")?;
//! // let mut req = ScReq::new().with_proxy(proxy);
//! ```
//!
//! ## Ecosystem Integration
//!
//! - **reqo-base**: Buffers, URL types and content coding shared with TLS backends
//! - **pack**: HTTP/2 header compression support
//!
//! For more examples and advanced usage, visit the [GitHub repository](https://github.com/xllgl2017/reqrio)

#[cfg(feature = "aync")]
mod acq;
pub mod pack;
mod error;
mod ext;
mod packet;
mod scq;
mod stream;
mod body;
mod fingerprint;
mod reader;
mod cookie;
pub mod tls;
mod macros;
mod time;
#[cfg(feature = "log")]
mod logger;

pub type ReqCallback = Box<dyn FnMut(&[u8]) -> HlsResult<()> + Send + Sync>;
pub const HTTP_GAP: &[u8; 4] = b"\r\n\r\n";
pub const CHUNK_END: [u8; 7] = [13, 10, 48, 13, 10, 13, 10];

#[cfg(feature = "aync")]
pub use acq::AcReq;
pub use body::{Body, BodyExt, Field, FileForm, HttpFile, ToJson};
#[doc(hidden)]
pub use body::__private;
pub use error::{HlsError, HlsResult};
pub use ext::{ReqExt, ReqStreamExt, UrlExt};
pub use fingerprint::{Fingerprint, H2Finger};
pub use packet::{
    Application, ContentType, Cookie, Font, H2FrameFlag, H2FrameType, H2Frame, H2Setting, Header,
    HeaderItem, HeaderValue, HttpStatus, Method, Response, Text, WsFrame, WsOpcode, Request, ImageType,
    H2PayloadValue,
};
#[cfg(feature = "quic")]
pub use packet::{H3Payload, H3FrameType, H3Setting, H3Frame};
pub use reqo_base::*;
#[cfg(feature = "log")]
pub use log::*;
pub use scq::ScReq;
pub use stream::{Proxy, ProxyStream, ConnParam, WebSocket, TlsStream, Stream, StreamMessage};
#[cfg(feature = "aync")]
pub use stream::AsyncTlsStream;
pub use tls::{ClientIdentity, TlsConnector, TlsVersion};

// `aync` always pulls in tokio-rustls (Cargo can't express "aync AND rustls");
// it is only used together with the `rustls` feature.
#[cfg(all(feature = "aync", not(feature = "rustls")))]
use tokio_rustls as _;

#[cfg(feature = "quic")]
compile_error!("the `quic` feature is not supported yet with the pluggable TLS layer");
#[cfg(feature = "quic")]
pub use stream::QUICStream;
pub use time::{Time, TimeError, Timeout};
#[cfg(feature = "aync")]
pub use tokio;
#[cfg(feature = "log")]
pub use logger::Logger;
use crate::ext::ReqUrl;

/// Send a GET request with a temporary session.
///
/// * `url` - request URL or URL-like value.
/// * `body` - request body payload.
pub fn get<'a>(url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
    ScReq::new().get(url, body)
}

/// Send a POST request with a temporary session.
///
/// * `url` - request URL or URL-like value.
/// * `body` - request body payload.
pub fn post<'a>(url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
    ScReq::new().post(url, body)
}

/// Send a PUT request with a temporary session.
///
/// * `url` - request URL or URL-like value.
/// * `body` - request body payload.
pub fn put<'a>(url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
    ScReq::new().put(url, body)
}
