#![doc = include_str!("../../README.md")]

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
pub mod aio {
    //! Async session (tokio). Same methods as [`crate::Session`], with `.await`:
    //!
    //! ```rust,ignore
    //! use reqo::aio::Session;
    //! let mut s = Session::new();
    //! let res = s.get("https://httpbin.org/get", None).await?;
    //! ```
    pub use crate::acq::Session;
}
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
pub use scq::Session;
pub use stream::{Proxy, ProxyStream, ConnParam, WebSocket, TlsStream, Stream, StreamMessage};
pub use tls::{ClientIdentity, TlsConnector, TlsVersion};

// `aync` enables tokio-rustls even without `rustls` (Cargo has no "both
// features" dependency); it is only used when `rustls` is on.
#[cfg(all(feature = "aync", not(feature = "rustls")))]
use tokio_rustls as _;

#[cfg(feature = "quic")]
compile_error!("the `quic` feature (HTTP/3) does not work yet");
#[cfg(feature = "quic")]
pub use stream::QUICStream;
pub use time::{Time, TimeError, Timeout};
#[cfg(feature = "aync")]
pub use tokio;
#[cfg(feature = "log")]
pub use logger::Logger;
use crate::ext::ReqUrl;

/// GET using a new [`Session`] that is dropped afterwards.
pub fn get<'a>(url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
    Session::new().get(url, body)
}

/// POST using a new [`Session`] that is dropped afterwards.
pub fn post<'a>(url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
    Session::new().post(url, body)
}

/// PUT using a new [`Session`] that is dropped afterwards.
pub fn put<'a>(url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
    Session::new().put(url, body)
}
