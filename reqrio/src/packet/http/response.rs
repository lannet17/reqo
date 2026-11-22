#[cfg(feature = "serde")]
use crate::error::HlsResult;
use crate::*;
use std::fmt::{Display, Formatter};
use std::str::Utf8Error;


/// A response with its full body.
#[repr(C)]
pub struct Response {
    pub(crate) sid: u64,
    pub(crate) status: HttpStatus,
    pub(crate) alpn: ALPN,
    pub(crate) body: Writer,
    pub(crate) header: Header,
}

impl Default for Response {
    fn default() -> Self {
        Response {
            alpn: Default::default(),
            status: HttpStatus::None,
            sid: 0,
            header: Header::default(),
            body: Writer::with_capacity(8192),
        }
    }
}

impl Response {
    /// Response headers.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Response headers, mutable.
    pub fn header_mut(&mut self) -> &mut Header { &mut self.header }

    /// Parse the body as JSON: `res.json::<MyStruct>()`, `res.json::<serde_json::Value>()`.
    #[cfg(feature = "serde")]
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> HlsResult<T> {
        serde_json::from_slice(self.body.filled()).map_err(|e| format!("json decode error: {}", e).into())
    }

    /// Body as `&str`; fails if it isn't UTF-8.
    pub fn as_text(&self) -> Result<&str, Utf8Error> { std::str::from_utf8(self.body.filled()) }

    /// Body as `String`.
    pub fn text(self) -> Result<String, Utf8Error> { Ok(self.as_text()?.to_owned()) }

    /// Body bytes.
    pub fn as_bytes(&self) -> &[u8] { self.body.filled() }

    /// Body bytes as `Vec<u8>`.
    pub fn bytes(self) -> Vec<u8> { self.body.filled().to_vec() }

    /// Status code.
    pub const fn status(&self) -> HttpStatus { self.status }

    /// Protocol used for this response (HTTP/1.1 or HTTP/2).
    pub const fn alpn(&self) -> &ALPN { &self.alpn }

    pub const fn sid(&self) -> u64 { self.sid }
}

impl Display for Response {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if !self.alpn.is_empty() {
            write!(f, "{} {} {}", self.alpn, self.status.code(), self.status.spec())?;
            write!(f, "\r\n")?;
        }
        write!(f, "{}", self.header)?;
        let body = self.as_text().unwrap_or("(二进制数据)");
        if !body.is_empty() {
            write!(f, "\r\n\r\n")?;
            write!(f, "{}", body)?;
            write!(f, "\r\n")?;
        }
        Ok(())
    }
}