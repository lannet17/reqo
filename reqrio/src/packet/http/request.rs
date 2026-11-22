#[cfg(feature = "serde")]
use crate::error::HlsResult;
use crate::{Header, Method};
use reqo_base::{ALPN, Buffer, Uri};
use std::fmt::{Display, Formatter};
use std::str::Utf8Error;

pub struct Request {
    pub(crate) method: Method,
    pub(crate) uri: Uri,
    pub(crate) alpn: ALPN,
    pub(crate) header: Header,
    pub(crate) body: Buffer,
}

impl Request {
    pub fn header(&self) -> &Header { &self.header }

    pub fn header_mut(&mut self) -> &mut Header { &mut self.header }

    /// Deserialize the body as JSON, e.g. `res.json::<MyStruct>()` or `res.json::<serde_json::Value>()`.
    #[cfg(feature = "serde")]
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> HlsResult<T> {
        serde_json::from_slice(self.body.filled()).map_err(|e| format!("json decode error: {}", e).into())
    }

    pub fn as_text(&self) -> Result<&str, Utf8Error> { std::str::from_utf8(self.body.filled()) }

    pub fn text(self) -> Result<String, Utf8Error> { Ok(self.as_text()?.to_owned()) }

    pub fn as_bytes(&self) -> &[u8] { self.body.filled() }

    pub fn bytes(self) -> Vec<u8> { self.body.filled().to_vec() }

    pub fn method(&self) -> Method { self.method }

    pub fn uri(&self) -> &Uri { &self.uri }

    pub fn alpn(&self) -> &ALPN { &self.alpn }
}

impl Display for Request {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if !self.alpn.is_empty() {
            write!(f, "{} {} {}", self.method, self.uri, self.alpn)?;
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