//! Types used by [reqo](https://crates.io/crates/reqo): byte buffers, URLs,
//! ALPN, gzip/deflate/brotli/zstd coding, md5 and base64 helpers.

mod alpn;
mod buffer;
pub mod coder;
mod error;
mod url;

pub use alpn::ALPN;
pub use buffer::{u24, Buf, BufferError, Reader, Writer};
pub use error::{BaseError, BaseResult};
pub use hex;
pub use rand;
pub use url::{Addr, Param, Scheme, Uri, Url, UrlError};

pub type Buffer = Writer;

pub mod hash {
    use md5::{Digest, Md5};

    pub fn md5(context: impl AsRef<[u8]>) -> [u8; 16] {
        Md5::digest(context.as_ref()).into()
    }

    pub fn md5_hex(context: impl AsRef<[u8]>) -> String {
        hex::encode(md5(context))
    }
}

pub mod base64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    pub fn b64encode(context: impl AsRef<[u8]>) -> String {
        STANDARD.encode(context)
    }

    pub fn b64decode(context: impl AsRef<[u8]>) -> Result<Vec<u8>, crate::BaseError> {
        STANDARD.decode(context).map_err(|e| crate::BaseError::Currently(e.to_string()))
    }
}
