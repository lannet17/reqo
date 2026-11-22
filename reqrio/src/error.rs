use crate::pack::PackError;
use reqo_base::{hex, BaseError, BufferError, UrlError, ALPN};
use std::array::TryFromSliceError;
use std::convert::Infallible;
use std::error::Error;
use std::ffi::NulError;
use std::fmt::{Display, Formatter};
use std::io;
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::sync::PoisonError;
#[cfg(feature = "aync")]
use tokio::time::error::Elapsed;
use crate::body::FormError;
use crate::H2FrameType;
use crate::packet::HeaderError;
use crate::time::TimeError;

#[derive(Debug)]
pub enum HlsError {
    NullPointer,
    InvalidHeadSize,
    PeerClosedConnection,
    PayloadNone,
    DecrypterNone,
    EncrypterNone,
    WsFrameTypeNone,
    H2(H2FrameType),
    UnsupportedAlpn(ALPN),
    Body(FormError),
    Base(BaseError),
    /// Error from the TLS connector.
    Tls(String),
    HPack(PackError),
    Time(TimeError),
    Header(HeaderError),
    Currently(String),
}

impl From<&str> for HlsError {
    fn from(s: &str) -> Self {
        HlsError::Currently(s.to_string())
    }
}

impl From<String> for HlsError {
    fn from(s: String) -> Self {
        HlsError::Currently(s)
    }
}

impl From<FromUtf8Error> for HlsError {
    fn from(e: FromUtf8Error) -> Self {
        HlsError::Currently(e.to_string())
    }
}

impl From<ParseIntError> for HlsError {
    fn from(e: ParseIntError) -> Self {
        HlsError::Currently(e.to_string())
    }
}

impl Display for HlsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HlsError::Currently(e) => f.write_str(e),
            HlsError::InvalidHeadSize => f.write_str("InvalidHeadSize"),
            HlsError::PeerClosedConnection => f.write_str("PeerClosedConnection"),
            HlsError::PayloadNone => f.write_str("PayloadNone"),
            HlsError::DecrypterNone => f.write_str("DecrypterNone"),
            HlsError::NullPointer => f.write_str("NonePointer"),
            HlsError::EncrypterNone => f.write_str("EncrypterNone"),
            HlsError::WsFrameTypeNone => f.write_str("WsFrameTypeNone"),
            HlsError::Base(e) => write!(f, "{}", e),
            HlsError::Tls(e) => write!(f, "Tls({})", e),
            HlsError::HPack(e) => write!(f, "HPack({})", e),
            HlsError::Body(e) => write!(f, "Body({})", e),
            HlsError::Time(e) => write!(f, "Time({:?})", e),
            HlsError::UnsupportedAlpn(alpn) => write!(f, "UnsupportedAlpn({})", alpn),
            HlsError::H2(typ) => write!(f, "H2({:?})", typ),
            HlsError::Header(e) => write!(f, "Header({:?})", e),
        }
    }
}

impl From<TryFromSliceError> for HlsError {
    fn from(value: TryFromSliceError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<io::Error> for HlsError {
    fn from(value: io::Error) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<Infallible> for HlsError {
    fn from(value: Infallible) -> Self {
        #[allow(unused)]
        HlsError::Currently(value.to_string())
    }
}

impl From<PackError> for HlsError {
    fn from(value: PackError) -> Self {
        HlsError::HPack(value)
    }
}

impl<T: 'static> From<PoisonError<T>> for HlsError {
    fn from(value: PoisonError<T>) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<Utf8Error> for HlsError {
    fn from(value: Utf8Error) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<BaseError> for HlsError {
    fn from(value: BaseError) -> Self {
        HlsError::Base(value)
    }
}

#[cfg(feature = "aync")]
impl From<Elapsed> for HlsError {
    fn from(value: Elapsed) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<HlsError> for io::Error {
    fn from(err: HlsError) -> io::Error {
        io::Error::other(err.to_string())
    }
}

impl From<AddrParseError> for HlsError {
    fn from(value: AddrParseError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<hex::FromHexError> for HlsError {
    fn from(value: hex::FromHexError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<NulError> for HlsError {
    fn from(value: NulError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<BufferError> for HlsError {
    fn from(value: BufferError) -> Self {
        HlsError::Base(BaseError::Buffer(value))
    }
}

impl From<FormError> for HlsError {
    fn from(value: FormError) -> Self {
        HlsError::Body(value)
    }
}

impl From<TimeError> for HlsError {
    fn from(value: TimeError) -> Self {
        HlsError::Time(value)
    }
}
impl From<UrlError> for HlsError {
    fn from(value: UrlError) -> Self {
        HlsError::Base(BaseError::Url(value))
    }
}

// impl From<io::ErrorKind> for HlsError {
//     fn from(value: io::ErrorKind) -> Self {
//         HlsError::Currently(value.to_string())
//     }
// }

impl From<HeaderError> for HlsError {
    fn from(value: HeaderError) -> Self {
        HlsError::Header(value)
    }
}

impl From<H2FrameType> for HlsError {
    fn from(value: H2FrameType) -> Self {
        HlsError::H2(value)
    }
}

impl Error for HlsError {}


pub type HlsResult<T> = Result<T, HlsError>;
