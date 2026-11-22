use crate::{BufferError, UrlError};
use std::fmt::{Display, Formatter};

pub type BaseResult<T> = Result<T, BaseError>;

/// Errors produced by reqo-base (buffers, URL parsing, content coding).
#[derive(Debug)]
pub enum BaseError {
    Buffer(BufferError),
    Url(UrlError),
    Coder(String),
    Io(std::io::Error),
    Currently(String),
}

impl Display for BaseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BaseError::Buffer(e) => write!(f, "Buffer({e})"),
            BaseError::Url(e) => write!(f, "Url({e})"),
            BaseError::Coder(e) => write!(f, "Coder({e})"),
            BaseError::Io(e) => write!(f, "Io({e})"),
            BaseError::Currently(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for BaseError {}

impl From<BaseError> for std::io::Error {
    fn from(value: BaseError) -> Self {
        match value {
            BaseError::Io(e) => e,
            e => std::io::Error::other(e),
        }
    }
}

macro_rules! from_into {
    ($($t:ty => $v:ident),* $(,)?) => {$(
        impl From<$t> for BaseError {
            fn from(e: $t) -> Self { BaseError::$v(e) }
        }
    )*};
}

from_into! {
    BufferError => Buffer,
    UrlError => Url,
    std::io::Error => Io,
    String => Currently,
}

macro_rules! from_display {
    ($($t:ty),* $(,)?) => {$(
        impl From<$t> for BaseError {
            fn from(e: $t) -> Self { BaseError::Currently(e.to_string()) }
        }
    )*};
}

from_display! {
    &str,
    std::num::ParseIntError,
    std::string::FromUtf8Error,
    std::str::Utf8Error,
    std::net::AddrParseError,
    std::time::SystemTimeError,
    std::array::TryFromSliceError,
}

impl<T> From<std::sync::PoisonError<T>> for BaseError {
    fn from(e: std::sync::PoisonError<T>) -> Self { BaseError::Currently(e.to_string()) }
}
