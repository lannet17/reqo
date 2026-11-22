use super::{Body, BodyKind};
use crate::ContentType;
use std::borrow::Cow;

pub trait BodyExt {
    fn ty(&self, ct: impl Into<ContentType>) -> Body<'_>;
}

impl BodyExt for String {
    fn ty(&self, ct: impl Into<ContentType>) -> Body<'_> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(self.as_bytes())),
            ct: ct.into(),
        }
    }
}

impl BodyExt for &str {
    fn ty(&self, ct: impl Into<ContentType>) -> Body<'_> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(self.as_bytes())),
            ct: ct.into(),
        }
    }
}

impl BodyExt for &[u8] {
    fn ty(&self, ct: impl Into<ContentType>) -> Body<'_> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(self)),
            ct: ct.into(),
        }
    }
}

impl BodyExt for Vec<u8> {
    fn ty(&self, ct: impl Into<ContentType>) -> Body<'_> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(self)),
            ct: ct.into(),
        }
    }
}

impl<const N: usize> BodyExt for [u8; N] {
    fn ty(&self, ct: impl Into<ContentType>) -> Body<'_> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(self)),
            ct: ct.into(),
        }
    }
}