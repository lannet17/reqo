mod ext;
mod fields;
mod reader;
mod multi_form;

use crate::error::HlsResult;
use crate::reader::{HCow, ReadExt, RefReader, StrCow};
use crate::*;
use crate::{Application, ContentType, Text};
pub use ext::BodyExt;
pub use multi_form::{FileForm, FormError, HttpFile};
pub use reader::RawBodyReader;
pub use fields::{Field, ToJson};
#[doc(hidden)]
pub use fields::__private;
use reqo_base::{hash, rand};
#[cfg(feature = "serde")]
use serde::Serialize;
use std::borrow::Cow;
use std::sync::Arc;

pub enum BodyKind<'a> {
    /// Sent as a form if the content type is urlencoded, otherwise as JSON.
    Fields(HCow<'a, Vec<Field>>),
    Bytes(Cow<'a, [u8]>),
    Files(HCow<'a, HttpFile>),
}

impl<'a, 'b: 'a> From<&'b BodyKind<'a>> for BodyKind<'a> {
    fn from(value: &'b BodyKind) -> Self {
        match value {
            BodyKind::Fields(data) => BodyKind::Fields(HCow::Borrowed(data.as_ref())),
            BodyKind::Bytes(bytes) => BodyKind::Bytes(Cow::Borrowed(bytes.as_ref())),
            BodyKind::Files(file) => BodyKind::Files(HCow::Borrowed(file.as_ref())),
        }
    }
}

/// Request body: bytes, text, fields (JSON or form) or multipart.
pub struct Body<'a> {
    kind: BodyKind<'a>,
    ct: ContentType,
}

impl<'a, 'b: 'a> From<&'b Body<'a>> for Body<'a> {
    fn from(value: &'b Body<'a>) -> Self {
        Body {
            kind: BodyKind::from(&value.kind),
            ct: value.ct.clone(),
        }
    }
}


impl<'a> From<&'a [u8]> for Body<'a> {
    fn from(bytes: &'a [u8]) -> Body<'a> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(bytes)),
            ct: ContentType::Application(Application::OctetStream),
        }
    }
}

impl<'a> From<&'a Vec<u8>> for Body<'a> {
    fn from(bytes: &'a Vec<u8>) -> Body<'a> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(bytes)),
            ct: ContentType::Application(Application::OctetStream),
        }
    }
}

impl<'a> From<Vec<u8>> for Body<'a> {
    fn from(bytes: Vec<u8>) -> Body<'a> {
        Body {
            kind: BodyKind::Bytes(Cow::Owned(bytes)),
            ct: ContentType::Application(Application::OctetStream),
        }
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for Body<'a> {
    fn from(bytes: &'a [u8; N]) -> Body<'a> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(bytes)),
            ct: ContentType::Application(Application::OctetStream),
        }
    }
}

impl<'a> From<&'a str> for Body<'a> {
    fn from(text: &'a str) -> Body<'a> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(text.as_bytes())),
            ct: ContentType::Text(Text::Plain),
        }
    }
}

impl<'a> From<String> for Body<'a> {
    fn from(text: String) -> Body<'a> {
        Body {
            kind: BodyKind::Bytes(Cow::Owned(text.into_bytes())),
            ct: ContentType::Text(Text::Plain),
        }
    }
}

impl<'a> From<HttpFile> for Body<'a> {
    fn from(file: HttpFile) -> Body<'a> {
        let r = rand::random::<[u8; 16]>();
        let md5 = hash::md5_hex(r);
        let boundary = Arc::new(format!("----WebKitFormBoundary{}", &md5[..16]));
        Body {
            ct: ContentType::File(boundary.clone()),
            kind: BodyKind::Files(HCow::Owned(file.with_boundary(boundary))),

        }
    }
}

impl<'a> From<Option<()>> for Body<'a> {
    fn from(_: Option<()>) -> Self {
        Body::none()
    }
}


impl<'a> Body<'a> {
    // /// Create a body from a specific payload kind and content type.
    // ///
    // /// * `body` - wire data kind.
    // /// * `ty` - content type.
    // pub fn new(body: &'a [u8], ty: ContentType) -> Body<'a> {
    //     Body {
    //         kind: body,
    //         ct: ty,
    //     }
    // }

    /// Create an empty body.
    pub fn none() -> Body<'a> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(&[])),
            ct: ContentType::Null,
        }
    }

    /// JSON body from fields. [`body!`](crate::body!) calls this.
    pub fn from_fields(fields: Vec<Field>) -> Body<'a> {
        Body { kind: BodyKind::Fields(HCow::Owned(fields)), ct: ContentType::json() }
    }

    /// The fields, if the body has them.
    pub fn fields(&self) -> Option<&[Field]> {
        match &self.kind {
            BodyKind::Fields(f) => Some(f.as_slice()),
            _ => None,
        }
    }

    /// Send as `application/x-www-form-urlencoded`: `k=v&...`, where a string
    /// value is used as is and anything else as JSON text.
    pub fn form(mut self) -> Body<'a> {
        self.ct = ContentType::form();
        self
    }

    #[cfg(feature = "serde")]
    /// JSON body from a `Serialize` value. If it serializes to an object, `.form()` works too.
    pub fn json<T: Serialize + ?Sized>(value: &T) -> HlsResult<Body<'a>> {
        let value = serde_json::to_value(value).map_err(|e| format!("struct to json error, {}", e))?;
        Ok(match value {
            serde_json::Value::Object(map) => Body::from_fields(map.iter().map(|(k, v)| Field::new(k.as_str(), v)).collect()),
            other => Body {
                kind: BodyKind::Bytes(Cow::Owned(other.to_string().into_bytes())),
                ct: ContentType::json(),
            },
        })
    }

    pub(crate) fn as_reader(&'a self) -> HlsResult<RawBodyReader<'a>> {
        match &self.kind {
            BodyKind::Fields(fields) => {
                if !matches!(self.ct, ContentType::Application(Application::XWwwFormUrlencoded)) {
                    return Ok(RawBodyReader::Data(RefReader::new_buf(StrCow::Owned(fields::object_json(fields)))));
                }
                let mut readers: RefReader<StrCow> = RefReader::default();
                for (i, field) in fields.iter().enumerate() {
                    if i > 0 { readers.add_str("&") }
                    readers.add_str(&field.key);
                    readers.add_str("=");
                    match coder::url_encode(field.form_value()) {
                        Cow::Borrowed(v) => readers.add_str(v),
                        Cow::Owned(o) => readers.add_string(o)
                    }
                }
                Ok(RawBodyReader::Data(readers))
            }
            BodyKind::Bytes(bytes) => Ok(RawBodyReader::Bytes(RefReader::new_buf(bytes.as_ref()))),
            BodyKind::Files(file) => Ok(RawBodyReader::File(file.as_reader()?)),
        }
    }

    /// Body as it is sent.
    pub fn to_vec(&self) -> HlsResult<Vec<u8>> {
        let mut body = self.as_reader()?;
        let mut writer = Writer::with_capacity(body.len());
        let len = body.read(&mut writer)?;
        assert_eq!(len, writer.len());
        Ok(writer.filled().to_vec())
    }

    /// Body as it is sent, as a string.
    pub fn to_string(&self) -> HlsResult<String> {
        let res = self.to_vec()?;
        Ok(String::from_utf8(res)?)
    }

    /// Content type.
    pub fn context_type(&self) -> &ContentType { &self.ct }

    pub fn with_ct(mut self, ct: impl Into<ContentType>) -> Body<'a> {
        self.ct = ct.into();
        self
    }
}