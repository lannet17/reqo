//! Key/value fields produced by [`body!`](crate::body!), serialized either as a
//! JSON object (default) or as `application/x-www-form-urlencoded` (`.form()`).
//!
//! There is deliberately no JSON value type here: each value is turned into its
//! JSON text when the macro is evaluated, via [`ToJson`].

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;

/// One top-level `key: value` entry of a body.
#[derive(Debug, Clone)]
pub struct Field {
    pub(crate) key: String,
    /// JSON text of the value.
    pub(crate) json: String,
    /// The raw string when the value is a string (used unquoted in forms / multipart).
    pub(crate) plain: Option<String>,
}

impl Field {
    pub fn new<V: ToJson + ?Sized>(key: impl Into<String>, value: &V) -> Field {
        let mut json = String::new();
        value.write_json(&mut json);
        Field { key: key.into(), json, plain: value.as_plain().map(str::to_string) }
    }

    pub fn key(&self) -> &str { &self.key }

    /// JSON text of the value.
    pub fn json(&self) -> &str { &self.json }

    /// Value as used in form / multipart encodings: strings unquoted, everything else as JSON.
    pub fn form_value(&self) -> &str {
        self.plain.as_deref().unwrap_or(&self.json)
    }
}

/// Fields serialized as a JSON object.
pub(crate) fn object_json(fields: &[Field]) -> String {
    let mut out = String::with_capacity(fields.iter().map(|f| f.key.len() + f.json.len() + 4).sum::<usize>() + 2);
    out.push('{');
    for (i, f) in fields.iter().enumerate() {
        if i > 0 { out.push(','); }
        write_json_str(&f.key, &mut out);
        out.push(':');
        out.push_str(&f.json);
    }
    out.push('}');
    out
}

pub(crate) fn write_json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => { let _ = write!(out, "\\u{:04x}", c as u32); }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Values usable inside [`body!`](crate::body!): std scalars, strings, `Option`,
/// sequences and string-keyed maps (and `serde_json::Value` with the `serde` feature).
pub trait ToJson {
    fn write_json(&self, out: &mut String);

    /// `Some` for string values.
    fn as_plain(&self) -> Option<&str> { None }

    fn to_json(&self) -> String {
        let mut s = String::new();
        self.write_json(&mut s);
        s
    }
}

impl<T: ToJson + ?Sized> ToJson for &T {
    fn write_json(&self, out: &mut String) { (**self).write_json(out) }
    fn as_plain(&self) -> Option<&str> { (**self).as_plain() }
}

impl<T: ToJson + ?Sized> ToJson for Box<T> {
    fn write_json(&self, out: &mut String) { (**self).write_json(out) }
    fn as_plain(&self) -> Option<&str> { (**self).as_plain() }
}

impl ToJson for str {
    fn write_json(&self, out: &mut String) { write_json_str(self, out) }
    fn as_plain(&self) -> Option<&str> { Some(self) }
}

impl ToJson for String {
    fn write_json(&self, out: &mut String) { write_json_str(self, out) }
    fn as_plain(&self) -> Option<&str> { Some(self) }
}

impl ToJson for std::borrow::Cow<'_, str> {
    fn write_json(&self, out: &mut String) { write_json_str(self, out) }
    fn as_plain(&self) -> Option<&str> { Some(self) }
}

impl ToJson for char {
    fn write_json(&self, out: &mut String) { write_json_str(self.encode_utf8(&mut [0; 4]), out) }
}

impl ToJson for bool {
    fn write_json(&self, out: &mut String) { out.push_str(if *self { "true" } else { "false" }) }
}

/// `()` serializes as `null` (the `null` keyword in `body!` maps to it).
impl ToJson for () {
    fn write_json(&self, out: &mut String) { out.push_str("null") }
}

macro_rules! int_to_json {
    ($($t:ty),*) => {$(
        impl ToJson for $t {
            fn write_json(&self, out: &mut String) { let _ = write!(out, "{}", self); }
        }
    )*};
}
int_to_json!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize);

macro_rules! float_to_json {
    ($($t:ty),*) => {$(
        impl ToJson for $t {
            fn write_json(&self, out: &mut String) {
                if self.is_finite() { let _ = write!(out, "{}", self); } else { out.push_str("null") }
            }
        }
    )*};
}
float_to_json!(f32, f64);

impl<T: ToJson> ToJson for Option<T> {
    fn write_json(&self, out: &mut String) {
        match self {
            Some(v) => v.write_json(out),
            None => out.push_str("null"),
        }
    }
    fn as_plain(&self) -> Option<&str> { self.as_ref().and_then(|v| v.as_plain()) }
}

fn write_seq<'a, T: ToJson + 'a>(items: impl Iterator<Item = &'a T>, out: &mut String) {
    out.push('[');
    for (i, v) in items.enumerate() {
        if i > 0 { out.push(','); }
        v.write_json(out);
    }
    out.push(']');
}

impl<T: ToJson> ToJson for [T] {
    fn write_json(&self, out: &mut String) { write_seq(self.iter(), out) }
}

impl<T: ToJson, const N: usize> ToJson for [T; N] {
    fn write_json(&self, out: &mut String) { write_seq(self.iter(), out) }
}

impl<T: ToJson> ToJson for Vec<T> {
    fn write_json(&self, out: &mut String) { write_seq(self.iter(), out) }
}

fn write_map<'a, K: AsRef<str> + 'a, V: ToJson + 'a>(items: impl Iterator<Item = (&'a K, &'a V)>, out: &mut String) {
    out.push('{');
    for (i, (k, v)) in items.enumerate() {
        if i > 0 { out.push(','); }
        write_json_str(k.as_ref(), out);
        out.push(':');
        v.write_json(out);
    }
    out.push('}');
}

impl<K: AsRef<str>, V: ToJson, S> ToJson for HashMap<K, V, S> {
    fn write_json(&self, out: &mut String) { write_map(self.iter(), out) }
}

impl<K: AsRef<str>, V: ToJson> ToJson for BTreeMap<K, V> {
    fn write_json(&self, out: &mut String) { write_map(self.iter(), out) }
}

#[cfg(feature = "serde")]
impl ToJson for serde_json::Value {
    fn write_json(&self, out: &mut String) { out.push_str(&self.to_string()) }
    fn as_plain(&self) -> Option<&str> { self.as_str() }
}

/// Already-serialized JSON (nested `{}` / `[]` inside `body!`).
#[doc(hidden)]
pub struct RawJson(pub String);

impl ToJson for RawJson {
    fn write_json(&self, out: &mut String) { out.push_str(&self.0) }
}

/// Support code for the exported macros. Not public API.
#[doc(hidden)]
pub mod __private {
    pub use super::{Field, RawJson, ToJson};
    use crate::Header;

    pub fn field<V: ToJson + ?Sized>(key: impl Into<String>, value: &V) -> Field { Field::new(key, value) }

    pub fn object_json(fields: Vec<Field>) -> String { super::object_json(&fields) }

    pub fn array_json(items: Vec<String>) -> String {
        let mut out = String::from("[");
        out.push_str(&items.join(","));
        out.push(']');
        out
    }

    pub fn to_json<V: ToJson + ?Sized>(value: &V) -> String { value.to_json() }

    pub fn header_insert(header: &mut Header, key: &str, value: impl ToString) {
        header.insert(key, value.to_string());
    }
}
