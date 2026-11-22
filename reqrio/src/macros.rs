//! `body!` and `header!`.

/// Build a request [`Body`](crate::Body) from `key: value` pairs.
///
/// * Sent as JSON by default; call `.form()` to send it as
///   `application/x-www-form-urlencoded` instead.
/// * Keys: string literals, identifiers, or `[expr]`.
/// * Values: any [`ToJson`](crate::ToJson) expression (numbers, `bool`, `&str` / `String`,
///   `Option`, `Vec`, maps...), `null`, or nested `{ ... }` / `[ ... ]`.
///
/// ```
/// use reqo::*;
/// let name = "reqo";
/// let json = body! {
///     "name": name,
///     page: 2,
///     "tags": ["http", "tls"],
///     "extra": { "debug": true, "proxy": null },
/// };
/// assert_eq!(json.to_string().unwrap(), r#"{"name":"reqo","page":2,"tags":["http","tls"],"extra":{"debug":true,"proxy":null}}"#);
///
/// let form = body! { "name": name, "page": 2 }.form();
/// assert_eq!(form.to_string().unwrap(), "name=reqo&page=2");
/// ```
#[macro_export]
macro_rules! body {
    ($($t:tt)*) => {
        $crate::Body::from_fields($crate::__reqo_entries!(@acc [] $($t)*))
    };
}

/// Build a [`Header`](crate::Header) from `name: value` pairs, keeping their order.
/// Values can be anything implementing `Display`; `cookie` is parsed into cookies.
///
/// ```
/// use reqo::*;
/// let header = header! {
///     "user-agent": "Mozilla/5.0",
///     "accept": "*/*",
///     "cookie": "a=1; b=2",
/// };
/// assert_eq!(header.get_str("accept"), Some("*/*"));
/// ```
#[macro_export]
macro_rules! header {
    ($($k:tt : $v:expr),* $(,)?) => {{
        let mut header = $crate::Header::default();
        $( $crate::__private::header_insert(&mut header, $crate::__reqo_key!($k), $v); )*
        header
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __reqo_key {
    ($k:ident) => { stringify!($k) };
    ([$k:expr]) => { &*$k };
    ($k:expr) => { $k };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __reqo_value {
    (null) => { &() };
    ({ $($t:tt)* }) => { &$crate::__private::RawJson($crate::__private::object_json($crate::__reqo_entries!(@acc [] $($t)*))) };
    ([ $($t:tt)* ]) => { &$crate::__private::RawJson($crate::__private::array_json($crate::__reqo_items!(@acc [] $($t)*))) };
    ($e:expr) => { &$e };
}

/// `key: value, ...` → `Vec<Field>`
#[doc(hidden)]
#[macro_export]
macro_rules! __reqo_entries {
    (@acc [$($out:tt)*]) => {{
        let v: ::std::vec::Vec<$crate::__private::Field> = ::std::vec![$($out)*];
        v
    }};
    (@acc [$($out:tt)*] $k:ident : $($rest:tt)*) => { $crate::__reqo_entries!(@val [$($out)*] (stringify!($k)) $($rest)*) };
    (@acc [$($out:tt)*] $k:literal : $($rest:tt)*) => { $crate::__reqo_entries!(@val [$($out)*] ($k) $($rest)*) };
    (@acc [$($out:tt)*] [$k:expr] : $($rest:tt)*) => { $crate::__reqo_entries!(@val [$($out)*] ($k) $($rest)*) };
    // single-token values (literals, idents, null, {..}, [..])
    (@val [$($out:tt)*] ($k:expr) $v:tt , $($rest:tt)*) => {
        $crate::__reqo_entries!(@acc [$($out)* $crate::__private::field($k, $crate::__reqo_value!($v)),] $($rest)*)
    };
    (@val [$($out:tt)*] ($k:expr) $v:tt) => {
        $crate::__reqo_entries!(@acc [$($out)* $crate::__private::field($k, $crate::__reqo_value!($v)),])
    };
    // arbitrary expressions
    (@val [$($out:tt)*] ($k:expr) $v:expr , $($rest:tt)*) => {
        $crate::__reqo_entries!(@acc [$($out)* $crate::__private::field($k, &$v),] $($rest)*)
    };
    (@val [$($out:tt)*] ($k:expr) $v:expr) => {
        $crate::__reqo_entries!(@acc [$($out)* $crate::__private::field($k, &$v),])
    };
}

/// `value, ...` → `Vec<String>` of JSON texts
#[doc(hidden)]
#[macro_export]
macro_rules! __reqo_items {
    (@acc [$($out:tt)*]) => {{
        let v: ::std::vec::Vec<::std::string::String> = ::std::vec![$($out)*];
        v
    }};
    (@acc [$($out:tt)*] $v:tt , $($rest:tt)*) => {
        $crate::__reqo_items!(@acc [$($out)* $crate::__private::to_json($crate::__reqo_value!($v)),] $($rest)*)
    };
    (@acc [$($out:tt)*] $v:tt) => {
        $crate::__reqo_items!(@acc [$($out)* $crate::__private::to_json($crate::__reqo_value!($v)),])
    };
    (@acc [$($out:tt)*] $v:expr , $($rest:tt)*) => {
        $crate::__reqo_items!(@acc [$($out)* $crate::__private::to_json(&$v),] $($rest)*)
    };
    (@acc [$($out:tt)*] $v:expr) => {
        $crate::__reqo_items!(@acc [$($out)* $crate::__private::to_json(&$v),])
    };
}

#[cfg(test)]
mod tests {
    

    #[test]
    fn body_json_and_form() {
        let n = 3u8;
        let opt: Option<&str> = None;
        let b = body! {
            "s": "a\"b",
            num: -1,
            "f": 1.5,
            "n": n + 1,
            "o": opt,
            "nil": null,
            ["dyn".to_string()]: true,
            "arr": [1, "x", { "k": [] }, null],
            "obj": {},
        };
        assert_eq!(
            b.to_string().unwrap(),
            r#"{"s":"a\"b","num":-1,"f":1.5,"n":4,"o":null,"nil":null,"dyn":true,"arr":[1,"x",{"k":[]},null],"obj":{}}"#
        );
        assert_eq!(body! {}.to_string().unwrap(), "{}");
        assert_eq!(body! { "q": "a b&c", "p": 2 }.form().to_string().unwrap(), "q=a%20b%26c&p=2");
    }

    #[test]
    fn header_macro() {
        let ua = String::from("ua/1");
        let h = header! { "User-Agent": ua, accept: "*/*", "cookie": "a=1; b=2", "x-n": 5 };
        assert_eq!(h.get_str("user-agent"), Some("ua/1"));
        assert_eq!(h.get_str("accept"), Some("*/*"));
        assert_eq!(h.get_str("x-n"), Some("5"));
        assert_eq!(h.cookies().map(|c| c.len()), Some(2));
    }
}
