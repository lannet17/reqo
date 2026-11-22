# reqo

[中文](https://github.com/lannet17/reqo/blob/main/README_zh.md)

HTTP/1.1 and HTTP/2 client for Rust, sync and async. Headers go out in the
order you set them, HTTP/2 settings can be changed, and TLS goes through a
trait (rustls by default) so it can be replaced.

```toml
[dependencies]
reqo = "0.5"
```

## Example

```rust,no_run
use reqo::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let res = reqo::get("https://httpbin.org/get", None)?;
    println!("{} {}", res.status(), res.as_text()?);

    let mut s = Session::new()
        .with_alpn(ALPN::HTTP20)
        .with_timeout(Timeout::new_same(5000, 3))
        .with_header(header! {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br, zstd",
        });

    let res = s.post("https://httpbin.org/post", body! { "name": "reqo", "page": 2 })?;
    println!("{}", res.as_text()?);
    Ok(())
}
```

`Timeout::new_same(5000, 3)`: 5 s for connect, read and write; at most 3 attempts to connect and 3 per request.

Async needs the `aync` feature. Same methods, from `reqo::aio`:

```rust,ignore
use reqo::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut s = aio::Session::new();
    let res = s.get("https://httpbin.org/get", None).await?;
    println!("{}", res.as_text()?);
    Ok(())
}
```

A `Session` holds one connection plus its headers and cookies. Use one session
per connection; it is not a pool.

## Bodies

```rust
use reqo::*;

let name = "reqo";

// JSON
let json = body! {
    "name": name,
    page: 2,
    "tags": ["http", "tls"],
    "extra": { "debug": true, "proxy": null },
};

// same fields, sent as application/x-www-form-urlencoded
let form = body! { "name": name, "page": 2 }.form();

let text = Body::from("hello");
let bytes = Body::from(vec![1u8, 2, 3]);

// multipart
let mut file = HttpFile::new_bytes_data([("desc", "avatar")], b"...".to_vec());
file.add_form(FileForm::new_bytes(b"second file".to_vec()).with_field_name("file2"));
let multipart = Body::from(file);
```

Values in `body!` can be numbers, `bool`, strings, `Option`, `Vec`, arrays and
string-keyed maps. Other types need a `ToJson` impl, or use `Body::json(&v)`
with the `serde` feature.

## Responses

```rust,ignore
let res = s.get("https://httpbin.org/json", None)?;
res.status();
res.header();
res.as_text()?;
res.as_bytes();

// serde feature
let v: serde_json::Value = res.json()?;
let data: MyStruct = res.json()?;
```

## Query, pipelining, streaming

```rust,no_run
# use reqo::*;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let mut s = Session::new();
let url = "https://httpbin.org/get".params([("q", "rust"), ("page", "2")])?;
let res = s.get(url, None)?;

// send first, read later
let a = s.send(Method::GET, "https://httpbin.org/uuid", None)?;
let b = s.send(Method::GET, "https://httpbin.org/ip", None)?;
let (ra, rb) = (s.recv(a)?, s.recv(b)?);

// read the body chunk by chunk
let sid = s.send_stream(Method::GET, "https://httpbin.org/stream/20", None)?.sid;
while let Some(chunk) = s.next_chunk(sid)? {
    println!("{} bytes", chunk.len());
}
# Ok(())
# }
```

## Headers

`header!` keeps the order you write. `merge_headers` adds to what the session
already has; `with_header` replaces it.

```rust,no_run
# use reqo::*;
# let mut s = Session::new();
s.merge_headers(header! { "x-trace": 42, "cookie": "a=1; b=2" });
s.insert_header("x-late", "late");
```

## HTTP/2 settings

Frames sent after the connection preface:

```rust
use reqo::*;

let h2 = H2Finger {
    frames: vec![
        H2Frame::new_setting(vec![
            H2Setting::HeaderTableSize(65536),
            H2Setting::EnablePush(0),
            H2Setting::InitialWindowSize(6291456),
            H2Setting::MaxHeaderListSize(262144),
        ]),
        H2Frame::new_window_update(15663105),
    ],
    weight: 255,
    priority: true,
};
let s = Session::new().with_fingerprint(Fingerprint::new_h2(h2));
```

## TLS

With the default `rustls` feature:

```rust,no_run
use reqo::*;

let id = ClientIdentity::from_pem_files("client.pem", "client.key")?;
let s = Session::new()
    .with_version(TlsVersion::Tls13)  // max version offered
    .with_mtls(id, None)
    .with_key_log("keys.log");
# Ok::<(), Box<dyn std::error::Error>>(())
```

- Trusted roots: `webpki-roots`, plus anything in `SSL_CERT_FILE`, plus `RustlsConnector::with_extra_roots_pem`.
- `with_verify(false)` turns off certificate checks.

To use a different TLS library, implement `reqo::tls::TlsConnector` and build
without rustls:

```toml
reqo = { version = "0.5", default-features = false, features = ["zstd"] }
```

```rust,ignore
use reqo::tls::{SyncIo, TlsConnector, TlsIo, TlsOptions};
use reqo::HlsResult;

struct MyTls;

impl TlsConnector for MyTls {
    fn connect(&self, io: Box<dyn SyncIo>, opts: &TlsOptions<'_>) -> HlsResult<Box<dyn TlsIo>> {
        // handshake on `io` for opts.server_name, offer opts.alpn
        todo!()
    }
    // also connect_async with the `aync` feature
}

let s = Session::new().with_tls_connector(std::sync::Arc::new(MyTls));
```

`io` is the TCP stream, already through the proxy if one is set.

## Proxy, WebSocket

```rust,no_run
# use reqo::*;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let s = Session::new().with_proxy(Proxy::try_from("socks5://user:pass@127.0.0.1:1080")?);
let s = Session::new().with_proxy(Proxy::try_from("http://127.0.0.1:8080")?);

let mut ws = WebSocket::open_sync("wss://echo.websocket.org")?;
ws.send_text("hello").wait()?;
let frame = ws.read_frame().wait()?;
# Ok(())
# }
```

## Features

| Feature  | Default | |
|----------|:-------:|---|
| `rustls` | yes     | rustls (ring, webpki-roots) as the TLS backend |
| `zstd`   | yes     | zstd decoding; builds libzstd with `cc` |
| `aync`   |         | `reqo::aio`, tokio |
| `serde`  |         | `Response::json`, `Body::json` |
| `log`    |         | logging via `log` |

gzip, deflate and brotli decoding are always on. HTTP/3 isn't supported yet.

## License

Apache-2.0. Forked from [reqrio](https://github.com/xllgl2017/reqrio) 0.4.2.
