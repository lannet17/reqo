# reqo

[中文](README_zh.md)

**reqo** is a lightweight HTTP client for Rust with a **pluggable TLS layer**.
It speaks HTTP/1.1 and HTTP/2, has both blocking and async sessions, keeps
request headers in exactly the order you write them, and lets you control the
HTTP/2 connection settings. TLS is handled by rustls out of the box, and you can
swap in any other TLS stack by implementing a single trait.

```toml
[dependencies]
reqo = "0.5"
```

## Highlights

- **Sync and async**: `ScReq` (blocking) and `AcReq` (tokio, `aync` feature) share the same API.
- **HTTP/1.1 and HTTP/2**, negotiated through ALPN, with pipelining (`send` / `recv`) and streaming responses.
- **Header order is preserved** exactly as written; per-protocol default orders follow real browsers.
- **HTTP/2 fingerprint**: SETTINGS / WINDOW_UPDATE frames and stream priority are configurable.
- **Pluggable TLS**: rustls by default (mTLS, TLS 1.2/1.3, session resumption, key log), or your own `TlsConnector`.
- **Small macro layer**: `body!` for JSON / form bodies and `header!` for headers, built on std types only.
- **Content decoding**: gzip, deflate, brotli and zstd responses are decoded automatically, including chunked transfer.
- **Proxies**: HTTP CONNECT and SOCKS5, with or without authentication.
- **WebSocket** client (sync and async), with permessage-deflate support.
- **Pure Rust core**: no FFI and nothing downloaded at build time.

## Quick start

```rust,no_run
use reqo::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // One-off request
    let res = reqo::get("https://httpbin.org/get", None)?;
    println!("{} {}", res.status(), res.as_text()?);

    // Reusable session: keeps the connection, cookies and headers
    let mut req = ScReq::new()
        .with_alpn(ALPN::HTTP20)                    // offer h2, fall back to http/1.1
        .with_timeout(Timeout::new_same(5000, 3))   // 5s timeouts, up to 3 attempts
        .with_header(header! {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br, zstd",
        });

    let res = req.post("https://httpbin.org/post", body! { "name": "reqo", "page": 2 })?;
    println!("{}", res.as_text()?);
    Ok(())
}
```

Async works the same way with `AcReq` and `.await` (enable the `aync` feature):

```rust,ignore
use reqo::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut req = AcReq::new().with_alpn(ALPN::HTTP20);
    let res = req.get("https://httpbin.org/get", None).await?;
    println!("{}", res.as_text()?);
    Ok(())
}
```

## Request bodies

```rust
use reqo::*;

let name = "reqo";

// JSON (default): nested objects, arrays and null are supported
let json = body! {
    "name": name,
    page: 2,
    "tags": ["http", "tls"],
    "extra": { "debug": true, "proxy": null },
};

// The same fields as application/x-www-form-urlencoded
let form = body! { "name": name, "page": 2 }.form();

// Plain text and raw bytes
let text = Body::from("hello");
let bytes = Body::from(vec![1u8, 2, 3]);

// Multipart upload: form fields + files
let mut file = HttpFile::new_bytes_data([("desc", "avatar")], b"...png bytes...".to_vec());
file.add_form(FileForm::new_bytes(b"second file".to_vec()).with_field_name("file2"));
let multipart = Body::from(file);
```

Values in `body!` can be any std type: numbers, `bool`, `&str` / `String`,
`Option`, `Vec`, arrays, `HashMap` / `BTreeMap`. For your own types, implement
`ToJson`, or use `Body::json(&value)` with the `serde` feature.

## Responses

```rust,ignore
let res = req.get("https://httpbin.org/json", None)?;
res.status();          // HttpStatus
res.header();          // &Header
res.as_text()?;        // &str
res.as_bytes();        // &[u8]

// With the `serde` feature
let doc: serde_json::Value = res.json()?;
let typed: MyStruct = res.json()?;
```

## Query parameters, pipelining, streaming

```rust,no_run
# use reqo::*;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let mut req = ScReq::new();
// Query parameters
let url = "https://httpbin.org/get".params([("q", "rust"), ("page", "2")])?;
let res = req.get(url, None)?;

// Pipelining: send several requests, then collect the responses
let a = req.send(Method::GET, "https://httpbin.org/uuid", None)?;
let b = req.send(Method::GET, "https://httpbin.org/ip", None)?;
let (ra, rb) = (req.recv(a)?, req.recv(b)?);

// Streaming: headers first, then the body chunk by chunk
let head = req.send_stream(Method::GET, "https://httpbin.org/stream/20", None)?;
let sid = head.sid;
while let Some(chunk) = req.next_chunk(sid)? {
    println!("{} bytes", chunk.len());
}
# Ok(())
# }
```

## Headers and HTTP/2 fingerprint

Headers are sent in exactly the order you insert them. `header!` builds a
`Header`, and `merge_headers` adds headers to a session without replacing the
existing ones:

```rust,no_run
# use reqo::*;
# let mut req = ScReq::new();
req.merge_headers(header! { "x-trace": 42, "cookie": "a=1; b=2" });
req.insert_header("x-late", "late");
```

The frames sent right after the HTTP/2 preface are configurable:

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
let req = ScReq::new().with_fingerprint(Fingerprint::new_h2(h2));
```

## TLS

reqo never performs a TLS handshake itself. It hands the (possibly proxied)
connection to a `TlsConnector` and gets an encrypted stream back.

**Default: rustls** (`rustls` feature, enabled by default)

```rust,no_run
use reqo::*;

let identity = ClientIdentity::from_pem_files("client.pem", "client.key")?;
let req = ScReq::new()
    .with_version(TlsVersion::Tls13)            // highest version to offer
    .with_mtls(identity, None)                  // client certificate (mTLS)
    .with_key_log("keys.log");                  // NSS key log for Wireshark (debugging only)
# Ok::<(), Box<dyn std::error::Error>>(())
```

- Roots come from the Mozilla set (`webpki-roots`). Certificates in the PEM file
  named by `SSL_CERT_FILE` are trusted as well, and `RustlsConnector::with_extra_roots_pem` adds more.
- `with_verify(false)` skips certificate validation. Use it only for testing.
- Session tickets are cached per configuration, so later connections resume automatically.

**Your own TLS stack**: implement `reqo::tls::TlsConnector`, then disable the
default `rustls` feature so rustls isn't compiled in:

```toml
reqo = { version = "0.5", default-features = false, features = ["zstd"] }
```

```rust,ignore
use reqo::tls::{SyncIo, TlsConnector, TlsIo, TlsOptions};
use reqo::HlsResult;

struct MyConnector;

impl TlsConnector for MyConnector {
    fn connect(&self, io: Box<dyn SyncIo>, opts: &TlsOptions<'_>) -> HlsResult<Box<dyn TlsIo>> {
        // Handshake over `io` for `opts.server_name`, offering `opts.alpn`,
        // then return a stream that reports the negotiated ALPN.
        todo!()
    }
    // With the `aync` feature, also override `connect_async`.
}

let req = ScReq::new().with_tls_connector(std::sync::Arc::new(MyConnector));
```

`TlsOptions` passes the server name, the ALPN list, verify mode, maximum
version, client identity, CA bundle and key-log path. A backend is free to
ignore what it doesn't support, or to add its own settings (such as a
ClientHello fingerprint) on its connector type.

## Proxies and WebSocket

```rust,no_run
# use reqo::*;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let req = ScReq::new().with_proxy(Proxy::try_from("socks5://user:pass@127.0.0.1:1080")?);
let req = ScReq::new().with_proxy(Proxy::try_from("http://127.0.0.1:8080")?);

let mut ws = WebSocket::open_sync("wss://echo.websocket.org")?;
ws.send_text("hello").wait()?;
let frame = ws.read_frame().wait()?;
# Ok(())
# }
```

## Feature flags

| Feature  | Default | Description                                                       |
|----------|:-------:|-------------------------------------------------------------------|
| `rustls` |   yes   | Default TLS backend (rustls + ring + webpki-roots)                |
| `zstd`   |   yes   | zstd content decoding (libzstd is compiled from source by `cc`)   |
| `aync`   |         | Async API (`AcReq`, async WebSocket) on tokio                     |
| `serde`  |         | `Response::json::<T>()`, `Body::json(&T)`, serde derives          |
| `log`    |         | Internal logging through the `log` crate                          |

HTTP/3 (QUIC) is not available yet with the pluggable TLS layer.

## Crates

| Crate       | Description                                                                 |
|-------------|-----------------------------------------------------------------------------|
| `reqo`      | The HTTP client                                                             |
| `reqo-base` | Buffers, URL types, ALPN and content coding, shared with TLS backend crates |

## Acknowledgements

reqo is a fork of [reqrio](https://github.com/xllgl2017/reqrio) 0.4.2.

## License

Apache-2.0. See [LICENSE-APACHE](LICENSE-APACHE).
