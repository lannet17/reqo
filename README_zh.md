# reqo

[English](https://github.com/lannet17/reqo/blob/main/README.md)

Rust 的 HTTP/1.1、HTTP/2 客户端，有同步和异步两套接口。请求头按设置的顺序发送，
HTTP/2 的 SETTINGS 可以改，TLS 通过 trait 接入（默认 rustls），可以换成别的实现。

```toml
[dependencies]
reqo = "0.5"
```

## 示例

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

`Timeout::new_same(5000, 3)`：连接、读、写超时都是 5 秒；建立连接最多尝试 3 次，每个请求也最多尝试 3 次。

异步要开 `aync` feature，方法一样，类型在 `reqo::aio` 下：

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

一个 `Session` 对应一条连接，连同这条连接上的请求头和 cookie。它不是连接池，需要多条连接就建多个 `Session`。

## 请求体

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

// 同样的字段，按 application/x-www-form-urlencoded 发送
let form = body! { "name": name, "page": 2 }.form();

let text = Body::from("hello");
let bytes = Body::from(vec![1u8, 2, 3]);

// multipart
let mut file = HttpFile::new_bytes_data([("desc", "avatar")], b"...".to_vec());
file.add_form(FileForm::new_bytes(b"second file".to_vec()).with_field_name("file2"));
let multipart = Body::from(file);
```

`body!` 里的值可以是数字、`bool`、字符串、`Option`、`Vec`、数组和以字符串为键的 map。
其他类型要实现 `ToJson`，或者开 `serde` feature 用 `Body::json(&v)`。

## 响应

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

## 查询参数、流水线、分块读取

```rust,no_run
# use reqo::*;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let mut s = Session::new();
let url = "https://httpbin.org/get".params([("q", "rust"), ("page", "2")])?;
let res = s.get(url, None)?;

// 先发，后收
let a = s.send(Method::GET, "https://httpbin.org/uuid", None)?;
let b = s.send(Method::GET, "https://httpbin.org/ip", None)?;
let (ra, rb) = (s.recv(a)?, s.recv(b)?);

// 一块一块读响应体
let sid = s.send_stream(Method::GET, "https://httpbin.org/stream/20", None)?.sid;
while let Some(chunk) = s.next_chunk(sid)? {
    println!("{} bytes", chunk.len());
}
# Ok(())
# }
```

## 请求头

`header!` 保持书写顺序。`merge_headers` 在会话已有的请求头上追加，`with_header` 是整个替换。

```rust,no_run
# use reqo::*;
# let mut s = Session::new();
s.merge_headers(header! { "x-trace": 42, "cookie": "a=1; b=2" });
s.insert_header("x-late", "late");
```

## HTTP/2 设置

连接前言之后发送的帧：

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

默认的 `rustls` feature 下：

```rust,no_run
use reqo::*;

let id = ClientIdentity::from_pem_files("client.pem", "client.key")?;
let s = Session::new()
    .with_version(TlsVersion::Tls13)  // 最高版本
    .with_mtls(id, None)
    .with_key_log("keys.log");
# Ok::<(), Box<dyn std::error::Error>>(())
```

- 信任的根证书：`webpki-roots`，加上 `SSL_CERT_FILE` 里的证书，再加上 `RustlsConnector::with_extra_roots_pem` 添加的。
- `with_verify(false)` 关闭证书校验。

要换别的 TLS 库，实现 `reqo::tls::TlsConnector`，并且不编译 rustls：

```toml
reqo = { version = "0.5", default-features = false, features = ["zstd"] }
```

```rust,ignore
use reqo::tls::{SyncIo, TlsConnector, TlsIo, TlsOptions};
use reqo::HlsResult;

struct MyTls;

impl TlsConnector for MyTls {
    fn connect(&self, io: Box<dyn SyncIo>, opts: &TlsOptions<'_>) -> HlsResult<Box<dyn TlsIo>> {
        // 在 io 上和 opts.server_name 握手，ALPN 用 opts.alpn
        todo!()
    }
    // 开了 aync 还要实现 connect_async
}

let s = Session::new().with_tls_connector(std::sync::Arc::new(MyTls));
```

`io` 是 TCP 连接，设置了代理的话已经走完代理握手。

## 代理、WebSocket

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

| Feature  | 默认 | |
|----------|:----:|---|
| `rustls` | 是   | 用 rustls（ring、webpki-roots）做 TLS |
| `zstd`   | 是   | zstd 解码，用 `cc` 编译 libzstd |
| `aync`   |      | `reqo::aio`，基于 tokio |
| `serde`  |      | `Response::json`、`Body::json` |
| `log`    |      | 通过 `log` 输出日志 |

gzip、deflate、brotli 解码始终可用。暂不支持 HTTP/3。

## License

Apache-2.0。fork 自 [reqrio](https://github.com/xllgl2017/reqrio) 0.4.2。
