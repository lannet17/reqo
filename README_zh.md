# reqo

[English](README.md)

**reqo** 是一个轻量的 Rust HTTP 客户端，**TLS 层可插拔**。
它支持 HTTP/1.1 和 HTTP/2，同时提供同步和异步两套会话，请求头严格按照你写的顺序发送，
HTTP/2 的连接参数也可以自定义。默认使用 rustls 处理 TLS，实现一个 trait 就能换成任何其他 TLS 实现。

```toml
[dependencies]
reqo = "0.5"
```

## 特性

- **同步 + 异步**：`reqo::Session`（阻塞）和 `reqo::aio::Session`（基于 tokio，需开启 `aync` feature）API 一致。
- **HTTP/1.1 和 HTTP/2**：通过 ALPN 协商，支持流水线请求（`send` / `recv`）和流式响应。
- **请求头保序**：严格按书写顺序发送；各协议的默认顺序参照真实浏览器。
- **HTTP/2 指纹**：SETTINGS / WINDOW_UPDATE 帧和流优先级都可以配置。
- **可插拔 TLS**：默认 rustls（支持 mTLS、TLS 1.2/1.3、会话恢复、key log），也可以接入自己的 `TlsConnector`。
- **轻量宏**：`body!` 构造 JSON / 表单请求体，`header!` 构造请求头，只依赖标准库类型。
- **自动解码**：自动解压 gzip、deflate、brotli、zstd 响应，包括 chunked 传输。
- **代理**：HTTP CONNECT 和 SOCKS5，支持认证。
- **WebSocket** 客户端（同步 / 异步），支持 permessage-deflate。
- **纯 Rust 核心**：没有 FFI，编译时不需要下载任何东西。

## 快速开始

```rust,no_run
use reqo::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 一次性请求
    let res = reqo::get("https://httpbin.org/get", None)?;
    println!("{} {}", res.status(), res.as_text()?);

    // 可复用的会话：保持连接、cookie 和请求头
    let mut req = Session::new()
        .with_alpn(ALPN::HTTP20)                    // 优先 h2，不支持时回落到 http/1.1
        .with_timeout(Timeout::new_same(5000, 3))   // 超时 5 秒，最多尝试 3 次
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

异步用法相同，换成 `aio::Session` 并加上 `.await`（需开启 `aync` feature）：

```rust,ignore
use reqo::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut req = aio::Session::new().with_alpn(ALPN::HTTP20);
    let res = req.get("https://httpbin.org/get", None).await?;
    println!("{}", res.as_text()?);
    Ok(())
}
```

## 请求体

```rust
use reqo::*;

let name = "reqo";

// 默认是 JSON：支持嵌套对象、数组和 null
let json = body! {
    "name": name,
    page: 2,
    "tags": ["http", "tls"],
    "extra": { "debug": true, "proxy": null },
};

// 同样的字段，以 application/x-www-form-urlencoded 发送
let form = body! { "name": name, "page": 2 }.form();

// 纯文本和原始字节
let text = Body::from("hello");
let bytes = Body::from(vec![1u8, 2, 3]);

// multipart 上传：表单字段 + 文件
let mut file = HttpFile::new_bytes_data([("desc", "avatar")], b"...png bytes...".to_vec());
file.add_form(FileForm::new_bytes(b"second file".to_vec()).with_field_name("file2"));
let multipart = Body::from(file);
```

`body!` 中的值可以是任意标准库类型：数字、`bool`、`&str` / `String`、`Option`、`Vec`、
数组、`HashMap` / `BTreeMap`。自定义类型可以实现 `ToJson`，或在开启 `serde` feature 后使用 `Body::json(&value)`。

## 响应

```rust,ignore
let res = req.get("https://httpbin.org/json", None)?;
res.status();          // HttpStatus
res.header();          // &Header
res.as_text()?;        // &str
res.as_bytes();        // &[u8]

// 开启 `serde` feature 后
let doc: serde_json::Value = res.json()?;
let typed: MyStruct = res.json()?;
```

## 查询参数、流水线、流式响应

```rust,no_run
# use reqo::*;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let mut req = Session::new();
// 查询参数
let url = "https://httpbin.org/get".params([("q", "rust"), ("page", "2")])?;
let res = req.get(url, None)?;

// 流水线：先连续发送多个请求，再依次取回响应
let a = req.send(Method::GET, "https://httpbin.org/uuid", None)?;
let b = req.send(Method::GET, "https://httpbin.org/ip", None)?;
let (ra, rb) = (req.recv(a)?, req.recv(b)?);

// 流式响应：先拿到响应头，再逐块读取响应体
let head = req.send_stream(Method::GET, "https://httpbin.org/stream/20", None)?;
let sid = head.sid;
while let Some(chunk) = req.next_chunk(sid)? {
    println!("{} bytes", chunk.len());
}
# Ok(())
# }
```

## 请求头与 HTTP/2 指纹

请求头严格按插入顺序发送。`header!` 构造一个 `Header`；`merge_headers` 把请求头合并进会话，
不会清掉已有的请求头：

```rust,no_run
# use reqo::*;
# let mut req = Session::new();
req.merge_headers(header! { "x-trace": 42, "cookie": "a=1; b=2" });
req.insert_header("x-late", "late");
```

HTTP/2 连接前言之后发送的帧可以自定义：

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
let req = Session::new().with_fingerprint(Fingerprint::new_h2(h2));
```

## TLS

reqo 自己不做 TLS 握手。它把（可能经过代理的）连接交给一个 `TlsConnector`，拿回加密后的流。

**默认：rustls**（`rustls` feature，默认开启）

```rust,no_run
use reqo::*;

let identity = ClientIdentity::from_pem_files("client.pem", "client.key")?;
let req = Session::new()
    .with_version(TlsVersion::Tls13)            // 最高提供的 TLS 版本
    .with_mtls(identity, None)                  // 客户端证书（mTLS）
    .with_key_log("keys.log");                  // 导出 NSS key log 供 Wireshark 解密（仅限调试）
# Ok::<(), Box<dyn std::error::Error>>(())
```

- 根证书使用 Mozilla 根证书集（`webpki-roots`）。`SSL_CERT_FILE` 指向的 PEM 文件中的证书也会被信任，
  还可以用 `RustlsConnector::with_extra_roots_pem` 追加。
- `with_verify(false)` 会跳过证书校验，只应在测试中使用。
- 会话票据按配置缓存，后续连接会自动恢复会话。

**接入自己的 TLS 实现**：实现 `reqo::tls::TlsConnector`，并关闭默认的 `rustls` feature，避免把 rustls 编译进来：

```toml
reqo = { version = "0.5", default-features = false, features = ["zstd"] }
```

```rust,ignore
use reqo::tls::{SyncIo, TlsConnector, TlsIo, TlsOptions};
use reqo::HlsResult;

struct MyConnector;

impl TlsConnector for MyConnector {
    fn connect(&self, io: Box<dyn SyncIo>, opts: &TlsOptions<'_>) -> HlsResult<Box<dyn TlsIo>> {
        // 在 `io` 上针对 `opts.server_name` 完成握手，提供 `opts.alpn` 中的协议，
        // 然后返回一个能报告协商结果（ALPN）的流。
        todo!()
    }
    // 开启 `aync` feature 时，还需要实现 `connect_async`。
}

let req = Session::new().with_tls_connector(std::sync::Arc::new(MyConnector));
```

`TlsOptions` 会传入服务器名、ALPN 列表、是否校验证书、最高版本、客户端证书、CA 证书和 key log 路径。
后端可以忽略自己不支持的选项，也可以在自己的 connector 类型上提供额外配置（比如 ClientHello 指纹）。

## 代理与 WebSocket

```rust,no_run
# use reqo::*;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let req = Session::new().with_proxy(Proxy::try_from("socks5://user:pass@127.0.0.1:1080")?);
let req = Session::new().with_proxy(Proxy::try_from("http://127.0.0.1:8080")?);

let mut ws = WebSocket::open_sync("wss://echo.websocket.org")?;
ws.send_text("hello").wait()?;
let frame = ws.read_frame().wait()?;
# Ok(())
# }
```

## Feature 列表

| Feature  | 默认 | 说明                                                   |
|----------|:----:|--------------------------------------------------------|
| `rustls` |  是  | 默认 TLS 后端（rustls + ring + webpki-roots）          |
| `zstd`   |  是  | zstd 解码（libzstd 由 `cc` 从源码编译）                |
| `aync`   |      | 基于 tokio 的异步 API（`aio::Session`、异步 WebSocket）       |
| `serde`  |      | `Response::json::<T>()`、`Body::json(&T)`、serde 派生  |
| `log`    |      | 通过 `log` crate 输出内部日志                          |

可插拔 TLS 层暂时还不支持 HTTP/3（QUIC）。

## Crate

| Crate       | 说明                                                         |
|-------------|--------------------------------------------------------------|
| `reqo`      | HTTP 客户端本体                                              |
| `reqo-base` | 缓冲区、URL 类型、ALPN 和内容编解码，供 TLS 后端 crate 共用  |

## 致谢

reqo fork 自 [reqrio](https://github.com/xllgl2017/reqrio) 0.4.2。

## 许可证

Apache-2.0，见 [LICENSE-APACHE](LICENSE-APACHE)。
