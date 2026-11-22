//! End-to-end: reqo (without rustls) + reqtls as the TLS backend.
#![cfg(feature = "reqo")]

use reqo::{ALPN, Method, ReqExt, ScReq, Timeout};
use reqtls::{ReqtlsConnector, TlsFinger};
use std::sync::Arc;

const JA3: &str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,18-45-5-10-11-16-23-27-0-13-35-65281-43-51-17613,29-23-24,0";
const PATHS: &[&str] = &["/get", "/headers", "/image/png", "/gzip", "/deflate", "/brotli", "/stream/5", "/bytes/2048"];

fn connector(ja3: bool) -> Arc<ReqtlsConnector> {
    let finger = if ja3 { TlsFinger::from_ja3(JA3).unwrap() } else { TlsFinger::Default };
    Arc::new(ReqtlsConnector::new(finger))
}

#[test]
fn sync_pipelined_matrix() {
    for ja3 in [false, true] {
        for alpn in [ALPN::HTTP11, ALPN::HTTP20] {
            let mut req = ScReq::new().with_alpn(alpn.clone()).with_timeout(Timeout::new_same(8000, 1)).with_tls_connector(connector(ja3));
            let sids: Vec<u64> = PATHS.iter().map(|p| req.send(Method::GET, format!("https://httpbin.reqrio.com{p}"), None).unwrap()).collect();
            for (p, sid) in PATHS.iter().zip(sids) {
                let res = req.recv(sid).unwrap_or_else(|e| panic!("{alpn} ja3={ja3} {p}: {e}"));
                assert_eq!(res.status().code(), 200, "{alpn} {p}");
                assert_eq!(res.alpn(), &alpn, "{p}");
                assert!(!res.bytes().is_empty(), "{alpn} {p}");
            }
        }
    }
}

#[cfg(feature = "reqo-async")]
#[test]
fn async_pipelined_matrix() {
    reqo::tokio::runtime::Runtime::new().unwrap().block_on(async {
        for alpn in [ALPN::HTTP11, ALPN::HTTP20] {
            let mut req = reqo::AcReq::new().with_alpn(alpn.clone()).with_timeout(Timeout::new_same(8000, 1)).with_tls_connector(connector(true));
            let mut sids = vec![];
            for p in PATHS { sids.push(req.send(Method::GET, format!("https://httpbin.reqrio.com{p}"), None).await.unwrap()); }
            for (p, sid) in PATHS.iter().zip(sids) {
                let res = req.recv(sid).await.unwrap_or_else(|e| panic!("{alpn} {p}: {e}"));
                assert_eq!(res.status().code(), 200, "{alpn} {p}");
                assert_eq!(res.alpn(), &alpn, "{p}");
            }
        }
    });
}
