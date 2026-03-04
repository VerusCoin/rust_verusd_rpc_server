use rust_verusd_rpc_server::{VerusRPC, handle_req, read_body_limited, ReadBodyError, load_tls_config, MAX_BODY_BYTES};
use hyper::{Body, Request, StatusCode, server::conn::Http, service::service_fn};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Returns a URL for a port that was just released — nothing is listening on it,
/// so any TCP connect attempt gets ECONNREFUSED immediately.
fn refused_rpc_url() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    format!("127.0.0.1:{}", port)
}

fn dummy_rpc() -> Arc<VerusRPC> {
    Arc::new(VerusRPC::new(&refused_rpc_url(), "u", "p").unwrap())
}

/// Spawn a plain-HTTP test server on an OS-assigned port; returns its address.
async fn spawn_plain_server(rpc: Arc<VerusRPC>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp, _)) => {
                    let rpc = rpc.clone();
                    tokio::spawn(async move {
                        let _ = Http::new()
                            .serve_connection(tcp, service_fn(move |req| handle_req(req, rpc.clone())))
                            .await;
                    });
                }
                Err(_) => break,
            }
        }
    });
    addr
}

async fn post(addr: SocketAddr, body: Body) -> hyper::Response<Body> {
    hyper::Client::new()
        .request(Request::post(format!("http://{}", addr)).body(body).unwrap())
        .await
        .unwrap()
}

async fn post_json(addr: SocketAddr, json: &str) -> hyper::Response<Body> {
    post(addr, Body::from(json.to_string())).await
}

async fn body_string(resp: hyper::Response<Body>) -> String {
    let b = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    String::from_utf8(b.to_vec()).unwrap()
}

#[tokio::test]
async fn body_limit_empty_body_accepted() {
    let result = read_body_limited(Body::empty(), 1024).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn body_limit_under_limit_accepted() {
    let result = read_body_limited(Body::from(vec![0u8; 512]), 1024).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 512);
}

#[tokio::test]
async fn body_limit_exactly_at_limit_accepted() {
    // boundary: buf.len() + chunk.len() == limit is NOT > limit, so it passes
    let result = read_body_limited(Body::from(vec![0u8; 1024]), 1024).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1024);
}

#[tokio::test]
async fn body_limit_single_chunk_over_limit_rejected() {
    let result = read_body_limited(Body::from(vec![0u8; 1025]), 1024).await;
    assert!(matches!(result, Err(ReadBodyError::TooLarge)));
}

#[tokio::test]
async fn body_limit_multi_chunk_accumulation_rejected() {
    // Three 512-byte chunks; limit is 1024. Rejected when the 2nd chunk arrives.
    let (mut sender, body) = Body::channel();
    tokio::spawn(async move {
        for _ in 0..3 {
            if sender.send_data(vec![0u8; 512].into()).await.is_err() {
                break;
            }
        }
    });
    assert!(matches!(read_body_limited(body, 1024).await, Err(ReadBodyError::TooLarge)));
}

#[tokio::test]
async fn http_oversized_body_no_content_length_returns_413() {
    let addr = spawn_plain_server(dummy_rpc()).await;

    // Body::channel() produces chunked transfer encoding with no Content-Length.
    let (mut sender, body) = Body::channel();
    let chunk = vec![b'x'; 1024];
    tokio::spawn(async move {
        for _ in 0..=(MAX_BODY_BYTES / 1024) + 2 {
            if sender.send_data(hyper::body::Bytes::from(chunk.clone())).await.is_err() {
                break;
            }
        }
    });

    let resp = post(addr, body).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// Sanity-check: an oversized body that does set Content-Length is also rejected.
#[tokio::test]
async fn http_oversized_body_with_content_length_returns_413() {
    let addr = spawn_plain_server(dummy_rpc()).await;
    let resp = post(addr, Body::from(vec![b'x'; MAX_BODY_BYTES + 1])).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// Content-Length claims 100 bytes (well under the limit) but the actual body
/// is delivered via Transfer-Encoding: chunked and exceeds MAX_BODY_BYTES.
/// The fix for CRIT-1 accumulates real bytes, so the lie is caught.
#[tokio::test]
async fn http_lying_content_length_oversized_body_rejected() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let addr = spawn_plain_server(dummy_rpc()).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    // Content-Length: 100 (lies — under limit); Transfer-Encoding: chunked wins.
    let header = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n"
    );
    stream.write_all(header.as_bytes()).await.unwrap();

    let chunk = vec![b'x'; 1024];
    for _ in 0..=(MAX_BODY_BYTES / 1024) + 2 {
        let line = format!("{:x}\r\n", chunk.len());
        if stream.write_all(line.as_bytes()).await.is_err() { break; }
        if stream.write_all(&chunk).await.is_err() { break; }
        if stream.write_all(b"\r\n").await.is_err() { break; }
    }
    let _ = stream.write_all(b"0\r\n\r\n").await;

    let mut response = vec![0u8; 4096];
    let n = stream.read(&mut response).await.unwrap_or(0);
    let response_str = String::from_utf8_lossy(&response[..n]);
    // Server must reject the request — 413 if limit enforced, 400 if hyper
    // treats the conflicting headers as a smuggling attempt. Either is correct.
    assert!(
        response_str.contains("413") || response_str.contains("400"),
        "Expected rejection (413 or 400), got: {response_str}"
    );
}

/// A body under the limit sent without Content-Length must be accepted.
#[tokio::test]
async fn http_body_under_limit_no_content_length_accepted() {
    let addr = spawn_plain_server(dummy_rpc()).await;
    let (mut sender, body) = Body::channel();
    tokio::spawn(async move {
        let _ = sender.send_data(b"{\"method\":\"getinfo\",\"params\":[]}".to_vec().into()).await;
    });
    let resp = post(addr, body).await;
    // Reaches the RPC backend (fails — no server), but must NOT be 413 or 400
    assert_ne!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_ne!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── CORS / OPTIONS ────────────────────────────────────────────────────────────

#[tokio::test]
async fn options_returns_200_with_cors_headers() {
    let addr = spawn_plain_server(dummy_rpc()).await;
    let resp = hyper::Client::new()
        .request(Request::options(format!("http://{}", addr)).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["access-control-allow-origin"], "*");
    assert!(resp.headers().contains_key("access-control-allow-methods"));
    assert!(resp.headers().contains_key("access-control-allow-headers"));
    assert!(resp.headers().contains_key("access-control-max-age"));
}

#[tokio::test]
async fn post_response_includes_cors_origin_header() {
    let addr = spawn_plain_server(dummy_rpc()).await;
    let resp = post_json(addr, "{\"method\":\"getinfo\",\"params\":[]}").await;
    assert_eq!(resp.headers()["access-control-allow-origin"], "*");
}

// ── Input validation ──────────────────────────────────────────────────────────

#[tokio::test]
async fn invalid_utf8_body_returns_400() {
    let addr = spawn_plain_server(dummy_rpc()).await;
    let resp = post(addr, Body::from(vec![0xff, 0xfe, 0x00])).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invalid_json_returns_parse_error_code() {
    let addr = spawn_plain_server(dummy_rpc()).await;
    let resp = post_json(addr, "not json at all {{").await;
    assert_eq!(resp.status(), StatusCode::OK); // JSON-RPC errors are 200 per spec
    let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(v["error"]["code"], -32700);
}

#[tokio::test]
async fn missing_method_field_returns_invalid_params() {
    let addr = spawn_plain_server(dummy_rpc()).await;
    let resp = post_json(addr, "{\"params\":[]}").await;
    let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(v["error"]["code"], -32602);
}

#[tokio::test]
async fn missing_params_field_returns_invalid_params() {
    let addr = spawn_plain_server(dummy_rpc()).await;
    let resp = post_json(addr, "{\"method\":\"getinfo\"}").await;
    let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(v["error"]["code"], -32602);
}

// ── Allowlist enforcement (HTTP-level integration) ────────────────────────────

#[tokio::test]
async fn unlisted_method_returns_method_not_found() {
    let addr = spawn_plain_server(dummy_rpc()).await;
    for method in &["getbalance", "listaccounts", "dumpprivkey", "importprivkey", "stop"] {
        let payload = format!("{{\"method\":\"{}\",\"params\":[]}}", method);
        let resp = post_json(addr, &payload).await;
        let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert_eq!(v["error"]["code"], -32601, "method {} should be blocked", method);
    }
}

#[tokio::test]
async fn allowed_method_wrong_param_types_blocked() {
    let addr = spawn_plain_server(dummy_rpc()).await;
    // getinfo takes no params; sending one fails allowlist
    let resp = post_json(addr, "{\"method\":\"getinfo\",\"params\":[\"unexpected\"]}").await;
    let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(v["error"]["code"], -32601);
}

#[tokio::test]
async fn allowed_method_correct_params_reaches_rpc_backend() {
    // getinfo passes the allowlist. The dummy backend is not running, so we get
    // a -32603 internal error — NOT a -32601 method-not-found.
    let addr = spawn_plain_server(dummy_rpc()).await;
    let resp = post_json(addr, "{\"method\":\"getinfo\",\"params\":[]}").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_ne!(v["error"]["code"], -32601, "getinfo should pass the allowlist");
}

#[tokio::test]
async fn sendcurrency_without_simulation_flag_blocked() {
    let addr = spawn_plain_server(dummy_rpc()).await;
    let resp = post_json(addr, r#"{"method":"sendcurrency","params":["*",[],0,0.001,false]}"#).await;
    let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(v["error"]["code"], -32601);
}

#[tokio::test]
async fn sendcurrency_with_simulation_flag_passes_allowlist() {
    let addr = spawn_plain_server(dummy_rpc()).await;
    let resp = post_json(addr, r#"{"method":"sendcurrency","params":["*",[],0,0.001,true]}"#).await;
    let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_ne!(v["error"]["code"], -32601);
}

#[tokio::test]
async fn signdata_with_address_field_blocked() {
    let addr = spawn_plain_server(dummy_rpc()).await;
    let resp = post_json(addr, r#"{"method":"signdata","params":[{"address":"R1","data":"aa"}]}"#).await;
    let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(v["error"]["code"], -32601);
}

#[tokio::test]
async fn signdata_without_address_passes_allowlist() {
    let addr = spawn_plain_server(dummy_rpc()).await;
    let resp = post_json(addr, r#"{"method":"signdata","params":[{"data":"aabbcc"}]}"#).await;
    let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_ne!(v["error"]["code"], -32601);
}

// ── HIGH-4: shared VerusRPC — concurrent-request behavioral test ──────────────

/// 20 concurrent requests must all complete. This would surface mutex poisoning
/// or connection exhaustion if the old per-connection VerusRPC bug were present.
#[tokio::test]
async fn concurrent_requests_all_complete_successfully() {
    let addr = spawn_plain_server(dummy_rpc()).await;
    let handles: Vec<_> = (0..20)
        .map(|_| tokio::spawn(async move {
            post_json(addr, "{\"method\":\"getinfo\",\"params\":[]}").await
        }))
        .collect();

    for h in handles {
        let resp = h.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

// ── MED-5: TLS config loading ─────────────────────────────────────────────────

#[test]
fn tls_config_nonexistent_paths_fail() {
    assert!(load_tls_config("/nonexistent/cert.pem", "/nonexistent/key.pem").is_err());
}

#[test]
fn tls_config_empty_files_fail() {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key  = dir.path().join("key.pem");
    std::fs::write(&cert, "").unwrap();
    std::fs::write(&key,  "").unwrap();
    assert!(load_tls_config(cert.to_str().unwrap(), key.to_str().unwrap()).is_err());
}

#[test]
fn tls_config_valid_self_signed_succeeds() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path  = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.serialize_pem().unwrap()).unwrap();
    std::fs::write(&key_path,  cert.serialize_private_key_pem()).unwrap();

    let result = load_tls_config(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
    assert!(result.is_ok(), "load_tls_config failed: {:?}", result.err());
}

#[test]
fn tls_config_swapped_cert_and_key_fails() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path  = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.serialize_pem().unwrap()).unwrap();
    std::fs::write(&key_path,  cert.serialize_private_key_pem()).unwrap();

    // cert where key expected and vice versa → must fail
    assert!(load_tls_config(key_path.to_str().unwrap(), cert_path.to_str().unwrap()).is_err());
}

/// Full end-to-end: TLS server → rustls client that trusts the self-signed cert →
/// HTTP/1.1 request → valid JSON-RPC response envelope returned over HTTPS.
#[tokio::test]
async fn tls_server_accepts_https_connection_and_returns_rpc_response() {
    // 1. Generate self-signed certificate
    let rcgen_cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rcgen_cert.serialize_der().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path  = dir.path().join("key.pem");
    std::fs::write(&cert_path, rcgen_cert.serialize_pem().unwrap()).unwrap();
    std::fs::write(&key_path,  rcgen_cert.serialize_private_key_pem()).unwrap();

    // 2. Start TLS server
    let tls_config =
        load_tls_config(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let rpc = dummy_rpc();

    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(tls) = acceptor.accept(tcp).await {
                let _ = Http::new()
                    .serve_connection(tls, service_fn(move |req| handle_req(req, rpc.clone())))
                    .await;
            }
        }
    });

    // 3. Build TLS client that trusts the self-signed cert
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(&rustls::Certificate(cert_der)).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    // 4. TCP + TLS handshake
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name = rustls::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();

    // 5. HTTP/1.1 over TLS via hyper's low-level conn API
    let (mut send_req, conn) = hyper::client::conn::handshake(tls_stream).await.unwrap();
    tokio::spawn(conn);

    let request = Request::post("/")
        .header("host", "localhost")
        .body(Body::from("{\"method\":\"getinfo\",\"params\":[]}"))
        .unwrap();
    let response = send_req.send_request(request).await.unwrap();

    // 6. Must be a valid JSON-RPC envelope — transport worked even though the
    //    dummy backend refuses connections.
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v.get("error").is_some() || v.get("result").is_some());
    if let Some(code) = v["error"]["code"].as_i64() {
        assert_ne!(code, -32601, "getinfo should be allowlisted");
    }
}
