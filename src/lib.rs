use hyper::{Body, Request, Response};
use jsonrpc::simple_http::{self, SimpleHttpTransport};
use jsonrpc::{error::RpcError, Client};
use serde_json::value::RawValue;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::time::{timeout, Duration};

pub mod allowlist;
pub mod auth;
pub mod usage_log;
use auth::AuthState;
use usage_log::ApiUsageLog;

const READ_TIMEOUT_SECS: Duration = Duration::from_secs(5);
static NEXT_REQUEST_LOG_ID: AtomicU64 = AtomicU64::new(1);
// 1 MiB — sufficient for any JSON-RPC payload on this API surface.
// Enforced on actual accumulated bytes, not the Content-Length header.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Default)]
pub struct RequestLogConfig {
    pub enabled: bool,
    pub peer_addr: Option<SocketAddr>,
}

impl RequestLogConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            peer_addr: None,
        }
    }

    pub fn enabled_for_peer(peer_addr: SocketAddr) -> Self {
        Self {
            enabled: true,
            peer_addr: Some(peer_addr),
        }
    }
}

struct RequestTrace {
    config: RequestLogConfig,
    id: u64,
    started_at: Instant,
}

impl RequestTrace {
    fn new(config: RequestLogConfig) -> Self {
        let id = if config.enabled {
            NEXT_REQUEST_LOG_ID.fetch_add(1, Ordering::Relaxed)
        } else {
            0
        };

        Self {
            config,
            id,
            started_at: Instant::now(),
        }
    }

    fn enabled(&self) -> bool {
        self.config.enabled
    }

    fn peer_label(&self) -> String {
        self.config
            .peer_addr
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn log(&self, message: impl AsRef<str>) {
        if self.enabled() {
            eprintln!(
                "[request:{} +{}ms] {}",
                self.id,
                self.started_at.elapsed().as_millis(),
                message.as_ref()
            );
        }
    }
}

macro_rules! request_log {
    ($trace:expr, $($arg:tt)*) => {
        if $trace.enabled() {
            $trace.log(format!($($arg)*));
        }
    };
}

pub struct VerusRPC {
    client: Client,
}

impl VerusRPC {
    pub fn new(url: &str, user: &str, pass: &str) -> Result<VerusRPC, simple_http::Error> {
        let transport = SimpleHttpTransport::builder()
            .url(url)?
            .auth(user, Some(pass))
            .build();
        Ok(VerusRPC {
            client: Client::with_transport(transport),
        })
    }

    fn handle(&self, req_body: Value, trace: &RequestTrace) -> Result<Value, RpcError> {
        let method = match req_body["method"].as_str() {
            Some(method) => {
                request_log!(trace, "JSON-RPC method extracted: {method}");
                method
            }
            None => {
                trace.log("JSON-RPC validation failed: missing or non-string method");
                return Err(RpcError {
                    code: -32602,
                    message: "Invalid method parameter".into(),
                    data: None,
                });
            }
        };
        let params: Vec<Box<RawValue>> = match req_body["params"].as_array() {
            Some(params) => {
                request_log!(
                    trace,
                    "JSON-RPC params accepted as array: count={}, params={}",
                    params.len(),
                    Value::Array(params.clone())
                );
                params
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        if method == "getblock" && i == 0 {
                            if let Ok(num) = v.to_string().parse::<i64>() {
                                // Legacy hack because getblock in JS used to allow
                                // strings to be passed in clientside and the former JS rpc server
                                // wouldn't care. This will be deprecated in the future and shouldn't
                                // be relied upon.
                                RawValue::from_string(format!("\"{}\"", num)).unwrap()
                            } else {
                                RawValue::from_string(v.to_string()).unwrap()
                            }
                        } else {
                            RawValue::from_string(v.to_string()).unwrap()
                        }
                    })
                    .collect()
            }
            None => {
                trace.log("JSON-RPC validation failed: missing or non-array params");
                return Err(RpcError {
                    code: -32602,
                    message: "Invalid params parameter".into(),
                    data: None,
                });
            }
        };

        if !allowlist::is_method_allowed(method, &params) {
            request_log!(
                trace,
                "allowlist rejected method={method}, params_count={}",
                params.len()
            );
            return Err(RpcError {
                code: -32601,
                message: "Method not found".into(),
                data: None,
            });
        }
        request_log!(
            trace,
            "allowlist accepted method={method}, params_count={}",
            params.len()
        );

        let request = self.client.build_request(method, &params);

        let send_started_at = Instant::now();
        request_log!(
            trace,
            "sending request to Verus RPC backend: method={method}"
        );
        let response = self.client.send_request(request).map_err(|e| {
            request_log!(
                trace,
                "Verus RPC backend send_request failed after {}ms: {:?}",
                send_started_at.elapsed().as_millis(),
                e
            );
            match e {
                jsonrpc::Error::Rpc(rpc_error) => rpc_error,
                _ => RpcError {
                    code: -32603,
                    message: "Internal error".into(),
                    data: None,
                },
            }
        })?;
        request_log!(
            trace,
            "Verus RPC backend send_request completed after {}ms",
            send_started_at.elapsed().as_millis()
        );

        let result_started_at = Instant::now();
        let result: Value = response.result().map_err(|e| {
            request_log!(
                trace,
                "Verus RPC backend response.result failed after {}ms: {:?}",
                result_started_at.elapsed().as_millis(),
                e
            );
            match e {
                jsonrpc::Error::Rpc(rpc_error) => rpc_error,
                _ => RpcError {
                    code: -32603,
                    message: "Internal error".into(),
                    data: None,
                },
            }
        })?;
        request_log!(
            trace,
            "Verus RPC backend returned result after {}ms: {}",
            result_started_at.elapsed().as_millis(),
            result
        );
        Ok(result)
    }
}

#[derive(Debug)]
pub enum ReadBodyError {
    ReadFailed,
    TooLarge,
}

pub async fn read_body_limited(mut body: Body, limit: usize) -> Result<Vec<u8>, ReadBodyError> {
    use hyper::body::HttpBody;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|_| ReadBodyError::ReadFailed)?;
        if buf.len() + chunk.len() > limit {
            return Err(ReadBodyError::TooLarge);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

pub async fn handle_req(
    req: Request<Body>,
    rpc: Arc<VerusRPC>,
    auth: Option<Arc<AuthState>>,
    usage_log: Option<Arc<ApiUsageLog>>,
) -> Result<Response<Body>, hyper::Error> {
    handle_req_with_logging(req, rpc, auth, usage_log, RequestLogConfig::disabled()).await
}

pub async fn handle_req_with_logging(
    req: Request<Body>,
    rpc: Arc<VerusRPC>,
    auth: Option<Arc<AuthState>>,
    usage_log: Option<Arc<ApiUsageLog>>,
    log_config: RequestLogConfig,
) -> Result<Response<Body>, hyper::Error> {
    let trace = RequestTrace::new(log_config);

    // Split early so headers remain accessible after the body is consumed.
    let (parts, body) = req.into_parts();
    request_log!(
        trace,
        "incoming request: peer={}, method={}, uri={}, version={:?}, headers={}",
        trace.peer_label(),
        parts.method,
        parts.uri,
        parts.version,
        headers_for_log(&parts.headers)
    );

    // Handle CORS preflight (OPTIONS) request
    if parts.method == hyper::Method::OPTIONS {
        trace.log("handling CORS preflight request");
        let mut response = Response::new(Body::empty());
        response.headers_mut().insert(
            hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            "*".parse().unwrap(),
        );
        response.headers_mut().insert(
            hyper::header::ACCESS_CONTROL_ALLOW_METHODS,
            "GET, POST".parse().unwrap(),
        );
        response.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_HEADERS, "Content-Type, Authorization, Accept, X-App-ID, X-Timestamp, X-Auth-Token, X-VRPC-API-Version, X-Salt".parse().unwrap());
        response.headers_mut().insert(
            hyper::header::ACCESS_CONTROL_MAX_AGE,
            "3600".parse().unwrap(),
        );
        return log_and_return_response(&trace, response, "");
    }

    // CRIT-1 fix: size is enforced during accumulation inside read_body_limited,
    // so a missing or lying Content-Length header cannot bypass the limit.
    let whole_body = match timeout(READ_TIMEOUT_SECS, read_body_limited(body, MAX_BODY_BYTES)).await
    {
        Ok(Ok(b)) => {
            request_log!(trace, "request body read completed: bytes={}", b.len());
            b
        }
        Ok(Err(ReadBodyError::TooLarge)) => {
            request_log!(
                trace,
                "request body rejected: exceeded {} byte limit",
                MAX_BODY_BYTES
            );
            let body_text = "Payload too large";
            let response = Response::builder()
                .status(hyper::StatusCode::PAYLOAD_TOO_LARGE)
                .body(Body::from(body_text))
                .unwrap();
            return log_and_return_response(&trace, response, body_text);
        }
        Ok(Err(ReadBodyError::ReadFailed)) => {
            trace.log("request body read failed");
            let body_text = "Failed to read request body";
            let response = Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Body::from(body_text))
                .unwrap();
            return log_and_return_response(&trace, response, body_text);
        }
        Err(_) => {
            request_log!(
                trace,
                "request body read timed out after {}s",
                READ_TIMEOUT_SECS.as_secs()
            );
            let body_text = "Failed to read request body - timeout";
            let response = Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Body::from(body_text))
                .unwrap();
            return log_and_return_response(&trace, response, body_text);
        }
    };

    let str_body = match String::from_utf8(whole_body) {
        Ok(s) => {
            request_log!(
                trace,
                "request body decoded as UTF-8: chars={}, body={}",
                s.chars().count(),
                s
            );
            s
        }
        Err(_e) => {
            trace.log("request body rejected: invalid UTF-8");
            let body_text = "Invalid UTF-8 in request body";
            let response = Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Body::from(body_text))
                .unwrap();
            return log_and_return_response(&trace, response, body_text);
        }
    };

    // Auth gate: version check then token check, both before JSON parsing.
    // The full raw body is hashed so any parameter tampering invalidates the token.
    if let Some(auth_state) = &auth {
        trace.log("API key auth enabled for request");
        let version = parts
            .headers
            .get("x-vrpc-api-version")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        request_log!(trace, "auth header x-vrpc-api-version={version:?}");
        if version != "2" {
            trace.log("auth rejected: X-VRPC-API-Version must be 2");
            let body_text =
                json!({"error": {"code": -32600, "message": "X-VRPC-API-Version: 2 required"}})
                    .to_string();
            let mut response = Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Body::from(body_text.clone()))
                .unwrap();
            response.headers_mut().insert(
                hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                "*".parse().unwrap(),
            );
            return log_and_return_response(&trace, response, &body_text);
        }
        let salt = parts
            .headers
            .get("x-salt")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        request_log!(
            trace,
            "auth header x-salt length={}, value={salt:?}",
            salt.len()
        );
        if salt.len() != 64 || !salt.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            trace.log("auth rejected: X-Salt malformed");
            let body_text = json!({"error": {"code": -32600, "message": "X-Salt must be exactly 64 lowercase hex characters (32 bytes)"}}).to_string();
            let mut response = Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Body::from(body_text.clone()))
                .unwrap();
            response.headers_mut().insert(
                hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                "*".parse().unwrap(),
            );
            return log_and_return_response(&trace, response, &body_text);
        }
        let app_id = parts
            .headers
            .get("x-app-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let timestamp: i64 = parts
            .headers
            .get("x-timestamp")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let token = parts
            .headers
            .get("x-auth-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        request_log!(
            trace,
            "auth headers parsed: app_id={app_id:?}, timestamp_ms={timestamp}, token_chars={}",
            token.len()
        );

        match auth_state.check_token_detailed(token, &str_body, timestamp, app_id, version, salt) {
            Ok(()) => trace.log("auth accepted"),
            Err(reason) => {
                request_log!(trace, "auth rejected: {:?}", reason);
                let body_text =
                    json!({"error": {"code": -32600, "message": "Unauthorized"}}).to_string();
                let mut response = Response::builder()
                    .status(hyper::StatusCode::UNAUTHORIZED)
                    .body(Body::from(body_text.clone()))
                    .unwrap();
                response.headers_mut().insert(
                    hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                    "*".parse().unwrap(),
                );
                return log_and_return_response(&trace, response, &body_text);
            }
        }

        if let Some(usage_log) = &usage_log {
            match usage_log.record_call(app_id) {
                Ok(counts) => request_log!(
                    trace,
                    "API usage recorded for app_id={app_id:?}: last_hour={}, last_24_hours={}, last_7_days={}, last_30_days={}",
                    counts.last_hour,
                    counts.last_24_hours,
                    counts.last_7_days,
                    counts.last_30_days
                ),
                Err(err) => {
                    request_log!(
                        trace,
                        "API usage record failed for app_id={app_id:?}: {err}"
                    );
                    eprintln!("Failed to record API usage for {app_id}: {err}");
                }
            }
        }
    } else {
        trace.log("API key auth disabled for request");
    }

    let json_body: Result<Value, _> = serde_json::from_str(&str_body);
    let result = match json_body {
        Ok(req_body) => {
            request_log!(trace, "JSON parse accepted body: {}", req_body);
            rpc.handle(req_body, &trace)
        }
        Err(err) => {
            request_log!(trace, "JSON parse failed: {err}");
            Err(RpcError {
                code: -32700,
                message: "Parse error".into(),
                data: None,
            })
        }
    };

    let response_body = match result {
        Ok(res) => {
            request_log!(
                trace,
                "request handler succeeded with JSON-RPC result: {res}"
            );
            json!({"result": res}).to_string()
        }
        Err(err) => {
            request_log!(
                trace,
                "request handler returning JSON-RPC error: code={}, message={}",
                err.code,
                err.message
            );
            json!({"error": { "code": err.code, "message": err.message }}).to_string()
        }
    };
    let mut response = Response::new(Body::from(response_body.clone()));

    // Add CORS headers
    response.headers_mut().insert(
        hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        "*".parse().unwrap(),
    );
    response.headers_mut().insert(
        hyper::header::ACCESS_CONTROL_ALLOW_METHODS,
        "GET, HEAD, PUT, OPTIONS, POST".parse().unwrap(),
    );
    response.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_HEADERS, "Content-Type, Authorization, Accept, X-App-ID, X-Timestamp, X-Auth-Token, X-VRPC-API-Version, X-Salt".parse().unwrap());
    response.headers_mut().insert(
        hyper::header::ACCESS_CONTROL_MAX_AGE,
        "3600".parse().unwrap(),
    );

    // Set the Referrer Policy header
    response.headers_mut().insert(
        hyper::header::REFERRER_POLICY,
        "origin-when-cross-origin".parse().unwrap(),
    );

    log_and_return_response(&trace, response, &response_body)
}

fn log_and_return_response(
    trace: &RequestTrace,
    response: Response<Body>,
    body: &str,
) -> Result<Response<Body>, hyper::Error> {
    request_log!(
        trace,
        "returning response: status={}, headers={}, body_bytes={}, body={}",
        response.status(),
        headers_for_log(response.headers()),
        body.as_bytes().len(),
        body
    );
    Ok(response)
}

fn headers_for_log(headers: &hyper::HeaderMap) -> Value {
    let mut map = serde_json::Map::new();
    for (name, value) in headers.iter() {
        let key = name.as_str().to_string();
        let value = header_value_for_log(name.as_str(), value);
        if let Some(existing) = map.get_mut(&key) {
            match existing {
                Value::Array(values) => values.push(value),
                other => {
                    let first = other.take();
                    *other = Value::Array(vec![first, value]);
                }
            }
        } else {
            map.insert(key, value);
        }
    }
    Value::Object(map)
}

fn header_value_for_log(name: &str, value: &hyper::header::HeaderValue) -> Value {
    if is_sensitive_header(name) {
        return Value::String(format!("<redacted bytes={}>", value.as_bytes().len()));
    }

    match value.to_str() {
        Ok(value) => Value::String(value.to_string()),
        Err(_) => Value::String(format!("<non-utf8 bytes={}>", value.as_bytes().len())),
    }
}

fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "proxy-authorization" | "x-auth-token" | "cookie" | "set-cookie"
    )
}

// Load TLS certificate chain and private key from PEM files.
pub fn load_tls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::BufReader;

    let certs: Vec<rustls::Certificate> = {
        let mut reader = BufReader::new(File::open(cert_path)?);
        rustls_pemfile::certs(&mut reader)?
            .into_iter()
            .map(rustls::Certificate)
            .collect()
    };

    let key: rustls::PrivateKey = {
        let mut reader = BufReader::new(File::open(key_path)?);
        // Try PKCS#8 first, then RSA PKCS#1.
        let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?;
        if keys.is_empty() {
            let mut reader = BufReader::new(File::open(key_path)?);
            keys = rustls_pemfile::rsa_private_keys(&mut reader)?;
        }
        if keys.is_empty() {
            return Err("No private key found in key file".into());
        }
        rustls::PrivateKey(keys.remove(0))
    };

    Ok(rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?)
}
