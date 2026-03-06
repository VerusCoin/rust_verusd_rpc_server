use hyper::{Body, Request, Response};
use serde_json::{Value, json};
use jsonrpc::{Client, error::RpcError};
use jsonrpc::simple_http::{self, SimpleHttpTransport};
use serde_json::value::RawValue;
use std::sync::{Arc, Mutex};
use tokio::time::{timeout, Duration};

pub mod allowlist;
pub mod auth;
use auth::AuthState;

const READ_TIMEOUT_SECS: Duration = Duration::from_secs(5);
// 1 MiB — sufficient for any JSON-RPC payload on this API surface.
// Enforced on actual accumulated bytes, not the Content-Length header.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

pub struct VerusRPC {
    client: Arc<Mutex<Client>>,
}

impl VerusRPC {
    pub fn new(url: &str, user: &str, pass: &str) -> Result<VerusRPC, simple_http::Error> {
        let transport = SimpleHttpTransport::builder()
            .url(url)?
            .auth(user, Some(pass))
            .build();
        Ok(VerusRPC { client: Arc::new(Mutex::new(Client::with_transport(transport))) })
    }

    fn handle(&self, req_body: Value) -> Result<Value, RpcError> {
        let method = match req_body["method"].as_str() {
            Some(method) => method,
            None => return Err(RpcError { code: -32602, message: "Invalid method parameter".into(), data: None }),
        };
        let params: Vec<Box<RawValue>> = match req_body["params"].as_array() {
            Some(params) => {
                params.iter().enumerate().map(|(i, v)| {
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
                }).collect()
            },
            None => return Err(RpcError { code: -32602, message: "Invalid params parameter".into(), data: None }),
        };

        if !allowlist::is_method_allowed(method, &params) {
            return Err(RpcError { code: -32601, message: "Method not found".into(), data: None });
        }

        let client = self.client.lock().unwrap_or_else(|e| e.into_inner());
        let request = client.build_request(method, &params);

        let response = client.send_request(request).map_err(|e| match e {
            jsonrpc::Error::Rpc(rpc_error) => rpc_error,
            _ => RpcError { code: -32603, message: "Internal error".into(), data: None },
        })?;

        let result: Value = response.result().map_err(|e| match e {
            jsonrpc::Error::Rpc(rpc_error) => rpc_error,
            _ => RpcError { code: -32603, message: "Internal error".into(), data: None },
        })?;
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

pub async fn handle_req(req: Request<Body>, rpc: Arc<VerusRPC>, auth: Option<Arc<AuthState>>) -> Result<Response<Body>, hyper::Error> {
    // Split early so headers remain accessible after the body is consumed.
    let (parts, body) = req.into_parts();

    // Handle CORS preflight (OPTIONS) request
    if parts.method == hyper::Method::OPTIONS {
        let mut response = Response::new(Body::empty());
        response.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
        response.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST".parse().unwrap());
        response.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_HEADERS, "Content-Type, Authorization, Accept, X-App-ID, X-Timestamp, X-Auth-Token, X-VRPC-API-Version, X-Salt".parse().unwrap());
        response.headers_mut().insert(hyper::header::ACCESS_CONTROL_MAX_AGE, "3600".parse().unwrap());
        return Ok(response);
    }

    // CRIT-1 fix: size is enforced during accumulation inside read_body_limited,
    // so a missing or lying Content-Length header cannot bypass the limit.
    let whole_body = match timeout(READ_TIMEOUT_SECS, read_body_limited(body, MAX_BODY_BYTES)).await {
        Ok(Ok(b)) => b,
        Ok(Err(ReadBodyError::TooLarge)) => {
            return Ok(Response::builder()
                .status(hyper::StatusCode::PAYLOAD_TOO_LARGE)
                .body(Body::from("Payload too large"))
                .unwrap());
        }
        Ok(Err(ReadBodyError::ReadFailed)) => {
            return Ok(Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Body::from("Failed to read request body"))
                .unwrap());
        }
        Err(_) => {
            return Ok(Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Body::from("Failed to read request body - timeout"))
                .unwrap());
        }
    };

    let str_body = match String::from_utf8(whole_body) {
        Ok(s) => s,
        Err(_e) => {
            return Ok(Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Body::from("Invalid UTF-8 in request body"))
                .unwrap());
        }
    };

    // Auth gate: version check then token check, both before JSON parsing.
    // The full raw body is hashed so any parameter tampering invalidates the token.
    if let Some(auth_state) = &auth {
        let version = parts.headers.get("x-vrpc-api-version")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if version != "2" {
            let mut response = Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Body::from(json!({"error": {"code": -32600, "message": "X-VRPC-API-Version: 2 required"}}).to_string()))
                .unwrap();
            response.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
            return Ok(response);
        }
        let salt = parts.headers.get("x-salt")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if salt.len() != 64 || !salt.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            let mut response = Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Body::from(json!({"error": {"code": -32600, "message": "X-Salt must be exactly 64 lowercase hex characters (32 bytes)"}}).to_string()))
                .unwrap();
            response.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
            return Ok(response);
        }
        let app_id = parts.headers.get("x-app-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let timestamp: i64 = parts.headers.get("x-timestamp")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let token = parts.headers.get("x-auth-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !auth_state.check_token(token, &str_body, timestamp, app_id, version, salt) {
            let mut response = Response::builder()
                .status(hyper::StatusCode::UNAUTHORIZED)
                .body(Body::from(json!({"error": {"code": -32600, "message": "Unauthorized"}}).to_string()))
                .unwrap();
            response.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
            return Ok(response);
        }
    }

    let json_body: Result<Value, _> = serde_json::from_str(&str_body);
    let result = match json_body {
        Ok(req_body) => rpc.handle(req_body),
        Err(_) => Err(RpcError { code: -32700, message: "Parse error".into(), data: None }),
    };

    let mut response = match result {
        Ok(res) => Response::new(Body::from(json!({"result": res}).to_string())),
        Err(err) => Response::new(Body::from(json!({"error": { "code": err.code, "message": err.message }}).to_string())),
    };

    // Add CORS headers
    response.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    response.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_METHODS, "GET, HEAD, PUT, OPTIONS, POST".parse().unwrap());
    response.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_HEADERS, "Content-Type, Authorization, Accept, X-App-ID, X-Timestamp, X-Auth-Token, X-VRPC-API-Version, X-Salt".parse().unwrap());
    response.headers_mut().insert(hyper::header::ACCESS_CONTROL_MAX_AGE, "3600".parse().unwrap());

    // Set the Referrer Policy header
    response.headers_mut().insert(hyper::header::REFERRER_POLICY, "origin-when-cross-origin".parse().unwrap());

    Ok(response)
}

// Load TLS certificate chain and private key from PEM files.
pub fn load_tls_config(cert_path: &str, key_path: &str) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    use std::io::BufReader;
    use std::fs::File;

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
