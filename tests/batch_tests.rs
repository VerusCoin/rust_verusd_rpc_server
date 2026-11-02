use hyper::{server::conn::Http, service::service_fn, Body, Request, Response, StatusCode};
use rust_verusd_rpc_server::auth::{compute_token, AuthState};
use rust_verusd_rpc_server::{
    handle_localhost_req_with_logging, handle_req, RequestLogConfig, RequestPolicy, VerusRPC,
    MAX_BATCH_REQUESTS,
};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    io,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::Notify, task::JoinHandle};

enum BackendReply {
    Json(Value),
    Raw(&'static str),
    Disconnect,
    Wait(Arc<Notify>, Value),
}

struct Backend {
    url: String,
    requests: Arc<Mutex<Vec<Value>>>,
    listener: JoinHandle<()>,
}

impl Backend {
    fn rpc(&self) -> Arc<VerusRPC> {
        Arc::new(VerusRPC::new(&self.url, "u", "p").unwrap())
    }

    fn requests(&self) -> Vec<Value> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

async fn backend(handler: impl Fn(&Value) -> BackendReply + Send + Sync + 'static) -> Backend {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = listener.local_addr().unwrap().to_string();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let handler = Arc::new(handler);
    let listener = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let captured = captured.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                let _ = Http::new()
                    .serve_connection(
                        socket,
                        service_fn(move |req: Request<Body>| {
                            let captured = captured.clone();
                            let handler = handler.clone();
                            async move {
                                let bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
                                let request: Value = serde_json::from_slice(&bytes).unwrap();
                                captured.lock().unwrap().push(request.clone());
                                let body = match handler(&request) {
                                    BackendReply::Json(value) => value.to_string(),
                                    BackendReply::Raw(text) => text.to_string(),
                                    BackendReply::Disconnect => {
                                        return Err(io::Error::new(
                                            io::ErrorKind::ConnectionAborted,
                                            "response lost after execution",
                                        ));
                                    }
                                    BackendReply::Wait(release, value) => {
                                        release.notified().await;
                                        value.to_string()
                                    }
                                };
                                Ok::<_, io::Error>(
                                    Response::builder()
                                        .header("content-type", "application/json")
                                        .body(Body::from(body))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    Backend {
        url,
        requests,
        listener,
    }
}

fn successful_responses(request: &Value) -> Value {
    Value::Array(
        request
            .as_array()
            .expect("the gateway must send a native batch")
            .iter()
            .map(|item| {
                json!({
                    "id": item["id"],
                    "result": {"method": item["method"], "params": item["params"]},
                    "error": null,
                })
            })
            .collect(),
    )
}

fn request(body: impl Into<String>) -> Request<Body> {
    Request::post("/").body(Body::from(body.into())).unwrap()
}

async fn execute(
    rpc: Arc<VerusRPC>,
    request: Request<Body>,
    auth: Option<Arc<AuthState>>,
) -> (StatusCode, Value) {
    execute_on_listener(rpc, request, auth, false).await
}

async fn execute_on_listener(
    rpc: Arc<VerusRPC>,
    request: Request<Body>,
    auth: Option<Arc<AuthState>>,
    localhost: bool,
) -> (StatusCode, Value) {
    let response = tokio::time::timeout(Duration::from_secs(3), async move {
        if localhost {
            handle_localhost_req_with_logging(
                request,
                rpc,
                auth,
                None,
                RequestLogConfig::disabled(),
            )
            .await
        } else {
            handle_req(request, rpc, auth, None).await
        }
    })
    .await
    .expect("the gateway must finish without blocking the async runtime")
    .unwrap();
    let status = response.status();
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn batch(rpc: Arc<VerusRPC>, body: Value) -> Value {
    let (status, body) = execute(rpc, request(body.to_string()), None).await;
    assert_eq!(status, StatusCode::OK);
    body
}

fn reads(count: usize) -> Value {
    json!(vec![json!({"method": "getinfo", "params": []}); count])
}

#[tokio::test]
async fn disabled_batching_rejects_both_listeners_before_policy_lookup_but_allows_singles() {
    let backend = backend(|request| {
        BackendReply::Json(json!({
            "id": request["id"], "result": "single works", "error": null
        }))
    })
    .await;
    let policy = RequestPolicy::new(
        vec!["getidentity".to_string(), "getinfo".to_string()],
        vec!["iEHpmxiynXmwZKNgMm7BpXWP3EqCJt663q".to_string()],
        Vec::new(),
    )
    .unwrap()
    .with_identity_name_resolution_for_blocklist(true)
    .with_batching_enabled(false);
    let rpc = Arc::new(VerusRPC::new_with_policy(&backend.url, "u", "p", policy).unwrap());
    // This otherwise valid member would require a getvdxfid policy lookup.
    let body = json!([{"method": "getidentity", "params": ["alice@"]}]);
    for localhost in [false, true] {
        let mut req = request(body.to_string());
        if localhost {
            req.headers_mut()
                .insert("origin", "http://localhost:3000".parse().unwrap());
        }
        let (status, response) = execute_on_listener(rpc.clone(), req, None, localhost).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            response,
            json!({"error": {
                "code": -32600, "message": "Batching is disabled"
            }})
        );
        assert!(
            backend.requests().is_empty(),
            "even policy lookups must be skipped"
        );
    }

    for localhost in [false, true] {
        let req = request(json!({"method": "getinfo", "params": []}).to_string());
        let (status, response) = execute_on_listener(rpc.clone(), req, None, localhost).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response, json!({"result": "single works"}));
    }
    let forwarded = backend.requests();
    assert_eq!(forwarded.len(), 2);
    assert!(forwarded
        .iter()
        .all(|item| item.is_object() && item["method"] == "getinfo"));
}

#[tokio::test]
async fn batch_sends_one_ordered_request_and_correlates_reversed_responses() {
    let backend = backend(|request| {
        let mut seen = Vec::new();
        let mut replies = Vec::new();
        for item in request.as_array().unwrap() {
            seen.push(item["params"][0].clone());
            replies.push(json!({"id": item["id"], "result": seen, "error": null}));
        }
        replies.reverse();
        BackendReply::Json(json!(replies))
    })
    .await;
    // Duplicate JSON keys use the existing parser's final value. Caller IDs and
    // extra fields must never become the backend request's identity or method.
    let body = r#"[
        {"method":"stop","method":"getblockhash","params":[],"params":[7],"id":"same","ignored":{"method":"stop"}},
        {"method":"getblockhash","params":[9],"id":"same","jsonrpc":"unexpected"},
        {"method":"getblockhash","params":[11]}
    ]"#;
    let (status, response) = execute(backend.rpc(), request(body), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response,
        json!([{"result": [7]}, {"result": [7, 9]}, {"result": [7, 9, 11]}])
    );

    let requests = backend.requests();
    assert_eq!(requests.len(), 1);
    let forwarded = requests[0].as_array().unwrap();
    let ids: HashSet<_> = forwarded
        .iter()
        .map(|item| item["id"].to_string())
        .collect();
    assert_eq!(
        ids.len(),
        3,
        "backend IDs must be unique even for duplicate caller IDs"
    );
    for (item, height) in forwarded.iter().zip([7, 9, 11]) {
        assert_eq!(item["method"], "getblockhash");
        assert_eq!(item["params"], json!([height]));
        assert_eq!(item["jsonrpc"], "2.0");
        assert!(item["id"].is_number());
        assert_eq!(item.as_object().unwrap().len(), 4);
    }
}

#[tokio::test]
async fn batch_checks_every_item_and_keeps_local_error_positions() {
    const BLOCKED_ADDRESS: &str = "iEHpmxiynXmwZKNgMm7BpXWP3EqCJt663q";
    let blocked_txid = "ab".repeat(32);
    let backend = backend(|request| BackendReply::Json(successful_responses(request))).await;
    let policy = RequestPolicy::new(
        [
            "getinfo",
            "getidentity",
            "getrawtransaction",
            "sendcurrency",
            "updateidentity",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        vec![BLOCKED_ADDRESS.to_string()],
        vec![blocked_txid.clone()],
    )
    .unwrap();
    let rpc = Arc::new(VerusRPC::new_with_policy(&backend.url, "u", "p", policy).unwrap());
    let template_params = json!([
        "*", [{"currency": "VRSC", "amount": 1, "address": "Rdestination"}],
        1, 0.0001, true
    ]);
    let mut submission_params = template_params.clone();
    submission_params[4] = json!(false);
    let response = batch(
        rpc,
        json!([
            {"method": "getinfo", "params": []},
            17,
            [{"method": "getinfo", "params": []}],
            {"params": []},
            {"method": "getinfo"},
            {"method": "stop", "params": []},
            {"method": "getblockcount", "params": []},
            {"method": "getidentity", "params": [BLOCKED_ADDRESS]},
            {"method": "getrawtransaction", "params": [blocked_txid]},
            {"method": "sendcurrency", "params": submission_params},
            {"method": "sendcurrency", "params": template_params},
            {"method": "updateidentity", "params": [{"name": "alice"}, false]}
        ]),
    )
    .await;
    assert_eq!(response.as_array().unwrap().len(), 12);
    assert_eq!(response[0]["result"]["method"], "getinfo");
    assert_eq!(response[10]["result"]["method"], "sendcurrency");
    for (index, code) in [
        (1, -32600),
        (2, -32600),
        (3, -32602),
        (4, -32602),
        (5, -32601),
        (6, -32601),
        (7, -32602),
        (8, -32602),
        (9, -32601),
        (11, -32601),
    ] {
        assert_eq!(response[index]["error"]["code"], code, "slot {index}");
    }
    let requests = backend.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].as_array().unwrap().len(), 2);
    assert_eq!(requests[0][0]["method"], "getinfo");
    assert_eq!(requests[0][1]["method"], "sendcurrency");
    assert_eq!(requests[0][1]["params"], template_params);
}

#[tokio::test]
async fn batch_rejects_empty_oversized_and_all_invalid_without_dispatch() {
    let backend = backend(|request| BackendReply::Json(successful_responses(request))).await;
    let rpc = backend.rpc();
    for body in [json!([]), reads(MAX_BATCH_REQUESTS + 1)] {
        let response = batch(rpc.clone(), body).await;
        assert!(response.is_object());
        assert_eq!(response["error"]["code"], -32600);
    }
    let response = batch(
        rpc.clone(),
        json!([null, [], {"method": "stop", "params": []}]),
    )
    .await;
    assert_eq!(response[0]["error"]["code"], -32600);
    assert_eq!(response[1]["error"]["code"], -32600);
    assert_eq!(response[2]["error"]["code"], -32601);
    assert!(backend.requests().is_empty());

    // Both boundaries are actual batches, including a single accepted member.
    for count in [1, MAX_BATCH_REQUESTS] {
        let response = batch(rpc.clone(), reads(count)).await;
        assert_eq!(response.as_array().unwrap().len(), count);
    }
    let requests = backend.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].as_array().unwrap().len(), 1);
    assert_eq!(requests[1].as_array().unwrap().len(), MAX_BATCH_REQUESTS);
}

#[tokio::test]
async fn batch_preserves_backend_errors_and_missing_response_slots() {
    let backend = backend(|request| {
        BackendReply::Json(json!([
            {"id": request[3]["id"], "result": "last", "error": null},
            {"id": request[1]["id"], "result": null,
             "error": {"code": -8, "message": "backend rejected item", "data": {"item": 1}}},
            {"id": request[0]["id"], "result": "first", "error": null}
        ]))
    })
    .await;
    let response = batch(backend.rpc(), reads(4)).await;
    assert_eq!(response[0], json!({"result": "first"}));
    assert_eq!(
        response[1],
        json!({"error": {
            "code": -8, "message": "backend rejected item"
        }})
    );
    assert_eq!(response[2]["error"]["code"], -32603);
    assert_eq!(response[3], json!({"result": "last"}));
    assert_eq!(backend.requests().len(), 1);
}

#[tokio::test]
async fn batch_rejects_corrupt_backend_responses_without_retry() {
    for corruption in ["duplicate", "unknown", "extra", "malformed", "object"] {
        let backend = backend(move |request| {
            let mut replies = successful_responses(request);
            match corruption {
                "duplicate" => replies[1]["id"] = replies[0]["id"].clone(),
                "unknown" => replies[1]["id"] = json!("never-issued"),
                "extra" => {
                    let extra = replies[0].clone();
                    replies.as_array_mut().unwrap().push(extra);
                }
                "malformed" => return BackendReply::Raw("{invalid json"),
                "object" => return BackendReply::Json(replies[0].clone()),
                _ => unreachable!(),
            }
            BackendReply::Json(replies)
        })
        .await;
        let response = batch(backend.rpc(), reads(2)).await;
        assert_eq!(response.as_array().unwrap().len(), 2, "{corruption}");
        for slot in response.as_array().unwrap() {
            assert_eq!(slot["error"]["code"], -32603, "{corruption}");
        }
        assert_eq!(
            backend.requests().len(),
            1,
            "{corruption} must not trigger retry"
        );
    }
}

#[tokio::test]
async fn lost_batch_response_does_not_retry_or_erase_local_rejections() {
    let backend = backend(|_| BackendReply::Disconnect).await;
    let response = batch(
        backend.rpc(),
        json!([
            {"method": "sendrawtransaction", "params": ["00"]},
            {"method": "stop", "params": []},
            {"method": "getinfo", "params": []}
        ]),
    )
    .await;
    assert_eq!(response[0]["error"]["code"], -32603);
    assert_eq!(response[1]["error"]["code"], -32601);
    assert_eq!(response[2]["error"]["code"], -32603);
    let requests = backend.requests();
    assert_eq!(
        requests.len(),
        1,
        "a lost response must not repeat a possible mutation"
    );
    assert_eq!(requests[0].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn signed_batch_authenticates_the_whole_raw_array_and_rejects_replay() {
    let backend = backend(|request| BackendReply::Json(successful_responses(request))).await;
    let rpc = backend.rpc();
    let auth = Arc::new(AuthState::new(HashMap::from([(
        "app".to_string(),
        "secret".to_string(),
    )])));
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let salt = "a".repeat(64);
    let original = r#"[{"method":"getinfo","params":[]},{"method":"getblockcount","params":[]}]"#;
    let reordered = r#"[{"method":"getblockcount","params":[]},{"method":"getinfo","params":[]}]"#;
    let token = compute_token("secret", original, timestamp, "app", "2", &salt);
    let signed = |body: &str| {
        Request::post("/")
            .header("x-app-id", "app")
            .header("x-timestamp", timestamp.to_string())
            .header("x-vrpc-api-version", "2")
            .header("x-salt", &salt)
            .header("x-auth-token", &token)
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    for tampered in [reordered.to_string(), format!("{original} ")] {
        let (status, _) = execute(rpc.clone(), signed(&tampered), Some(auth.clone())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    assert!(backend.requests().is_empty());
    let (status, response) = execute(rpc.clone(), signed(original), Some(auth.clone())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response.as_array().unwrap().len(), 2);
    let (status, _) = execute(rpc, signed(original), Some(auth)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(backend.requests().len(), 1);
}

#[tokio::test]
async fn pending_batch_does_not_block_the_async_runtime() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let started_in_backend = started.clone();
    let release_in_backend = release.clone();
    let backend = backend(move |request| {
        started_in_backend.notify_one();
        BackendReply::Wait(release_in_backend.clone(), successful_responses(request))
    })
    .await;
    let rpc = backend.rpc();
    let pending = tokio::spawn(async move { batch(rpc, reads(1)).await });
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("the mock daemon must run while the gateway awaits the backend");
    assert!(!pending.is_finished());
    // This timer and the mock daemon share the test's single-threaded runtime.
    tokio::time::sleep(Duration::from_millis(10)).await;
    release.notify_one();
    let response = pending.await.unwrap();
    assert_eq!(response[0]["result"]["method"], "getinfo");
}
