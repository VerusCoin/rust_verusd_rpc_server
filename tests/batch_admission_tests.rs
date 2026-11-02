use hyper::{server::conn::Http, service::service_fn, Body, Request, Response, StatusCode};
use rust_verusd_rpc_server::auth::{compute_token, AuthState};
use rust_verusd_rpc_server::usage_log::ApiUsageLog;
use rust_verusd_rpc_server::{
    handle_localhost_req_with_logging, handle_req, RequestLogConfig, RequestPolicy, VerusRPC,
    MAX_BATCH_REQUESTS,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    future::Future,
    io,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

const BLOCKED_IADDR: &str = "iEHpmxiynXmwZKNgMm7BpXWP3EqCJt663q";
const SAFE_IADDR: &str = "i8byHmWFAeFMajYdgrXiQ9qZ1Y9FqxJUx1";
// Assert the documented production limits through the public handlers.
const GLOBAL_WORK_LIMIT: usize = 16;
const APP_WORK_LIMIT: usize = 8;

struct PendingCall {
    request: Value,
    respond: oneshot::Sender<Value>,
}

impl PendingCall {
    fn succeed(self) {
        self.respond_with(json!(true));
    }

    fn respond_with(self, result: Value) {
        let response =
            |request: &Value| json!({"id": request["id"], "result": result, "error": null});
        let reply = match &self.request {
            Value::Array(requests) => Value::Array(requests.iter().map(response).collect()),
            request => response(request),
        };
        self.respond.send(reply).unwrap();
    }
}

struct Backend {
    url: String,
    pending: mpsc::UnboundedReceiver<PendingCall>,
    listener: JoinHandle<()>,
}

impl Backend {
    fn rpc(&self) -> Arc<VerusRPC> {
        Arc::new(VerusRPC::new(&self.url, "u", "p").unwrap())
    }

    fn rpc_with_identity_policy(&self) -> Arc<VerusRPC> {
        let policy = RequestPolicy::new(Vec::new(), vec![BLOCKED_IADDR.into()], Vec::new())
            .unwrap()
            .with_identity_name_resolution_for_blocklist(true);
        Arc::new(VerusRPC::new_with_policy(&self.url, "u", "p", policy).unwrap())
    }

    async fn next(&mut self) -> PendingCall {
        bounded(self.pending.recv()).await.unwrap()
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

async fn backend() -> Backend {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = listener.local_addr().unwrap().to_string();
    let (send_pending, pending) = mpsc::unbounded_channel();
    let listener = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let send_pending = send_pending.clone();
            tokio::spawn(async move {
                let _ = Http::new()
                    .serve_connection(
                        socket,
                        service_fn(move |request: Request<Body>| {
                            let send_pending = send_pending.clone();
                            async move {
                                let bytes =
                                    hyper::body::to_bytes(request.into_body()).await.unwrap();
                                let request = serde_json::from_slice(&bytes).unwrap();
                                let (respond, response) = oneshot::channel();
                                send_pending
                                    .send(PendingCall { request, respond })
                                    .map_err(|_| io::Error::other("test backend closed"))?;
                                let response = response
                                    .await
                                    .map_err(|_| io::Error::other("test response abandoned"))?;
                                Ok::<_, io::Error>(Response::new(Body::from(response.to_string())))
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    Backend {
        url,
        pending,
        listener,
    }
}

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("event-driven test operation did not complete")
}

fn request(body: impl Into<String>) -> Request<Body> {
    Request::post("/").body(Body::from(body.into())).unwrap()
}

fn read_request() -> Request<Body> {
    request(r#"{"method":"getinfo","params":[]}"#)
}

fn auth() -> Arc<AuthState> {
    Arc::new(AuthState::new(HashMap::from([
        ("a".into(), "secret".into()),
        ("b".into(), "secret".into()),
        ("c".into(), "secret".into()),
    ])))
}

fn signed(body: &str, app: &str) -> Request<Body> {
    static NONCE: AtomicU64 = AtomicU64::new(1);
    let salt = format!("{:064x}", NONCE.fetch_add(1, Ordering::Relaxed));
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let token = compute_token("secret", body, timestamp, app, "2", &salt);
    Request::post("/")
        .header("x-app-id", app)
        .header("x-timestamp", timestamp.to_string())
        .header("x-vrpc-api-version", "2")
        .header("x-salt", salt)
        .header("x-auth-token", token)
        .body(Body::from(body.to_owned()))
        .unwrap()
}

async fn json_response(response: Response<Body>) -> Value {
    let bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn work_limits_are_shared_by_application_and_both_handler_paths() {
    let mut backend = backend().await;
    let rpc = backend.rpc();
    let auth = auth();
    let mut workers = Vec::new();
    let mut pending = Vec::new();

    for _ in 0..APP_WORK_LIMIT {
        workers.push(tokio::spawn(handle_req(
            signed(r#"{"method":"getinfo","params":[]}"#, "a"),
            rpc.clone(),
            Some(auth.clone()),
            None,
        )));
        pending.push(backend.next().await);
    }
    let limited = bounded(handle_localhost_req_with_logging(
        signed(r#"{"method":"getinfo","params":[]}"#, "a"),
        rpc.clone(),
        Some(auth.clone()),
        None,
        RequestLogConfig::disabled(),
    ))
    .await
    .unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

    for _ in 0..(GLOBAL_WORK_LIMIT - APP_WORK_LIMIT) {
        workers.push(tokio::spawn(handle_localhost_req_with_logging(
            signed(r#"{"method":"getinfo","params":[]}"#, "b"),
            rpc.clone(),
            Some(auth.clone()),
            None,
            RequestLogConfig::disabled(),
        )));
        pending.push(backend.next().await);
    }
    let global_limit = bounded(handle_req(
        signed(r#"{"method":"getinfo","params":[]}"#, "c"),
        rpc.clone(),
        Some(auth.clone()),
        None,
    ))
    .await
    .unwrap();
    assert_eq!(global_limit.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(backend.pending.try_recv().is_err());

    for call in pending {
        call.succeed();
    }
    for worker in workers {
        assert_eq!(
            bounded(worker).await.unwrap().unwrap().status(),
            StatusCode::OK
        );
    }
    let resumed = tokio::spawn(handle_req(
        signed(r#"{"method":"getinfo","params":[]}"#, "c"),
        rpc,
        Some(auth),
        None,
    ));
    backend.next().await.succeed();
    assert_eq!(
        bounded(resumed).await.unwrap().unwrap().status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn cancelling_a_client_keeps_its_worker_permit_until_backend_completion() {
    let mut backend = backend().await;
    let rpc = backend.rpc();
    let abandoned = tokio::spawn(handle_req(read_request(), rpc.clone(), None, None));
    let abandoned_call = backend.next().await;
    let mut retained_workers = Vec::new();
    let mut retained_calls = Vec::new();
    for _ in 1..APP_WORK_LIMIT {
        retained_workers.push(tokio::spawn(handle_req(
            read_request(),
            rpc.clone(),
            None,
            None,
        )));
        retained_calls.push(backend.next().await);
    }

    abandoned.abort();
    assert!(bounded(abandoned).await.unwrap_err().is_cancelled());
    let limited = bounded(handle_req(read_request(), rpc.clone(), None, None))
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(backend.pending.try_recv().is_err());

    abandoned_call.succeed();
    // Probe until the detached worker has processed its response and dropped
    // its guard. The daemon-observed replacement is the completion barrier;
    // no sleep or elapsed-time assumption determines the assertion.
    let replacement = tokio::spawn(async move {
        loop {
            let response = handle_req(read_request(), rpc.clone(), None, None)
                .await
                .unwrap();
            if response.status() != StatusCode::TOO_MANY_REQUESTS {
                return response;
            }
            tokio::task::yield_now().await;
        }
    });
    let replacement_call = backend.next().await;
    replacement_call.succeed();
    for call in retained_calls {
        call.succeed();
    }
    assert_eq!(bounded(replacement).await.unwrap().status(), StatusCode::OK);
    for worker in retained_workers {
        assert_eq!(
            bounded(worker).await.unwrap().unwrap().status(),
            StatusCode::OK
        );
    }
}

#[tokio::test]
async fn unread_responses_and_retained_bytes_hold_all_32_body_permits() {
    let backend = backend().await;
    let rpc = backend.rpc();
    let mut responses = Vec::new();
    for _ in 0..32 {
        let response = bounded(handle_req(request("not json"), rpc.clone(), None, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        responses.push(response);
    }
    let exhausted = bounded(handle_req(request("not json"), rpc.clone(), None, None))
        .await
        .unwrap();
    assert_eq!(exhausted.status(), StatusCode::TOO_MANY_REQUESTS);

    let retained_bytes = hyper::body::to_bytes(responses.pop().unwrap().into_body())
        .await
        .unwrap();
    let still_exhausted = bounded(handle_req(request("not json"), rpc.clone(), None, None))
        .await
        .unwrap();
    assert_eq!(still_exhausted.status(), StatusCode::TOO_MANY_REQUESTS);
    drop(retained_bytes);
    let replacement = bounded(handle_req(request("not json"), rpc.clone(), None, None))
        .await
        .unwrap();
    assert_eq!(replacement.status(), StatusCode::OK);
    drop(responses);
    drop(replacement);
    let released = bounded(handle_req(request("not json"), rpc, None, None))
        .await
        .unwrap();
    assert_eq!(released.status(), StatusCode::OK);
}

#[tokio::test]
async fn body_admission_happens_before_reading_and_cancelled_readers_release_it() {
    let backend = backend().await;
    let rpc = backend.rpc();
    let mut senders = Vec::new();
    let mut readers = Vec::new();
    for _ in 0..32 {
        let (mut sender, body) = Body::channel();
        readers.push(tokio::spawn(handle_req(
            Request::post("/").body(body).unwrap(),
            rpc.clone(),
            None,
            None,
        )));
        // The first chunk can fit before the handler is polled; the second
        // waits for that chunk to be consumed and proves admission is held.
        // Keep the channel open afterward so the handler is still awaiting EOF.
        bounded(sender.send_data(" ".into())).await.unwrap();
        bounded(sender.send_data(" ".into())).await.unwrap();
        senders.push(sender);
    }
    let rejected = bounded(handle_req(read_request(), rpc.clone(), None, None))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    for reader in readers {
        reader.abort();
        assert!(bounded(reader).await.unwrap_err().is_cancelled());
    }
    drop(senders);
    let released = bounded(handle_req(request("not json"), rpc, None, None))
        .await
        .unwrap();
    assert_eq!(released.status(), StatusCode::OK);
}

#[tokio::test]
async fn authenticated_mixed_batch_records_one_envelope_and_actual_lookup_counts() {
    let mut backend = backend().await;
    let rpc = backend.rpc_with_identity_policy();
    let auth = auth();
    let directory = tempfile::tempdir().unwrap();
    let log = Arc::new(ApiUsageLog::new(directory.path(), vec!["a".into()]).unwrap());
    let body = json!([
        {"method": "getidentity", "params": ["alice"]},
        {"method": "stop", "params": []},
        {"method": "getinfo", "params": []}
    ])
    .to_string();
    let signed_request = signed(&body, "a");
    let original_headers = signed_request.headers().clone();
    let worker = tokio::spawn(handle_req(
        signed_request,
        rpc.clone(),
        Some(auth.clone()),
        Some(log.clone()),
    ));
    let lookup = backend.next().await;
    assert_eq!(lookup.request["method"], "getvdxfid");
    lookup.respond_with(json!({"vdxfid": SAFE_IADDR}));
    let batch = backend.next().await;
    assert_eq!(batch.request.as_array().unwrap().len(), 2);
    batch.succeed();
    let response = json_response(bounded(worker).await.unwrap().unwrap()).await;
    assert_eq!(response[0]["result"], true);
    assert_eq!(response[1]["error"]["code"], -32601);
    assert_eq!(response[2]["result"], true);

    let mut replay = request(body);
    *replay.headers_mut() = original_headers;
    let replay = bounded(handle_req(replay, rpc, Some(auth), Some(log.clone())))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    log.flush_snapshot().unwrap();
    let snapshot: Value = serde_json::from_slice(&std::fs::read(log.log_path()).unwrap()).unwrap();
    assert_eq!(snapshot["apps"]["a"]["counts"]["last_hour"], 1);
    assert_eq!(
        snapshot["apps"]["a"]["rpc_items"],
        json!({"attempted": 3, "forwarded": 2, "rejected": 1, "policy_lookups": 1})
    );
    assert!(backend.pending.try_recv().is_err());
}

#[tokio::test]
async fn admission_rejection_counts_all_logical_items_without_forwarding_them() {
    let mut backend = backend().await;
    let rpc = backend.rpc();
    let auth = auth();
    let directory = tempfile::tempdir().unwrap();
    let log = Arc::new(ApiUsageLog::new(directory.path(), vec!["a".into()]).unwrap());
    let mut workers = Vec::new();
    let mut pending = Vec::new();
    for _ in 0..APP_WORK_LIMIT {
        workers.push(tokio::spawn(handle_req(
            signed(r#"{"method":"getinfo","params":[]}"#, "a"),
            rpc.clone(),
            Some(auth.clone()),
            Some(log.clone()),
        )));
        pending.push(backend.next().await);
    }
    let body = json!(vec![json!({"method": "getinfo", "params": []}); 3]).to_string();
    let response = bounded(handle_req(
        signed(&body, "a"),
        rpc,
        Some(auth),
        Some(log.clone()),
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(backend.pending.try_recv().is_err());
    for call in pending {
        call.succeed();
    }
    for worker in workers {
        assert_eq!(
            bounded(worker).await.unwrap().unwrap().status(),
            StatusCode::OK
        );
    }
    log.flush_snapshot().unwrap();
    let snapshot: Value = serde_json::from_slice(&std::fs::read(log.log_path()).unwrap()).unwrap();
    assert_eq!(
        snapshot["apps"]["a"]["counts"]["last_hour"],
        APP_WORK_LIMIT + 1
    );
    assert_eq!(
        snapshot["apps"]["a"]["rpc_items"],
        json!({
            "attempted": APP_WORK_LIMIT + 3,
            "forwarded": APP_WORK_LIMIT,
            "rejected": 3,
            "policy_lookups": 0
        })
    );
}

#[tokio::test]
async fn excessive_batch_count_is_rejected_before_any_identity_lookup() {
    let mut backend = backend().await;
    let rpc = backend.rpc_with_identity_policy();
    let body = json!(vec![
        json!({"method": "getidentity", "params": ["alice"]});
        MAX_BATCH_REQUESTS + 1
    ]);
    let response = bounded(handle_req(request(body.to_string()), rpc, None, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_response(response).await["error"]["code"], -32600);
    assert!(backend.pending.try_recv().is_err());
}
