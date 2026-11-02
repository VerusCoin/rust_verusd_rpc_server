//! Bounded daemon transport. Call its synchronous JSON-RPC client from a
//! blocking worker; each client shares one envelope deadline and byte budget.

use base64::{engine::general_purpose::STANDARD, Engine};
use hyper::{
    body::HttpBody,
    client::HttpConnector,
    header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Body, Client, Request, StatusCode, Uri,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{
    fmt,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

pub const MAX_BACKEND_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_HTTP_BUFFER_BYTES: usize = 32 * 1024;

#[derive(Debug)]
pub enum BackendError {
    InvalidUrl,
    InvalidCredentials,
    DeadlineExceeded,
    ResponseTooLarge,
    HeadersTooLarge,
    HttpStatus(StatusCode),
    Http(hyper::Error),
    Json(serde_json::Error),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl => {
                f.write_str("daemon URL must be an HTTP URL without embedded credentials")
            }
            Self::InvalidCredentials => f.write_str("invalid daemon credentials"),
            Self::DeadlineExceeded => f.write_str("daemon request deadline exceeded"),
            Self::ResponseTooLarge => f.write_str("daemon response byte budget exceeded"),
            Self::HeadersTooLarge => f.write_str("daemon response headers exceeded the byte limit"),
            Self::HttpStatus(status) => write!(f, "daemon returned HTTP {status}"),
            Self::Http(error) => write!(f, "daemon HTTP transport failed: {error}"),
            Self::Json(error) => write!(f, "invalid daemon JSON response: {error}"),
        }
    }
}

impl std::error::Error for BackendError {}

#[derive(Clone)]
pub struct Backend {
    http: Client<HttpConnector>,
    uri: Uri,
    authorization: HeaderValue,
}

impl Backend {
    pub fn new(url: &str, user: &str, password: &str) -> Result<Self, BackendError> {
        let url = if url.contains("://") {
            url.to_owned()
        } else {
            format!("http://{url}")
        };
        let uri: Uri = url.parse().map_err(|_| BackendError::InvalidUrl)?;
        if uri.scheme_str() != Some("http")
            || uri.host().is_none()
            || uri
                .authority()
                .is_some_and(|authority| authority.as_str().contains('@'))
        {
            return Err(BackendError::InvalidUrl);
        }
        let mut authorization = HeaderValue::from_str(&format!(
            "Basic {}",
            STANDARD.encode(format!("{user}:{password}"))
        ))
        .map_err(|_| BackendError::InvalidCredentials)?;
        authorization.set_sensitive(true);
        let http = Client::builder()
            .http1_max_buf_size(MAX_HTTP_BUFFER_BYTES)
            .pool_max_idle_per_host(4)
            .retry_canceled_requests(false)
            .build_http();
        Ok(Self {
            http,
            uri,
            authorization,
        })
    }

    pub fn client(&self, deadline: Instant) -> jsonrpc::Client {
        self.client_with_budget(deadline, MAX_BACKEND_RESPONSE_BYTES)
    }

    fn client_with_budget(&self, deadline: Instant, budget: usize) -> jsonrpc::Client {
        jsonrpc::Client::with_transport(EnvelopeTransport {
            backend: self.clone(),
            deadline,
            remaining_bytes: AtomicUsize::new(budget),
        })
    }
}

struct EnvelopeTransport {
    backend: Backend,
    deadline: Instant,
    remaining_bytes: AtomicUsize,
}

// Option<RawValue> alone treats an explicit JSON null as absent. Preserve
// presence so malformed replies cannot acknowledge a mutation as null success.
#[derive(Default)]
struct ResultField(Option<Box<RawValue>>);

impl<'de> Deserialize<'de> for ResultField {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Box::<RawValue>::deserialize(deserializer).map(|value| Self(Some(value)))
    }
}

struct ValidatedResponse(jsonrpc::Response);

impl<'de> Deserialize<'de> for ValidatedResponse {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct WireResponse {
            #[serde(default)]
            result: ResultField,
            error: Option<jsonrpc::error::RpcError>,
            id: serde_json::Value,
            jsonrpc: Option<String>,
        }

        let response = WireResponse::deserialize(deserializer)?;
        if response.result.0.is_none() && response.error.is_none() {
            return Err(serde::de::Error::custom(
                "RPC reply has neither result nor error",
            ));
        }
        if response.error.is_some()
            && response
                .result
                .0
                .as_ref()
                .is_some_and(|result| result.get().trim() != "null")
        {
            return Err(serde::de::Error::custom(
                "RPC reply has both a result and an error",
            ));
        }
        Ok(Self(jsonrpc::Response {
            result: response.result.0,
            error: response.error,
            id: response.id,
            jsonrpc: response.jsonrpc,
        }))
    }
}

impl EnvelopeTransport {
    fn send<T: Serialize, R: DeserializeOwned>(&self, value: T) -> Result<R, jsonrpc::Error> {
        let result = (|| {
            if Instant::now() >= self.deadline {
                return Err(BackendError::DeadlineExceeded);
            }
            if self.remaining_bytes.load(Ordering::Relaxed) == 0 {
                return Err(BackendError::ResponseTooLarge);
            }
            let bytes = serde_json::to_vec(&value).map_err(BackendError::Json)?;
            let mut request = Request::new(Body::from(bytes));
            *request.method_mut() = hyper::Method::POST;
            *request.uri_mut() = self.backend.uri.clone();
            request
                .headers_mut()
                .insert(AUTHORIZATION, self.backend.authorization.clone());
            request
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

            // A timeout stops this HTTP operation, not work already accepted by
            // the daemon. The caller must never automatically retry mutations.
            let bytes = tokio::runtime::Handle::current().block_on(async {
                tokio::time::timeout_at(tokio::time::Instant::from_std(self.deadline), async {
                    // Do not dispatch if serialization or the worker queue used
                    // the remaining time; timeout alone may poll once when due.
                    if Instant::now() >= self.deadline {
                        return Err(BackendError::DeadlineExceeded);
                    }
                    let response = self
                        .backend
                        .http
                        .request(request)
                        .await
                        .map_err(BackendError::Http)?;
                    // Hyper bounds parser buffering, but a complete final read
                    // may exceed its growth threshold. Enforce the header
                    // content limit as well, without implementing HTTP parsing.
                    let header_bytes: usize = response
                        .headers()
                        .iter()
                        .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
                        .sum();
                    if header_bytes > MAX_HTTP_BUFFER_BYTES {
                        return Err(BackendError::HeadersTooLarge);
                    }
                    let status = response.status();
                    if status.is_redirection() {
                        return Err(BackendError::HttpStatus(status));
                    }
                    let mut body = response.into_body();
                    let mut bytes = Vec::new();
                    while let Some(chunk) = body.data().await {
                        if Instant::now() >= self.deadline {
                            return Err(BackendError::DeadlineExceeded);
                        }
                        let chunk = chunk.map_err(BackendError::Http)?;
                        if self
                            .remaining_bytes
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                                remaining.checked_sub(chunk.len())
                            })
                            .is_err()
                        {
                            self.remaining_bytes.store(0, Ordering::Relaxed);
                            return Err(BackendError::ResponseTooLarge);
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    Ok((status, bytes))
                })
                .await
                .map_err(|_| BackendError::DeadlineExceeded)?
            })?;
            if Instant::now() >= self.deadline {
                return Err(BackendError::DeadlineExceeded);
            }
            let (status, bytes) = bytes;
            // Verus uses HTTP error statuses for valid JSON-RPC errors. Keep
            // those per-call errors; never follow an HTTP redirect.
            let response = serde_json::from_slice(&bytes).map_err(|error| {
                if status.is_success() {
                    BackendError::Json(error)
                } else {
                    BackendError::HttpStatus(status)
                }
            })?;
            if Instant::now() >= self.deadline {
                return Err(BackendError::DeadlineExceeded);
            }
            Ok(response)
        })();
        result.map_err(|error| jsonrpc::Error::Transport(Box::new(error)))
    }
}

impl jsonrpc::Transport for EnvelopeTransport {
    fn send_request(
        &self,
        request: jsonrpc::Request<'_>,
    ) -> Result<jsonrpc::Response, jsonrpc::Error> {
        let id = request.id.clone();
        let response = self.send::<_, ValidatedResponse>(request)?.0;
        if response.id != id {
            return Err(jsonrpc::Error::NonceMismatch);
        }
        check_version(&response)?;
        Ok(response)
    }

    fn send_batch(
        &self,
        requests: &[jsonrpc::Request<'_>],
    ) -> Result<Vec<jsonrpc::Response>, jsonrpc::Error> {
        let responses: Vec<ValidatedResponse> = self.send(requests)?;
        for response in &responses {
            check_version(&response.0)?;
        }
        Ok(responses.into_iter().map(|response| response.0).collect())
    }

    fn fmt_target(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.backend.uri)
    }
}

fn check_version(response: &jsonrpc::Response) -> Result<(), jsonrpc::Error> {
    if response
        .jsonrpc
        .as_deref()
        .is_some_and(|version| version != "2.0")
    {
        Err(jsonrpc::Error::VersionMismatch)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{server::conn::Http, service::service_fn, Response};
    use serde_json::{json, Value};
    use std::{convert::Infallible, future::Future, sync::Arc, time::Duration};
    use tokio::{net::TcpListener, task::JoinHandle};

    async fn server<F, Fut>(handler: F) -> (String, JoinHandle<()>)
    where
        F: Fn(Request<Body>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Response<Body>, Infallible>> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handler = Arc::new(handler);
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let _ = Http::new()
                        .serve_connection(stream, service_fn(move |req| handler(req)))
                        .await;
                });
            }
        });
        (url, task)
    }

    fn error_kind(error: &jsonrpc::Error) -> &BackendError {
        match error {
            jsonrpc::Error::Transport(error) => error.downcast_ref().unwrap(),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[tokio::test]
    async fn aggregate_limit_counts_prior_lookup_replies_and_stops_further_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let (url, task) = server(move |request| {
            let counted = counted.clone();
            async move {
                counted.fetch_add(1, Ordering::Relaxed);
                assert_eq!(request.headers()[AUTHORIZATION], "Basic dTpw");
                let request: Value =
                    serde_json::from_slice(&hyper::body::to_bytes(request).await.unwrap()).unwrap();
                // Channel bodies have no known length: enforcement must count
                // received chunks rather than rely on Content-Length.
                let (mut sender, body) = Body::channel();
                let reply =
                    json!({"id": request["id"], "result":"value", "error":null}).to_string();
                tokio::spawn(async move {
                    for part in reply.as_bytes().chunks(8) {
                        if sender.send_data(part.to_vec().into()).await.is_err() {
                            break;
                        }
                    }
                });
                Ok(Response::new(body))
            }
        })
        .await;
        let backend = Backend::new(&url, "u", "p").unwrap();
        let reply_size = json!({"id":1,"result":"value","error":null})
            .to_string()
            .len();
        tokio::task::spawn_blocking(move || {
            let client = backend
                .client_with_budget(Instant::now() + Duration::from_secs(2), reply_size * 2 - 1);
            let first: Value = client.call("getvdxfid", &[]).unwrap();
            assert_eq!(first, "value");
            let second = client.call::<Value>("getinfo", &[]).unwrap_err();
            assert!(matches!(
                error_kind(&second),
                BackendError::ResponseTooLarge
            ));
            let third = client.call::<Value>("getinfo", &[]).unwrap_err();
            assert!(matches!(error_kind(&third), BackendError::ResponseTooLarge));
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        task.abort();
    }

    #[tokio::test]
    async fn trickled_response_cannot_extend_absolute_deadline() {
        let (url, task) = server(|_| async {
            let (mut sender, body) = Body::channel();
            tokio::spawn(async move {
                loop {
                    if sender.send_data(" ".into()).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            });
            Ok(Response::new(body))
        })
        .await;
        let backend = Backend::new(&url, "u", "p").unwrap();
        tokio::task::spawn_blocking(move || {
            let started = Instant::now();
            let client = backend.client(started + Duration::from_millis(100));
            let error = client.call::<Value>("getinfo", &[]).unwrap_err();
            assert!(matches!(error_kind(&error), BackendError::DeadlineExceeded));
            assert!(started.elapsed() < Duration::from_secs(2));
        })
        .await
        .unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn http_rpc_errors_are_preserved_and_redirects_are_not_followed() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let (url, task) = server(move |request| {
            let counted = counted.clone();
            async move {
                counted.fetch_add(1, Ordering::Relaxed);
                let request: Value = serde_json::from_slice(&hyper::body::to_bytes(request).await.unwrap()).unwrap();
                if request["method"] == "redirect" {
                    Ok(Response::builder().status(StatusCode::FOUND).header("location", "/followed").body(Body::empty()).unwrap())
                } else {
                    Ok(Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from(json!({"id":request["id"],"result":null,"error":{"code":-8,"message":"mock error"}}).to_string())).unwrap())
                }
            }
        }).await;
        let backend = Backend::new(&url, "u", "p").unwrap();
        tokio::task::spawn_blocking(move || {
            let client = backend.client(Instant::now() + Duration::from_secs(2));
            assert!(matches!(client.call::<Value>("getinfo", &[]), Err(jsonrpc::Error::Rpc(error)) if error.code == -8));
            let error = client.call::<Value>("redirect", &[]).unwrap_err();
            assert!(matches!(error_kind(&error), BackendError::HttpStatus(StatusCode::FOUND)));
        }).await.unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        task.abort();
    }

    #[tokio::test]
    async fn malformed_rpc_envelopes_fail_while_null_results_and_legacy_errors_work() {
        fn reply(request: &Value) -> Value {
            match request["method"].as_str().unwrap() {
                "missing" => json!({"id":request["id"]}),
                "contradictory" => {
                    json!({"id":request["id"],"result":true,"error":{"code":-8,"message":"error"}})
                }
                "null" => json!({"id":request["id"],"result":null,"error":null}),
                "error" => {
                    json!({"id":request["id"],"result":null,"error":{"code":-8,"message":"error"}})
                }
                _ => unreachable!(),
            }
        }
        let (url, task) = server(|request| async {
            let request: Value =
                serde_json::from_slice(&hyper::body::to_bytes(request).await.unwrap()).unwrap();
            let response = match request.as_array() {
                Some(requests) => Value::Array(requests.iter().map(reply).collect()),
                None => reply(&request),
            };
            Ok(Response::new(Body::from(response.to_string())))
        })
        .await;
        let backend = Backend::new(&url, "u", "p").unwrap();
        tokio::task::spawn_blocking(move || {
            let client = backend.client(Instant::now() + Duration::from_secs(2));
            for method in ["missing", "contradictory"] {
                let error = client.call::<Value>(method, &[]).unwrap_err();
                assert!(matches!(error_kind(&error), BackendError::Json(_)));
                let requests = [
                    client.build_request("null", &[]),
                    client.build_request(method, &[]),
                ];
                let error = client.send_batch(&requests).unwrap_err();
                assert!(matches!(error_kind(&error), BackendError::Json(_)));
            }
            assert_eq!(client.call::<Value>("null", &[]).unwrap(), Value::Null);
            assert!(matches!(client.call::<Value>("error", &[]), Err(jsonrpc::Error::Rpc(error)) if error.code == -8));
            let requests = [
                client.build_request("null", &[]),
                client.build_request("error", &[]),
            ];
            let responses = client.send_batch(&requests).unwrap();
            assert_eq!(responses[0].as_ref().unwrap().result::<Value>().unwrap(), Value::Null);
            assert!(matches!(responses[1].as_ref().unwrap().result::<Value>(), Err(jsonrpc::Error::Rpc(error)) if error.code == -8));
        })
        .await
        .unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn batches_are_sent_once_and_responses_match_request_order() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let (url, task) = server(move |request| {
            let counted = counted.clone();
            async move {
                counted.fetch_add(1, Ordering::Relaxed);
                let request: Value = serde_json::from_slice(&hyper::body::to_bytes(request).await.unwrap()).unwrap();
                let requests = request.as_array().unwrap();
                assert_eq!(requests[0]["method"], "first");
                assert_eq!(requests[1]["method"], "second");
                let replies: Vec<_> = requests.iter().rev().map(|request| json!({"id":request["id"],"result":request["method"],"error":null})).collect();
                Ok(Response::new(Body::from(serde_json::to_vec(&replies).unwrap())))
            }
        }).await;
        let backend = Backend::new(&url, "u", "p").unwrap();
        tokio::task::spawn_blocking(move || {
            let client = backend.client(Instant::now() + Duration::from_secs(2));
            let requests = [
                client.build_request("first", &[]),
                client.build_request("second", &[]),
            ];
            let responses = client.send_batch(&requests).unwrap();
            assert_eq!(
                responses[0].as_ref().unwrap().result::<String>().unwrap(),
                "first"
            );
            assert_eq!(
                responses[1].as_ref().unwrap().result::<String>().unwrap(),
                "second"
            );
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        task.abort();
    }

    #[tokio::test]
    async fn interrupted_response_is_not_retried() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let (url, task) = server(move |request| {
            let counted = counted.clone();
            async move {
                let _ = hyper::body::to_bytes(request).await.unwrap();
                counted.fetch_add(1, Ordering::Relaxed);
                let (sender, body) = Body::channel();
                sender.abort();
                Ok(Response::new(body))
            }
        })
        .await;
        let backend = Backend::new(&url, "u", "p").unwrap();
        tokio::task::spawn_blocking(move || {
            let client = backend.client(Instant::now() + Duration::from_secs(2));
            let error = client.call::<Value>("mutation", &[]).unwrap_err();
            assert!(matches!(error_kind(&error), BackendError::Http(_)));
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        task.abort();
    }

    #[tokio::test]
    async fn oversized_response_headers_are_rejected() {
        let (url, task) = server(|_| async {
            Ok(Response::builder()
                .header("x-large", "x".repeat(MAX_HTTP_BUFFER_BYTES + 1024))
                .body(Body::empty())
                .unwrap())
        })
        .await;
        let backend = Backend::new(&url, "u", "p").unwrap();
        tokio::task::spawn_blocking(move || {
            let client = backend.client(Instant::now() + Duration::from_secs(2));
            let error = client.call::<Value>("getinfo", &[]).unwrap_err();
            assert!(matches!(
                error_kind(&error),
                BackendError::Http(_) | BackendError::HeadersTooLarge
            ));
        })
        .await
        .unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn an_expired_envelope_never_contacts_the_daemon() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let (url, task) = server(move |_| {
            counted.fetch_add(1, Ordering::Relaxed);
            async { Ok(Response::new(Body::empty())) }
        })
        .await;
        let backend = Backend::new(&url, "u", "p").unwrap();
        tokio::task::spawn_blocking(move || {
            let client = backend.client(Instant::now() - Duration::from_millis(1));
            let error = client.call::<Value>("getinfo", &[]).unwrap_err();
            assert!(matches!(error_kind(&error), BackendError::DeadlineExceeded));
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        task.abort();
    }

    #[test]
    fn unsupported_and_credential_bearing_urls_are_rejected() {
        for url in [
            "https://localhost:8232",
            "http://u:p@localhost:8232",
            "http:///",
            "",
        ] {
            assert!(matches!(
                Backend::new(url, "u", "p"),
                Err(BackendError::InvalidUrl)
            ));
        }
    }
}
