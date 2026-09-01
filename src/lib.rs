use hyper::header::{
    HeaderValue, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD,
    ORIGIN, VARY,
};
use hyper::{Body, Method, Request, Response, StatusCode, Uri};
use jsonrpc::simple_http::{self, SimpleHttpTransport};
use jsonrpc::{error::RpcError, Client};
use serde_json::value::RawValue;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::time::{timeout, Duration};

pub mod allowlist;
pub mod auth;
mod identity;
pub mod usage_log;
use auth::AuthState;
use identity::{derive_parented_identity_address, is_canonical_identity_leaf_name};
use usage_log::ApiUsageLog;

const READ_TIMEOUT_SECS: Duration = Duration::from_secs(5);
const MAX_BLOCKLIST_IDENTITY_CACHE_ENTRIES: usize = 4_096;
const JSON_RPC_PATH: &str = "/";
const LOCALHOST_CORS_ALLOW_HEADERS: &str =
    "Content-Type, Accept, X-App-ID, X-Timestamp, X-Auth-Token, X-VRPC-API-Version, X-Salt";
const LOCALHOST_CORS_ALLOWED_HEADER_NAMES: &[&str] = &[
    "content-type",
    "accept",
    "x-app-id",
    "x-timestamp",
    "x-auth-token",
    "x-vrpc-api-version",
    "x-salt",
];
static NEXT_REQUEST_LOG_ID: AtomicU64 = AtomicU64::new(1);
// 1 MiB — sufficient for any JSON-RPC payload on this API surface.
// Enforced on actual accumulated bytes, not the Content-Length header.
pub const MAX_BODY_BYTES: usize = 2048 * 1024;

#[derive(Clone, Debug, Default)]
pub struct RequestPolicy {
    method_whitelist: HashSet<String>,
    address_blocklist: HashSet<String>,
    txid_blocklist: HashSet<String>,
    resolve_identity_names_for_blocklist: bool,
    require_canonical_identity_leaf_names: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestPolicyRejection {
    Blocked,
    InvalidAddress,
    IdentityNameLookupDisabled,
    IdentityResolutionFailed,
    NonCanonicalIdentityName,
}

type BlocklistIdentityCacheEntry = Arc<Mutex<Option<String>>>;

#[derive(Debug, Default)]
struct BlocklistIdentityCacheState {
    entries: HashMap<String, BlocklistIdentityCacheEntry>,
    insertion_order: VecDeque<String>,
}

/// Shared cache for identity selectors resolved solely for blocklist checks.
///
/// Keys are the exact selectors sent to `getvdxfid`, so distinct aliases may
/// intentionally map to the same i-address. Each entry has its own lock so
/// concurrent lookups for one selector are coalesced without serializing
/// lookups for unrelated selectors.
#[derive(Debug, Default)]
pub struct BlocklistIdentityCache {
    state: Mutex<BlocklistIdentityCacheState>,
}

impl BlocklistIdentityCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn resolve<E, F>(&self, selector: &str, resolve: F) -> Result<(String, bool), E>
    where
        F: FnOnce() -> Result<String, E>,
    {
        let entry = self.entry_for(selector);
        let mut cached = entry.lock().unwrap_or_else(|error| error.into_inner());
        let result = if let Some(address) = cached.as_ref() {
            Ok((address.clone(), true))
        } else {
            match resolve() {
                Ok(address) => {
                    *cached = Some(address.clone());
                    Ok((address, false))
                }
                Err(error) => Err(error),
            }
        };
        drop(cached);
        drop(entry);
        self.trim_to_limit();
        result
    }

    fn entry_for(&self, selector: &str) -> BlocklistIdentityCacheEntry {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(entry) = state.entries.get(selector) {
            return entry.clone();
        }

        while state.entries.len() >= MAX_BLOCKLIST_IDENTITY_CACHE_ENTRIES {
            if !state.evict_one_inactive_entry() {
                // Every cached entry is currently in use. Allow a temporary
                // overage so this selector still has single-flight behavior;
                // later insertions will trim inactive entries back to the cap.
                break;
            }
        }

        let entry = Arc::new(Mutex::new(None));
        state.entries.insert(selector.to_owned(), entry.clone());
        state.insertion_order.push_back(selector.to_owned());
        entry
    }

    fn trim_to_limit(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        while state.entries.len() > MAX_BLOCKLIST_IDENTITY_CACHE_ENTRIES
            && state.evict_one_inactive_entry()
        {}
    }
}

impl BlocklistIdentityCacheState {
    fn evict_one_inactive_entry(&mut self) -> bool {
        let candidates = self.insertion_order.len();
        for _ in 0..candidates {
            let Some(selector) = self.insertion_order.pop_front() else {
                return false;
            };
            let is_inactive = self
                .entries
                .get(&selector)
                .is_some_and(|entry| Arc::strong_count(entry) == 1);
            if is_inactive {
                self.entries.remove(&selector);
                return true;
            }
            self.insertion_order.push_back(selector);
        }
        false
    }
}

#[cfg(test)]
mod blocklist_identity_cache_tests {
    use super::BlocklistIdentityCache;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    #[test]
    fn concurrent_requests_for_one_selector_share_one_resolution() {
        let cache = Arc::new(BlocklistIdentityCache::new());
        let start = Arc::new(Barrier::new(3));
        let resolution_started = Arc::new(Barrier::new(2));
        let release_resolution = Arc::new(Barrier::new(2));
        let daemon_calls = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..2)
            .map(|_| {
                let cache = cache.clone();
                let start = start.clone();
                let resolution_started = resolution_started.clone();
                let release_resolution = release_resolution.clone();
                let daemon_calls = daemon_calls.clone();
                std::thread::spawn(move || {
                    start.wait();
                    cache
                        .resolve("alice@", || -> Result<String, ()> {
                            daemon_calls.fetch_add(1, Ordering::SeqCst);
                            resolution_started.wait();
                            release_resolution.wait();
                            Ok("iEHpmxiynXmwZKNgMm7BpXWP3EqCJt663q".to_owned())
                        })
                        .unwrap()
                })
            })
            .collect();

        start.wait();
        resolution_started.wait();
        release_resolution.wait();

        let mut cache_hits = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().1)
            .collect::<Vec<_>>();
        cache_hits.sort_unstable();
        assert_eq!(daemon_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cache_hits, vec![false, true]);
    }
}

impl RequestPolicy {
    pub fn new(
        method_whitelist: Vec<String>,
        address_blocklist: Vec<String>,
        txid_blocklist: Vec<String>,
    ) -> Result<Self, String> {
        let method_whitelist = validated_set("method_whitelist", method_whitelist, |value| {
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_lowercase())
        })?;
        let address_blocklist =
            validated_set("address_blocklist", address_blocklist, is_direct_address)?;
        let txid_blocklist = validated_set("txid_blocklist", txid_blocklist, |value| {
            value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })?
        .into_iter()
        .map(|txid| txid.to_ascii_lowercase())
        .collect();

        Ok(Self {
            method_whitelist,
            address_blocklist,
            txid_blocklist,
            resolve_identity_names_for_blocklist: false,
            require_canonical_identity_leaf_names: false,
        })
    }

    pub fn from_config(
        settings: &config::Config,
        secrets: &config::Config,
    ) -> Result<Self, String> {
        let resolve_identity_names =
            optional_bool(settings, "resolve_identity_names_for_blocklist", false)?;
        let require_canonical_names =
            optional_bool(settings, "require_canonical_identity_leaf_names", false)?;
        Ok(Self::new(
            optional_string_list(settings, "method_whitelist")?,
            optional_string_list(secrets, "address_blocklist")?,
            optional_string_list(secrets, "txid_blocklist")?,
        )?
        .with_identity_name_resolution_for_blocklist(resolve_identity_names)
        .with_canonical_identity_leaf_names_required(require_canonical_names))
    }

    pub fn with_identity_name_resolution_for_blocklist(mut self, enabled: bool) -> Self {
        self.resolve_identity_names_for_blocklist = enabled;
        self
    }

    pub fn with_canonical_identity_leaf_names_required(mut self, required: bool) -> Self {
        self.require_canonical_identity_leaf_names = required;
        self
    }

    /// An empty whitelist preserves the built-in allowlist as the sole method
    /// gate. A non-empty whitelist is an additional, exact-match restriction.
    pub fn method_is_whitelisted(&self, method: &str) -> bool {
        self.method_whitelist.is_empty() || self.method_whitelist.contains(method)
    }

    pub fn method_whitelist_len(&self) -> usize {
        self.method_whitelist.len()
    }

    pub fn address_blocklist_len(&self) -> usize {
        self.address_blocklist.len()
    }

    pub fn txid_blocklist_len(&self) -> usize {
        self.txid_blocklist.len()
    }

    pub fn resolves_identity_names_for_blocklist(&self) -> bool {
        self.resolve_identity_names_for_blocklist
    }

    pub fn requires_canonical_identity_leaf_names(&self) -> bool {
        self.require_canonical_identity_leaf_names
    }

    /// Applies lookup blocklists to the RPC methods that consume addresses or
    /// transaction IDs. Direct addresses never require a backend lookup.
    /// Human-readable identity selectors are resolved through the supplied
    /// `getvdxfid` callback only when explicitly enabled; otherwise they are
    /// rejected when an address blocklist is configured. An empty address
    /// blocklist bypasses all address extraction and identity resolution.
    pub fn check_blocklists<F>(
        &self,
        method: &str,
        params: &[Value],
        mut resolve_identity: F,
    ) -> Result<(), RequestPolicyRejection>
    where
        F: FnMut(&str) -> Result<String, ()>,
    {
        if self.require_canonical_identity_leaf_names && method == "updateidentity" {
            let name = params
                .first()
                .and_then(Value::as_object)
                .and_then(|identity| identity.get("name"))
                .and_then(Value::as_str)
                .ok_or(RequestPolicyRejection::NonCanonicalIdentityName)?;
            if !is_canonical_identity_leaf_name(name) {
                return Err(RequestPolicyRejection::NonCanonicalIdentityName);
            }
        }

        if method == "getrawtransaction" {
            if let Some(txid) = params.first().and_then(Value::as_str) {
                if self.txid_blocklist.contains(&txid.to_ascii_lowercase()) {
                    return Err(RequestPolicyRejection::Blocked);
                }
            }
        }

        if self.address_blocklist.is_empty() {
            return Ok(());
        }

        let mut seen = HashSet::new();

        // updateidentity selects its target from name + parent. Never trust a
        // caller-supplied identityaddress as the lookup target: derive a
        // parented target locally, or resolve a root/name-only target through
        // getvdxfid even when the name happens to resemble an address.
        if method == "updateidentity" {
            let identity = params
                .first()
                .and_then(Value::as_object)
                .ok_or(RequestPolicyRejection::IdentityResolutionFailed)?;
            let name = identity
                .get("name")
                .and_then(Value::as_str)
                .ok_or(RequestPolicyRejection::IdentityResolutionFailed)?;
            let supplied_address = identity.get("identityaddress").and_then(Value::as_str);

            let target_address = if let Some(parent) = identity.get("parent") {
                let parent = parent
                    .as_str()
                    .ok_or(RequestPolicyRejection::IdentityResolutionFailed)?;
                let derived = derive_parented_identity_address(name, parent)
                    .ok_or(RequestPolicyRejection::IdentityResolutionFailed)?;
                if supplied_address != Some(derived.as_str()) {
                    return Err(RequestPolicyRejection::IdentityResolutionFailed);
                }
                derived
            } else {
                if !self.resolve_identity_names_for_blocklist {
                    return Err(RequestPolicyRejection::IdentityNameLookupDisabled);
                }
                let identity_name = identity_name_for_resolution(name);
                let resolved = resolve_identity(&identity_name)
                    .map_err(|_| RequestPolicyRejection::IdentityResolutionFailed)?;
                if !is_identity_address(&resolved)
                    || supplied_address.is_some_and(|supplied| supplied != resolved)
                {
                    return Err(RequestPolicyRejection::IdentityResolutionFailed);
                }
                resolved
            };

            if self.address_blocklist.contains(&target_address) {
                return Err(RequestPolicyRejection::Blocked);
            }
            seen.insert(target_address);
        }

        for lookup in address_lookup_values(method, params) {
            let is_direct = is_direct_address(&lookup.value);
            let direct_kind_is_valid = match lookup.kind {
                AddressLookupKind::AnyDirectAddress => is_direct,
                AddressLookupKind::Identity => is_identity_address(&lookup.value),
                AddressLookupKind::TransparentAddress => is_direct && lookup.value.starts_with('R'),
            };

            if is_direct && !direct_kind_is_valid {
                return Err(RequestPolicyRejection::InvalidAddress);
            }
            if !is_direct && lookup.kind != AddressLookupKind::Identity {
                return Err(RequestPolicyRejection::InvalidAddress);
            }
            if !is_direct && !self.resolve_identity_names_for_blocklist {
                return Err(RequestPolicyRejection::IdentityNameLookupDisabled);
            }

            if !seen.insert(lookup.value.clone()) {
                continue;
            }
            if self.address_blocklist.contains(&lookup.value) {
                return Err(RequestPolicyRejection::Blocked);
            }
            if is_direct {
                continue;
            }

            // getvdxfid needs an '@' identity qualifier; without one, the same
            // text denotes a VDXF data key. Preserve an explicit qualifier so
            // blocklist resolution matches the daemon's target semantics.
            let identity_name = identity_name_for_resolution(&lookup.value);
            let resolved = resolve_identity(&identity_name)
                .map_err(|_| RequestPolicyRejection::IdentityResolutionFailed)?;
            if !is_identity_address(&resolved) {
                return Err(RequestPolicyRejection::IdentityResolutionFailed);
            }
            if self.address_blocklist.contains(&resolved) {
                return Err(RequestPolicyRejection::Blocked);
            }
        }

        Ok(())
    }
}

pub fn configured_api_keys(
    auth_enabled: bool,
    secrets: &config::Config,
) -> Result<Option<HashMap<String, String>>, String> {
    if !auth_enabled {
        return Ok(None);
    }

    let api_keys = secrets
        .get::<HashMap<String, String>>("api_keys")
        .map_err(|error| {
            format!("auth_enabled is true, but 'api_keys' is missing or invalid: {error}")
        })?;
    if api_keys.is_empty() {
        return Err("auth_enabled is true, but 'api_keys' is empty".to_string());
    }
    if api_keys
        .iter()
        .any(|(app_id, api_key)| app_id.trim().is_empty() || api_key.trim().is_empty())
    {
        return Err(
            "auth_enabled is true, but 'api_keys' contains an empty app ID or key".to_string(),
        );
    }

    Ok(Some(api_keys))
}

fn optional_string_list(config: &config::Config, key: &str) -> Result<Vec<String>, String> {
    match config.get::<Vec<String>>(key) {
        Ok(values) => Ok(values),
        Err(config::ConfigError::NotFound(_)) => Ok(Vec::new()),
        Err(error) => Err(format!("'{key}' must be an array of strings: {error}")),
    }
}

fn optional_bool(config: &config::Config, key: &str, default: bool) -> Result<bool, String> {
    match config.get::<bool>(key) {
        Ok(value) => Ok(value),
        Err(config::ConfigError::NotFound(_)) => Ok(default),
        Err(error) => Err(format!("'{key}' must be a boolean: {error}")),
    }
}

fn validated_set<F>(name: &str, values: Vec<String>, is_valid: F) -> Result<HashSet<String>, String>
where
    F: Fn(&str) -> bool,
{
    let mut result = HashSet::with_capacity(values.len());
    for value in values {
        if value.trim() != value || !is_valid(&value) {
            return Err(format!("'{name}' contains an invalid entry"));
        }
        if !result.insert(value) {
            return Err(format!("'{name}' contains a duplicate entry"));
        }
    }
    Ok(result)
}

fn is_direct_address(value: &str) -> bool {
    const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    value.len() == 34
        && matches!(value.as_bytes().first(), Some(b'i' | b'R'))
        && value.bytes().all(|byte| BASE58.as_bytes().contains(&byte))
}

fn is_identity_address(value: &str) -> bool {
    is_direct_address(value) && value.starts_with('i')
}

fn identity_name_for_resolution(name: &str) -> String {
    if name.contains('@') {
        name.to_owned()
    } else {
        format!("{name}@")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressLookupKind {
    AnyDirectAddress,
    Identity,
    TransparentAddress,
}

#[derive(Clone, Debug)]
struct AddressLookupValue {
    value: String,
    kind: AddressLookupKind,
}

impl AddressLookupValue {
    fn new(value: &str, kind: AddressLookupKind) -> Self {
        Self {
            value: value.to_owned(),
            kind,
        }
    }
}

fn address_lookup_values(method: &str, params: &[Value]) -> Vec<AddressLookupValue> {
    let mut values = Vec::new();
    match method {
        "getaddressutxos" | "getaddressmempool" | "getaddressbalance" | "getaddressdeltas" => {
            if let Some(addresses) = params
                .first()
                .and_then(Value::as_object)
                .and_then(|object| object.get("addresses"))
                .and_then(Value::as_array)
            {
                values.extend(addresses.iter().filter_map(Value::as_str).map(|address| {
                    AddressLookupValue::new(address, AddressLookupKind::AnyDirectAddress)
                }));
            }
        }
        "getidentitieswithaddress" => {
            if let Some(address) = params
                .first()
                .and_then(Value::as_object)
                .and_then(|object| object.get("address"))
                .and_then(Value::as_str)
            {
                values.push(AddressLookupValue::new(
                    address,
                    AddressLookupKind::TransparentAddress,
                ));
            }
        }
        "getidentity" | "getidentitycontent" => {
            if let Some(address) = params.first().and_then(Value::as_str) {
                values.push(AddressLookupValue::new(
                    address,
                    AddressLookupKind::Identity,
                ));
            }
        }
        "updateidentity" => {
            if let Some(identity) = params.first().and_then(Value::as_object) {
                // The target identityaddress is independently derived or
                // resolved above. These remaining fields are additional
                // address-bearing values consumed by the update.
                for field in [
                    "parent",
                    "recoveryauthority",
                    "revocationauthority",
                    "systemid",
                ] {
                    if let Some(value) = identity.get(field).and_then(Value::as_str) {
                        values.push(AddressLookupValue::new(value, AddressLookupKind::Identity));
                    }
                }
                if let Some(primary_addresses) =
                    identity.get("primaryaddresses").and_then(Value::as_array)
                {
                    values.extend(primary_addresses.iter().filter_map(Value::as_str).map(
                        |address| {
                            AddressLookupValue::new(address, AddressLookupKind::TransparentAddress)
                        },
                    ));
                }
            }
        }
        _ => {}
    }
    values
}

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
    client: Arc<Mutex<Client>>,
    request_policy: RequestPolicy,
    blocklist_identity_cache: Arc<BlocklistIdentityCache>,
}

impl VerusRPC {
    pub fn new(url: &str, user: &str, pass: &str) -> Result<VerusRPC, simple_http::Error> {
        Self::new_with_policy(url, user, pass, RequestPolicy::default())
    }

    pub fn new_with_policy(
        url: &str,
        user: &str,
        pass: &str,
        request_policy: RequestPolicy,
    ) -> Result<VerusRPC, simple_http::Error> {
        Self::new_with_policy_and_blocklist_identity_cache(
            url,
            user,
            pass,
            request_policy,
            Arc::new(BlocklistIdentityCache::new()),
        )
    }

    pub fn new_with_policy_and_blocklist_identity_cache(
        url: &str,
        user: &str,
        pass: &str,
        request_policy: RequestPolicy,
        blocklist_identity_cache: Arc<BlocklistIdentityCache>,
    ) -> Result<VerusRPC, simple_http::Error> {
        let transport = SimpleHttpTransport::builder()
            .url(url)?
            .auth(user, Some(pass))
            .build();
        Ok(VerusRPC {
            client: Arc::new(Mutex::new(Client::with_transport(transport))),
            request_policy,
            blocklist_identity_cache,
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
        if !self.request_policy.method_is_whitelisted(method) {
            request_log!(
                trace,
                "configured method whitelist rejected method={method}"
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

        let params_json = req_body["params"]
            .as_array()
            .expect("params were validated as an array above");
        self.request_policy
            .check_blocklists(method, params_json, |identity_name| {
                self.resolve_identity_address(identity_name, trace)
                    .map_err(|_| ())
            })
            .map_err(|reason| {
                request_log!(
                    trace,
                    "request policy rejected method={method}, reason={reason:?}"
                );
                RpcError {
                    code: -32602,
                    message: "Invalid params".into(),
                    data: None,
                }
            })?;

        let client = self.client.lock().unwrap_or_else(|e| e.into_inner());
        let request = client.build_request(method, &params);

        let send_started_at = Instant::now();
        request_log!(
            trace,
            "sending request to Verus RPC backend: method={method}"
        );
        let response = client.send_request(request).map_err(|e| {
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

    fn resolve_identity_address(
        &self,
        identity_name: &str,
        trace: &RequestTrace,
    ) -> Result<String, RpcError> {
        let (address, cache_hit) = self.blocklist_identity_cache.resolve(identity_name, || {
            self.resolve_identity_address_uncached(identity_name, trace)
        })?;
        if cache_hit {
            request_log!(
                trace,
                "blocklist identity resolution cache hit for selector={identity_name:?}"
            );
        }
        Ok(address)
    }

    fn resolve_identity_address_uncached(
        &self,
        identity_name: &str,
        trace: &RequestTrace,
    ) -> Result<String, RpcError> {
        let param = RawValue::from_string(
            serde_json::to_string(identity_name).expect("serializing a string cannot fail"),
        )
        .expect("serialized JSON string must be valid raw JSON");
        let params = vec![param];
        let client = self.client.lock().unwrap_or_else(|e| e.into_inner());
        let request = client.build_request("getvdxfid", &params);
        request_log!(
            trace,
            "resolving human-readable identity for request blocklist"
        );
        let response = client.send_request(request).map_err(|_| RpcError {
            code: -32603,
            message: "Internal error".into(),
            data: None,
        })?;
        let result: Value = response.result().map_err(|_| RpcError {
            code: -32603,
            message: "Internal error".into(),
            data: None,
        })?;
        let address = result
            .get("vdxfid")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| RpcError {
                code: -32603,
                message: "Internal error".into(),
                data: None,
            })?;
        if !is_identity_address(&address) {
            return Err(RpcError {
                code: -32603,
                message: "Internal error".into(),
                data: None,
            });
        }
        Ok(address)
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

/// Handles requests received by the optional loopback-only HTTP listener.
///
/// The listener itself is responsible for enforcing a loopback peer address.
/// This wrapper adds narrowly scoped browser support: only exact HTTP(S)
/// origins hosted on localhost, 127.0.0.1, or ::1 receive CORS permission.
/// Authentication and all normal request policy checks are still performed by
/// `handle_req_with_logging`.
pub async fn handle_localhost_req_with_logging(
    req: Request<Body>,
    rpc: Arc<VerusRPC>,
    auth: Option<Arc<AuthState>>,
    usage_log: Option<Arc<ApiUsageLog>>,
    log_config: RequestLogConfig,
) -> Result<Response<Body>, hyper::Error> {
    let origin = match localhost_cors_origin(req.headers()) {
        Ok(origin) => origin,
        Err(()) => {
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Origin not allowed"))
                .expect("static localhost CORS response must be valid"));
        }
    };

    if req.method() == Method::OPTIONS {
        let valid_route =
            req.uri().path_and_query().map(|value| value.as_str()) == Some(JSON_RPC_PATH);
        let requested_method_is_post = req
            .headers()
            .get(ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("POST"));
        let requested_headers_are_allowed = req
            .headers()
            .get(ACCESS_CONTROL_REQUEST_HEADERS)
            .is_none_or(cors_requested_headers_are_allowed);

        let Some(origin) = origin else {
            return handle_req_with_logging(req, rpc, auth, usage_log, log_config).await;
        };
        if !valid_route || !requested_method_is_post || !requested_headers_are_allowed {
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("CORS preflight not allowed"))
                .expect("static localhost CORS response must be valid"));
        }

        let mut response = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .expect("static localhost CORS response must be valid");
        add_localhost_cors_headers(&mut response, origin, true);
        return Ok(response);
    }

    let mut response = handle_req_with_logging(req, rpc, auth, usage_log, log_config).await?;
    if let Some(origin) = origin {
        add_localhost_cors_headers(&mut response, origin, false);
    }
    Ok(response)
}

fn localhost_cors_origin(headers: &hyper::HeaderMap) -> Result<Option<HeaderValue>, ()> {
    let mut origins = headers.get_all(ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return Ok(None);
    };
    if origins.next().is_some() {
        return Err(());
    }

    let origin_text = origin.to_str().map_err(|_| ())?;
    if is_allowed_localhost_origin(origin_text) {
        Ok(Some(origin.clone()))
    } else {
        Err(())
    }
}

fn is_allowed_localhost_origin(origin: &str) -> bool {
    let Ok(uri) = origin.parse::<Uri>() else {
        return false;
    };
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.path_and_query().map(|value| value.as_str()) != Some("/")
    {
        return false;
    }

    let Some(authority) = uri.authority() else {
        return false;
    };
    if authority.as_str().contains('@') {
        return false;
    }
    matches!(
        authority.host().to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1" | "[::1]"
    )
}

fn cors_requested_headers_are_allowed(value: &HeaderValue) -> bool {
    let Ok(value) = value.to_str() else {
        return false;
    };
    value.split(',').all(|header| {
        let header = header.trim();
        !header.is_empty()
            && LOCALHOST_CORS_ALLOWED_HEADER_NAMES
                .iter()
                .any(|allowed| header.eq_ignore_ascii_case(allowed))
    })
}

fn add_localhost_cors_headers(response: &mut Response<Body>, origin: HeaderValue, preflight: bool) {
    let headers = response.headers_mut();
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    headers.insert(VARY, HeaderValue::from_static("Origin"));
    if preflight {
        headers.insert(
            ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("POST"),
        );
        headers.insert(
            ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(LOCALHOST_CORS_ALLOW_HEADERS),
        );
    }
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

    if parts.method != hyper::Method::POST {
        trace.log("request rejected: only POST is allowed");
        let body_text = "Method not allowed";
        let response = Response::builder()
            .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
            .header(hyper::header::ALLOW, "POST")
            .body(Body::from(body_text))
            .unwrap();
        return log_and_return_response(&trace, response, body_text);
    }

    if parts.uri.path_and_query().map(|value| value.as_str()) != Some(JSON_RPC_PATH) {
        trace.log("request rejected: unknown JSON-RPC route");
        let body_text = "Not found";
        let response = Response::builder()
            .status(hyper::StatusCode::NOT_FOUND)
            .body(Body::from(body_text))
            .unwrap();
        return log_and_return_response(&trace, response, body_text);
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
            let response = Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Body::from(body_text.clone()))
                .unwrap();
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
            let response = Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Body::from(body_text.clone()))
                .unwrap();
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
                let response = Response::builder()
                    .status(hyper::StatusCode::UNAUTHORIZED)
                    .body(Body::from(body_text.clone()))
                    .unwrap();
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
        body.len(),
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
    use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

    let certs = CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key_path)?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}
