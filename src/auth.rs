use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct AuthState {
    api_keys: HashMap<String, String>,
    seen_times: Mutex<Vec<i64>>,
}

impl AuthState {
    pub fn new(api_keys: HashMap<String, String>) -> Self {
        AuthState {
            api_keys,
            seen_times: Mutex::new(Vec::new()),
        }
    }

    /// Returns true iff `validity_key` is the correct BLAKE2b-512 token for this
    /// (app_id, method, time) tuple, the timestamp is within 10 minutes of now,
    /// and the timestamp has not been seen before (replay guard).
    pub fn check_token(&self, validity_key: &str, method: &str, time: i64, app_id: &str) -> bool {
        let api_key = match self.api_keys.get(app_id) {
            Some(k) => k,
            None => return false,
        };

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_millis() as i64;

        if (now_ms - time).abs() > 600_000 {
            return false;
        }

        {
            let mut seen = self.seen_times.lock().unwrap_or_else(|e| e.into_inner());
            if seen.contains(&time) {
                return false;
            }
            seen.push(time);
            // Prune timestamps outside the 10-minute window so the vec stays bounded.
            seen.retain(|&t| (now_ms - t).abs() < 600_000);
        }

        compute_token(api_key, method, time, app_id) == validity_key
    }
}

/// Computes the BLAKE2b-512 token used to authenticate a request.
///
/// Hash input (in order): time-as-decimal-string | api_key | method | app_id.
/// The output is the 128-character lowercase hex digest.
pub fn compute_token(api_key: &str, method: &str, time: i64, app_id: &str) -> String {
    let mut state = blake2b_simd::Params::new()
        .hash_length(64)
        .to_state();
    state.update(time.to_string().as_bytes());
    state.update(api_key.as_bytes());
    state.update(method.as_bytes());
    state.update(app_id.as_bytes());
    let token = state.finalize().to_hex().to_string();
    token
}
