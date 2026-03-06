use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct AuthState {
    api_keys: HashMap<String, String>,
    // Each entry is (timestamp_ms, salt). Replay is rejected only when both match.
    seen_times: Mutex<Vec<(i64, String)>>,
}

impl AuthState {
    pub fn new(api_keys: HashMap<String, String>) -> Self {
        AuthState {
            api_keys,
            seen_times: Mutex::new(Vec::new()),
        }
    }

    /// Returns true iff `validity_key` is the correct BLAKE2b-512 token for this
    /// (app_id, body, time, version, salt) tuple, the timestamp is within 10 minutes
    /// of now, and the (time, salt) pair has not been seen before (replay guard).
    pub fn check_token(&self, validity_key: &str, body: &str, time: i64, app_id: &str, version: &str, salt: &str) -> bool {
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
            if seen.iter().any(|(t, s)| *t == time && s == salt) {
                return false;
            }
            seen.push((time, salt.to_string()));
            // Prune by time only — salt is not relevant to the expiry window.
            seen.retain(|(t, _)| (now_ms - t).abs() < 600_000);
        }

        compute_token(api_key, body, time, app_id, version, salt) == validity_key
    }
}

/// Decodes a 64-char lowercase hex string into 32 raw bytes.
/// Caller must ensure `hex` is exactly 64 lowercase hex characters.
fn decode_salt(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for (i, chunk) in bytes.chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).unwrap() as u8;
        let lo = (chunk[1] as char).to_digit(16).unwrap() as u8;
        out[i] = (hi << 4) | lo;
    }
    out
}

/// Computes the BLAKE2b-512 token used to authenticate a request.
///
/// Hash input (in order): time-as-decimal-string | api_key | request-body | app_id | api-version | salt-bytes.
/// salt is a 64-char lowercase hex string; it is decoded to 32 raw bytes before hashing.
/// The output is the 128-character lowercase hex digest.
pub fn compute_token(api_key: &str, body: &str, time: i64, app_id: &str, version: &str, salt: &str) -> String {
    let salt_bytes = decode_salt(salt);
    let mut state = blake2b_simd::Params::new()
        .hash_length(64)
        .to_state();
    state.update(time.to_string().as_bytes());
    state.update(api_key.as_bytes());
    state.update(body.as_bytes());
    state.update(app_id.as_bytes());
    state.update(version.as_bytes());
    state.update(&salt_bytes);
    state.finalize().to_hex().to_string()
}
