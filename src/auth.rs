use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, PartialEq, Eq)]
pub enum AuthCheckFailure {
    UnknownAppId,
    TimestampOutOfWindow {
        now_ms: i64,
        request_ms: i64,
        max_skew_ms: i64,
    },
    Replay {
        timestamp_ms: i64,
        salt: String,
    },
    InvalidToken,
}

pub struct AuthState {
    api_keys: HashMap<String, String>,
    // Each entry is (app_id, timestamp_ms, salt). Replay identity is scoped to
    // an application because different applications do not share a key.
    seen_requests: Mutex<Vec<(String, i64, String)>>,
}

const MAX_CLOCK_SKEW_MS: u64 = 600_000;

impl AuthState {
    pub fn new(api_keys: HashMap<String, String>) -> Self {
        AuthState {
            api_keys,
            seen_requests: Mutex::new(Vec::new()),
        }
    }

    /// Returns true iff `validity_key` is the correct BLAKE2b-512 token for this
    /// (app_id, body, time, version, salt) tuple, the timestamp is within 10 minutes
    /// of now, and the (app_id, time, salt) tuple has not been seen before.
    pub fn check_token(
        &self,
        validity_key: &str,
        body: &str,
        time: i64,
        app_id: &str,
        version: &str,
        salt: &str,
    ) -> bool {
        self.check_token_detailed(validity_key, body, time, app_id, version, salt)
            .is_ok()
    }

    pub fn check_token_detailed(
        &self,
        validity_key: &str,
        body: &str,
        time: i64,
        app_id: &str,
        version: &str,
        salt: &str,
    ) -> Result<(), AuthCheckFailure> {
        let api_key = match self.api_keys.get(app_id) {
            Some(k) => k,
            None => return Err(AuthCheckFailure::UnknownAppId),
        };

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_millis() as i64;

        if now_ms.abs_diff(time) > MAX_CLOCK_SKEW_MS {
            return Err(AuthCheckFailure::TimestampOutOfWindow {
                now_ms,
                request_ms: time,
                max_skew_ms: MAX_CLOCK_SKEW_MS as i64,
            });
        }

        if salt.len() != 64
            || !salt
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(AuthCheckFailure::InvalidToken);
        }

        let expected = compute_token_hash(api_key, body, time, app_id, version, salt);
        let provided = decode_token(validity_key).ok_or(AuthCheckFailure::InvalidToken)?;
        // blake2b_simd::Hash implements constant-time comparison against a
        // byte slice through constant_time_eq.
        if expected != provided[..] {
            return Err(AuthCheckFailure::InvalidToken);
        }

        // Token verification must precede replay insertion. Otherwise an
        // unauthenticated caller can burn a legitimate (timestamp, salt).
        let mut seen = self
            .seen_requests
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        seen.retain(|(_, timestamp, _)| now_ms.abs_diff(*timestamp) <= MAX_CLOCK_SKEW_MS);
        if seen.iter().any(|(seen_app_id, timestamp, seen_salt)| {
            seen_app_id == app_id && *timestamp == time && seen_salt == salt
        }) {
            return Err(AuthCheckFailure::Replay {
                timestamp_ms: time,
                salt: salt.to_string(),
            });
        }
        seen.push((app_id.to_string(), time, salt.to_string()));
        Ok(())
    }
}

fn decode_token(hex: &str) -> Option<[u8; 64]> {
    if hex.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = lower_hex_value(chunk[0])?;
        let low = lower_hex_value(chunk[1])?;
        out[index] = (high << 4) | low;
    }
    Some(out)
}

fn lower_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
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
pub fn compute_token(
    api_key: &str,
    body: &str,
    time: i64,
    app_id: &str,
    version: &str,
    salt: &str,
) -> String {
    compute_token_hash(api_key, body, time, app_id, version, salt)
        .to_hex()
        .to_string()
}

fn compute_token_hash(
    api_key: &str,
    body: &str,
    time: i64,
    app_id: &str,
    version: &str,
    salt: &str,
) -> blake2b_simd::Hash {
    let salt_bytes = decode_salt(salt);
    let mut state = blake2b_simd::Params::new().hash_length(64).to_state();
    state.update(time.to_string().as_bytes());
    state.update(api_key.as_bytes());
    state.update(body.as_bytes());
    state.update(app_id.as_bytes());
    state.update(version.as_bytes());
    state.update(&salt_bytes);
    state.finalize()
}
