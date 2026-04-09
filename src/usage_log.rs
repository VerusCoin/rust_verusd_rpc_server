use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const FILE_PREFIX: &str = "api-call-counts-";
const SNAPSHOT_FILE_SUFFIX: &str = ".json";
const SNAPSHOT_FORMAT: &str = "api_usage_snapshot_v1";
const BUCKET_MS: i64 = 30_000;
const LAST_HOUR_MS: i64 = 60 * 60 * 1000;
const LAST_24_HOURS_MS: i64 = 24 * LAST_HOUR_MS;
const LAST_7_DAYS_MS: i64 = 7 * LAST_24_HOURS_MS;
const LAST_30_DAYS_MS: i64 = 30 * LAST_24_HOURS_MS;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowCounts {
    pub last_hour: usize,
    pub last_24_hours: usize,
    pub last_7_days: usize,
    pub last_30_days: usize,
}

pub struct ApiUsageLog {
    path: PathBuf,
    inner: Mutex<ApiUsageLogInner>,
}

struct ApiUsageLogInner {
    configured_app_ids: Vec<String>,
    current_run_buckets_by_app: HashMap<String, BTreeMap<i64, u64>>,
    run_started_at_ms: i64,
}

impl ApiUsageLog {
    pub fn new<P, I>(log_dir: P, app_ids: I) -> io::Result<Self>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = String>,
    {
        let log_dir = log_dir.as_ref().to_path_buf();
        fs::create_dir_all(&log_dir)?;

        let run_started_at_ms = now_ms();
        let mut configured_app_ids: Vec<String> = app_ids.into_iter().collect();
        configured_app_ids.sort();
        configured_app_ids.dedup();

        let mut current_run_buckets_by_app = HashMap::new();
        for app_id in &configured_app_ids {
            current_run_buckets_by_app.insert(app_id.clone(), BTreeMap::new());
        }

        let log = ApiUsageLog {
            path: log_dir.join(unique_log_filename()),
            inner: Mutex::new(ApiUsageLogInner {
                configured_app_ids,
                current_run_buckets_by_app,
                run_started_at_ms,
            }),
        };
        log.flush_snapshot_at(run_started_at_ms)?;
        Ok(log)
    }

    pub fn log_path(&self) -> &Path {
        &self.path
    }

    pub fn record_call(&self, app_id: &str) -> io::Result<WindowCounts> {
        self.record_call_at(app_id, now_ms())
    }

    pub fn flush_snapshot(&self) -> io::Result<()> {
        self.flush_snapshot_at(now_ms())
    }

    fn record_call_at(&self, app_id: &str, timestamp_ms: i64) -> io::Result<WindowCounts> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.prune_old(timestamp_ms);
        let bucket_start_ms = bucket_start_ms(timestamp_ms);
        let run_buckets = inner
            .current_run_buckets_by_app
            .entry(app_id.to_string())
            .or_default();
        *run_buckets.entry(bucket_start_ms).or_insert(0) += 1;
        Ok(inner.snapshot_for(app_id, timestamp_ms))
    }

    fn flush_snapshot_at(&self, timestamp_ms: i64) -> io::Result<()> {
        let snapshot = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.prune_old(timestamp_ms);
            inner.snapshot_json(timestamp_ms)
        };
        atomic_write_json(&self.path, &snapshot)
    }
}

impl ApiUsageLogInner {
    fn prune_old(&mut self, now_ms: i64) {
        prune_bucket_sets(&mut self.current_run_buckets_by_app, now_ms);
    }

    fn snapshot_for(&self, app_id: &str, now_ms: i64) -> WindowCounts {
        let current_run = self.current_run_buckets_by_app.get(app_id);
        WindowCounts {
            last_hour: count_since(current_run, now_ms - LAST_HOUR_MS),
            last_24_hours: count_since(current_run, now_ms - LAST_24_HOURS_MS),
            last_7_days: count_since(current_run, now_ms - LAST_7_DAYS_MS),
            last_30_days: count_since(current_run, now_ms - LAST_30_DAYS_MS),
        }
    }

    fn snapshot_json(&self, now_ms: i64) -> Value {
        let mut apps = serde_json::Map::new();
        for app_id in &self.configured_app_ids {
            let counts = self.snapshot_for(app_id, now_ms);
            apps.insert(
                app_id.clone(),
                json!({
                    "counts": {
                        "last_hour": counts.last_hour,
                        "last_24_hours": counts.last_24_hours,
                        "last_7_days": counts.last_7_days,
                        "last_30_days": counts.last_30_days,
                    }
                }),
            );
        }

        json!({
            "format": SNAPSHOT_FORMAT,
            "updated_at_ms": now_ms,
            "run_started_at_ms": self.run_started_at_ms,
            "pid": process::id(),
            "bucket_size_seconds": BUCKET_MS / 1000,
            "app_ids": self.configured_app_ids,
            "apps": apps,
        })
    }
}

fn atomic_write_json(path: &Path, value: &Value) -> io::Result<()> {
    let temp_path = path.with_file_name(format!(
        "{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("usage-log")
    ));
    fs::write(&temp_path, value.to_string())?;
    fs::rename(temp_path, path)
}

fn prune_bucket_sets(bucket_sets: &mut HashMap<String, BTreeMap<i64, u64>>, now_ms: i64) {
    for bucket_counts in bucket_sets.values_mut() {
        prune_bucket_counts(bucket_counts, now_ms);
    }
}

fn prune_bucket_counts(bucket_counts: &mut BTreeMap<i64, u64>, now_ms: i64) {
    let cutoff_ms = now_ms - LAST_30_DAYS_MS;
    let stale_keys: Vec<i64> = bucket_counts
        .range(..cutoff_ms)
        .map(|(bucket_start_ms, _)| *bucket_start_ms)
        .collect();
    for bucket_start_ms in stale_keys {
        bucket_counts.remove(&bucket_start_ms);
    }
}

fn count_since(bucket_counts: Option<&BTreeMap<i64, u64>>, cutoff_ms: i64) -> usize {
    let cutoff_bucket_ms = bucket_start_ms(cutoff_ms);
    bucket_counts
        .map(|bucket_counts| {
            bucket_counts
                .range(cutoff_bucket_ms..)
                .map(|(_, count)| *count as usize)
                .sum()
        })
        .unwrap_or(0)
}

fn bucket_start_ms(timestamp_ms: i64) -> i64 {
    timestamp_ms.div_euclid(BUCKET_MS) * BUCKET_MS
}

fn unique_log_filename() -> String {
    let run_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch")
        .as_nanos();
    format!(
        "{FILE_PREFIX}{run_id}-pid{}{}",
        process::id(),
        SNAPSHOT_FILE_SUFFIX
    )
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch")
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_json(path: &Path) -> Value {
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn startup_snapshot_is_a_single_json_document() {
        let dir = tempfile::tempdir().unwrap();
        let log = ApiUsageLog::new(
            dir.path(),
            vec!["verus-mobile".to_string(), "valu-mobile".to_string()],
        )
        .unwrap();
        let snapshot = read_json(log.log_path());

        assert_eq!(snapshot["format"], SNAPSHOT_FORMAT);
        assert_eq!(snapshot["bucket_size_seconds"], 30);
        assert_eq!(snapshot["app_ids"], json!(["valu-mobile", "verus-mobile"]));
        assert_eq!(snapshot["apps"]["verus-mobile"]["counts"]["last_hour"], 0);
        assert_eq!(snapshot["apps"]["valu-mobile"]["counts"]["last_30_days"], 0);
        assert!(snapshot["apps"]["verus-mobile"].get("run_buckets").is_none());
    }

    #[test]
    fn record_call_only_changes_the_file_when_a_snapshot_is_flushed() {
        let dir = tempfile::tempdir().unwrap();
        let log = ApiUsageLog::new(dir.path(), vec!["verus-mobile".to_string()]).unwrap();
        let initial = fs::read_to_string(log.log_path()).unwrap();

        let base = now_ms();
        let counts = log.record_call_at("verus-mobile", base + 5_000).unwrap();
        assert_eq!(
            counts,
            WindowCounts {
                last_hour: 1,
                last_24_hours: 1,
                last_7_days: 1,
                last_30_days: 1,
            }
        );
        assert_eq!(fs::read_to_string(log.log_path()).unwrap(), initial);

        log.flush_snapshot_at(base + 30_000).unwrap();
        let snapshot = read_json(log.log_path());
        assert_eq!(snapshot["apps"]["verus-mobile"]["counts"]["last_hour"], 1);
        assert!(snapshot["apps"]["verus-mobile"].get("run_buckets").is_none());
    }

    #[test]
    fn prunes_internal_run_buckets_older_than_30_days() {
        let dir = tempfile::tempdir().unwrap();
        let log = ApiUsageLog::new(dir.path(), vec!["verus-mobile".to_string()]).unwrap();
        let base = now_ms();
        let stale_bucket_ms = base - LAST_30_DAYS_MS - BUCKET_MS;
        let fresh_bucket_ms = base;

        log.record_call_at("verus-mobile", stale_bucket_ms).unwrap();
        log.record_call_at("verus-mobile", fresh_bucket_ms).unwrap();

        {
            let inner = log.inner.lock().unwrap_or_else(|e| e.into_inner());
            let buckets = inner.current_run_buckets_by_app.get("verus-mobile").unwrap();
            assert_eq!(buckets.len(), 1);
            assert!(buckets.contains_key(&bucket_start_ms(fresh_bucket_ms)));
            assert!(!buckets.contains_key(&bucket_start_ms(stale_bucket_ms)));
        }

        log.flush_snapshot_at(base).unwrap();
        let snapshot = read_json(log.log_path());
        assert_eq!(snapshot["apps"]["verus-mobile"]["counts"]["last_30_days"], 1);
        assert!(snapshot["apps"]["verus-mobile"].get("run_buckets").is_none());
    }
}
