//! Shared, fail-fast admission for request bodies and blocking daemon work.
//!
//! The server must share one `Arc<Admission>` across connections and listeners.
//! Work permits belong inside the blocking worker, so abandoning an HTTP future
//! cannot release capacity while its daemon request is still running.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

// These are simultaneous envelope limits, not queues. Body permits cover body
// ingestion; work permits cover validation lookups and daemon execution.
const MAX_ACTIVE_BODIES: usize = 32;
const MAX_ACTIVE_WORK: usize = 16;
const MAX_ACTIVE_APP_WORK: usize = 8;
const MAX_AUTHENTICATED_APPLICATIONS: usize = 1_024;

// Each logical RPC and each internal identity lookup consumes one token. Tokens
// are never refunded: even failed daemon operations consume server resources.
const GLOBAL_ITEMS_PER_SECOND: u32 = 200;
const GLOBAL_ITEM_BURST: u32 = 200;
const APP_ITEMS_PER_SECOND: u32 = 100;
const APP_ITEM_BURST: u32 = 100;
const TOKEN_UNITS: u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    BodyCapacity,
    GlobalCapacity,
    ApplicationCapacity,
    GlobalRateLimit,
    ApplicationRateLimit,
    ApplicationRegistryFull,
    InvalidItemCount,
}

#[derive(Debug)]
pub(crate) struct Admission {
    state: Mutex<AdmissionState>,
}

#[derive(Debug)]
struct AdmissionState {
    active_bodies: usize,
    active_work: usize,
    global_tokens: TokenBucket,
    // None is the one fixed anonymous bucket. Some keys must come only from
    // successful authentication, never directly from an unverified header.
    applications: HashMap<Option<String>, ApplicationState>,
}

#[derive(Debug)]
struct ApplicationState {
    active_work: usize,
    tokens: TokenBucket,
}

impl ApplicationState {
    fn new(now: Instant) -> Self {
        Self {
            active_work: 0,
            tokens: TokenBucket::new(APP_ITEM_BURST, APP_ITEMS_PER_SECOND, now),
        }
    }
}

#[derive(Debug)]
struct TokenBucket {
    balance: u64,
    capacity: u64,
    tokens_per_second: u32,
    updated_at: Instant,
}

impl TokenBucket {
    fn new(burst: u32, tokens_per_second: u32, now: Instant) -> Self {
        let capacity = u64::from(burst) * TOKEN_UNITS;
        Self {
            balance: capacity,
            capacity,
            tokens_per_second,
            updated_at: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.updated_at);
        if elapsed.is_zero() {
            return;
        }
        let added = elapsed
            .as_nanos()
            .saturating_mul(u128::from(self.tokens_per_second));
        self.balance = (u128::from(self.balance) + added.min(u128::from(self.capacity)))
            .min(u128::from(self.capacity)) as u64;
        self.updated_at = now;
    }
}

#[derive(Debug)]
pub(crate) struct BodyPermit {
    admission: Arc<Admission>,
}

#[derive(Debug)]
pub(crate) struct WorkPermit {
    admission: Arc<Admission>,
    app_id: Option<String>,
}

impl Admission {
    pub(crate) fn new() -> Self {
        Self::new_at(Instant::now())
    }

    fn new_at(now: Instant) -> Self {
        Self {
            state: Mutex::new(AdmissionState {
                active_bodies: 0,
                active_work: 0,
                global_tokens: TokenBucket::new(GLOBAL_ITEM_BURST, GLOBAL_ITEMS_PER_SECOND, now),
                applications: HashMap::from([(None, ApplicationState::new(now))]),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, AdmissionState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn try_acquire_body(self: &Arc<Self>) -> Result<BodyPermit, AdmissionError> {
        let mut state = self.lock();
        if state.active_bodies >= MAX_ACTIVE_BODIES {
            return Err(AdmissionError::BodyCapacity);
        }
        state.active_bodies += 1;
        Ok(BodyPermit {
            admission: self.clone(),
        })
    }

    /// Admit one envelope and charge its logical RPCs before spawning work.
    ///
    /// `Some(app_id)` must be the identity from a successful authentication
    /// check. Unauthenticated operation must use `None`, never a header value.
    /// The registry is additionally capped so even configuration churn cannot
    /// cause unbounded memory growth. Rejections do not consume tokens.
    pub(crate) fn try_enter(
        self: &Arc<Self>,
        app_id: Option<&str>,
        logical_items: usize,
    ) -> Result<WorkPermit, AdmissionError> {
        self.try_enter_at(app_id, logical_items, Instant::now())
    }

    fn try_enter_at(
        self: &Arc<Self>,
        app_id: Option<&str>,
        logical_items: usize,
        now: Instant,
    ) -> Result<WorkPermit, AdmissionError> {
        if logical_items == 0 {
            return Err(AdmissionError::InvalidItemCount);
        }
        if logical_items > APP_ITEM_BURST as usize {
            return Err(AdmissionError::ApplicationRateLimit);
        }
        let units = logical_items as u64 * TOKEN_UNITS;
        let mut state = self.lock();
        if state.active_work >= MAX_ACTIVE_WORK {
            return Err(AdmissionError::GlobalCapacity);
        }

        let app_id = app_id.map(str::to_owned);
        if !state.applications.contains_key(&app_id) {
            // The permanent anonymous entry is not part of the authenticated
            // application limit.
            if state.applications.len() > MAX_AUTHENTICATED_APPLICATIONS {
                return Err(AdmissionError::ApplicationRegistryFull);
            }
            state
                .applications
                .insert(app_id.clone(), ApplicationState::new(now));
        }
        if state.applications[&app_id].active_work >= MAX_ACTIVE_APP_WORK {
            return Err(AdmissionError::ApplicationCapacity);
        }
        Self::charge(&mut state, &app_id, units, now)?;
        state.active_work += 1;
        state.applications.get_mut(&app_id).unwrap().active_work += 1;
        Ok(WorkPermit {
            admission: self.clone(),
            app_id,
        })
    }

    fn charge(
        state: &mut AdmissionState,
        app_id: &Option<String>,
        units: u64,
        now: Instant,
    ) -> Result<(), AdmissionError> {
        state.global_tokens.refill(now);
        let application = state
            .applications
            .get_mut(app_id)
            .expect("work permit application remains registered");
        application.tokens.refill(now);
        if state.global_tokens.balance < units {
            return Err(AdmissionError::GlobalRateLimit);
        }
        if application.tokens.balance < units {
            return Err(AdmissionError::ApplicationRateLimit);
        }
        state.global_tokens.balance -= units;
        application.tokens.balance -= units;
        Ok(())
    }
}

impl WorkPermit {
    /// Charge immediately before an uncached internal identity lookup. A cache
    /// hit consumes no daemon work and therefore needs no additional token.
    pub(crate) fn try_charge_lookup(&self) -> Result<(), AdmissionError> {
        self.try_charge_lookup_at(Instant::now())
    }

    fn try_charge_lookup_at(&self, now: Instant) -> Result<(), AdmissionError> {
        Admission::charge(&mut self.admission.lock(), &self.app_id, TOKEN_UNITS, now)
    }
}

impl Drop for BodyPermit {
    fn drop(&mut self) {
        let mut state = self.admission.lock();
        state.active_bodies -= 1;
    }
}

impl Drop for WorkPermit {
    fn drop(&mut self) {
        let mut state = self.admission.lock();
        state.active_work -= 1;
        state
            .applications
            .get_mut(&self.app_id)
            .expect("work permit application remains registered")
            .active_work -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn admission() -> (Arc<Admission>, Instant) {
        let now = Instant::now();
        (Arc::new(Admission::new_at(now)), now)
    }

    #[test]
    fn body_capacity_is_shared_and_released_on_drop() {
        let admission = Arc::new(Admission::new());
        let connection = admission.clone();
        let mut permits: Vec<_> = (0..MAX_ACTIVE_BODIES)
            .map(|_| admission.try_acquire_body().unwrap())
            .collect();
        assert_eq!(
            connection.try_acquire_body().unwrap_err(),
            AdmissionError::BodyCapacity
        );
        permits.pop();
        let replacement = connection.try_acquire_body().unwrap();
        drop(permits);
        drop(replacement);
        assert_eq!(admission.lock().active_bodies, 0);
    }

    #[test]
    fn active_work_limits_apply_across_shared_connections_and_apps() {
        let (admission, now) = admission();
        let other_connection = admission.clone();
        let mut app_permits = vec![admission.try_enter_at(Some("a"), 1, now).unwrap()];
        app_permits.extend(
            (1..MAX_ACTIVE_APP_WORK)
                .map(|_| other_connection.try_enter_at(Some("a"), 1, now).unwrap()),
        );
        assert_eq!(
            admission.try_enter_at(Some("a"), 1, now).unwrap_err(),
            AdmissionError::ApplicationCapacity
        );
        let other_permits: Vec<_> = (MAX_ACTIVE_APP_WORK..MAX_ACTIVE_WORK)
            .map(|index| {
                admission
                    .try_enter_at(Some(&format!("other-{index}")), 1, now)
                    .unwrap()
            })
            .collect();
        assert_eq!(
            other_connection
                .try_enter_at(Some("new-app"), 1, now)
                .unwrap_err(),
            AdmissionError::GlobalCapacity
        );
        drop(app_permits.pop().unwrap());
        let replacement = other_connection
            .try_enter_at(Some("new-app"), 1, now)
            .unwrap();
        assert_eq!(admission.lock().active_work, MAX_ACTIVE_WORK);
        drop((app_permits, other_permits, replacement));
        assert_eq!(admission.lock().active_work, 0);
    }

    #[test]
    fn logical_items_charge_both_buckets_and_refill_at_their_rates() {
        let (admission, now) = admission();
        drop(admission.try_enter_at(Some("a"), 60, now).unwrap());
        drop(admission.try_enter_at(Some("a"), 40, now).unwrap());
        assert_eq!(
            admission.try_enter_at(Some("a"), 1, now).unwrap_err(),
            AdmissionError::ApplicationRateLimit
        );
        // The rejected application call must not spend global tokens.
        drop(admission.try_enter_at(Some("b"), 100, now).unwrap());
        assert_eq!(
            admission.try_enter_at(Some("c"), 1, now).unwrap_err(),
            AdmissionError::GlobalRateLimit
        );
        let later = now + Duration::from_millis(10);
        drop(admission.try_enter_at(Some("a"), 1, later).unwrap());
        drop(admission.try_enter_at(Some("b"), 1, later).unwrap());
        assert_eq!(
            admission.try_enter_at(Some("c"), 1, later).unwrap_err(),
            AdmissionError::GlobalRateLimit
        );
    }

    #[test]
    fn capacity_rejection_does_not_spend_tokens() {
        let (admission, now) = admission();
        let permits: Vec<_> = (0..MAX_ACTIVE_APP_WORK)
            .map(|_| admission.try_enter_at(Some("a"), 1, now).unwrap())
            .collect();
        let remaining_items = APP_ITEM_BURST as usize - MAX_ACTIVE_APP_WORK;
        assert_eq!(
            admission
                .try_enter_at(Some("a"), remaining_items, now)
                .unwrap_err(),
            AdmissionError::ApplicationCapacity
        );
        drop(permits);
        drop(
            admission
                .try_enter_at(Some("a"), remaining_items, now)
                .unwrap(),
        );
        assert_eq!(
            admission.try_enter_at(Some("a"), 1, now).unwrap_err(),
            AdmissionError::ApplicationRateLimit
        );
    }

    #[test]
    fn lookup_charges_share_rpc_budgets_and_do_not_refund_on_drop() {
        let (admission, now) = admission();
        let work = admission.try_enter_at(Some("a"), 99, now).unwrap();
        work.try_charge_lookup_at(now).unwrap();
        assert_eq!(
            work.try_charge_lookup_at(now).unwrap_err(),
            AdmissionError::ApplicationRateLimit
        );
        let other = admission.try_enter_at(Some("b"), 100, now).unwrap();
        assert_eq!(
            other.try_charge_lookup_at(now).unwrap_err(),
            AdmissionError::GlobalRateLimit
        );
        drop((work, other));
        assert_eq!(
            admission.try_enter_at(Some("c"), 1, now).unwrap_err(),
            AdmissionError::GlobalRateLimit
        );
    }

    #[test]
    fn worker_owns_capacity_until_it_actually_finishes() {
        let (admission, now) = admission();
        let first = admission.try_enter_at(Some("a"), 1, now).unwrap();
        let mut retained: Vec<_> = (1..MAX_ACTIVE_APP_WORK)
            .map(|_| admission.try_enter_at(Some("a"), 1, now).unwrap())
            .collect();
        let (release, wait_for_release) = mpsc::channel();
        let (finished, wait_for_finish) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            wait_for_release.recv().unwrap();
            drop(first);
            finished.send(()).unwrap();
        });
        // Dropping the join handle models an HTTP caller abandoning its future.
        drop(worker);
        assert_eq!(
            admission.try_enter_at(Some("a"), 1, now).unwrap_err(),
            AdmissionError::ApplicationCapacity
        );
        // One retained permit releases synchronously; the detached worker still
        // retains its permit until told to finish.
        drop(retained.pop().unwrap());
        let replacement = admission.try_enter_at(Some("a"), 1, now).unwrap();
        assert_eq!(admission.lock().active_work, MAX_ACTIVE_APP_WORK);
        drop((replacement, retained));
        assert_eq!(admission.lock().active_work, 1);
        release.send(()).unwrap();
        wait_for_finish
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert_eq!(admission.lock().active_work, 0);
    }

    #[test]
    fn anonymous_calls_share_one_bucket_and_registry_growth_is_bounded() {
        let (admission, now) = admission();
        drop(admission.try_enter_at(None, 100, now).unwrap());
        assert_eq!(
            admission.try_enter_at(None, 1, now).unwrap_err(),
            AdmissionError::ApplicationRateLimit
        );
        for index in 0..MAX_AUTHENTICATED_APPLICATIONS {
            let app_id = format!("app-{index}");
            let time = now + Duration::from_secs(index as u64 + 1);
            drop(admission.try_enter_at(Some(&app_id), 1, time).unwrap());
        }
        let later = now + Duration::from_secs(MAX_AUTHENTICATED_APPLICATIONS as u64 + 1);
        assert_eq!(
            admission
                .try_enter_at(Some("one-too-many"), 1, later)
                .unwrap_err(),
            AdmissionError::ApplicationRegistryFull
        );
        drop(admission.try_enter_at(Some("app-0"), 1, later).unwrap());
        drop(admission.try_enter_at(None, 1, later).unwrap());
        assert_eq!(
            admission.lock().applications.len(),
            MAX_AUTHENTICATED_APPLICATIONS + 1
        );
    }

    #[test]
    fn invalid_counts_do_not_register_apps_or_overflow() {
        let (admission, now) = admission();
        assert_eq!(
            admission.try_enter_at(Some("a"), 0, now).unwrap_err(),
            AdmissionError::InvalidItemCount
        );
        assert_eq!(
            admission
                .try_enter_at(Some("a"), usize::MAX, now)
                .unwrap_err(),
            AdmissionError::ApplicationRateLimit
        );
        assert_eq!(admission.lock().applications.len(), 1);
    }

    #[test]
    fn production_clock_methods_accept_work_and_charge_lookups() {
        let admission = Arc::new(Admission::new());
        let work = admission.try_enter(Some("a"), 1).unwrap();
        work.try_charge_lookup().unwrap();
    }
}
