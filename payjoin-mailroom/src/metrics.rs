use std::collections::hash_map::RandomState;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hyperloglogplus::{HyperLogLog, HyperLogLogPlus};
use opentelemetry::metrics::{Counter, MeterProvider, ObservableGauge, UpDownCounter};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use payjoin::directory::ShortId;

pub(crate) const TOTAL_CONNECTIONS: &str = "total_connections";
pub(crate) const ACTIVE_CONNECTIONS: &str = "active_connections";
pub(crate) const HTTP_REQUESTS: &str = "http_request_total";
pub(crate) const DB_ENTRIES: &str = "db_entries_total";
pub(crate) const UNIQUE_SHORT_IDS: &str = "unique_short_ids";

const HLL_PRECISION: u8 = 14;
const HOURLY_RETENTION_HOURS: u64 = 168; // 7 days
const DAILY_RETENTION_DAYS: u64 = 90;

type HllSketch = HyperLogLogPlus<[u8; 8], RandomState>;

const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(86400);

/// Convenience helpers for SystemTime to get integer intervals
/// since the UNIX epoch.
trait SystemTimeExt {
    fn intervals_since_epoch(&self, interval: Duration) -> u64;

    fn hours_since_epoch(&self) -> u64 { self.intervals_since_epoch(HOUR) }

    fn days_since_epoch(&self) -> u64 { self.intervals_since_epoch(DAY) }
}

impl SystemTimeExt for SystemTime {
    fn intervals_since_epoch(&self, interval: Duration) -> u64 {
        self.duration_since(UNIX_EPOCH).expect("system clock before UNIX epoch").as_secs()
            / interval.as_secs()
    }
}

fn new_sketch() -> HllSketch {
    HyperLogLogPlus::new(HLL_PRECISION, RandomState::new()).expect("precision 14 is always valid")
}

/// Estimates the number of unique ShortIds seen per time window.
/// Two tiers of HLL sketches:
/// - **Hourly** -- one sketch per hour, pruned after 7 days.
/// - **Daily** -- one sketch per day, pruned after 90 days.
struct HllSketches {
    hourly: BTreeMap<u64, HllSketch>,
    daily: BTreeMap<u64, HllSketch>,
}

impl HllSketches {
    fn new() -> Self { Self { hourly: BTreeMap::new(), daily: BTreeMap::new() } }

    // NOTE: ShortIds are passed directly to the HyperLogLog sketches held in mailroom's
    // RAM; only the resulting cardinality estimates are published to Prometheus. If
    // Prometheus ever gains native cardinality-estimation support and raw IDs are
    // exposed to it, they should be hashed (e.g. with a keyed PRF) before being
    // forwarded to avoid leaking session identifiers through the metrics pipeline.
    fn add_id(&mut self, id: &ShortId) {
        let now = SystemTime::now();
        let hour = now.hours_since_epoch();
        let day = now.days_since_epoch();

        self.hourly.entry(hour).or_insert_with(new_sketch).insert(&id.0);
        self.daily.entry(day).or_insert_with(new_sketch).insert(&id.0);

        let hourly_cutoff = hour.saturating_sub(HOURLY_RETENTION_HOURS);
        while let Some((&k, _)) = self.hourly.first_key_value() {
            if k < hourly_cutoff {
                self.hourly.pop_first();
            } else {
                break;
            }
        }
        let daily_cutoff = day.saturating_sub(DAILY_RETENTION_DAYS);
        while let Some((&k, _)) = self.daily.first_key_value() {
            if k < daily_cutoff {
                self.daily.pop_first();
            } else {
                break;
            }
        }
    }

    fn hourly_count(&mut self) -> u64 {
        let hour = SystemTime::now().hours_since_epoch();
        self.hourly.get_mut(&hour).map(|hll| hll.count().trunc() as u64).unwrap_or(0)
    }

    fn daily_count(&mut self) -> u64 {
        let day = SystemTime::now().days_since_epoch();
        self.daily.get_mut(&day).map(|hll| hll.count().trunc() as u64).unwrap_or(0)
    }

    fn weekly_count(&mut self) -> u64 {
        let today = SystemTime::now().days_since_epoch();
        self.daily_union_count(today.saturating_sub(6)..=today)
    }

    fn monthly_count(&mut self) -> u64 {
        let today = SystemTime::now().days_since_epoch();
        self.daily_union_count(today.saturating_sub(30)..=today)
    }

    fn daily_union_count<R: std::ops::RangeBounds<u64>>(&self, range: R) -> u64 {
        let mut union = new_sketch();
        for sketch in self.daily.range(range).map(|(_, v)| v) {
            union.merge(sketch).expect("same precision");
        }
        union.count().trunc() as u64
    }
}

#[derive(Clone)]
pub struct UniqueShortIdTracker {
    inner: Arc<Mutex<HllSketches>>,
}

impl UniqueShortIdTracker {
    pub fn new() -> Self { Self { inner: Arc::new(Mutex::new(HllSketches::new())) } }

    pub fn add_id(&self, id: &ShortId) {
        self.inner.lock().expect("tracker lock poisoned").add_id(id);
    }

    pub fn hourly_count(&self) -> u64 {
        self.inner.lock().expect("tracker lock poisoned").hourly_count()
    }

    pub fn daily_count(&self) -> u64 {
        self.inner.lock().expect("tracker lock poisoned").daily_count()
    }

    pub fn weekly_count(&self) -> u64 {
        self.inner.lock().expect("tracker lock poisoned").weekly_count()
    }

    pub fn monthly_count(&self) -> u64 {
        self.inner.lock().expect("tracker lock poisoned").monthly_count()
    }
}

impl Default for UniqueShortIdTracker {
    fn default() -> Self { Self::new() }
}

#[derive(Clone)]
pub struct MetricsService {
    /// Total number of HTTP requests by endpoint type, method, and status code
    http_requests_total: Counter<u64>,
    /// Total number of connections
    total_connections: Counter<u64>,
    /// Number of active connections right now
    active_connections: UpDownCounter<i64>,
    /// Total v1/v2 mailbox entries written, labelled by `version`
    db_entries_total: Counter<u64>,
    tracker: UniqueShortIdTracker,
    _unique_ids_gauge: Option<Arc<ObservableGauge<u64>>>,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PayjoinVersion {
    /// BIP 78 Payjoin
    One = 1,
    /// BIP 77 Async Payjoin
    Two = 2,
}

impl fmt::Display for PayjoinVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { (*self as u8).fmt(f) }
}

impl MetricsService {
    pub fn new(provider: Option<SdkMeterProvider>) -> Self {
        let has_reader = provider.is_some();
        let provider = provider.unwrap_or_default();
        let meter = provider.meter("payjoin-mailroom");

        let http_requests_total = meter
            .u64_counter(HTTP_REQUESTS)
            .with_description("Total number of HTTP requests")
            .build();

        let total_connections = meter
            .u64_counter(TOTAL_CONNECTIONS)
            .with_description("Total number of connections")
            .build();

        let active_connections = meter
            .i64_up_down_counter(ACTIVE_CONNECTIONS)
            .with_description("Number of active connections")
            .build();

        let db_entries_total = meter
            .u64_counter(DB_ENTRIES)
            .with_description("Total mailbox entries stored by protocol version")
            .build();

        let tracker = UniqueShortIdTracker::new();

        let unique_ids_gauge = if has_reader {
            let gauge_tracker = tracker.clone();
            Some(Arc::new(
                meter
                    .u64_observable_gauge(UNIQUE_SHORT_IDS)
                    .with_description("Estimated unique short IDs")
                    .with_callback(move |observer| {
                        observer.observe(
                            gauge_tracker.hourly_count(),
                            &[KeyValue::new("interval", "hourly")],
                        );
                        observer.observe(
                            gauge_tracker.daily_count(),
                            &[KeyValue::new("interval", "daily")],
                        );
                        observer.observe(
                            gauge_tracker.weekly_count(),
                            &[KeyValue::new("interval", "weekly")],
                        );
                        observer.observe(
                            gauge_tracker.monthly_count(),
                            &[KeyValue::new("interval", "monthly")],
                        );
                    })
                    .build(),
            ))
        } else {
            None
        };

        Self {
            http_requests_total,
            total_connections,
            active_connections,
            db_entries_total,
            tracker,
            _unique_ids_gauge: unique_ids_gauge,
        }
    }

    pub fn record_http_request(&self, endpoint: &str, method: &str, status_code: u16) {
        self.http_requests_total.add(
            1,
            &[
                KeyValue::new("endpoint", endpoint.to_string()),
                KeyValue::new("method", method.to_string()),
                KeyValue::new("status_code", status_code.to_string()),
            ],
        );
    }

    pub fn record_connection_open(&self) {
        self.total_connections.add(1, &[]);
        self.active_connections.add(1, &[]);
    }

    pub fn record_connection_close(&self) { self.active_connections.add(-1, &[]); }

    pub fn record_db_entry(&self, version: PayjoinVersion) {
        self.db_entries_total.add(1, &[KeyValue::new("version", version.to_string())]);
    }

    pub fn record_short_id(&self, id: &ShortId) { self.tracker.add_id(id); }
}
