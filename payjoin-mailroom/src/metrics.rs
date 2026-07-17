use std::collections::hash_map::RandomState;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "telemetry")]
pub fn build_telemetry_resource(operator_domain: &str) -> opentelemetry_sdk::Resource {
    use opentelemetry::KeyValue;
    opentelemetry_sdk::Resource::builder()
        .with_service_name("payjoin-mailroom")
        .with_attribute(KeyValue::new("operator.domain", operator_domain.to_string()))
        .with_attribute(KeyValue::new("service.instance.id", uuid::Uuid::new_v4().to_string()))
        .build()
}

use hyperloglogplus::{HyperLogLog, HyperLogLogPlus};
use opentelemetry::metrics::{Counter, MeterProvider, ObservableGauge, UpDownCounter};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use payjoin::directory::ShortId;

pub(crate) const HTTP_REQUESTS_STARTED: &str = "http_requests_started_total";
pub(crate) const HTTP_REQUESTS_IN_FLIGHT: &str = "http_requests_in_flight";
pub(crate) const ACTIVE_TUNNELS: &str = "bootstrap_active_tunnels";
pub(crate) const TUNNEL_SHEDS: &str = "bootstrap_tunnel_shed_total";
pub(crate) const HTTP_REQUESTS_TOTAL: &str = "http_requests_total";
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
    /// Total number of HTTP requests that ran to completion, by endpoint
    /// type, method, and status code. Recorded after the handler returns, so
    /// requests that did not complete are absent. The gap from
    /// `http_requests_started_total` is therefore an upper bound on dropped
    /// requests -- client cancellation before the handler returned, requests
    /// still in flight at scrape time, or a handler panic -- not a precise
    /// cancellation count.
    http_requests_total: Counter<u64>,
    /// Total number of HTTP requests started (counted before the handler runs)
    http_requests_started_total: Counter<u64>,
    /// Number of HTTP requests currently in flight
    http_requests_in_flight: UpDownCounter<i64>,
    /// Number of OHTTP bootstrap tunnels open right now
    active_tunnels: UpDownCounter<i64>,
    /// Total OHTTP bootstrap tunnels shed at the concurrency cap
    tunnel_sheds_total: Counter<u64>,
    /// Total v1/v2 mailbox entries written, labelled by `version`
    db_entries_total: Counter<u64>,
    tracker: UniqueShortIdTracker,
    _unique_ids_gauge: Option<Arc<ObservableGauge<u64>>>,
}

impl fmt::Debug for MetricsService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetricsService").finish_non_exhaustive()
    }
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
            .u64_counter(HTTP_REQUESTS_TOTAL)
            .with_description("Total number of HTTP requests completed")
            .build();

        let http_requests_started_total = meter
            .u64_counter(HTTP_REQUESTS_STARTED)
            .with_description("Total number of HTTP requests started")
            .build();

        let http_requests_in_flight = meter
            .i64_up_down_counter(HTTP_REQUESTS_IN_FLIGHT)
            .with_description("Number of HTTP requests currently in flight")
            .build();

        let active_tunnels = meter
            .i64_up_down_counter(ACTIVE_TUNNELS)
            .with_description("Number of OHTTP bootstrap tunnels open right now")
            .build();

        let tunnel_sheds_total = meter
            .u64_counter(TUNNEL_SHEDS)
            .with_description("Total OHTTP bootstrap tunnels shed at the concurrency cap")
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
            http_requests_started_total,
            http_requests_in_flight,
            active_tunnels,
            tunnel_sheds_total,
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

    /// Records the start of an HTTP request and returns a guard that marks it
    /// finished when dropped.
    ///
    /// Increments `http_requests_started_total` and `http_requests_in_flight`
    /// immediately. The returned [`InFlightGuard`] decrements
    /// `http_requests_in_flight` in its `Drop`, so the in-flight count is
    /// corrected on normal return, on client cancellation (the request future
    /// is dropped), and on a handler panic during unwind -- none of which a
    /// manual decrement after the handler could guarantee.
    pub(crate) fn track_request(&self) -> InFlightGuard {
        self.http_requests_started_total.add(1, &[]);
        self.http_requests_in_flight.add(1, &[]);
        InFlightGuard { in_flight: self.http_requests_in_flight.clone() }
    }

    pub fn record_tunnel_open(&self) { self.active_tunnels.add(1, &[]); }

    pub fn record_tunnel_close(&self) { self.active_tunnels.add(-1, &[]); }

    pub fn record_tunnel_shed(&self) { self.tunnel_sheds_total.add(1, &[]); }

    pub fn record_db_entry(&self, version: PayjoinVersion) {
        self.db_entries_total.add(1, &[KeyValue::new("version", version.to_string())]);
    }

    pub fn record_short_id(&self, id: &ShortId) { self.tracker.add_id(id); }
}

/// Guard that decrements `http_requests_in_flight` when dropped.
///
/// Returned by [`MetricsService::track_request`] and held for the duration of a
/// request. Because the decrement happens in `Drop`, the in-flight count is
/// corrected whether the request returns normally, is cancelled (the future is
/// dropped without completing), or panics. A manual decrement placed after the
/// request future would be skipped on cancellation and on unwind, leaking the
/// count upward.
pub(crate) struct InFlightGuard {
    in_flight: UpDownCounter<i64>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        // Kept trivial and non-panicking: this runs during stack unwinding.
        self.in_flight.add(-1, &[]);
    }
}

#[cfg(test)]
mod tests {
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};

    #[cfg(feature = "telemetry")]
    #[test]
    fn telemetry_resource_attributes() {
        use opentelemetry::Key;

        use super::build_telemetry_resource;

        let r1 = build_telemetry_resource("example.com");

        assert_eq!(
            r1.get(&Key::from("service.name")),
            Some(opentelemetry::Value::String("payjoin-mailroom".into())),
            "service.name must be payjoin-mailroom"
        );
        assert_eq!(
            r1.get(&Key::from("operator.domain")),
            Some(opentelemetry::Value::String("example.com".into())),
            "operator.domain must match configured value"
        );

        let id1 = r1
            .get(&Key::from("service.instance.id"))
            .expect("service.instance.id must be present")
            .to_string();
        assert!(!id1.is_empty(), "service.instance.id must not be empty");
        uuid::Uuid::parse_str(&id1).expect("service.instance.id must parse as a UUID");

        let r2 = build_telemetry_resource("example.com");
        let id2 = r2
            .get(&Key::from("service.instance.id"))
            .expect("service.instance.id must be present in second resource")
            .to_string();
        assert_ne!(id1, id2, "service.instance.id must differ across constructions");
    }
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};

    use super::*;

    fn sum_i64(exporter: &InMemoryMetricExporter, name: &str) -> i64 {
        let finished = exporter.get_finished_metrics().expect("metrics");
        finished
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .filter(|m| m.name() == name)
            .flat_map(|m| match m.data() {
                AggregatedMetrics::I64(MetricData::Sum(sum)) =>
                    sum.data_points().map(|dp| dp.value()).collect::<Vec<_>>(),
                _ => Vec::new(),
            })
            .sum()
    }

    fn sum_u64(exporter: &InMemoryMetricExporter, name: &str) -> u64 {
        let finished = exporter.get_finished_metrics().expect("metrics");
        finished
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .filter(|m| m.name() == name)
            .flat_map(|m| match m.data() {
                AggregatedMetrics::U64(MetricData::Sum(sum)) =>
                    sum.data_points().map(|dp| dp.value()).collect::<Vec<_>>(),
                _ => Vec::new(),
            })
            .sum()
    }

    #[test]
    fn track_request_guard_decrements_in_flight_on_drop() {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let metrics = MetricsService::new(Some(provider.clone()));

        // Two requests start; one finishes (its guard is dropped at the end of
        // the inner scope), one is still in flight across the flush.
        let _held = metrics.track_request();
        {
            let _finished = metrics.track_request();
        }

        provider.force_flush().expect("flush failed");

        assert_eq!(
            sum_u64(&exporter, HTTP_REQUESTS_STARTED),
            2,
            "track_request increments the started counter once per call"
        );
        assert_eq!(
            sum_i64(&exporter, HTTP_REQUESTS_IN_FLIGHT),
            1,
            "two started, one guard dropped => exactly one still in flight"
        );
    }

    #[test]
    fn in_flight_guard_decrements_during_panic_unwind() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let metrics = MetricsService::new(Some(provider.clone()));

        // A handler that panics while holding the guard must still decrement the
        // in-flight count as the stack unwinds (the crate builds panic=unwind).
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _guard = metrics.track_request();
            panic!("handler blew up mid-request");
        }));
        assert!(result.is_err(), "the closure was expected to panic");

        provider.force_flush().expect("flush failed");

        assert_eq!(
            sum_u64(&exporter, HTTP_REQUESTS_STARTED),
            1,
            "the request was counted as started before the panic"
        );
        assert_eq!(
            sum_i64(&exporter, HTTP_REQUESTS_IN_FLIGHT),
            0,
            "the guard's Drop decremented in-flight while unwinding"
        );
    }
}
