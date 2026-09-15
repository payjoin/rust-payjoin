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

pub(crate) const HTTP_REQUESTS_STARTED: &str = "http_requests_started_total";
pub(crate) const HTTP_REQUESTS_IN_FLIGHT: &str = "http_requests_in_flight";
pub(crate) const ACTIVE_TUNNELS: &str = "bootstrap_active_tunnels";
pub(crate) const TUNNEL_SHEDS: &str = "bootstrap_tunnel_shed_total";
pub(crate) const HTTP_REQUESTS_TOTAL: &str = "http_requests_total";
pub(crate) const DB_ENTRIES: &str = "db_entries_total";
pub(crate) const UNIQUE_SHORT_IDS: &str = "unique_short_ids";

// Names of the coarse, settled-window gauges that make up the entire export
// surface. Everything above stays in-process; only these leave the operator
// boundary, and only after passing through an ExportPolicy.
pub(crate) const HTTP_REQUESTS_WEEKLY: &str = "http_requests_weekly";
pub(crate) const HTTP_REQUESTS_STARTED_WEEKLY: &str = "http_requests_started_weekly";
pub(crate) const DB_ENTRIES_WEEKLY: &str = "db_entries_weekly";
pub(crate) const TUNNEL_SHEDS_WEEKLY: &str = "bootstrap_tunnel_sheds_weekly";
pub(crate) const UNIQUE_SHORT_IDS_WEEKLY: &str = "unique_short_ids_weekly";

const HLL_PRECISION: u8 = 14;
const HOURLY_RETENTION_HOURS: u64 = 168; // 7 days
const DAILY_RETENTION_DAYS: u64 = 90;

/// Number of UTC days in each exported reporting window.
///
/// Counts that leave the operator boundary cover one completed, fixed UTC
/// week. The in-progress week is never exported, preventing live probing and
/// avoiding the daily differencing possible with a sliding window.
pub const EXPORT_WINDOW_DAYS: u64 = 7;

/// Day since the UNIX epoch for Monday 1970-01-05, the reporting-week anchor.
const REPORTING_WEEK_ANCHOR_DAY: u64 = 4;

/// Default for [`ExportPolicy::suppression_threshold`].
pub const DEFAULT_SUPPRESSION_THRESHOLD: u64 = 10;

/// Default for [`ExportPolicy::quantization_bin`].
pub const DEFAULT_QUANTIZATION_BIN: u64 = 5;

/// Coarsening applied to every count before it leaves the operator boundary.
///
/// Exported aggregates are visible outside the operator, so small counts and
/// precise integers are a linkage risk: a weekly count of 1-2 at a small
/// operator can be tied to a known real-world event, and precise integers let
/// an attacker who sends known traffic infer the remainder by subtraction.
/// Below-threshold windows are dropped entirely (rounding them would still
/// reveal that a small count existed) and surviving counts are quantized.
#[derive(Debug, Clone, Copy)]
pub struct ExportPolicy {
    /// Windows whose raw count is below this are not exported at all.
    pub suppression_threshold: u64,
    /// Surviving counts are rounded to the nearest multiple of this bin.
    /// A value of 0 is treated as 1 (no rounding).
    pub quantization_bin: u64,
}

impl Default for ExportPolicy {
    fn default() -> Self {
        Self {
            suppression_threshold: DEFAULT_SUPPRESSION_THRESHOLD,
            quantization_bin: DEFAULT_QUANTIZATION_BIN,
        }
    }
}

impl ExportPolicy {
    /// Applies suppression, then quantization, to a raw windowed count.
    ///
    /// Suppression is evaluated on the raw count before any rounding, so a
    /// count just under the threshold is dropped rather than rounded up into
    /// visibility. Rounding is to the nearest multiple of the bin, with ties
    /// rounding up.
    pub fn apply(&self, raw: u64) -> Option<u64> {
        if raw < self.suppression_threshold {
            return None;
        }
        let bin = self.quantization_bin.max(1);
        Some(raw.saturating_add(bin / 2) / bin * bin)
    }
}

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

fn reporting_week(day: u64) -> u64 {
    day.saturating_sub(REPORTING_WEEK_ANCHOR_DAY) / EXPORT_WINDOW_DAYS
}

fn reporting_week_start(week: u64) -> u64 { week * EXPORT_WINDOW_DAYS + REPORTING_WEEK_ANCHOR_DAY }

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

    /// Unique-id estimate over the most recently completed UTC reporting
    /// week. This is the only cardinality figure eligible for export.
    fn settled_weekly_count(&mut self) -> u64 {
        let current_week = reporting_week(SystemTime::now().days_since_epoch());
        let settled_week = current_week.saturating_sub(1);
        let start = reporting_week_start(settled_week);
        self.daily_union_count(start..=start + EXPORT_WINDOW_DAYS - 1)
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

    pub(crate) fn settled_weekly_count(&self) -> u64 {
        self.inner.lock().expect("tracker lock poisoned").settled_weekly_count()
    }
}

impl Default for UniqueShortIdTracker {
    fn default() -> Self { Self::new() }
}

/// Per-UTC-week counter buckets backing the settled-window export.
///
/// Weeks are anchored on Monday UTC. Each `add` retains only the active and
/// immediately preceding week, the only two windows relevant to export.
#[derive(Default)]
struct WeeklyBuckets {
    weeks: BTreeMap<u64, u64>,
}

impl WeeklyBuckets {
    fn add(&mut self, day: u64) {
        let week = reporting_week(day);
        *self.weeks.entry(week).or_insert(0) += 1;
        let cutoff = week.saturating_sub(1);
        while let Some((&k, _)) = self.weeks.first_key_value() {
            if k < cutoff {
                self.weeks.pop_first();
            } else {
                break;
            }
        }
    }

    /// Count in the most recently completed fixed UTC week.
    ///
    /// The in-progress week is excluded, so traffic sent now is invisible
    /// until the week completes. Releasing fixed weeks also prevents a viewer
    /// from differencing adjacent rolling windows to recover daily traffic.
    fn settled_window_count(&self, today: u64) -> u64 {
        self.weeks.get(&reporting_week(today).saturating_sub(1)).copied().unwrap_or(0)
    }
}

/// In-process weekly accounting for every count eligible for export.
///
/// Point-in-time gauges (requests in flight, open tunnels) are deliberately
/// absent: they are live values and never leave the process.
#[derive(Default)]
struct ExportWindows {
    http_requests: WeeklyBuckets,
    http_requests_started: WeeklyBuckets,
    db_entries: WeeklyBuckets,
    tunnel_sheds: WeeklyBuckets,
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
    /// Weekly buckets feeding the settled-window export gauges.
    windows: Arc<Mutex<ExportWindows>>,
    _unique_ids_gauge: Option<Arc<ObservableGauge<u64>>>,
    _export_gauges: Vec<Arc<ObservableGauge<u64>>>,
    /// Keeps the export pipeline alive for as long as the service exists.
    _export_provider: Option<SdkMeterProvider>,
}

impl fmt::Debug for MetricsService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetricsService").finish_non_exhaustive()
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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
            windows: Arc::new(Mutex::new(ExportWindows::default())),
            _unique_ids_gauge: unique_ids_gauge,
            _export_gauges: Vec::new(),
            _export_provider: None,
        }
    }

    /// Builds a service whose precise instruments stay in-process and whose
    /// only exported instruments are the coarse settled-window gauges
    /// registered on `export_provider`, filtered through `policy`.
    ///
    /// This is the constructor for anything that exports beyond the operator
    /// boundary: no live counter, no in-progress window, and no count that
    /// survives the policy's suppression threshold unquantized ever reaches
    /// the export provider.
    pub fn with_export(export_provider: &SdkMeterProvider, policy: ExportPolicy) -> Self {
        let mut service = Self::new(None);
        service.register_export_gauges(export_provider, policy);
        service._export_provider = Some(export_provider.clone());
        service
    }

    fn register_export_gauges(&mut self, provider: &SdkMeterProvider, policy: ExportPolicy) {
        let meter = provider.meter("payjoin-mailroom");

        let windows = self.windows.clone();
        let http_requests_weekly = meter
            .u64_observable_gauge(HTTP_REQUESTS_WEEKLY)
            .with_description(
                "Completed HTTP requests in the last settled UTC reporting week, coarsened",
            )
            .with_callback(move |observer| {
                let today = SystemTime::now().days_since_epoch();
                let windows = windows.lock().expect("windows lock poisoned");
                if let Some(count) = policy.apply(windows.http_requests.settled_window_count(today))
                {
                    observer.observe(count, &[]);
                }
            })
            .build();

        let windows = self.windows.clone();
        let http_requests_started_weekly = meter
            .u64_observable_gauge(HTTP_REQUESTS_STARTED_WEEKLY)
            .with_description(
                "HTTP requests started in the last settled UTC reporting week, coarsened",
            )
            .with_callback(move |observer| {
                let today = SystemTime::now().days_since_epoch();
                let windows = windows.lock().expect("windows lock poisoned");
                if let Some(count) =
                    policy.apply(windows.http_requests_started.settled_window_count(today))
                {
                    observer.observe(count, &[]);
                }
            })
            .build();

        let windows = self.windows.clone();
        let db_entries_weekly = meter
            .u64_observable_gauge(DB_ENTRIES_WEEKLY)
            .with_description(
                "Mailbox entries stored in the last settled UTC reporting week, coarsened",
            )
            .with_callback(move |observer| {
                let today = SystemTime::now().days_since_epoch();
                let windows = windows.lock().expect("windows lock poisoned");
                if let Some(count) = policy.apply(windows.db_entries.settled_window_count(today)) {
                    observer.observe(count, &[]);
                }
            })
            .build();

        let windows = self.windows.clone();
        let tunnel_sheds_weekly = meter
            .u64_observable_gauge(TUNNEL_SHEDS_WEEKLY)
            .with_description(
                "OHTTP bootstrap tunnels shed in the last settled UTC reporting week, coarsened",
            )
            .with_callback(move |observer| {
                let today = SystemTime::now().days_since_epoch();
                let windows = windows.lock().expect("windows lock poisoned");
                if let Some(count) = policy.apply(windows.tunnel_sheds.settled_window_count(today))
                {
                    observer.observe(count, &[]);
                }
            })
            .build();

        let tracker = self.tracker.clone();
        let unique_short_ids_weekly = meter
            .u64_observable_gauge(UNIQUE_SHORT_IDS_WEEKLY)
            .with_description(
                "Estimated unique short IDs in the last settled UTC reporting week, coarsened",
            )
            .with_callback(move |observer| {
                if let Some(count) = policy.apply(tracker.settled_weekly_count()) {
                    observer.observe(count, &[]);
                }
            })
            .build();

        self._export_gauges = vec![
            Arc::new(http_requests_weekly),
            Arc::new(http_requests_started_weekly),
            Arc::new(db_entries_weekly),
            Arc::new(tunnel_sheds_weekly),
            Arc::new(unique_short_ids_weekly),
        ];
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
        let day = SystemTime::now().days_since_epoch();
        self.windows.lock().expect("windows lock poisoned").http_requests.add(day);
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
        let day = SystemTime::now().days_since_epoch();
        self.windows.lock().expect("windows lock poisoned").http_requests_started.add(day);
        InFlightGuard { in_flight: self.http_requests_in_flight.clone() }
    }

    pub fn record_tunnel_open(&self) { self.active_tunnels.add(1, &[]); }

    pub fn record_tunnel_close(&self) { self.active_tunnels.add(-1, &[]); }

    pub fn record_tunnel_shed(&self) {
        self.tunnel_sheds_total.add(1, &[]);
        let day = SystemTime::now().days_since_epoch();
        self.windows.lock().expect("windows lock poisoned").tunnel_sheds.add(day);
    }

    pub fn record_db_entry(&self, version: PayjoinVersion) {
        self.db_entries_total.add(1, &[KeyValue::new("version", version.to_string())]);
        let day = SystemTime::now().days_since_epoch();
        self.windows.lock().expect("windows lock poisoned").db_entries.add(day);
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

    #[test]
    fn weekly_buckets_exclude_the_in_progress_week() {
        let mut buckets = WeeklyBuckets::default();
        let settled_day = reporting_week_start(100) + 1;
        let active_day = reporting_week_start(101) + 1;
        for _ in 0..3 {
            buckets.add(settled_day);
            buckets.add(active_day);
        }
        assert_eq!(buckets.settled_window_count(active_day), 3);
    }

    #[test]
    fn weekly_buckets_release_non_overlapping_windows_and_prune() {
        let mut buckets = WeeklyBuckets::default();
        let first = reporting_week_start(100);
        buckets.add(first);
        buckets.add(first);
        assert_eq!(buckets.settled_window_count(reporting_week_start(101)), 2);
        assert_eq!(buckets.settled_window_count(reporting_week_start(102)), 0);
        buckets.add(reporting_week_start(102));
        assert_eq!(buckets.weeks.len(), 1, "older reporting weeks are pruned on add");
    }

    /// Collects (metric name, attribute keys per data point) for everything
    /// the exporter saw. Metrics with no data points still appear once with
    /// an empty key list so name assertions can see them.
    fn exported_points(exporter: &InMemoryMetricExporter) -> Vec<(String, Vec<String>)> {
        let mut points = Vec::new();
        for rm in exporter.get_finished_metrics().expect("metrics").iter() {
            for sm in rm.scope_metrics() {
                for m in sm.metrics() {
                    let name = m.name().to_string();
                    match m.data() {
                        AggregatedMetrics::U64(MetricData::Gauge(gauge)) =>
                            for dp in gauge.data_points() {
                                let keys =
                                    dp.attributes().map(|kv| kv.key.as_str().to_string()).collect();
                                points.push((name.clone(), keys));
                            },
                        _ => points.push((name.clone(), Vec::new())),
                    }
                }
            }
        }
        points
    }

    fn in_memory_provider() -> (InMemoryMetricExporter, SdkMeterProvider) {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        (exporter, provider)
    }

    /// The export surface must contain only the coarse settled-window gauges
    /// with no metric attributes. Anything else on the export provider
    /// is a leak: precise counters, live gauges, or an attribute that could
    /// identify the operator or a client (hostname, IP, instance id, path).
    #[test]
    fn export_surface_is_windowed_gauges_with_allowed_attributes_only() {
        const EXPORTED_METRICS: &[&str] = &[
            HTTP_REQUESTS_WEEKLY,
            HTTP_REQUESTS_STARTED_WEEKLY,
            DB_ENTRIES_WEEKLY,
            TUNNEL_SHEDS_WEEKLY,
            UNIQUE_SHORT_IDS_WEEKLY,
        ];

        let (exporter, provider) = in_memory_provider();
        // A permissive policy so every gauge observes a point (today's traffic
        // is settled to 0, which threshold 0 still emits) and its attributes
        // become visible to the audit.
        let policy = ExportPolicy { suppression_threshold: 0, quantization_bin: 1 };
        let metrics = MetricsService::with_export(&provider, policy);

        metrics.record_http_request("/health", "GET", 200);
        drop(metrics.track_request());
        metrics.record_db_entry(PayjoinVersion::Two);
        metrics.record_tunnel_shed();
        metrics.record_short_id(&ShortId([0; 8]));

        provider.force_flush().expect("flush failed");

        let points = exported_points(&exporter);
        let names: std::collections::HashSet<&str> =
            points.iter().map(|(name, _)| name.as_str()).collect();
        for expected in EXPORTED_METRICS {
            assert!(names.contains(expected), "{expected} missing from the export surface");
        }
        for (name, keys) in &points {
            assert!(
                EXPORTED_METRICS.contains(&name.as_str()),
                "unexpected metric {name} on the export provider"
            );
            assert!(
                keys.is_empty(),
                "disallowed attribute keys {keys:?} on exported metric {name}"
            );
        }
    }

    /// Under the default policy, traffic recorded today must be invisible in
    /// the export: the in-progress window is never emitted, so there is no
    /// live counter for an active prober to watch move.
    #[test]
    fn export_omits_in_progress_window() {
        let (exporter, provider) = in_memory_provider();
        let metrics = MetricsService::with_export(&provider, ExportPolicy::default());

        for _ in 0..100 {
            metrics.record_http_request("/health", "GET", 200);
        }
        metrics.record_short_id(&ShortId([1; 8]));

        provider.force_flush().expect("flush failed");

        // Today's traffic sits in the in-progress bucket, so every settled
        // window is 0 and falls under the suppression threshold: the flush
        // must carry no data points at all.
        let points = exported_points(&exporter);
        assert!(
            points.is_empty(),
            "data points left the process while their window was in progress: {points:?}"
        );
    }

    /// Precise instruments registered via `new` are unaffected by the export
    /// pipeline: an operator's own reader still sees exact counts.
    #[test]
    fn precise_local_metrics_remain_exact() {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let metrics = MetricsService::new(Some(provider.clone()));

        for _ in 0..3 {
            metrics.record_http_request("/health", "GET", 200);
        }
        provider.force_flush().expect("flush failed");
        assert_eq!(sum_u64(&exporter, HTTP_REQUESTS_TOTAL), 3);
    }

    #[test]
    fn export_policy_suppresses_below_threshold() {
        let policy = ExportPolicy::default();
        assert_eq!(policy.apply(0), None, "zero is below the default threshold");
        assert_eq!(policy.apply(9), None, "counts under the threshold are dropped, not rounded");
        assert_eq!(policy.apply(10), Some(10), "the threshold itself is exported");
    }

    #[test]
    fn export_policy_quantizes_to_nearest_bin() {
        let policy = ExportPolicy { suppression_threshold: 0, quantization_bin: 5 };
        assert_eq!(policy.apply(11), Some(10), "11 rounds down to the nearest bin");
        assert_eq!(policy.apply(12), Some(10), "12 rounds down to the nearest bin");
        assert_eq!(policy.apply(13), Some(15), "13 rounds up to the nearest bin");
        assert_eq!(policy.apply(15), Some(15), "exact multiples are unchanged");
        assert_eq!(policy.apply(17), Some(15), "17 rounds down");
        assert_eq!(policy.apply(18), Some(20), "18 rounds up");
    }

    #[test]
    fn export_policy_suppression_precedes_quantization() {
        // 8 would quantize to 10, meeting the threshold, but suppression is
        // decided on the raw count: small precise counts are the leak, so
        // they must be dropped rather than rounded into visibility.
        let policy = ExportPolicy { suppression_threshold: 10, quantization_bin: 5 };
        assert_eq!(policy.apply(8), None);
    }

    #[test]
    fn export_policy_degenerate_bins() {
        let identity = ExportPolicy { suppression_threshold: 0, quantization_bin: 1 };
        assert_eq!(identity.apply(7), Some(7), "bin of 1 leaves counts unchanged");
        let zero_bin = ExportPolicy { suppression_threshold: 0, quantization_bin: 0 };
        assert_eq!(zero_bin.apply(7), Some(7), "bin of 0 is treated as 1");
        let large = ExportPolicy { suppression_threshold: 0, quantization_bin: 5 };
        assert_eq!(large.apply(u64::MAX), Some(u64::MAX / 5 * 5), "no overflow near u64::MAX");
    }
}
