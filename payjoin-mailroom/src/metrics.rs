use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

// Names of the coarse, settled-window gauges that make up the entire export
// surface. Everything above stays in-process; only these leave the operator
// boundary.
pub(crate) const HTTP_REQUESTS_WEEKLY: &str = "http_requests_weekly";
pub(crate) const HTTP_REQUESTS_STARTED_WEEKLY: &str = "http_requests_started_weekly";
pub(crate) const DB_ENTRIES_WEEKLY: &str = "db_entries_weekly";
pub(crate) const TUNNEL_SHEDS_WEEKLY: &str = "bootstrap_tunnel_sheds_weekly";
pub(crate) const UNIQUE_SHORT_IDS_WEEKLY: &str = "unique_short_ids_weekly";

/// Number of UTC days in each exported reporting window.
///
/// Counts that leave the operator boundary cover one completed, fixed UTC
/// week. The in-progress week is never exported, preventing live probing and
/// avoiding the daily differencing possible with a sliding window.
pub const EXPORT_WINDOW_DAYS: u64 = 7;

/// Day since the UNIX epoch for Monday 1970-01-05, the reporting-week anchor.
const REPORTING_WEEK_ANCHOR_DAY: u64 = 4;

/// Most distinct mailbox IDs one reporting week keeps.
///
/// Far above any honest week of traffic. Past it the window stops
/// accepting IDs and reports the cap, so a week that exports exactly this
/// value was flooded rather than counted. At the cap a window holds 80 MB
/// of IDs.
pub const UNIQUE_SHORT_IDS_CAP: usize = 10_000_000;

const DAY: Duration = Duration::from_secs(86400);

/// Convenience helpers for SystemTime to get integer intervals
/// since the UNIX epoch.
trait SystemTimeExt {
    fn intervals_since_epoch(&self, interval: Duration) -> u64;

    fn days_since_epoch(&self) -> u64 { self.intervals_since_epoch(DAY) }
}

fn reporting_week(day: u64) -> u64 {
    day.saturating_sub(REPORTING_WEEK_ANCHOR_DAY) / EXPORT_WINDOW_DAYS
}

#[cfg(test)]
fn reporting_week_start(week: u64) -> u64 { week * EXPORT_WINDOW_DAYS + REPORTING_WEEK_ANCHOR_DAY }

impl SystemTimeExt for SystemTime {
    fn intervals_since_epoch(&self, interval: Duration) -> u64 {
        self.duration_since(UNIX_EPOCH).expect("system clock before UNIX epoch").as_secs()
            / interval.as_secs()
    }
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

/// Distinct mailbox IDs touched per UTC reporting week.
///
/// Same Monday-anchored windows and same two-week retention as
/// [`WeeklyBuckets`]. A short ID is already the first eight bytes of a
/// SHA-256, so the IDs are kept as they are and the settled count is the
/// exact size of the set, bounded by [`UNIQUE_SHORT_IDS_CAP`].
#[derive(Default)]
struct WeeklyIdSets {
    weeks: BTreeMap<u64, HashSet<[u8; 8]>>,
}

impl WeeklyIdSets {
    fn add(&mut self, day: u64, id: [u8; 8]) {
        let week = reporting_week(day);
        let ids = self.weeks.entry(week).or_default();
        if ids.len() < UNIQUE_SHORT_IDS_CAP {
            ids.insert(id);
        }
        let cutoff = week.saturating_sub(1);
        while let Some((&k, _)) = self.weeks.first_key_value() {
            if k < cutoff {
                self.weeks.pop_first();
            } else {
                break;
            }
        }
    }

    /// Distinct IDs in the most recently completed fixed UTC week; see
    /// [`WeeklyBuckets::settled_window_count`].
    fn settled_window_count(&self, today: u64) -> u64 {
        self.weeks
            .get(&reporting_week(today).saturating_sub(1))
            .map(|ids| ids.len() as u64)
            .unwrap_or(0)
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
    unique_short_ids: WeeklyIdSets,
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
    /// Weekly buckets feeding the settled-window export gauges.
    windows: Arc<Mutex<ExportWindows>>,
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

        Self {
            http_requests_total,
            http_requests_started_total,
            http_requests_in_flight,
            active_tunnels,
            tunnel_sheds_total,
            db_entries_total,
            windows: Arc::new(Mutex::new(ExportWindows::default())),
            _export_gauges: Vec::new(),
            _export_provider: None,
        }
    }

    /// Builds a service whose precise instruments stay in-process and whose
    /// only exported instruments are the coarse settled-window gauges
    /// registered on `export_provider`.
    ///
    /// This is the constructor for anything that exports beyond the operator
    /// boundary: no live counter and no in-progress window ever reaches the
    /// export provider.
    pub fn with_export(export_provider: &SdkMeterProvider) -> Self {
        let mut service = Self::new(None);
        service.register_export_gauges(export_provider);
        service._export_provider = Some(export_provider.clone());
        service
    }

    fn register_export_gauges(&mut self, provider: &SdkMeterProvider) {
        let meter = provider.meter("payjoin-mailroom");

        let windows = self.windows.clone();
        let http_requests_weekly = meter
            .u64_observable_gauge(HTTP_REQUESTS_WEEKLY)
            .with_description("Completed HTTP requests in the last settled UTC reporting week")
            .with_callback(move |observer| {
                let today = SystemTime::now().days_since_epoch();
                let windows = windows.lock().expect("windows lock poisoned");
                observer.observe(windows.http_requests.settled_window_count(today), &[]);
            })
            .build();

        let windows = self.windows.clone();
        let http_requests_started_weekly = meter
            .u64_observable_gauge(HTTP_REQUESTS_STARTED_WEEKLY)
            .with_description("HTTP requests started in the last settled UTC reporting week")
            .with_callback(move |observer| {
                let today = SystemTime::now().days_since_epoch();
                let windows = windows.lock().expect("windows lock poisoned");
                observer.observe(windows.http_requests_started.settled_window_count(today), &[]);
            })
            .build();

        let windows = self.windows.clone();
        let db_entries_weekly = meter
            .u64_observable_gauge(DB_ENTRIES_WEEKLY)
            .with_description("Mailbox entries stored in the last settled UTC reporting week")
            .with_callback(move |observer| {
                let today = SystemTime::now().days_since_epoch();
                let windows = windows.lock().expect("windows lock poisoned");
                observer.observe(windows.db_entries.settled_window_count(today), &[]);
            })
            .build();

        let windows = self.windows.clone();
        let tunnel_sheds_weekly = meter
            .u64_observable_gauge(TUNNEL_SHEDS_WEEKLY)
            .with_description("OHTTP bootstrap tunnels shed in the last settled UTC reporting week")
            .with_callback(move |observer| {
                let today = SystemTime::now().days_since_epoch();
                let windows = windows.lock().expect("windows lock poisoned");
                observer.observe(windows.tunnel_sheds.settled_window_count(today), &[]);
            })
            .build();

        let windows = self.windows.clone();
        let unique_short_ids_weekly = meter
            .u64_observable_gauge(UNIQUE_SHORT_IDS_WEEKLY)
            .with_description("Distinct mailbox IDs touched in the last settled UTC reporting week")
            .with_callback(move |observer| {
                let today = SystemTime::now().days_since_epoch();
                let windows = windows.lock().expect("windows lock poisoned");
                observer.observe(windows.unique_short_ids.settled_window_count(today), &[]);
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

    pub fn record_short_id(&self, id: &ShortId) {
        let day = SystemTime::now().days_since_epoch();
        self.windows.lock().expect("windows lock poisoned").unique_short_ids.add(day, id.0);
    }

    /// Distinct mailbox IDs touched so far in the week in progress.
    #[cfg(test)]
    pub(crate) fn in_progress_unique_short_ids(&self) -> u64 {
        let week = reporting_week(SystemTime::now().days_since_epoch());
        let windows = self.windows.lock().expect("windows lock poisoned");
        windows.unique_short_ids.weeks.get(&week).map(|ids| ids.len() as u64).unwrap_or(0)
    }

    /// Records `n` of every exportable event into the most recently settled
    /// reporting week, as if they had happened last week.
    #[cfg(test)]
    fn seed_settled_week(&self, n: u64) {
        let today = SystemTime::now().days_since_epoch();
        let day = reporting_week_start(reporting_week(today).saturating_sub(1));
        let mut windows = self.windows.lock().expect("windows lock poisoned");
        for i in 0..n {
            windows.http_requests.add(day);
            windows.http_requests_started.add(day);
            windows.db_entries.add(day);
            windows.tunnel_sheds.add(day);
            windows.unique_short_ids.add(day, i.to_be_bytes());
        }
    }
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

    #[test]
    fn unique_id_sets_count_distinct_ids_in_the_settled_week() {
        let mut ids = WeeklyIdSets::default();
        let settled_day = reporting_week_start(100) + 1;
        let active_day = reporting_week_start(101) + 1;
        for i in 0..3u64 {
            ids.add(settled_day, i.to_be_bytes());
            ids.add(settled_day, i.to_be_bytes());
            ids.add(active_day, i.to_be_bytes());
        }
        assert_eq!(ids.settled_window_count(active_day), 3, "repeats count once");
        assert_eq!(ids.settled_window_count(settled_day), 0);
    }

    #[test]
    fn unique_id_sets_drop_windows_older_than_the_previous_week() {
        let mut ids = WeeklyIdSets::default();
        ids.add(reporting_week_start(100), [1; 8]);
        ids.add(reporting_week_start(101), [2; 8]);
        ids.add(reporting_week_start(102), [3; 8]);
        assert_eq!(ids.weeks.keys().copied().collect::<Vec<_>>(), vec![101, 102]);
        assert_eq!(ids.settled_window_count(reporting_week_start(102)), 1);
        assert_eq!(ids.settled_window_count(reporting_week_start(103)), 1);
        assert_eq!(ids.settled_window_count(reporting_week_start(104)), 0);
    }

    /// A flooded week reports the cap and stops keeping IDs, so memory is
    /// bounded and the exported value itself says the week was flooded.
    #[test]
    fn unique_id_sets_saturate_at_the_cap() {
        let mut ids = WeeklyIdSets::default();
        let day = reporting_week_start(100);
        let window = ids.weeks.entry(reporting_week(day)).or_default();
        window.extend((0..UNIQUE_SHORT_IDS_CAP as u64).map(u64::to_be_bytes));
        ids.add(day, [0xff; 8]);
        ids.add(day, [0xfe; 8]);
        let window = &ids.weeks[&reporting_week(day)];
        assert_eq!(window.len(), UNIQUE_SHORT_IDS_CAP);
        assert!(!window.contains(&[0xff; 8]), "inserts stop at the cap");
        assert_eq!(
            ids.settled_window_count(reporting_week_start(101)),
            UNIQUE_SHORT_IDS_CAP as u64
        );
    }

    /// Collects (metric name, attribute keys per data point) for everything
    /// the exporter saw. The export surface is gauges only, so any other
    /// instrument shape on the export provider is a leak and fails here
    /// rather than passing through with its attributes unexamined.
    fn exported_points(exporter: &InMemoryMetricExporter) -> Vec<(String, Vec<String>)> {
        let mut points = Vec::new();
        for rm in exporter.get_finished_metrics().expect("metrics").iter() {
            for sm in rm.scope_metrics() {
                for m in sm.metrics() {
                    let name = m.name().to_string();
                    let AggregatedMetrics::U64(MetricData::Gauge(gauge)) = m.data() else {
                        panic!("{name} on the export provider is not a u64 gauge");
                    };
                    for dp in gauge.data_points() {
                        let keys = dp.attributes().map(|kv| kv.key.as_str().to_string()).collect();
                        points.push((name.clone(), keys));
                    }
                }
            }
        }
        points
    }

    /// Value of the single data point of a u64 gauge, if it was emitted.
    fn gauge_value(exporter: &InMemoryMetricExporter, name: &str) -> Option<u64> {
        exporter
            .get_finished_metrics()
            .expect("metrics")
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .filter(|m| m.name() == name)
            .find_map(|m| match m.data() {
                AggregatedMetrics::U64(MetricData::Gauge(gauge)) =>
                    gauge.data_points().next().map(|dp| dp.value()),
                _ => None,
            })
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
        let metrics = MetricsService::with_export(&provider);

        // Live traffic, which must never surface, alongside a settled week so
        // every gauge emits a point whose attributes the audit can see.
        metrics.record_http_request("/health", "GET", 200);
        drop(metrics.track_request());
        metrics.record_db_entry(PayjoinVersion::Two);
        metrics.record_tunnel_shed();
        metrics.record_short_id(&ShortId([0; 8]));
        metrics.seed_settled_week(13);

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
        // Counts are exported exactly; the settled week is the only
        // coarsening applied to them.
        assert_eq!(gauge_value(&exporter, HTTP_REQUESTS_WEEKLY), Some(13));
        assert_eq!(gauge_value(&exporter, DB_ENTRIES_WEEKLY), Some(13));
        assert_eq!(gauge_value(&exporter, UNIQUE_SHORT_IDS_WEEKLY), Some(13));
    }

    /// Traffic recorded today must be invisible in the export: the in-progress
    /// window is never emitted, so there is no live counter for an active
    /// prober to watch move.
    #[test]
    fn export_omits_in_progress_window() {
        let (exporter, provider) = in_memory_provider();
        let metrics = MetricsService::with_export(&provider);

        for _ in 0..100 {
            metrics.record_http_request("/health", "GET", 200);
        }
        metrics.record_short_id(&ShortId([1; 8]));

        provider.force_flush().expect("flush failed");

        // Today's traffic sits in the in-progress bucket, so every settled
        // window is 0. Zero is a real sample: the gauges still emit, but
        // nothing recorded today can show through.
        for name in [HTTP_REQUESTS_WEEKLY, UNIQUE_SHORT_IDS_WEEKLY] {
            assert_eq!(
                gauge_value(&exporter, name),
                Some(0),
                "{name} exposed traffic whose window was still in progress"
            );
        }
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

    /// Small counts are neither rounded nor withheld: hiding them would keep
    /// only a handful of units from a passive viewer, and a sender who adds
    /// known traffic and subtracts it back out learns the true value anyway.
    #[test]
    fn export_reports_small_settled_week_exactly() {
        let (exporter, provider) = in_memory_provider();
        let metrics = MetricsService::with_export(&provider);
        metrics.seed_settled_week(1);

        provider.force_flush().expect("flush failed");

        assert_eq!(gauge_value(&exporter, HTTP_REQUESTS_WEEKLY), Some(1));
        assert_eq!(gauge_value(&exporter, DB_ENTRIES_WEEKLY), Some(1));
    }
}
