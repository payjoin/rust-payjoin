//! Periodic log line describing connection pressure.
//!
//! The in-flight request and open-tunnel gauges are only ever pushed to a
//! metrics sink, so without one an operator has no view of a slow
//! descriptor leak until the process hits its limit. The heartbeat puts the
//! same numbers, plus the process's open descriptor count and soft limit,
//! into the structured log every operator already has.

use std::future::Future;
use std::time::Duration;

use crate::metrics::MetricsService;

/// A leak that matters takes hours to reach the limit, so one line a minute
/// resolves the curve while staying cheap enough to leave on everywhere.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// Log target of the heartbeat line, for filtering.
pub const HEARTBEAT_TARGET: &str = "payjoin_mailroom::heartbeat";

/// Logs one heartbeat per `tick`, forever. `tick` resolves when the next
/// line is due; production passes a sleep, tests pass something immediate.
pub(crate) async fn run<F, Fut>(metrics: MetricsService, mut tick: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    loop {
        tick().await;
        log_heartbeat(&metrics);
    }
}

/// Emits one heartbeat line at INFO. The descriptor fields are Linux-only
/// and omitted elsewhere.
pub(crate) fn log_heartbeat(metrics: &MetricsService) {
    let active_connections = metrics.active_connections();
    let active_tunnels = metrics.active_tunnels();
    #[cfg(target_os = "linux")]
    tracing::info!(
        target: HEARTBEAT_TARGET,
        active_connections,
        active_tunnels,
        open_fds = linux::open_fds(),
        fd_soft_limit = linux::fd_soft_limit(),
        "heartbeat"
    );
    #[cfg(not(target_os = "linux"))]
    tracing::info!(target: HEARTBEAT_TARGET, active_connections, active_tunnels, "heartbeat");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;

    /// Descriptors this process holds open, from `/proc/self/fd`. The
    /// handle used to read the directory is excluded from the count.
    pub(super) fn open_fds() -> Option<u64> { count_entries(Path::new("/proc/self/fd")) }

    /// Soft "Max open files" limit from `/proc/self/limits`.
    pub(super) fn fd_soft_limit() -> Option<u64> {
        std::fs::read_to_string("/proc/self/limits")
            .ok()
            .and_then(|text| parse_fd_soft_limit(&text))
    }

    pub(super) fn count_entries(dir: &Path) -> Option<u64> {
        let entries = std::fs::read_dir(dir).ok()?.count() as u64;
        Some(entries.saturating_sub(1))
    }

    /// Columns are space-padded, so the soft limit is the first numeric
    /// field after the "Max open files" label.
    pub(super) fn parse_fd_soft_limit(limits: &str) -> Option<u64> {
        limits
            .lines()
            .find_map(|line| line.strip_prefix("Max open files"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|soft| soft.parse().ok())
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Collects everything a `tracing_subscriber::fmt` layer writes.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("capture lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }

    impl Captured {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("capture lock").clone()).expect("utf8")
        }
    }

    fn json_subscriber(captured: &Captured) -> impl tracing::Subscriber + Send + Sync {
        let sink = captured.clone();
        tracing_subscriber::fmt().json().with_writer(move || sink.clone()).finish()
    }

    #[test]
    fn heartbeat_line_carries_the_pressure_fields() {
        let metrics = MetricsService::new(None);
        let _request = metrics.track_request();
        metrics.record_tunnel_open();

        let captured = Captured::default();
        tracing::subscriber::with_default(json_subscriber(&captured), || log_heartbeat(&metrics));

        let line = captured.text();
        assert_eq!(line.lines().count(), 1, "{line}");
        for expected in [
            r#""target":"payjoin_mailroom::heartbeat""#,
            r#""message":"heartbeat""#,
            r#""active_connections":1"#,
            r#""active_tunnels":1"#,
        ] {
            assert!(line.contains(expected), "{expected} missing from {line}");
        }
        #[cfg(target_os = "linux")]
        for expected in [r#""open_fds":"#, r#""fd_soft_limit":"#] {
            assert!(line.contains(expected), "{expected} missing from {line}");
        }
    }

    #[tokio::test]
    async fn run_logs_once_per_tick() {
        let metrics = MetricsService::new(None);
        let captured = Captured::default();
        let _default = tracing::subscriber::set_default(json_subscriber(&captured));

        // Two immediate ticks, then a tick that never fires.
        let mut ticks = 0;
        let task = run(metrics, move || {
            ticks += 1;
            let due = ticks <= 2;
            async move {
                if !due {
                    std::future::pending::<()>().await;
                }
            }
        });
        let timed_out = tokio::time::timeout(Duration::from_millis(50), task).await.is_err();
        assert!(timed_out, "the heartbeat loop never returns on its own");

        let lines = captured.text().lines().count();
        assert_eq!(lines, 2, "one line per tick: {}", captured.text());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_readers_parse_limits_and_count_descriptors() {
        let limits = "Limit                     Soft Limit           Hard Limit           Units     \n\
                      Max cpu time              unlimited            unlimited            seconds   \n\
                      Max open files            1024                 524288               files     \n";
        assert_eq!(linux::parse_fd_soft_limit(limits), Some(1024));
        assert_eq!(linux::parse_fd_soft_limit("Max open files unlimited unlimited files"), None);
        assert_eq!(linux::parse_fd_soft_limit(""), None);

        let dir = tempfile::tempdir().expect("tempdir");
        for name in ["0", "1", "2"] {
            std::fs::write(dir.path().join(name), b"").expect("write");
        }
        // Three entries, minus the handle that read_dir itself holds.
        assert_eq!(linux::count_entries(dir.path()), Some(2));
        assert_eq!(linux::count_entries(&dir.path().join("missing")), None);

        assert!(linux::open_fds().is_some_and(|n| n > 0));
        assert!(linux::fd_soft_limit().is_some_and(|n| n > 0));
    }
}
