use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use maxminddb::PathElement;

use crate::config::AccessControlConfig;

pub struct GeoIp {
    geo_reader: Option<maxminddb::Reader<Vec<u8>>>,
    blocked_regions: HashSet<String>,
}

impl GeoIp {
    pub async fn from_config(
        config: &AccessControlConfig,
        storage_dir: &Path,
    ) -> anyhow::Result<Self> {
        let geo_reader = match &config.geo_db_path {
            Some(path) => Some(maxminddb::Reader::open_readfile(path)?),
            None if !config.blocked_regions.is_empty() => {
                let cached = storage_dir.join("access-control/geoip.mmdb");
                if cached.exists() {
                    match maxminddb::Reader::open_readfile(&cached) {
                        Ok(reader) => Some(reader),
                        Err(e) => {
                            tracing::warn!(
                                "Failed to open cached GeoIP database at {}: {e}; attempting refresh",
                                cached.display()
                            );
                            fetch_geoip_db(&cached).await?;
                            Some(maxminddb::Reader::open_readfile(&cached)?)
                        }
                    }
                } else {
                    fetch_geoip_db(&cached).await?;
                    Some(maxminddb::Reader::open_readfile(&cached)?)
                }
            }
            None => None,
        };

        let blocked_regions = config.blocked_regions.iter().cloned().collect();

        Ok(Self { geo_reader, blocked_regions })
    }

    /// Returns `true` if the IP is allowed. Fail-open on lookup errors.
    pub fn check_ip(&self, ip: IpAddr) -> bool {
        let reader = match &self.geo_reader {
            Some(r) => r,
            None => return true,
        };

        if self.blocked_regions.is_empty() {
            return true;
        }

        match reader.lookup(ip) {
            Ok(result) => {
                match result.decode_path::<String>(&[
                    PathElement::Key("country"),
                    PathElement::Key("iso_code"),
                ]) {
                    Ok(Some(iso_code)) => !self.blocked_regions.contains(&iso_code),
                    _ => true, // no country info or decode error -> allow
                }
            }
            Err(_) => true, // fail-open
        }
    }
}

pub fn load_blocked_address_text(path: &Path) -> anyhow::Result<String> {
    Ok(std::fs::read_to_string(path)?)
}

pub fn spawn_address_list_updater(
    url: String,
    refresh: std::time::Duration,
    cache_path: std::path::PathBuf,
    blocked: payjoin_directory::BlockedAddresses,
) {
    tokio::spawn(async move {
        loop {
            match reqwest::get(&url).await.and_then(|r| r.error_for_status()) {
                Ok(resp) => match resp.text().await {
                    Ok(body) => {
                        if let Err(e) = std::fs::write(&cache_path, &body) {
                            tracing::warn!("Failed to write address cache: {e}");
                        }
                        let count = blocked.update_from_lines(&body).await;
                        tracing::info!("Updated blocked address list ({count} entries)");
                    }
                    Err(e) => tracing::warn!("Failed to read address list response: {e}"),
                },
                Err(e) => tracing::warn!("Failed to fetch address list: {e}"),
            }
            tokio::time::sleep(refresh).await;
        }
    });
}

async fn fetch_geoip_db(dest: &Path) -> anyhow::Result<()> {
    use std::io::Read;

    let now = chrono_month_year();
    let url =
        format!("https://download.db-ip.com/free/dbip-country-lite-{}-{}.mmdb.gz", now.0, now.1);
    tracing::info!("Fetching GeoIP database from {}", url);

    let response = reqwest::get(&url).await?;
    if !response.status().is_success() {
        anyhow::bail!("Failed to fetch GeoIP database: HTTP {}", response.status());
    }
    let compressed = response.bytes().await?;
    let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(dest, &decompressed)?;
    tracing::info!("GeoIP database saved to {}", dest.display());
    Ok(())
}

/// Returns (year, month) as strings for the DB-IP download URL.
fn chrono_month_year() -> (String, String) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after UNIX_EPOCH");
    let days_since_epoch = (now.as_secs() / 86_400) as i64;
    let (year, month) = year_month_from_days_since_epoch(days_since_epoch);
    (year.to_string(), format!("{month:02}"))
}

fn year_month_from_days_since_epoch(days_since_epoch: i64) -> (i32, u32) {
    // Exact conversion from Unix days to Gregorian year/month in UTC.
    // Based on Howard Hinnant's civil calendar algorithm.
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = (mp + if mp < 10 { 3 } else { -9 }) as u32;
    let year = (y + if month <= 2 { 1 } else { 0 }) as i32;
    (year, month)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_geo_reader() -> maxminddb::Reader<Vec<u8>> {
        maxminddb::Reader::open_readfile(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/GeoIP2-Country-Test.mmdb"
        ))
        .unwrap()
    }

    #[test]
    fn check_ip_allows_when_no_geo_reader() {
        let ac = GeoIp { geo_reader: None, blocked_regions: HashSet::new() };
        assert!(ac.check_ip("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn check_ip_allows_when_no_blocked_regions() {
        let reader = test_geo_reader();
        let ac = GeoIp { geo_reader: Some(reader), blocked_regions: HashSet::new() };
        assert!(ac.check_ip("2.125.160.216".parse().unwrap()));
    }

    #[test]
    fn check_ip_blocks_blocked_region() {
        let reader = test_geo_reader();
        // 2.125.160.216 is GB in the test database
        let blocked_regions: HashSet<String> = ["GB"].iter().map(|s| s.to_string()).collect();
        let ac = GeoIp { geo_reader: Some(reader), blocked_regions };
        assert!(!ac.check_ip("2.125.160.216".parse().unwrap()));
    }

    #[test]
    fn check_ip_allows_non_blocked_region() {
        let reader = test_geo_reader();
        // 2.125.160.216 is GB in the test database
        let blocked_regions: HashSet<String> = ["US"].iter().map(|s| s.to_string()).collect();
        let ac = GeoIp { geo_reader: Some(reader), blocked_regions };
        assert!(ac.check_ip("2.125.160.216".parse().unwrap()));
    }

    #[test]
    fn check_ip_fail_open_on_unknown_ip() {
        let reader = test_geo_reader();
        let blocked_regions: HashSet<String> = ["US"].iter().map(|s| s.to_string()).collect();
        let ac = GeoIp { geo_reader: Some(reader), blocked_regions };
        // 127.0.0.1 won't be in test DB
        assert!(ac.check_ip("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn year_month_conversion_handles_leap_day() {
        // 2024-02-29 00:00:00 UTC
        let days = 19_782;
        let (year, month) = year_month_from_days_since_epoch(days);
        assert_eq!((year, month), (2024, 2));
    }

    #[test]
    fn year_month_conversion_handles_year_start() {
        // 2024-01-01 00:00:00 UTC
        let days = 19_723;
        let (year, month) = year_month_from_days_since_epoch(days);
        assert_eq!((year, month), (2024, 1));
    }
}
