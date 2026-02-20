use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use maxminddb::PathElement;

use crate::config::AccessControlConfig;

pub struct IpFilter {
    geo_reader: Option<maxminddb::Reader<Vec<u8>>>,
    blocked_regions: HashSet<String>,
    blocked_ips: Vec<ipnet::IpNet>,
}

impl IpFilter {
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

        let blocked_ips = config
            .blocked_ips
            .iter()
            .map(|s| {
                s.parse::<ipnet::IpNet>().or_else(|_| {
                    // Accept bare IP addresses without CIDR prefix length
                    Ok(ipnet::IpNet::from(s.parse::<IpAddr>()?))
                })
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?;

        Ok(Self { geo_reader, blocked_regions, blocked_ips })
    }

    /// Returns `true` if the IP is allowed. Fail-open on GeoIP lookup errors.
    pub fn check_ip(&self, ip: IpAddr) -> bool {
        if self.blocked_ips.iter().any(|net| net.contains(&ip)) {
            return false;
        }

        self.check_geoip(ip)
    }

    fn check_geoip(&self, ip: IpAddr) -> bool {
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

    let url = "https://cdn.jsdelivr.net/npm/geolite2-country/GeoLite2-Country.mmdb.gz";
    tracing::info!("Fetching GeoIP database from {}", url);

    let response = reqwest::get(url).await?;
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
        let ac =
            IpFilter { geo_reader: None, blocked_regions: HashSet::new(), blocked_ips: vec![] };
        assert!(ac.check_ip("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn check_ip_allows_when_no_blocked_regions() {
        let reader = test_geo_reader();
        let ac = IpFilter {
            geo_reader: Some(reader),
            blocked_regions: HashSet::new(),
            blocked_ips: vec![],
        };
        assert!(ac.check_ip("2.125.160.216".parse().unwrap()));
    }

    #[test]
    fn check_ip_blocks_blocked_region() {
        let reader = test_geo_reader();
        // 2.125.160.216 is GB in the test database
        let blocked_regions: HashSet<String> = ["GB"].iter().map(|s| s.to_string()).collect();
        let ac = IpFilter { geo_reader: Some(reader), blocked_regions, blocked_ips: vec![] };
        assert!(!ac.check_ip("2.125.160.216".parse().unwrap()));
    }

    #[test]
    fn check_ip_allows_non_blocked_region() {
        let reader = test_geo_reader();
        // 2.125.160.216 is GB in the test database
        let blocked_regions: HashSet<String> = ["US"].iter().map(|s| s.to_string()).collect();
        let ac = IpFilter { geo_reader: Some(reader), blocked_regions, blocked_ips: vec![] };
        assert!(ac.check_ip("2.125.160.216".parse().unwrap()));
    }

    #[test]
    fn check_ip_fail_open_on_unknown_ip() {
        let reader = test_geo_reader();
        let blocked_regions: HashSet<String> = ["US"].iter().map(|s| s.to_string()).collect();
        let ac = IpFilter { geo_reader: Some(reader), blocked_regions, blocked_ips: vec![] };
        // 127.0.0.1 won't be in test DB
        assert!(ac.check_ip("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn blocked_ips_blocks_exact_ipv4() {
        let blocked_ips = vec!["192.0.2.1/32".parse().unwrap()];
        let ac = IpFilter { geo_reader: None, blocked_regions: HashSet::new(), blocked_ips };
        assert!(!ac.check_ip("192.0.2.1".parse().unwrap()));
        assert!(ac.check_ip("192.0.2.2".parse().unwrap()));
    }

    #[test]
    fn blocked_ips_blocks_exact_ipv6() {
        let blocked_ips = vec!["2001:db8::1/128".parse().unwrap()];
        let ac = IpFilter { geo_reader: None, blocked_regions: HashSet::new(), blocked_ips };
        assert!(!ac.check_ip("2001:db8::1".parse().unwrap()));
        assert!(ac.check_ip("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn blocked_ips_blocks_cidr_range() {
        let blocked_ips = vec!["198.51.100.0/24".parse().unwrap()];
        let ac = IpFilter { geo_reader: None, blocked_regions: HashSet::new(), blocked_ips };
        assert!(!ac.check_ip("198.51.100.0".parse().unwrap()));
        assert!(!ac.check_ip("198.51.100.255".parse().unwrap()));
        assert!(ac.check_ip("198.51.101.0".parse().unwrap()));
    }

    #[test]
    fn empty_blocked_ips_allows_all() {
        let ac =
            IpFilter { geo_reader: None, blocked_regions: HashSet::new(), blocked_ips: vec![] };
        assert!(ac.check_ip("192.0.2.1".parse().unwrap()));
        assert!(ac.check_ip("2001:db8::1".parse().unwrap()));
    }
}
