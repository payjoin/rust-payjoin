//! Minimal URL type used internally by `payjoin`.
//!
//! This module provides a small, dependency-free URL parser that covers the
//! subset of RFC 3986 needed by the payjoin protocol (`http`, `https`, and
//! `bitcoin:` style URIs). It is not a full replacement for the `url` crate —
//! only the surface used by this library is implemented.
//!
//! The primary entry point is [`Url`], with parse errors surfaced through
//! [`ParseError`] (re-exported at the crate root as `UrlParseError`).

use core::fmt;
use core::str::FromStr;

/// A parsed URL.
///
/// Construct one with [`Url::parse`] or via the [`FromStr`] impl. The parser
/// accepts an absolute URL of the form `scheme://host[:port][/path][?query][#fragment]`.
/// When no path is supplied, `/` is stored so that round-tripping through
/// [`Url::as_str`] always yields a normalised form.
///
/// # Example
///
/// ```ignore
/// use payjoin::UrlParseError;
/// # fn demo() -> Result<(), UrlParseError> {
/// let url: payjoin::Url = "https://example.com/pj?v=2".parse()?;
/// assert_eq!(url.scheme(), "https");
/// assert_eq!(url.host_str(), "example.com");
/// assert_eq!(url.path(), "/pj");
/// assert_eq!(url.query(), Some("v=2"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    raw: String,
    scheme: String,
    host: Host,
    port: Option<u16>,
    path: String,
    query: Option<String>,
    fragment: Option<String>,
}

/// Iterator over the `/`-separated segments of a URL path.
///
/// Returned by [`Url::path_segments`]. The leading `/` is stripped before
/// splitting, so `"/a/b"` yields `["a", "b"]` and `"/"` yields no segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathSegments<'a> {
    segments: Vec<&'a str>,
    index: usize,
}

/// The host component of a [`Url`].
///
/// Parsed into one of three shapes depending on the input: a registered
/// domain name, a dotted-quad IPv4 address, or a bracketed IPv6 literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// A registered domain name, e.g. `example.com`.
    Domain(String),
    /// An IPv4 address in network byte order.
    Ipv4([u8; 4]),
    /// An IPv6 address as eight 16-bit groups in network byte order.
    Ipv6([u16; 8]),
}

impl<'a> Iterator for PathSegments<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.segments.len() {
            None
        } else {
            let item = self.segments[self.index];
            self.index += 1;
            Some(item)
        }
    }
}

/// Mutable handle for appending path segments to a [`Url`].
///
/// Obtained via [`Url::path_segments_mut`]. The underlying URL's serialised
/// form is rebuilt when this handle is dropped.
pub struct PathSegmentsMut<'a> {
    url: &'a mut Url,
}

impl<'a> PathSegmentsMut<'a> {
    /// Append a single path segment, inserting a `/` separator if needed.
    ///
    /// The segment is pushed verbatim — no percent-encoding is applied.
    pub fn push(&mut self, segment: &str) {
        if !self.url.path.ends_with('/') && !self.url.path.is_empty() {
            self.url.path.push('/');
        }
        self.url.path.push_str(segment);
    }
}

impl<'a> Drop for PathSegmentsMut<'a> {
    fn drop(&mut self) { self.url.rebuild_raw(); }
}

impl Url {
    /// Return a mutable handle for appending path segments.
    ///
    /// Always returns `Some`; the `Option` mirrors the `url` crate's API so
    /// callers can migrate without changes.
    pub fn path_segments_mut(&mut self) -> Option<PathSegmentsMut<'_>> {
        Some(PathSegmentsMut { url: self })
    }
}

/// Mutable handle for appending `key=value` pairs to a [`Url`]'s query string.
///
/// Obtained via [`Url::query_pairs_mut`]. Each [`append_pair`](Self::append_pair)
/// call rewrites the underlying URL's serialised form.
pub struct UrlQueryPairs<'a> {
    url: &'a mut Url,
}

impl<'a> UrlQueryPairs<'a> {
    /// Append a single `key=value` pair to the query string.
    ///
    /// Key and value are written verbatim — the caller is responsible for any
    /// percent-encoding. Returns `&mut self` to support fluent chaining.
    pub fn append_pair(&mut self, key: &str, value: &str) -> &mut UrlQueryPairs<'a> {
        let new_pair = format!("{}={}", key, value);
        if let Some(ref mut query) = self.url.query {
            query.push_str(&format!("&{}", new_pair));
        } else {
            self.url.query = Some(new_pair);
        }
        self.url.rebuild_raw();
        self
    }
}

/// Errors produced by [`Url::parse`].
///
/// Re-exported at the crate root as `UrlParseError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The authority section had no host between `://` and the path.
    EmptyHost,
    /// The scheme was empty.
    InvalidScheme,
    /// The overall structure did not match `scheme://host...`.
    InvalidFormat,
    /// The port was present but did not parse as a `u16`.
    InvalidPort,
    /// The host was not a valid domain, IPv4 literal, or IPv6 literal.
    InvalidHost,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::EmptyHost => write!(f, "empty host"),
            ParseError::InvalidScheme => write!(f, "invalid scheme"),
            ParseError::InvalidFormat => write!(f, "invalid format"),
            ParseError::InvalidPort => write!(f, "invalid port"),
            ParseError::InvalidHost => write!(f, "invalid host"),
        }
    }
}

impl std::error::Error for ParseError {}

impl FromStr for Url {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::parse(s) }
}

impl Url {
    /// Parse an absolute URL.
    ///
    /// The input must be of the form `scheme://host[:port][/path][?query][#fragment]`.
    /// An empty path is normalised to `/`. The scheme is lower-cased.
    pub fn parse(input: &str) -> Result<Url, ParseError> {
        let (rest, scheme) = parse_scheme(input)?;
        let (_rest, host, port, path, query, fragment) =
            if let Some(rest) = rest.strip_prefix("://") {
                let (rest, host) = parse_host(rest)?;
                let (rest, port) = parse_port(rest).unwrap_or((rest, None));
                let (path, query, fragment) = parse_path_query_fragment(rest);
                (rest, host, port, path, query, fragment)
            } else {
                return Err(ParseError::InvalidFormat);
            };

        let path = if path.is_empty() { "/".to_string() } else { path };

        let mut url = Url { raw: String::new(), scheme, host, port, path, query, fragment };
        url.rebuild_raw();
        Ok(url)
    }

    /// The URL's scheme, lower-cased (e.g. `"https"`).
    pub fn scheme(&self) -> &str { &self.scheme }

    /// The host as a domain name, or `None` for IP literals.
    pub fn domain(&self) -> Option<&str> {
        match &self.host {
            Host::Domain(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// The host rendered as a string.
    ///
    /// Domains are returned as-is; IPv4 addresses as dotted-quad; IPv6
    /// addresses in `[…]` bracket form.
    pub fn host_str(&self) -> String {
        match &self.host {
            Host::Domain(d) => d.clone(),
            Host::Ipv4(octets) =>
                format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]),
            Host::Ipv6(segs) => {
                let s = segs.iter().map(|s| format!("{:x}", s)).collect::<Vec<_>>().join(":");
                format!("[{}]", s)
            }
        }
    }

    /// The explicit port, if one was given.
    pub fn port(&self) -> Option<u16> { self.port }

    /// Replace the port. Pass `None` to remove it.
    pub fn set_port(&mut self, port: Option<u16>) {
        self.port = port;
        self.rebuild_raw();
    }

    /// The path component, always starting with `/`.
    pub fn path(&self) -> &str { &self.path }

    /// The fragment (without the leading `#`), if any.
    pub fn fragment(&self) -> Option<&str> { self.fragment.as_deref() }

    /// Replace the fragment. Pass `None` to remove it.
    pub fn set_fragment(&mut self, fragment: Option<&str>) {
        self.fragment = fragment.map(|s| s.to_string());
        self.rebuild_raw();
    }

    /// Iterate over the `/`-separated path segments.
    ///
    /// Always returns `Some`; the `Option` mirrors the `url` crate's API.
    pub fn path_segments(&self) -> Option<PathSegments<'_>> {
        if self.path.is_empty() || self.path == "/" {
            return Some(PathSegments { segments: vec![], index: 0 });
        }
        let segments: Vec<&str> = self.path.trim_start_matches('/').split('/').collect();
        Some(PathSegments { segments, index: 0 })
    }

    /// The query string (without the leading `?`), if any.
    pub fn query(&self) -> Option<&str> { self.query.as_deref() }

    /// Clear the query string.
    pub fn clear_query(&mut self) {
        self.query = None;
        self.rebuild_raw();
    }

    /// Return a handle for appending `key=value` pairs to the query string.
    pub fn query_pairs_mut(&mut self) -> UrlQueryPairs<'_> { UrlQueryPairs { url: self } }

    /// Return parsed query pairs as a Vec of Strings
    pub fn query_pairs(&self) -> Vec<(String, String)> {
        let Some(query) = &self.query else { return vec![] };
        query
            .split('&')
            .filter(|s| !s.is_empty())
            .filter_map(|pair| {
                let (k, v) = pair.split_once('=')?;
                let key =
                    percent_encoding_rfc3986::percent_decode_str(k).ok()?.decode_utf8().ok()?;
                let val =
                    percent_encoding_rfc3986::percent_decode_str(v).ok()?.decode_utf8().ok()?;
                Some((key.into_owned(), val.into_owned()))
            })
            .collect()
    }

    /// Resolve a reference against this URL per RFC 3986.
    ///
    /// - A `segment` with a scheme (`scheme://…`) is parsed as a new absolute URL.
    /// - A segment starting with `/` replaces the path and clears the query
    ///   and fragment.
    /// - Otherwise the segment is merged relative to the base, resolving
    ///   `.` and `..` dot-segments, and the query and fragment are cleared.
    pub fn join(&self, segment: &str) -> Result<Url, ParseError> {
        // If the segment is a full URL (scheme://...), parse it independently.
        // Only treat it as a full URL if no / appears before :// (i.e. in scheme position).
        if let Some(pos) = segment.find("://") {
            if !segment[..pos].contains('/') {
                return Url::parse(segment);
            }
        }

        let mut new_url = self.clone();

        if segment.starts_with('/') {
            // Absolute path reference: replace entire path, clear query/fragment
            new_url.path = segment.to_string();
            new_url.query = None;
            new_url.fragment = None;
        } else {
            // Relative reference: merge per RFC 3986
            // Remove everything after the last '/' in the base path, then append segment
            let base_path =
                if let Some(pos) = new_url.path.rfind('/') { &new_url.path[..=pos] } else { "/" };
            let merged = format!("{}{}", base_path, segment);

            // Resolve dot segments
            let mut output_segments: Vec<&str> = Vec::new();
            for part in merged.split('/') {
                match part {
                    "." => {}
                    ".." => {
                        output_segments.pop();
                    }
                    _ => output_segments.push(part),
                }
            }
            new_url.path = output_segments.join("/");
            if !new_url.path.starts_with('/') {
                new_url.path.insert(0, '/');
            }
            new_url.query = None;
            new_url.fragment = None;
        }

        new_url.rebuild_raw();
        Ok(new_url)
    }

    fn rebuild_raw(&mut self) {
        let mut raw = String::new();
        raw.push_str(&self.scheme);
        raw.push_str("://");
        raw.push_str(&self.host_str());

        if let Some(port) = self.port {
            raw.push(':');
            raw.push_str(&port.to_string());
        }

        raw.push_str(&self.path);
        if let Some(ref query) = self.query {
            raw.push('?');
            raw.push_str(query);
        }
        if let Some(ref fragment) = self.fragment {
            raw.push('#');
            raw.push_str(fragment);
        }
        self.raw = raw;
    }
}

impl AsRef<str> for Url {
    fn as_ref(&self) -> &str { &self.raw }
}

impl Url {
    /// The URL in its serialised form.
    ///
    /// Equivalent to the [`Display`](fmt::Display) output and to the
    /// [`AsRef<str>`] impl.
    pub fn as_str(&self) -> &str { &self.raw }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.raw) }
}

fn parse_scheme(input: &str) -> Result<(&str, String), ParseError> {
    let chars = input.chars();
    let mut scheme = String::new();

    for c in chars {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '+' | '-' | '.' => {
                scheme.push(c);
            }
            ':' => break,
            _ => return Err(ParseError::InvalidScheme),
        }
    }

    if scheme.is_empty() {
        return Err(ParseError::InvalidScheme);
    }

    let scheme = scheme.to_lowercase();
    Ok((&input[scheme.len()..], scheme))
}

fn parse_host(input: &str) -> Result<(&str, Host), ParseError> {
    // IPv6 literal: [xxxx:...]
    if input.starts_with('[') {
        let end = input.find(']').ok_or(ParseError::InvalidHost)?;
        let ipv6_str = &input[1..end];
        let rest = &input[end + 1..];
        return Ok((rest, parse_ipv6(ipv6_str)?));
    }

    // Split at the first ':', '/', '?', or '#' to separate host from port/path/query/fragment
    let mut end = input.len();
    for (i, c) in input.char_indices() {
        if c == ':' || c == '/' || c == '?' || c == '#' {
            end = i;
            break;
        }
    }
    let host_str = &input[..end];
    let rest = &input[end..];

    if let Some(host) = try_parse_ipv4(host_str) {
        return Ok((rest, host));
    }

    if host_str.is_empty() {
        return Err(ParseError::EmptyHost);
    }
    if !host_str.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        return Err(ParseError::InvalidHost);
    }

    Ok((rest, Host::Domain(host_str.to_string())))
}

fn try_parse_ipv4(s: &str) -> Option<Host> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let octets: [u8; 4] = [
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
        parts[3].parse().ok()?,
    ];
    Some(Host::Ipv4(octets))
}

fn parse_ipv6(s: &str) -> Result<Host, ParseError> {
    let mut groups = [0u16; 8];
    if let Some((left, right)) = s.split_once("::") {
        let left_parts = parse_ipv6_groups(left)?;
        let right_parts = parse_ipv6_groups(right)?;
        if left_parts.len() + right_parts.len() > 7 {
            return Err(ParseError::InvalidHost);
        }
        for (i, &v) in left_parts.iter().enumerate() {
            groups[i] = v;
        }
        let offset = 8 - right_parts.len();
        for (i, &v) in right_parts.iter().enumerate() {
            groups[offset + i] = v;
        }
    } else {
        let parts = parse_ipv6_groups(s)?;
        if parts.len() != 8 {
            return Err(ParseError::InvalidHost);
        }
        for (i, &v) in parts.iter().enumerate() {
            groups[i] = v;
        }
    }
    Ok(Host::Ipv6(groups))
}

fn parse_ipv6_groups(s: &str) -> Result<Vec<u16>, ParseError> {
    if s.is_empty() {
        return Ok(vec![]);
    }
    s.split(':').map(|p| u16::from_str_radix(p, 16).map_err(|_| ParseError::InvalidHost)).collect()
}

fn parse_port(input: &str) -> Result<(&str, Option<u16>), ParseError> {
    if !input.starts_with(':') {
        return Ok((input, None));
    }

    let rest = &input[1..];
    let mut port_str = String::new();

    for c in rest.chars() {
        match c {
            '0'..='9' => port_str.push(c),
            '/' | '?' | '#' => break,
            _ => return Err(ParseError::InvalidPort),
        }
    }

    if port_str.is_empty() {
        return Ok((rest, None));
    }

    let port: u16 = port_str.parse().map_err(|_| ParseError::InvalidPort)?;
    let remaining = &rest[port_str.len()..];
    Ok((remaining, Some(port)))
}

fn parse_path_query_fragment(input: &str) -> (String, Option<String>, Option<String>) {
    let (before_fragment, fragment) = match input.find('#') {
        Some(pos) => (&input[..pos], Some(input[pos + 1..].to_string())),
        None => (input, None),
    };
    let (path, query) = match before_fragment.find('?') {
        Some(pos) =>
            (before_fragment[..pos].to_string(), Some(before_fragment[pos + 1..].to_string())),
        None => (before_fragment.to_string(), None),
    };

    (path, query, fragment)
}

impl serde::Serialize for Url {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> serde::Deserialize<'de> for Url {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Url::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url_with_path() {
        let url = Url::parse("https://example.com/path/to/resource").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.domain(), Some("example.com"));
        assert_eq!(
            url.path_segments().map(|s| s.collect::<Vec<_>>()),
            Some(vec!["path", "to", "resource"])
        );
    }

    #[test]
    fn test_set_fragment() {
        let mut url = Url::parse("https://example.com/path").unwrap();
        url.set_fragment(Some("newfragment"));
        assert_eq!(url.fragment(), Some("newfragment"));
        assert!(url.as_ref().contains("#newfragment"));
    }

    #[test]
    fn test_join() {
        let base = Url::parse("http://example.com/base/").unwrap();
        let joined = base.join("next").unwrap();
        assert_eq!(joined.path, "/base/next");
    }

    #[test]
    fn test_parse_url_with_port_and_fragment() {
        let input = "http://localhost:1234/PATH#FRAGMENT";
        let url = Url::parse(input).unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.domain(), Some("localhost"));
        assert_eq!(url.port(), Some(1234));
        assert_eq!(url.path(), "/PATH");
        assert_eq!(url.fragment(), Some("FRAGMENT"));
        assert_eq!(url.as_str(), "http://localhost:1234/PATH#FRAGMENT");
    }

    #[test]
    fn test_empty_host_rejected() {
        assert!(matches!(Url::parse("http:///path"), Err(ParseError::EmptyHost)));
    }

    #[test]
    fn test_path_segments_mut_push_adds_separator() {
        let mut url = Url::parse("http://example.com/base").unwrap();
        {
            let mut segs = url.path_segments_mut().unwrap();
            segs.push("child");
        }
        assert_eq!(url.path(), "/base/child");
        assert_eq!(url.as_str(), "http://example.com/base/child");
    }

    #[test]
    fn test_host_str() {
        let url = Url::parse("http://example.com/").unwrap();
        assert_eq!(url.host_str(), "example.com".to_string());
    }

    #[test]
    fn test_set_port() {
        let mut url = Url::parse("http://example.com/path").unwrap();
        url.set_port(Some(9090));
        assert_eq!(url.port(), Some(9090));
        assert_eq!(url.as_str(), "http://example.com:9090/path");
        url.set_port(None);
        assert_eq!(url.port(), None);
        assert_eq!(url.as_str(), "http://example.com/path");
    }

    #[test]
    fn test_path_segments_root() {
        let url = Url::parse("http://example.com/").unwrap();
        let segs: Vec<_> = url.path_segments().unwrap().collect();
        assert!(segs.is_empty());

        let url = Url::parse("http://example.com").unwrap();
        let segs: Vec<_> = url.path_segments().unwrap().collect();
        assert!(segs.is_empty());
        assert_eq!(url.as_str(), "http://example.com/");
    }

    #[test]
    fn test_set_query() {
        let mut url = Url::parse("http://example.com/path").unwrap();
        url.query_pairs_mut().append_pair("key", "value");
        assert_eq!(url.query(), Some("key=value"));
        assert_eq!(url.as_str(), "http://example.com/path?key=value");
        url.clear_query();
        assert_eq!(url.query(), None);
        assert_eq!(url.as_str(), "http://example.com/path");
    }

    #[test]
    fn test_join_dot_segments() {
        let base = Url::parse("http://example.com/a/b/c").unwrap();

        let joined = base.join("./d").unwrap();
        assert_eq!(joined.path(), "/a/b/d");

        let joined = base.join("../d").unwrap();
        assert_eq!(joined.path(), "/a/d");
    }

    #[test]
    fn test_parse_query_and_fragment() {
        let url = Url::parse("http://example.com/path?q=1#frag").unwrap();
        assert_eq!(url.path(), "/path");
        assert_eq!(url.query(), Some("q=1"));
        assert_eq!(url.fragment(), Some("frag"));
    }

    #[test]
    fn test_parse_ipv4_with_port() {
        let url = Url::parse("http://127.0.0.1:8080/path").unwrap();
        assert_eq!(url.host, Host::Ipv4([127, 0, 0, 1]));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.as_str(), "http://127.0.0.1:8080/path");
    }

    #[test]
    fn test_parse_ipv6_full() {
        let url = Url::parse("http://[2001:db8:85a3:0:0:8a2e:370:7334]/").unwrap();
        assert_eq!(
            url.host,
            Host::Ipv6([0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334])
        );
        assert_eq!(url.as_str(), "http://[2001:db8:85a3:0:0:8a2e:370:7334]/");
    }

    #[test]
    fn test_parse_ipv6_with_port() {
        let url = Url::parse("http://[::1]:8080/path").unwrap();
        assert_eq!(url.host, Host::Ipv6([0, 0, 0, 0, 0, 0, 0, 1]));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.as_str(), "http://[0:0:0:0:0:0:0:1]:8080/path");
    }

    #[test]
    fn test_parse_ipv6_unclosed_bracket() {
        assert!(matches!(Url::parse("http://[::1/"), Err(ParseError::InvalidHost)));
    }

    #[test]
    fn test_ipv6_matches_std_parser() {
        let url = Url::parse("http://[::1]/").unwrap();
        let std_addr: std::net::Ipv6Addr = "::1".parse().unwrap();
        assert_eq!(url.host, Host::Ipv6(std_addr.segments()));
        assert_eq!(url.domain(), None);
        assert_eq!(url.host_str(), "[0:0:0:0:0:0:0:1]".to_string());
        assert_eq!(url.as_str(), "http://[0:0:0:0:0:0:0:1]/");

        let url = Url::parse("http://[1::1]/").unwrap();
        let std_addr: std::net::Ipv6Addr = "1::1".parse().unwrap();
        assert_eq!(url.host, Host::Ipv6(std_addr.segments()));

        let url = Url::parse("http://[1:2:3::4:5:6]/").unwrap();
        let std_addr: std::net::Ipv6Addr = "1:2:3::4:5:6".parse().unwrap();
        assert_eq!(url.host, Host::Ipv6(std_addr.segments()));

        let url = Url::parse("http://[1:2:3:4:5:6:7::]/").unwrap();
        let std_addr: std::net::Ipv6Addr = "1:2:3:4:5:6:7::".parse().unwrap();
        assert_eq!(url.host, Host::Ipv6(std_addr.segments()));

        let url = Url::parse("http://[2001:db8:85a3::8a2e:370:7334]/").unwrap();
        let std_addr: std::net::Ipv6Addr = "2001:db8:85a3::8a2e:370:7334".parse().unwrap();
        assert_eq!(url.host, Host::Ipv6(std_addr.segments()));
    }

    #[test]
    fn test_ipv4_matches_std_parser() {
        let url = Url::parse("http://127.0.0.1/").unwrap();
        let std_addr: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
        assert_eq!(url.host, Host::Ipv4(std_addr.octets()));
        assert_eq!(url.domain(), None);
        assert_eq!(url.host_str(), "127.0.0.1".to_string());
        assert_eq!(url.as_str(), "http://127.0.0.1/");

        let url = Url::parse("http://192.168.1.1/").unwrap();
        let std_addr: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();
        assert_eq!(url.host, Host::Ipv4(std_addr.octets()));

        let url = Url::parse("http://0.0.0.0/").unwrap();
        let std_addr: std::net::Ipv4Addr = "0.0.0.0".parse().unwrap();
        assert_eq!(url.host, Host::Ipv4(std_addr.octets()));

        let url = Url::parse("http://255.255.255.255/").unwrap();
        let std_addr: std::net::Ipv4Addr = "255.255.255.255".parse().unwrap();
        assert_eq!(url.host, Host::Ipv4(std_addr.octets()));
    }

    #[test]
    fn test_parse_ipv6_too_many_groups_rejected() {
        assert!(matches!(Url::parse("http://[1:2:3:4::5:6:7:8]/"), Err(ParseError::InvalidHost)));
    }
}
