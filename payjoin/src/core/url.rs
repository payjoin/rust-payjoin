use core::fmt;
use core::str::FromStr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    raw: String,
    scheme: String,
    cannot_be_a_base: bool,
    username: String,
    password: Option<String>,
    host: Option<Host>,
    port: Option<u16>,
    path: String,
    query: Option<String>,
    fragment: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathSegments<'a> {
    segments: Vec<&'a str>,
    index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Host {
    Domain(String),
    Ipv4([u8; 4]),
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

pub struct PathSegmentsMut<'a> {
    url: &'a mut Url,
}

impl<'a> PathSegmentsMut<'a> {
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
    pub fn path_segments_mut(&mut self) -> Option<PathSegmentsMut<'_>> {
        Some(PathSegmentsMut { url: self })
    }
}

pub struct UrlQueryPairs<'a> {
    url: &'a mut Url,
}

impl<'a> UrlQueryPairs<'a> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    EmptyHost,
    InvalidScheme,
    InvalidFormat,
    InvalidPort,
    InvalidCharacter,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::EmptyHost => write!(f, "empty host"),
            ParseError::InvalidScheme => write!(f, "invalid scheme"),
            ParseError::InvalidFormat => write!(f, "invalid format"),
            ParseError::InvalidPort => write!(f, "invalid port"),
            ParseError::InvalidCharacter => write!(f, "invalid character"),
        }
    }
}

impl std::error::Error for ParseError {}

impl FromStr for Url {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::parse(s) }
}

impl Url {
    pub fn parse(input: &str) -> Result<Url, ParseError> {
        let cannot_be_a_base = false;
        let (rest, scheme) = parse_scheme(input)?;
        let (_rest, host, port, path, query, fragment) =
            if let Some(rest) = rest.strip_prefix("://") {
                let (rest, host) = parse_host(rest)?;
                let (rest, port) = parse_port(rest).unwrap_or((rest, None));
                let (path, query, fragment) = parse_path_query_fragment(rest);

                let is_empty_host = matches!(&host, Host::Domain(s) if s.is_empty());
                if is_empty_host && matches!(scheme.as_str(), "file" | "blob") {
                    let after_colon = &input[scheme.len() + 1..];
                    let (path, query, fragment) = parse_path_query_fragment(after_colon);
                    (rest, None, None, path, query, fragment)
                } else {
                    (rest, Some(host), port, path, query, fragment)
                }
            } else if let Some(rest) = rest.strip_prefix(":") {
                let (path, query, fragment) = parse_path_query_fragment(rest);
                (rest, None, None, path, query, fragment)
            } else {
                return Err(ParseError::InvalidFormat);
            };

        let host = match host {
            Some(ref h) if h.is_empty() =>
                if matches!(scheme.as_str(), "file" | "blob") {
                    None
                } else {
                    return Err(ParseError::EmptyHost);
                },
            None if !matches!(scheme.as_str(), "file" | "blob") => {
                return Err(ParseError::EmptyHost);
            }
            _ => host,
        };

        let path = if path.is_empty() { "/".to_string() } else { path };

        let (username, password) = ("".to_string(), None);

        let mut url = Url {
            raw: String::new(),
            scheme,
            cannot_be_a_base,
            username,
            password,
            host,
            port,
            path,
            query,
            fragment,
        };
        url.rebuild_raw();
        Ok(url)
    }

    pub fn scheme(&self) -> &str { &self.scheme }

    pub fn has_host(&self) -> bool { self.host.is_some() }

    pub fn domain(&self) -> Option<&str> {
        match &self.host {
            Some(Host::Domain(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn host_str(&self) -> Option<String> {
        match &self.host {
            Some(Host::Domain(d)) => Some(d.clone()),
            Some(Host::Ipv4(octets)) =>
                Some(format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])),
            _ => None,
        }
    }

    pub fn port(&self) -> Option<u16> { self.port }

    pub fn set_port(&mut self, port: Option<u16>) {
        self.port = port;
        self.rebuild_raw();
    }

    pub fn path(&self) -> &str { &self.path }

    pub fn fragment(&self) -> Option<&str> { self.fragment.as_deref() }

    pub fn set_fragment(&mut self, fragment: Option<&str>) {
        self.fragment = fragment.map(|s| s.to_string());
        self.rebuild_raw();
    }

    pub fn path_segments(&self) -> Option<PathSegments<'_>> {
        if self.path.is_empty() || self.path == "/" {
            return Some(PathSegments { segments: vec![], index: 0 });
        }
        let segments: Vec<&str> = self.path.trim_start_matches('/').split('/').collect();
        Some(PathSegments { segments, index: 0 })
    }

    pub fn query(&self) -> Option<&str> { self.query.as_deref() }

    pub fn set_query(&mut self, query: Option<&str>) {
        self.query = query.map(|s| s.to_string());
        self.rebuild_raw();
    }

    pub fn query_pairs_mut(&mut self) -> UrlQueryPairs<'_> { UrlQueryPairs { url: self } }

    pub fn join(&self, segment: &str) -> Result<Url, ParseError> {
        // If the segment is a full URL (scheme://...), parse it independently.
        // Only treat it as a full URL if :// appears before any / (i.e. in scheme position).
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

        if self.host.is_some() {
            raw.push_str("://");
            if !self.username.is_empty() || self.password.is_some() {
                raw.push_str(&self.username);
                if let Some(ref pw) = self.password {
                    raw.push(':');
                    raw.push_str(pw);
                }
                raw.push('@');
            }
            if let Some(ref host) = self.host {
                match host {
                    Host::Domain(s) => raw.push_str(s),
                    Host::Ipv4(octets) => {
                        raw.push_str(&format!(
                            "{}.{}.{}.{}",
                            octets[0], octets[1], octets[2], octets[3]
                        ));
                    }
                    Host::Ipv6(segments) => {
                        raw.push('[');
                        raw.push_str(
                            &segments
                                .iter()
                                .map(|s| format!("{:x}", s))
                                .collect::<Vec<_>>()
                                .join(":"),
                        );
                        raw.push(']');
                    }
                }
            }
            if let Some(port) = self.port {
                raw.push(':');
                raw.push_str(&port.to_string());
            }
        } else {
            raw.push(':');
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

impl Host {
    fn is_empty(&self) -> bool {
        match self {
            Host::Domain(s) => s.is_empty(),
            Host::Ipv4(_) => false,
            Host::Ipv6(_) => false,
        }
    }
}

impl AsRef<str> for Url {
    fn as_ref(&self) -> &str { &self.raw }
}

impl Url {
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
            _ => return Err(ParseError::InvalidCharacter),
        }
    }

    if scheme.is_empty() {
        return Err(ParseError::InvalidScheme);
    }

    let scheme = scheme.to_lowercase();
    Ok((&input[scheme.len()..], scheme))
}

fn parse_host(input: &str) -> Result<(&str, Host), ParseError> {
    // Split at the first ':', '/', '?', or '#' to separate host from port/path/query/fragment
    let mut chars = input.char_indices();
    let mut end = input.len();
    for (i, c) in &mut chars {
        if c == ':' || c == '/' || c == '?' || c == '#' {
            end = i;
            break;
        }
    }
    let host_str = &input[..end];
    let rest = &input[end..];
    Ok((rest, Host::Domain(host_str.to_string())))
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
    let mut path = String::new();
    let mut query: Option<String> = None;
    let mut fragment: Option<String> = None;

    if let Some(frag_pos) = input.find('#') {
        let before_fragment = &input[..frag_pos];
        fragment = Some(input[frag_pos + 1..].to_string());

        if let Some(q_pos) = before_fragment.find('?') {
            path.push_str(&before_fragment[..q_pos]);
            let q_part = &before_fragment[q_pos + 1..];
            if let Some(f_pos) = q_part.find('#') {
                query = Some(q_part[..f_pos].to_string());
                fragment = Some(q_part[f_pos + 1..].to_string());
            } else {
                query = Some(q_part.to_string());
            }
        } else {
            path.push_str(before_fragment);
        }
    } else if let Some(q_pos) = input.find('?') {
        path.push_str(&input[..q_pos]);
        query = Some(input[q_pos + 1..].to_string());
    } else {
        path.push_str(input);
    }

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
    fn test_parse_basic_url() {
        let url = Url::parse("http://example.com").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.domain(), Some("example.com"));
        assert!(url.has_host());
    }

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
    fn test_parse_url_with_port() {
        let url = Url::parse("http://localhost:8080/path").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.domain(), Some("localhost"));
    }

    #[test]
    fn test_fragment() {
        let url = Url::parse("https://example.com/path#fragment").unwrap();
        assert_eq!(url.fragment(), Some("fragment"));
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
    fn test_as_str() {
        let url = Url::parse("http://example.com").unwrap();
        assert_eq!(url.as_str(), "http://example.com/");
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
}
