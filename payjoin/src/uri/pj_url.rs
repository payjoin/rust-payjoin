use url::Url;

pub struct PjUrl {
    url: Url,
    ohttp: Option<String>,
}

impl PjUrl {
    pub fn new(url: Url) -> Self {
        let (url, ohttp) = Self::extract_ohttp(url);
        PjUrl { url, ohttp }
    }

    fn extract_ohttp(mut url: Url) -> (Url, Option<String>) {
        let fragment = &mut url.fragment().and_then(|f| {
            let parts: Vec<&str> = f.splitn(2, "ohttp=").collect();
            if parts.len() == 2 {
                Some((parts[0].trim_end_matches('&'), parts[1].to_string()))
            } else {
                None
            }
        });

        if let Some((remaining_fragment, ohttp)) = fragment {
            url.set_fragment(Some(remaining_fragment));
            (url, Some(ohttp))
        } else {
            (url, None)
        }
    }

    pub fn into_url(self) -> Url {
        let mut url = self.url;
        if let Some(ohttp) = self.ohttp {
            let fragment = url
                .fragment()
                .map(|f| format!("{}&ohttp={}", f, ohttp))
                .unwrap_or_else(|| format!("ohttp={}", ohttp));
            url.set_fragment(Some(&fragment));
        }
        url
    }
}
