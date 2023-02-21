use rand::{distributions::Alphanumeric, Rng};
use reqwest::{Body, Client};
use std::borrow::Cow;


pub(crate) struct HttpRelay {
    http_relay_url: String,
    w_secret: String,
}

impl HttpRelay {
    pub fn new(http_relay_url: String, w_secret: String) -> Self {
        println!("http_relay_url: {}", http_relay_url);
        Self {
            http_relay_url,
            w_secret,
        }
    }

    /// Creates an HTTP Relay `proxy` communication method object.
    ///
    /// # Arguments
    ///
    /// * `http_relay_url` - The URL of the HTTP Relay server.
    /// * `base_url` - The base URL of the client that will use the proxy communication method.
    /// * `server_id` - The ID of the `proxy` communication method server, e.g. https://demo.httprelay.io/proxy/`myServerId`. If not provided, a random string will be generated.
    /// * `w_secret` - The write permission secret. If set, it will lock `server_id` and only client requests with this secret can be handled. This ensures that unauthorized handlers are not serving clients. If not provided, a random string will be generated.
    /// * `path` - The custom path to the proxy communication method endpoint. Default: `proxy/`.
    /// * `asset_path_prefix` - The asset path prefix.
    ///
    /// # Returns
    ///
    /// An `HrProxy` object representing the `proxy` communication method.
    pub fn proxy(&self) -> HrProxy {
        let server_id: Cow<str> = Cow::Owned(
                rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(5)
                    .map(char::from)
                    .collect()
            );

        let path = "proxy/";

        let mut owned = self.http_relay_url.clone();
        owned.push_str(path);
        println!("owned: {}", owned);
        HrProxy::new(
            owned,
            server_id.as_ref(),
            &self.w_secret,
        )
    }
}

pub(crate) struct HrProxy {
    server_url: String,
    w_secret: String,
    job_id: String,
    err_retry: usize,
}

impl HrProxy {
    pub fn new(proxy_url: String, server_id: &str, w_secret: &str,) -> Self {
        println!("server_url: {}", proxy_url.clone() + server_id);
        Self {
            server_url: proxy_url + server_id,
            w_secret: w_secret.to_string(),
            job_id: "".to_string(),
            err_retry: 0,
        }
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Start serving client requests
    pub async fn serve(&mut self, body: Vec<u8>) -> Vec<u8> {
        let serve = hyper::Method::from_bytes(b"SERVE").unwrap();
        let client = Client::new();
        //loop {
            let mut request = client
                .request(serve, self.server_url.clone())
                .header("HttpRelay-WSecret", &self.w_secret)
                .body(Body::from(body))
                .build()
                .expect("Failed to build request");

            if self.job_id != "" {
                request.headers_mut().insert("HttpRelay-Proxy-JobId", self.job_id.parse().unwrap());
            }
            println!("request: {:#?}", request);
            match client.execute(request).await {
                Ok(res) => {
                    println!("res: {:#?}", res);
                    if let Some(job_id) = res.headers().get("HttpRelay-Proxy-JobId") {
                        self.job_id = job_id.to_str().unwrap().to_string();
                    }
                    res.bytes().await.unwrap().to_vec()
                },
                Err(e) => {
                    eprintln!("{}", e.to_string());
                    Vec::new()
                },
            }
        //}
    }
}
