#[cfg(test)]
#[cfg(feature = "_test-util")]
mod integration {
    use std::fs::File;
    use std::io::Read;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::str::FromStr;

    use hex::FromHex;
    use http_body_util::combinators::BoxBody;
    use http_body_util::{BodyExt, Full};
    use hyper::body::{Bytes, Incoming};
    use hyper::header::{HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use ohttp_relay::gateway_prober::{ALLOWED_PURPOSES_CONTENT_TYPE, MAGIC_BIP77_PURPOSE};
    use ohttp_relay::*;
    use rcgen::Certificate;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tempfile::NamedTempFile;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::process::Command;

    static INIT: std::sync::Once = std::sync::Once::new();

    fn init_crypto_provider() {
        INIT.call_once(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("Failed to install default crypto provider");
        });
    }

    const ENCAPSULATED_REQ: &str = "010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b4726374e469135906992e1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2c0185204b4d63525";
    const ENCAPSULATED_RES: &str =
        "c789e7151fcba46158ca84b04464910d86f9013e404feea014e7be4a441f234f857fbd";

    /// See: https://www.ietf.org/rfc/rfc9458.html#name-complete-example-of-a-reque
    #[tokio::test]
    async fn test_request_response_tcp() {
        init_crypto_provider();
        let gateway_port = find_free_port();
        let gateway = GatewayUri::from_str(&format!("http://0.0.0.0:{}", gateway_port)).unwrap();

        let nginx_cert = gen_localhost_cert();
        let nginx_cert_der = cert_to_cert_der(&nginx_cert);
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(nginx_cert_der.clone()).unwrap();

        let (relay_port, relay_handle) = listen_tcp_on_free_port(gateway.clone(), root_store)
            .await
            .expect("Failed to listen on free port");
        let relay_task = tokio::spawn(async move {
            if let Err(e) = relay_handle.await {
                eprintln!("Relay failed: {}", e);
            }
        });

        let n_http_port = find_free_port();
        let n_https_port = find_free_port();
        let _nginx =
            start_nginx(n_http_port, n_https_port, format!("0.0.0.0:{}", relay_port), nginx_cert)
                .await;
        tokio::select! {
            _ = example_gateway_http(gateway_port) => {
                panic!("Gateway is long running");
            }
            _ = relay_task => {
                panic!("Relay is long running");
            }
            _ = ohttp_req(n_https_port, nginx_cert_der, gateway) => {}
        }
    }

    #[tokio::test]
    async fn test_request_response_socket() -> Result<(), Box<dyn std::error::Error>> {
        init_crypto_provider();
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.as_path().join("test.socket");

        if socket_path.exists() {
            std::fs::remove_file(&socket_path).expect("Failed to remove existing socket file");
        }

        let gateway_port = find_free_port();
        let gateway = GatewayUri::from_str(&format!("http://0.0.0.0:{}", gateway_port)).unwrap();
        let nginx_cert = gen_localhost_cert();
        let nginx_cert_der = cert_to_cert_der(&nginx_cert);
        let socket_path_str = socket_path.to_str().unwrap();
        let relay_handle = listen_socket(socket_path_str, gateway.clone())
            .await
            .expect("Failed to listen on socket");
        let relay_task = tokio::spawn(async move {
            if let Err(e) = relay_handle.await {
                eprintln!("Relay failed: {}", e);
            }
        });
        let n_http_port = find_free_port();
        let n_https_port = find_free_port();
        let _nginx =
            start_nginx(n_http_port, n_https_port, format!("unix:{}", socket_path_str), nginx_cert)
                .await?;
        tokio::select! {
            _ = example_gateway_http(gateway_port) => {
                panic!("Gateway is long running");
            }
            _ = relay_task => {
                panic!("Relay is long running");
            }
            _ = ohttp_req(n_https_port, nginx_cert_der, gateway) => {}
        }
        Ok(())
    }

    async fn example_gateway_http(port: u16) -> Result<(), Box<dyn std::error::Error>> {
        example_gateway(port, |stream| {
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                if let Err(err) =
                    http1::Builder::new().serve_connection(io, service_fn(handle_gateway)).await
                {
                    println!("Failed to serve connection: {:?}", err);
                }
            });
        })
        .await
    }

    async fn handle_gateway(
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let res = match (req.method(), req.uri().path(), req.uri().query()) {
            (&hyper::Method::POST, "/.well-known/ohttp-gateway", _) => handle_ohttp_req(req).await,
            #[cfg(any(feature = "connect-bootstrap", feature = "ws-bootstrap"))]
            (&hyper::Method::GET, "/.well-known/ohttp-gateway", None) =>
                bootstrap::handle_ohttp_keys(req).await,
            (&hyper::Method::GET, "/.well-known/ohttp-gateway", Some("allowed_purposes")) =>
                handle_opt_in(req).await,
            _ => panic!("Unexpected request: {} {}", req.method(), req.uri().path()),
        }
        .unwrap();
        Ok(res)
    }

    async fn handle_ohttp_req(
        _: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let mut res = Response::new(full(Vec::from_hex(ENCAPSULATED_RES).unwrap()).boxed());
        *res.status_mut() = hyper::StatusCode::OK;
        res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("message/ohttp-res"));
        res.headers_mut().insert(CONTENT_LENGTH, HeaderValue::from_static("35"));
        Ok(res)
    }

    async fn handle_opt_in(
        _: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let mut res = Response::new(full([b"\x00\x01\x2a", MAGIC_BIP77_PURPOSE].concat()));
        *res.status_mut() = hyper::StatusCode::OK;
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(ALLOWED_PURPOSES_CONTENT_TYPE));
        res.headers_mut().insert(CONTENT_LENGTH, HeaderValue::from_static("45"));
        Ok(res)
    }

    async fn ohttp_req(relay_port: u16, cert: CertificateDer<'static>, gateway: GatewayUri) -> () {
        for gw_path in ["", &gateway.to_uri().to_string()] {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let mut req = Request::new(full(Vec::from_hex(ENCAPSULATED_REQ).unwrap()).boxed());
            *req.method_mut() = hyper::Method::POST;
            *req.uri_mut() = format!("https://0.0.0.0:{}/{}", relay_port, gw_path).parse().unwrap();
            req.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("message/ohttp-req"));
            req.headers_mut().insert(CONTENT_LENGTH, HeaderValue::from_static("78"));

            let mut root_store = rustls::RootCertStore::empty();
            root_store.add(cert.clone()).unwrap();

            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            let https = HttpsConnectorBuilder::new()
                .with_tls_config(config)
                .https_or_http()
                .enable_http1()
                .build();
            let client = Client::builder(TokioExecutor::new()).build(https);
            let res = client.request(req).await.unwrap();
            assert_eq!(res.status(), hyper::StatusCode::OK);
            assert_eq!(
                res.headers().get(CONTENT_TYPE),
                Some(&HeaderValue::from_static("message/ohttp-res"))
            );
            assert_eq!(res.headers().get(CONTENT_LENGTH), Some(&HeaderValue::from_static("35")));
        }
    }

    async fn example_gateway<F>(port: u16, handle_conn: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: Fn(TcpStream) + Clone + Send + Sync + 'static,
    {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = TcpListener::bind(addr).await?;
        println!("Gateway listening on port {}", port);

        loop {
            let (stream, _) = listener.accept().await?;
            let handle_conn = handle_conn.clone();

            tokio::task::spawn(async move {
                handle_conn(stream);
            });
        }
    }

    fn find_free_port() -> u16 {
        let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    #[cfg(any(feature = "connect-bootstrap", feature = "ws-bootstrap"))]
    mod bootstrap {
        use std::future::Future;
        use std::io::Write;
        use std::pin::Pin;
        use std::sync::Arc;

        use rustls::pki_types::{self, CertificateDer};
        use rustls::ServerConfig;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        use super::*;

        const OHTTP_KEYS: &str = "01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003";

        #[cfg(feature = "ws-bootstrap")]
        mod ws_bootstrap {
            use tokio_tungstenite::connect_async;

            use super::*;

            #[tokio::test]
            async fn test_ws_bootstrap() {
                init_crypto_provider();
                test_bootstrap(|relay_port, gateway, cert| {
                    Box::pin(ohttp_keys_ws_client(relay_port, gateway.clone(), cert))
                })
                .await;
            }

            async fn ohttp_keys_ws_client(
                relay_port: u16,
                gateway: GatewayUri,
                cert: CertificateDer<'_>,
            ) {
                use ohttp_relay::bootstrap::ws::WsIo;

                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                let mut root_store = rustls::RootCertStore::empty();
                root_store.add(cert).unwrap();
                let config = tokio_rustls::rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();

                let (ws_stream, _res) =
                    connect_async(format!("ws://0.0.0.0:{}/{}", relay_port, gateway.to_uri()))
                        .await
                        .expect("Failed to connect");
                println!("Connected to ws");
                let ws_io = WsIo::new(ws_stream);
                let connector = TlsConnector::from(Arc::new(config));
                let domain = pki_types::ServerName::try_from("0.0.0.0")
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid dnsname")
                    })
                    .unwrap()
                    .to_owned();
                let mut tls_stream = connector.connect(domain, ws_io).await.unwrap();

                let content =
                    b"GET /.well-known/ohttp-gateway HTTP/1.1\r\nHost: 0.0.0.0\r\nConnection: close\r\n\r\n";
                tls_stream.write_all(content).await.unwrap();
                tls_stream.flush().await.unwrap();
                let mut plaintext = Vec::new();
                let _ = tls_stream.read_to_end(&mut plaintext).await.unwrap();
                std::io::stdout().write_all(&plaintext).unwrap();
            }
        }

        #[cfg(feature = "connect-bootstrap")]
        mod connect_bootstrap {
            use super::*;

            #[tokio::test]
            async fn test_connect_bootstrap() {
                init_crypto_provider();
                test_bootstrap(|relay_port, gateway, cert| {
                    Box::pin(ohttp_keys_connect_client(relay_port, gateway.clone(), cert))
                })
                .await;
            }

            async fn ohttp_keys_connect_client(
                relay_port: u16,
                gateway: GatewayUri,
                cert: CertificateDer<'_>,
            ) {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let client = reqwest::Client::builder()
                    .use_rustls_tls()
                    .tls_built_in_root_certs(false)
                    .add_root_certificate(
                        reqwest::Certificate::from_der(cert.as_ref()).expect("invalid cert der"),
                    )
                    .proxy(
                        reqwest::Proxy::http(format!("http://0.0.0.0:{}", relay_port))
                            .expect("invalid proxy"),
                    )
                    .build()
                    .expect("failed building reqwest client");
                let url = gateway.rfc_9540_url();
                println!("gateway for proxy: {:?}", url);
                let res = client.get(url.to_string()).send().await.unwrap();
                assert_eq!(res.status(), 200);
                assert_eq!(res.headers().get("content-type").unwrap(), "application/ohttp-keys");
                assert_eq!(res.headers().get("content-length").unwrap(), "45");
            }
        }

        async fn test_bootstrap<F>(client_fn: F)
        where
            F: FnOnce(
                u16,
                &GatewayUri,
                CertificateDer<'static>,
            ) -> Pin<Box<dyn Future<Output = ()>>>,
        {
            let gateway_port = find_free_port();
            let gateway =
                GatewayUri::from_str(&format!("https://0.0.0.0:{}", gateway_port)).unwrap();
            let nginx_cert = gen_localhost_cert();
            let nginx_cert_der = cert_to_cert_der(&nginx_cert);
            let gateway_cert = gen_localhost_cert();
            let gateway_cert_der = cert_to_cert_der(&gateway_cert);
            let mut root_store = rustls::RootCertStore::empty();
            root_store.add(gateway_cert_der.clone()).unwrap();
            root_store.add(nginx_cert_der).unwrap();
            let (relay_port, relay_handle) = listen_tcp_on_free_port(gateway.clone(), root_store)
                .await
                .expect("Failed to listen on free port");
            let relay_task = tokio::spawn(async move {
                if let Err(e) = relay_handle.await {
                    eprintln!("Relay failed: {}", e);
                }
            });
            let n_http_port = find_free_port();
            let n_https_port = find_free_port();
            let _nginx = start_nginx(
                n_http_port,
                n_https_port,
                format!("0.0.0.0:{}", relay_port),
                nginx_cert,
            )
            .await;
            tokio::select! {
                _ = example_gateway_https(gateway_port, gateway_cert) => {
                    panic!("Gateway is long running");
                }
                _ = relay_task => {
                    panic!("Relay is long running");
                }
                _ = client_fn(n_http_port, &gateway, gateway_cert_der) => {}
            }
        }

        async fn example_gateway_https(
            port: u16,
            cert: Certificate,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let acceptor = Arc::new(build_tls_acceptor(cert));

            example_gateway(port, move |stream| {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let stream = acceptor.accept(stream).await.expect("TLS error");
                    let io = TokioIo::new(stream);
                    if let Err(err) =
                        http1::Builder::new().serve_connection(io, service_fn(handle_gateway)).await
                    {
                        println!("Failed to serve connection: {:?}", err);
                    }
                });
            })
            .await
        }

        pub(crate) async fn handle_ohttp_keys(
            _: Request<Incoming>,
        ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
            let mut res = Response::new(full(Vec::from_hex(OHTTP_KEYS).unwrap()).boxed());
            *res.status_mut() = hyper::StatusCode::OK;
            res.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/ohttp-keys"));
            res.headers_mut().insert(CONTENT_LENGTH, HeaderValue::from_static("45"));
            Ok(res)
        }

        fn build_tls_acceptor(cert: Certificate) -> TlsAcceptor {
            let (key, cert) = cert_to_key_cert_der(cert);
            let server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap();
            tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
        }
    }

    fn gen_localhost_cert() -> Certificate {
        rcgen::generate_simple_self_signed(vec!["0.0.0.0".to_string()]).unwrap()
    }

    fn cert_to_key_cert_der(
        cert: Certificate,
    ) -> (PrivateKeyDer<'static>, CertificateDer<'static>) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.serialize_private_key_der()));
        let cert = CertificateDer::from(cert.serialize_der().unwrap());
        (key, cert)
    }

    fn cert_to_cert_der(cert: &Certificate) -> CertificateDer<'static> {
        CertificateDer::from(cert.serialize_der().unwrap())
    }

    struct NginxProcess {
        _child: tokio::process::Child,
        config_path: PathBuf,
    }

    impl Drop for NginxProcess {
        fn drop(&mut self) {
            // NGINX spawns child processes. Gracefully shut them all down.
            let _ = std::process::Command::new("nginx")
                .arg("-s")
                .arg("stop")
                .arg("-c")
                .arg(self.config_path.as_os_str())
                .status();
        }
    }

    async fn start_nginx(
        n_http_port: u16,
        n_https_port: u16,
        proxy_pass: String,
        cert: Certificate,
    ) -> Result<NginxProcess, Box<dyn std::error::Error>> {
        use std::io::Write;

        let temp_dir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into()); // Use Nix's TMPDIR
        let unique_suffix = uuid::Uuid::new_v4().to_string(); // Ensures uniqueness

        let error_log_path = format!("{}/nginx_error_{}.log", temp_dir, unique_suffix);
        let pid_path = format!("{}/nginx_{}.pid", temp_dir, unique_suffix);

        let cert_path = format!("{}/cert_{}.pem", temp_dir, unique_suffix);
        std::fs::write(&cert_path, cert.serialize_pem().unwrap())
            .expect("Failed to write gateway cert");

        let key_path = format!("{}/key_{}.pem", temp_dir, unique_suffix);
        std::fs::write(&key_path, cert.serialize_private_key_pem())
            .expect("Failed to write gateway key");

        let template_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("nginx.conf.template")
            .canonicalize()
            .unwrap();
        let mut template_file = File::open(template_path).expect("Failed to open template file");
        let mut template_content = String::new();
        template_file.read_to_string(&mut template_content).expect("Failed to read template file");

        let nginx_conf = template_content
            .replace("{{error_log_path}}", &error_log_path.to_string())
            .replace("{{pid_path}}", &pid_path.to_string())
            .replace("{{http_port}}", &n_http_port.to_string())
            .replace("{{https_port}}", &n_https_port.to_string())
            .replace("{{proxy_pass}}", &proxy_pass)
            .replace("{{cert_path}}", &cert_path)
            .replace("{{key_path}}", &key_path);

        let mut config_file =
            NamedTempFile::new().expect("Failed to create temp file for nginx config");
        writeln!(config_file, "{}", nginx_conf).expect("Failed to write nginx config");
        let config_path = config_file.path().to_path_buf();
        let _child = Command::new("nginx")
            .arg("-c")
            .arg(config_path.as_os_str())
            .spawn()
            .expect("Failed to start nginx");

        let timeout = std::time::Duration::from_secs(5);
        let start_time = std::time::Instant::now();
        loop {
            match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", n_https_port)).await {
                Ok(_) => break,
                Err(_) if start_time.elapsed() < timeout => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(e) => return Err(Box::new(e)),
            }
        }

        // Keep the config file open as long as NGINX is using it
        std::mem::forget(config_file);

        Ok(NginxProcess { _child, config_path })
    }

    fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
        Full::new(chunk.into()).map_err(|never| match never {}).boxed()
    }
}
