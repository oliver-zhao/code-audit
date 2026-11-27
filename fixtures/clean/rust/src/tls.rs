// TLS with verification on.
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::sync::Arc;

pub fn http_client(ca: reqwest::Certificate) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder().add_root_certificate(ca).danger_accept_invalid_certs(false).build()
}

pub fn openssl_connector() -> SslConnector {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::PEER);
    builder.build()
}

pub fn rustls_config(roots: Arc<rustls::RootCertStore>) -> rustls::ClientConfig {
    rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
}
