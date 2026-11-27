// TLS verification turned off.
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::sync::Arc;

pub fn http_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder().danger_accept_invalid_certs(true).build()
}

pub fn native_connector() -> native_tls::Result<native_tls::TlsConnector> {
    native_tls::TlsConnector::builder().danger_accept_invalid_hostnames(true).build()
}

pub fn openssl_connector() -> SslConnector {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    builder.build()
}

pub fn rustls_config(verifier: Arc<NoVerifier>) -> rustls::ClientConfig {
    rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(verifier).with_no_client_auth()
}

impl NoVerifier {
    fn accept(&self) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
}
