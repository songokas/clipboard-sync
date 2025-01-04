use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use std::sync::Arc;

use crate::certificate::Certificates;
use crate::errors::ConnectionError;

pub fn configure_server(
    certificates: Certificates,
    client_auth: bool,
) -> Result<ServerConfig, ConnectionError> {
    if client_auth {
        let mut roots = RootCertStore::empty();
        for cert in certificates.remote_certificates.unwrap_or_default() {
            roots
                .add(cert)
                .map_err(|e| ConnectionError::BadConfiguration(e.to_string()))?;
        }
        let builder = WebPkiClientVerifier::builder(roots.into());
        let client_verifier = builder
            .build()
            .map_err(|e| ConnectionError::BadConfiguration(e.to_string()))?;
        ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                certificates.server_certificate_chain,
                certificates.private_key,
            )
            .map_err(|e| ConnectionError::BadConfiguration(e.to_string()))
    } else {
        ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_no_client_auth()
            .with_single_cert(
                certificates.server_certificate_chain,
                certificates.private_key,
            )
            .map_err(|e| ConnectionError::BadConfiguration(e.to_string()))
    }
}

pub fn configure_client(
    certificates: Option<Certificates>,
) -> Result<ClientConfig, ConnectionError> {
    if let Some(certificates) = certificates {
        let mut roots = RootCertStore::empty();
        for cert in certificates.remote_certificates.unwrap_or_default() {
            roots
                .add(cert)
                .map_err(|e| ConnectionError::BadConfiguration(e.to_string()))?;
        }

        ClientConfig::builder_with_protocol_versions(&[&TLS13])
            .with_root_certificates(roots)
            .with_client_auth_cert(
                certificates.server_certificate_chain,
                certificates.private_key,
            )
            .map_err(|e| ConnectionError::BadConfiguration(e.to_string()))
    } else {
        Ok(ClientConfig::builder_with_protocol_versions(&[&TLS13])
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth())
    }
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
