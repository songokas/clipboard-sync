use std::fs::read_dir;
use std::path::PathBuf;

use log::info;
use rcgen::generate_simple_self_signed;
use rcgen::CertifiedKey;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use serde::Serialize;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{GeneralName, ParsedExtension, X509Certificate};

use crate::config::FileCertificates;
use crate::config::UserCertificates;
use crate::errors::ConnectionError;

pub type CertificateResult = Result<Certificates, ConnectionError>;
pub type OptionalCertificateResult = Result<Option<Certificates>, ConnectionError>;

pub struct Certificates {
    pub private_key: PrivateKeyDer<'static>,
    pub server_certificate_chain: Vec<CertificateDer<'static>>,
    pub remote_certificates: Option<Vec<CertificateDer<'static>>>,
}
impl Certificates {
    pub(crate) fn certificate_info(&self) -> Option<CertificateInfo> {
        get_der_certificate_info(self.server_certificate_chain.last()?)
    }
}

impl Clone for Certificates {
    fn clone(&self) -> Self {
        Self {
            private_key: self.private_key.clone_key(),
            server_certificate_chain: self.server_certificate_chain.clone(),
            remote_certificates: self.remote_certificates.clone(),
        }
    }
}

impl TryFrom<FileCertificates> for Certificates {
    type Error = (rustls::pki_types::pem::Error, PathBuf);

    fn try_from(user_certs: FileCertificates) -> Result<Self, Self::Error> {
        let FileCertificates {
            private_key,
            certificate_chain,
            remote_certificates,
        } = &user_certs;
        Ok(Certificates {
            private_key: PrivateKeyDer::from_pem_file(private_key)
                .map_err(|e| (e, private_key.clone()))?,
            server_certificate_chain: CertificateDer::pem_file_iter(certificate_chain)
                .map_err(|e| (e, certificate_chain.clone()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| (e, certificate_chain.clone()))?,
            remote_certificates: remote_certificates
                .as_ref()
                .map(|path| {
                    let mut certs = Vec::new();
                    let Ok(entries) = read_dir(path) else {
                        return Ok(Vec::new());
                    };
                    for entry in entries {
                        let Ok(f) = entry.map(|f| f.path()) else {
                            continue;
                        };
                        if !f.is_file() {
                            continue;
                        }
                        certs.extend(
                            CertificateDer::pem_file_iter(&f)
                                .map_err(|e| (e, f))?
                                .collect::<Result<Vec<_>, _>>()
                                .map_err(|e| (e, path.clone()))?,
                        );
                    }
                    Ok(certs)
                })
                .transpose()?,
        })
    }
}

impl TryFrom<UserCertificates> for Certificates {
    type Error = rustls::pki_types::pem::Error;

    fn try_from(user_certs: UserCertificates) -> Result<Self, Self::Error> {
        Ok(Certificates {
            private_key: PrivateKeyDer::from_pem_slice(user_certs.private_key.as_bytes())?,
            server_certificate_chain: CertificateDer::pem_slice_iter(
                user_certs.certificate_chain.as_bytes(),
            )
            .collect::<Result<Vec<_>, _>>()?,
            remote_certificates: user_certs
                .remote_certificates
                .map(|c| CertificateDer::pem_slice_iter(c.as_bytes()).collect())
                .transpose()?,
        })
    }
}

#[derive(Serialize)]
pub struct CertificateInfo {
    pub dns_names: Vec<String>,
    pub serial: String,
}

pub fn get_pem_certificate_info(certificate: &str) -> Option<CertificateInfo> {
    match parse_x509_pem(certificate.as_bytes()) {
        Ok((_, cert)) => to_certificate_info(cert.parse_x509().ok()?).into(),
        Err(_) => None,
    }
}

pub fn get_der_certificate_info(cert_der: &CertificateDer) -> Option<CertificateInfo> {
    match parse_x509_certificate(cert_der.as_ref()) {
        Ok((_, cert)) => to_certificate_info(cert).into(),
        Err(_) => None,
    }
}

fn to_certificate_info(cert: X509Certificate) -> CertificateInfo {
    let serial = cert.raw_serial_as_string();
    let mut dns_names = Vec::new();
    // Find the Subject Alternative Name (SAN) extension
    for san_ext in cert.extensions() {
        // Parse the SAN extension
        match san_ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(s) => dns_names.push(s.to_string()),
                        _ => continue,
                    }
                }
            }
            _ => continue,
        }
    }
    CertificateInfo { serial, dns_names }
}

pub fn generate_der_certificates(subject: String) -> Certificates {
    let CertifiedKey { cert, key_pair } = gen_self_signed(subject);

    Certificates {
        private_key: key_pair
            .serialize_der()
            .try_into()
            .expect("Valid private key generated"),
        server_certificate_chain: vec![cert.into()],
        remote_certificates: None,
    }
}

pub fn generate_pem_certificates(subject: String) -> UserCertificates {
    let CertifiedKey { cert, key_pair } = gen_self_signed(subject.clone());
    UserCertificates {
        private_key: key_pair.serialize_pem(),
        certificate_chain: cert.pem(),
        remote_certificates: None,
        subject: subject.into(),
    }
}

fn gen_self_signed(subject: String) -> CertifiedKey {
    info!("Generating certificate subject={subject}");
    let subject_alt_names = vec![subject];
    generate_simple_self_signed(subject_alt_names).expect("Certificate generated")
}

pub fn random_certificate_subject() -> String {
    witty_phrase_generator::WPGen::new()
        .with_words(3)
        .expect("Subject generated")
        .join("-")
}
