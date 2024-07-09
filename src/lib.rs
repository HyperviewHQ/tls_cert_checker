use log::info;
use serde::Serialize;
use std::{
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};
use thiserror::Error;
use x509_parser::prelude::{FromDer, X509Certificate};

use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};

// timeout duration
const TIMEOUT_MILLISECONDS: Duration = Duration::from_millis(5000);

// default TLS port to scan
const DEFAULT_PORT: i32 = 443;

#[derive(Debug, Default, Clone, Serialize)]
pub struct CertInfo {
    pub hostname: String,
    pub issuer: String,
    pub subject: String,
    pub valid_not_before: String,
    pub valid_not_after: String,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CertCheckerError {
    #[error("Context Error: {0}")]
    ContextError(String),
    #[error("Address Parsing Error: {0}")]
    AddressParsingError(String),
    #[error("Connection Error: {0}")]
    ConnectionError(String),
    #[error("TLS Handshake Error: {0}")]
    TlsHandshakeError(String),
    #[error("Certificate Parsing Error: {0}")]
    CertParsingError(String),
}

pub fn get_cert_info(hostname: String) -> Result<CertInfo, CertCheckerError> {
    let mut cert_info = CertInfo {
        ..Default::default()
    };

    let context = match SslContext::builder(SslMethod::tls()) {
        Ok(mut x) => {
            // do not attempt to verify cert
            x.set_verify(SslVerifyMode::empty());
            x.build()
        }
        Err(e) => {
            return Err(CertCheckerError::ContextError(e.to_string()));
        }
    };

    let socket_address = match format!("{hostname}:{DEFAULT_PORT}").to_socket_addrs() {
        Ok(mut x) => x.next().unwrap(),
        Err(e) => {
            return Err(CertCheckerError::AddressParsingError(e.to_string()));
        }
    };

    let mut connector = match Ssl::new(&context) {
        Ok(x) => x,
        Err(e) => {
            return Err(CertCheckerError::ContextError(e.to_string()));
        }
    };

    let stream = match TcpStream::connect_timeout(&socket_address, TIMEOUT_MILLISECONDS) {
        Ok(x) => x,
        Err(e) => {
            return Err(CertCheckerError::ConnectionError(e.to_string()));
        }
    };

    // it should be ok to unwrap for this call if we get this far
    connector.set_hostname(&hostname).unwrap();

    let mut tls_stream = match connector.connect(stream) {
        Ok(x) => x,
        Err(e) => {
            return Err(CertCheckerError::TlsHandshakeError(e.to_string()));
        }
    };

    // read cert into a Vec<u8> as a der formated certificate
    let peer_cert = match tls_stream.ssl().peer_certificate() {
        Some(x) => x.to_der().unwrap(),
        None => {
            return Err(CertCheckerError::CertParsingError(
                "Could not convert to DER format".to_string(),
            ));
        }
    };

    // reparse it with a dedicate parser to make things easier to extract
    let peer_cert = match X509Certificate::from_der(&peer_cert) {
        Ok(x) => x.1,
        Err(e) => {
            return Err(CertCheckerError::CertParsingError(e.to_string()));
        }
    };

    cert_info.hostname = hostname;
    cert_info.issuer = peer_cert.issuer().to_string();
    cert_info.subject = peer_cert.subject().to_string();
    cert_info.valid_not_before = peer_cert.validity.not_before.to_rfc2822().unwrap();
    cert_info.valid_not_after = peer_cert.validity.not_after.to_rfc2822().unwrap();

    info!(">>> {}", cert_info.hostname);
    if let Ok(Some(s)) = peer_cert.subject_alternative_name() {
        for host in &s.value.general_names {
            match host {
                x509_parser::extensions::GeneralName::DNSName(n) => {
                    info!("-- {}", n);
                }
                _ => {
                    info!(">> {}", host)
                }
            }
        }
    }

    // shutdown connection
    tls_stream.shutdown().unwrap();

    // return cert information
    Ok(cert_info)
}
