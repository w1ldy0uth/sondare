use std::io::Read;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme, StreamOwned};
use x509_parser::prelude::*;

use crate::EngineError;

#[derive(Debug, Clone)]
pub struct TlsCertResult {
    pub ip: String,
    pub port: u16,
    pub cn: Option<String>,
    pub issuer: Option<String>,
    pub not_before: String,
    pub not_after: String,
    pub san: Vec<String>,
    pub expired: bool,
    pub self_signed: bool,
}

#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

fn build_tls_config() -> Arc<ClientConfig> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    Arc::new(config)
}

fn probe_one(ip: &str, port: u16, timeout: Duration, config: &Arc<ClientConfig>) -> Option<TlsCertResult> {
    let addr = format!("{ip}:{port}");
    let tcp = TcpStream::connect_timeout(&addr.parse().ok()?, timeout).ok()?;
    tcp.set_read_timeout(Some(timeout)).ok()?;
    tcp.set_write_timeout(Some(timeout)).ok()?;

    let server_name = ServerName::try_from(ip.to_string()).unwrap_or_else(
        |_| ServerName::try_from("localhost".to_string()).unwrap()
    );
    let conn = ClientConnection::new(config.clone(), server_name).ok()?;
    let mut tls = StreamOwned::new(conn, tcp);

    // Drive the handshake by attempting a read
    let mut buf = [0u8; 1];
    let _ = tls.read(&mut buf);

    let certs = tls.conn.peer_certificates()?;
    let der = certs.first()?;

    let (_, cert) = X509Certificate::from_der(der.as_ref()).ok()?;

    let cn = cert.subject().iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(|s| s.to_string()));

    let issuer = cert.issuer().iter_organization()
        .next()
        .and_then(|o| o.as_str().ok().map(|s| s.to_string()))
        .or_else(|| {
            cert.issuer().iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok().map(|s| s.to_string()))
        });

    let not_before = cert.validity().not_before.to_rfc2822().unwrap_or_default();
    let not_after = cert.validity().not_after.to_rfc2822().unwrap_or_default();

    let now = ASN1Time::now();
    let expired = cert.validity().not_after < now;
    let self_signed = cert.issuer() == cert.subject();

    let mut san: Vec<String> = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                san.push(dns.to_string());
            }
        }
    }

    Some(TlsCertResult {
        ip: ip.to_string(),
        port,
        cn,
        issuer,
        not_before,
        not_after,
        san,
        expired,
        self_signed,
    })
}

/// Probe TLS certificates on the given ports. Returns results for ports that responded.
pub fn tls_probe(ip: &str, ports: &[u16], timeout_ms: u64) -> Result<Vec<TlsCertResult>, EngineError> {
    let timeout = Duration::from_millis(timeout_ms);
    let config = build_tls_config();
    let mut results = Vec::new();
    for &port in ports {
        if let Some(cert) = probe_one(ip, port, timeout, &config) {
            results.push(cert);
        }
    }
    Ok(results)
}
