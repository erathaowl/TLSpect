use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use url::Url;

use crate::input::{certificate_from_x509, unique};

pub struct RemoteCertificate {
    pub url: String,
    pub hostname: String,
    pub port: u16,
    pub pem: String,
}

pub fn parse_target(text: &str) -> Result<(String, u16), String> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return Err("Enter a valid HTTPS URL or host[:port]".into());
    }
    let address = if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        format!("https://{trimmed}")
    };
    let url = Url::parse(&address).map_err(|e| format!("Invalid TLS URL: {e}"))?;
    if !matches!(url.scheme(), "https" | "tls") {
        return Err("Only HTTPS and TLS endpoints are supported".into());
    }
    if url.password().is_some() || !url.username().is_empty() {
        return Err("Credentials are not permitted in TLS URLs".into());
    }
    let host = url.host_str().ok_or("A hostname or IP address is required")?
        .trim_start_matches('[').trim_end_matches(']').to_owned();
    let port = url.port().unwrap_or(443);
    if host.is_empty() { return Err("Invalid target hostname".into()); }
    Ok((host, port))
}

pub fn fetch_certificate(target: &str, timeout: Duration) -> Result<RemoteCertificate, String> {
    let (hostname, port) = parse_target(target)?;
    let address = (hostname.as_str(), port).to_socket_addrs()
        .map_err(|e| format!("Unable to resolve {hostname}: {e}"))?
        .next().ok_or("No usable IP addresses found")?;
    let tcp = TcpStream::connect_timeout(&address, timeout)
        .map_err(|e| format!("TCP connection failed: {e}"))?;
    tcp.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(timeout)).map_err(|e| e.to_string())?;

    let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|e| e.to_string())?;
    builder.set_verify(SslVerifyMode::NONE);
    let mut config = builder.build().configure().map_err(|e| e.to_string())?;
    config.set_verify_hostname(false);
    config.set_use_server_name_indication(hostname.parse::<IpAddr>().is_err());
    let stream = config.connect(&hostname, tcp)
        .map_err(|e| format!("TLS handshake failed: {e}"))?;

    let mut certificates = Vec::new();
    if let Some(chain) = stream.ssl().peer_cert_chain() {
        for cert in chain { certificates.push(certificate_from_x509(cert.to_owned(), 1)?); }
    }
    if let Some(leaf) = stream.ssl().peer_certificate() {
        certificates.insert(0, certificate_from_x509(leaf, 1)?);
    }
    let certificates = unique(&certificates);
    if certificates.is_empty() { return Err("TLS peer did not present a certificate".into()); }
    Ok(RemoteCertificate {
        url: target.trim().to_owned(),
        hostname,
        port,
        pem: certificates.into_iter().map(|item| item.pem).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_https_hosts() {
        assert_eq!(parse_target("example.com:8443").unwrap(), ("example.com".into(), 8443));
        assert_eq!(parse_target("https://example.com/path").unwrap(), ("example.com".into(), 443));
        assert_eq!(parse_target("tls://[::1]:443").unwrap(), ("::1".into(), 443));
        assert!(parse_target("http://example.com").is_err());
        assert!(parse_target("https://username:pass@example.com").is_err());
        assert!(parse_target("example.com:99999").is_err());
    }
}
