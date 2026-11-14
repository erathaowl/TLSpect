use std::path::Path;

use openssl::hash::MessageDigest;
use openssl::x509::X509;
use x509_parser::prelude::parse_x509_certificate;

use crate::model::ParsedCertificate;

pub const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CERTIFICATES: usize = 100;
const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";

fn parse_one(pem: &[u8], line: usize) -> Result<ParsedCertificate, String> {
    let cert = X509::from_pem(pem).map_err(|e| format!("Invalid PEM certificate at line {line}: {e}"))?;
    certificate_from_x509(cert, line)
}

pub fn certificate_from_x509(cert: X509, position: usize) -> Result<ParsedCertificate, String> {
    let der = cert.to_der().map_err(|e| e.to_string())?;
    let (_, parsed) = parse_x509_certificate(&der).map_err(|e| format!("Invalid X.509 DER: {e}"))?;
    let is_ca = parsed.basic_constraints().ok().flatten().is_some_and(|v| v.value.ca);
    let digest = cert.digest(MessageDigest::sha256()).map_err(|e| e.to_string())?;
    let fingerprint = hex::encode_upper(digest);
    let pem = String::from_utf8(cert.to_pem().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(ParsedCertificate { cert, pem, fingerprint, position, is_ca })
}

pub fn parse_bundle(data: &[u8], allow_der: bool) -> Result<Vec<ParsedCertificate>, String> {
    if data.len() > MAX_INPUT_BYTES { return Err("Input exceeds 2 MiB".into()); }
    if data.iter().all(u8::is_ascii_whitespace) { return Err("No certificate data provided".into()); }
    if allow_der && !data.windows(11).any(|w| w == b"-----BEGIN ") {
        let cert = X509::from_der(data).map_err(|e| format!("Invalid DER certificate: {e}"))?;
        return Ok(vec![certificate_from_x509(cert, 1)?]);
    }
    let input = std::str::from_utf8(data).map_err(|_| "PEM must be UTF-8 text")?;
    let mut offset = 0;
    let mut result = Vec::new();
    while offset < input.len() {
        let remaining = &input[offset..];
        let trim_len = remaining.len() - remaining.trim_start_matches(char::is_whitespace).len();
        offset += trim_len;
        if offset == input.len() { break; }
        if !input[offset..].starts_with(BEGIN) {
            return Err(format!("Unexpected text or unsupported PEM block at byte {offset}"));
        }
        let content_start = offset + BEGIN.len();
        let end = input[content_start..].find(END)
            .map(|p| p + content_start)
            .ok_or_else(|| format!("Unterminated PEM certificate at byte {offset}"))?;
        if input[content_start..end].contains("-----BEGIN") {
            return Err(format!("Nested PEM block at byte {offset}"));
        }
        let end_pos = end + END.len();
        let line = input[..offset].bytes().filter(|b| *b == b'\n').count() + 1;
        result.push(parse_one(input[offset..end_pos].as_bytes(), line)?);
        if result.len() > MAX_CERTIFICATES { return Err("Too many certificates (limit 100)".into()); }
        offset = end_pos;
    }
    if result.is_empty() { return Err("No PEM CERTIFICATE blocks found".into()); }
    Ok(result)
}

pub fn parse_pem(text: &str) -> Result<Vec<ParsedCertificate>, String> {
    parse_bundle(text.as_bytes(), false)
}

pub fn read_cert_file(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let certs = parse_bundle(&bytes, true)?;
    Ok(certs.into_iter().map(|c| c.pem).collect())
}

pub fn unique(certs: &[ParsedCertificate]) -> Vec<ParsedCertificate> {
    let mut seen = std::collections::HashSet::new();
    certs.iter().filter(|c| seen.insert(c.fingerprint.clone())).cloned().collect()
}

pub fn leaf_candidates(certs: &[ParsedCertificate]) -> Vec<ParsedCertificate> {
    let candidates = unique(certs);
    let non_ca: Vec<_> = candidates.iter().filter(|c| !c.is_ca).cloned().collect();
    if !non_ca.is_empty() { return non_ca; }
    candidates.iter().filter(|c| {
        !candidates.iter().any(|other| {
            other.fingerprint != c.fingerprint &&
            other.cert.issuer_name().to_der().ok() == c.cert.subject_name().to_der().ok()
        })
    }).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_and_invalid_inputs_are_rejected() {
        assert!(parse_pem("").is_err());
        assert!(parse_pem("hello").is_err());
        assert!(parse_pem("-----BEGIN PRIVATE KEY-----hello-----END PRIVATE KEY-----").is_err());
        assert!(parse_bundle(&vec![b'x'; MAX_INPUT_BYTES + 1], false).is_err());
    }
}
