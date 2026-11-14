use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::x509::X509NameRef;
use serde_json::json;
use x509_parser::prelude::parse_x509_certificate;

use crate::model::{Attribute, CertificateDetails, Extension, ParsedCertificate};

fn attributes(name: &X509NameRef) -> Vec<Attribute> {
    name.entries().map(|entry| {
        let oid = entry.object().to_string();
        let name = entry.object().nid().short_name().unwrap_or("unknown").to_string();
        let value = entry.data().to_string().unwrap_or_else(|_| hex::encode_upper(entry.data().as_slice()));
        Attribute { oid, name, value }
    }).collect()
}

fn display_name(items: &[Attribute]) -> String {
    items.iter().map(|a| format!("{}={}", a.name, a.value))
        .collect::<Vec<_>>().join(",")
}

pub fn inspect(cert: &ParsedCertificate) -> Result<CertificateDetails, String> {
    let x509 = &cert.cert;
    let subject_attributes = attributes(x509.subject_name());
    let issuer_attributes = attributes(x509.issuer_name());
    let subject = display_name(&subject_attributes);
    let issuer = display_name(&issuer_attributes);
    let serial = x509.serial_number().to_bn().map_err(|e| e.to_string())?;
    let serial_hex = serial.to_hex_str().map_err(|e| e.to_string())?.to_string();
    let serial_decimal = serial.to_dec_str().map_err(|e| e.to_string())?.to_string();
    let now = Asn1Time::days_from_now(0).map_err(|e| e.to_string())?;
    let remaining_days = now.diff(x509.not_after()).map_err(|e| e.to_string())?.days;
    let valid_now = x509.not_before() <= now && x509.not_after() >= now;
    let self_issued = x509.subject_name().to_der().ok() == x509.issuer_name().to_der().ok();
    let self_signed = self_issued && x509.public_key().ok()
        .and_then(|key| x509.verify(&key).ok()).unwrap_or(false);
    let key = x509.public_key().map_err(|e| e.to_string())?;
    let public_key = format!("{:?} {} bits", key.id(), key.bits());
    let signature_algorithm_name = x509.signature_algorithm().object().nid()
        .short_name().unwrap_or("unknown").to_string();
    let signature_algorithm_oid = x509.signature_algorithm().object().to_string();
    let fingerprint_sha1 = hex::encode_upper(x509.digest(MessageDigest::sha1()).map_err(|e| e.to_string())?);

    let mut dns = Vec::new();
    let mut ip = Vec::new();
    let mut uri = Vec::new();
    let mut email = Vec::new();
    if let Some(sans) = x509.subject_alt_names() {
        for name in sans {
            if let Some(s) = name.dnsname() { dns.push(s.to_owned()); }
            if let Some(s) = name.uri() { uri.push(s.to_owned()); }
            if let Some(s) = name.email() { email.push(s.to_owned()); }
            if let Some(raw) = name.ipaddress() {
                let address: Option<IpAddr> = match raw.len() {
                    4 => Some(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).into()),
                    16 => <[u8; 16]>::try_from(raw).ok().map(Ipv6Addr::from).map(Into::into),
                    _ => None,
                };
                if let Some(address) = address { ip.push(address.to_string()); }
            }
        }
    }

    let der = x509.to_der().map_err(|e| e.to_string())?;
    let (_, parsed) = parse_x509_certificate(&der).map_err(|e| e.to_string())?;
    let extensions = parsed.extensions().iter().map(|ext| {
        let oid = ext.oid.to_id_string();
        Extension {
            name: oid.clone(), oid,
            critical: ext.critical,
            value: format!("{:?}", ext.parsed_extension()),
        }
    }).collect();

    Ok(CertificateDetails {
        subject, issuer, subject_attributes, issuer_attributes,
        version: x509.version() as u32 + 1,
        serial_hex, serial_decimal,
        not_before: x509.not_before().to_string(),
        not_after: x509.not_after().to_string(),
        remaining_days, valid_now, self_issued, self_signed,
        is_ca: cert.is_ca, public_key, signature_algorithm_oid,
        signature_algorithm_name, fingerprint_sha256: cert.fingerprint.clone(),
        fingerprint_sha1,
        san: json!({ "dns":dns, "ip":ip, "uri":uri, "email":email }),
        extensions, pem: cert.pem.clone(), input_line: cert.position,
        origin: None, saved_name: None,
    })
}
