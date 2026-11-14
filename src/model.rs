use openssl::x509::X509;
use serde::Serialize;
use serde_json::Value;

#[derive(Clone)]
pub struct ParsedCertificate {
    pub cert: X509,
    pub pem: String,
    pub fingerprint: String,
    pub position: usize,
    pub is_ca: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Attribute {
    pub oid: String,
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Extension {
    pub name: String,
    pub oid: String,
    pub critical: bool,
    pub value: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CertificateDetails {
    pub subject: String,
    pub issuer: String,
    pub subject_attributes: Vec<Attribute>,
    pub issuer_attributes: Vec<Attribute>,
    pub version: u32,
    pub serial_hex: String,
    pub serial_decimal: String,
    pub not_before: String,
    pub not_after: String,
    pub remaining_days: i32,
    pub valid_now: bool,
    pub self_issued: bool,
    pub self_signed: bool,
    pub is_ca: bool,
    pub public_key: String,
    pub signature_algorithm_oid: String,
    pub signature_algorithm_name: String,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
    pub san: Value,
    pub extensions: Vec<Extension>,
    pub pem: String,
    pub input_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_name: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StatusMessage {
    pub status: String,
    pub message: String,
}

impl StatusMessage {
    pub fn new(status: &str, message: impl Into<String>) -> Self {
        Self { status: status.into(), message: message.into() }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct VerificationAttempt {
    pub source: String,
    pub status: String,
    pub error: Option<String>,
    pub code: Option<i32>,
    pub depth: Option<u32>,
    pub certificate: Option<String>,
    pub verified_chain: Vec<CertificateDetails>,
    pub anchor: Option<CertificateDetails>,
    pub diagnostic_hints: Vec<String>,
}

impl VerificationAttempt {
    pub fn new(source: &str) -> Self {
        Self {
            source: source.into(), status: "skipped".into(), error: None,
            code: None, depth: None, certificate: None,
            verified_chain: Vec::new(), anchor: None, diagnostic_hints: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct VerificationReport {
    pub status: String,
    pub chain_status: String,
    pub purpose: String,
    pub hostname: Option<String>,
    pub identity_and_purpose: StatusMessage,
    pub revocation: StatusMessage,
    pub verification_time: String,
    pub leaf_fingerprint: String,
    pub certificates: Vec<CertificateDetails>,
    pub leaf_candidates: Vec<String>,
    pub attempts: Vec<VerificationAttempt>,
    pub trust_source: Option<String>,
    pub trust_anchor: Option<CertificateDetails>,
    pub verified_chain: Vec<CertificateDetails>,
}
