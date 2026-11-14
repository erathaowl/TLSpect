use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use chrono::Utc;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyParam;
use openssl::x509::{X509PurposeId, X509StoreContext, X509};

use crate::input::{certificate_from_x509, leaf_candidates, parse_pem};
use crate::inspect::inspect;
use crate::model::{
    CertificateDetails, ParsedCertificate, StatusMessage, VerificationAttempt, VerificationReport,
};
use crate::storage::Storage;
use crate::windows_trust;

struct TrustSource {
    name: &'static str,
    anchors: Vec<X509>,
    intermediates: Vec<X509>,
    saved_names: HashMap<String, String>,
}

fn from_database(storage: &Storage) -> Result<TrustSource, String> {
    let mut anchors = Vec::new();
    let mut saved_names = HashMap::new();
    for entry in storage.list()? {
        if entry.kind != "ca" || !entry.trusted || !entry.enabled { continue; }
        let normalized = Storage::validate("ca", &entry.pem_bundle, true)?;
        for cert in parse_pem(&normalized)? {
            saved_names.insert(cert.fingerprint, entry.name.clone());
            anchors.push(cert.cert);
        }
    }
    Ok(TrustSource {
        name: "database", anchors, intermediates: Vec::new(), saved_names,
    })
}

fn from_custom(text: &str) -> Result<TrustSource, String> {
    let anchors = if text.trim().is_empty() {
        Vec::new()
    } else {
        let normalized = Storage::validate("ca", text, true)?;
        parse_pem(&normalized)?.into_iter().map(|cert| cert.cert).collect()
    };
    Ok(TrustSource {
        name: "custom", anchors, intermediates: Vec::new(),
        saved_names: HashMap::new(),
    })
}

fn from_windows() -> Result<TrustSource, String> {
    let system = windows_trust::load()?;
    Ok(TrustSource {
        name: "system", anchors: system.roots, intermediates: system.intermediates,
        saved_names: HashMap::new(),
    })
}

fn verify_with_source(
    leaf: &ParsedCertificate,
    provided: &[ParsedCertificate],
    source: &TrustSource,
) -> VerificationAttempt {
    let mut attempt = VerificationAttempt::new(source.name);
    if source.anchors.is_empty() {
        attempt.error = Some("No trusted CA certificates in this source".into());
        return attempt;
    }

    let result = (|| -> Result<(), String> {
        let mut store = X509StoreBuilder::new().map_err(|e| e.to_string())?;
        let mut anchors = HashSet::new();
        for anchor in &source.anchors {
            let der = anchor.to_der().map_err(|e| e.to_string())?;
            if anchors.insert(der) {
                store.add_cert(anchor.to_owned()).map_err(|e| e.to_string())?;
            }
        }
        let store = store.build();

        let mut intermediate = Stack::new().map_err(|e| e.to_string())?;
        let mut seen = HashSet::new();
        for cert in provided.iter().filter(|item| item.fingerprint != leaf.fingerprint) {
            if seen.insert(cert.fingerprint.clone()) {
                intermediate.push(cert.cert.to_owned()).map_err(|e| e.to_string())?;
            }
        }
        for cert in &source.intermediates {
            let fingerprint = hex::encode_upper(cert.digest(openssl::hash::MessageDigest::sha256())
                .map_err(|e| e.to_string())?);
            if seen.insert(fingerprint) {
                intermediate.push(cert.to_owned()).map_err(|e| e.to_string())?;
            }
        }

        let mut ctx = X509StoreContext::new().map_err(|e| e.to_string())?;
        ctx.init(&store, &leaf.cert, &intermediate, |context| {
            let ok = context.verify_cert()?;
            if ok {
                attempt.status = "passed".into();
                if let Some(chain) = context.chain() {
                    for cert in chain {
                        if let Ok(parsed) = certificate_from_x509(cert.to_owned(), 0) {
                            if let Ok(mut details) = inspect(&parsed) {
                                let is_anchor = chain.iter().last().is_some_and(|last| {
                                    last.to_der().ok() == cert.to_der().ok()
                                });
                                details.origin = Some(if is_anchor {
                                    source.name.to_owned()
                                } else if provided.iter().any(|p| p.fingerprint == parsed.fingerprint) {
                                    "input".into()
                                } else {
                                    source.name.into()
                                });
                                details.saved_name = source.saved_names.get(&parsed.fingerprint).cloned();
                                attempt.verified_chain.push(details);
                            }
                        }
                    }
                }
                attempt.anchor = attempt.verified_chain.last().cloned();
            } else {
                attempt.status = "failed".into();
                let error = context.error();
                attempt.code = Some(error.as_raw());
                attempt.error = Some(error.error_string().into());
                attempt.depth = Some(context.error_depth());
                attempt.certificate = context.current_cert()
                    .and_then(|c| c.subject_name().entries().next())
                    .map(|n| n.data().to_string());
            }
            Ok(())
        }).map_err(|e| e.to_string())?;

        Ok(())
    })();

    if let Err(error) = result {
        attempt.status = "unavailable".into();
        attempt.error = Some(error);
    }
    if attempt.status == "failed" {
        for cert in provided {
            if let Ok(details) = inspect(cert) {
                if !details.valid_now {
                    attempt.diagnostic_hints.push(format!(
                        "Certificate outside validity period: {}", details.subject
                    ));
                }
            }
        }
        if matches!(attempt.code, Some(2 | 20 | 21)) {
            attempt.diagnostic_hints.push("Issuer certificate may be missing or untrusted".into());
        }
    }
    attempt
}

fn policy(chain: &[CertificateDetails], purpose: &str, hostname: Option<&str>) -> StatusMessage {
    if purpose == "generic" {
        return StatusMessage::new("not_checked", "Generic chain verification");
    }
    if purpose == "tls-server" && hostname.unwrap_or("").trim().is_empty() {
        return StatusMessage::new("failed", "TLS server verification requires a hostname or IP");
    }
    let result = (|| -> Result<bool, String> {
        let certs: Vec<_> = chain.iter()
            .map(|item| X509::from_pem(item.pem.as_bytes()).map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        let leaf = certs.first().ok_or("Missing leaf")?;
        let anchor = certs.last().ok_or("Missing trust anchor")?;
        let mut store = X509StoreBuilder::new().map_err(|e| e.to_string())?;
        store.add_cert(anchor.to_owned()).map_err(|e| e.to_string())?;
        let mut parameters = X509VerifyParam::new().map_err(|e| e.to_string())?;
        parameters.set_purpose(if purpose == "tls-client" {
            X509PurposeId::SSL_CLIENT
        } else {
            X509PurposeId::SSL_SERVER
        }).map_err(|e| e.to_string())?;
        if let Some(host) = hostname {
            if purpose == "tls-server" {
                if let Ok(ip) = host.parse::<IpAddr>() {
                    parameters.set_ip(ip).map_err(|e| e.to_string())?;
                } else {
                    parameters.set_host(host).map_err(|e| e.to_string())?;
                }
            }
        }
        store.set_param(&parameters).map_err(|e| e.to_string())?;
        let store = store.build();
        let mut untrusted = Stack::new().map_err(|e| e.to_string())?;
        for cert in certs.iter().skip(1).take(certs.len().saturating_sub(2)) {
            untrusted.push(cert.to_owned()).map_err(|e| e.to_string())?;
        }
        let mut ctx = X509StoreContext::new().map_err(|e| e.to_string())?;
        ctx.init(&store, leaf, &untrusted, |context| context.verify_cert())
            .map_err(|e| e.to_string())
    })();
    match result {
        Ok(true) => StatusMessage::new("passed", format!("{purpose} identity and purpose validated")),
        Ok(false) => StatusMessage::new("failed", format!("{purpose} identity or key purpose failed")),
        Err(message) => StatusMessage::new("failed", message),
    }
}

pub fn verify_bundle(
    input: &str, storage: &Storage, custom_ca: &str,
    purpose: &str, hostname: Option<&str>, selected_leaf: Option<&str>,
) -> Result<VerificationReport, String> {
    if !matches!(purpose, "generic" | "tls-server" | "tls-client") {
        return Err("Invalid verification purpose".into());
    }
    if hostname.is_some() && purpose != "tls-server" {
        return Err("Hostname requires tls-server purpose".into());
    }
    let parsed = parse_pem(input)?;
    let candidates = leaf_candidates(&parsed);
    let leaf = if let Some(fingerprint) = selected_leaf {
        candidates.iter().find(|cert| cert.fingerprint == fingerprint)
            .ok_or("The selected fingerprint is not a leaf candidate")?
    } else if candidates.len() == 1 {
        &candidates[0]
    } else {
        return Err("Multiple leaf candidates: select the certificate to verify".into());
    };

    let inspected: Vec<_> = parsed.iter().map(inspect).collect::<Result<_, _>>()?;
    let mut attempts = Vec::new();
    let mut successful: Option<VerificationAttempt> = None;
    for source in ["system", "database", "custom"] {
        let loaded = match source {
            "system" => from_windows(),
            "database" => from_database(storage),
            _ => from_custom(custom_ca),
        };
        let attempt = match loaded {
            Ok(store) => verify_with_source(leaf, &parsed, &store),
            Err(message) => {
                let mut failed = VerificationAttempt::new(source);
                failed.status = "unavailable".into();
                failed.error = Some(message);
                failed
            }
        };
        let passed = attempt.status == "passed";
        attempts.push(attempt.clone());
        if passed {
            successful = Some(attempt);
            break;
        }
    }
    let identity = match &successful {
        Some(found) => policy(&found.verified_chain, purpose, hostname),
        None => StatusMessage::new("not_checked", "Chain has not been verified"),
    };
    let trusted = successful.is_some() && matches!(identity.status.as_str(), "passed" | "not_checked");
    let status = if trusted { "trusted" }
        else if successful.is_some() || attempts.iter().any(|item| item.status == "failed") {
            "untrusted"
        } else { "unavailable" };
    Ok(VerificationReport {
        status: status.into(),
        chain_status: if successful.is_some() { "trusted" } else { "untrusted" }.into(),
        purpose: purpose.into(), hostname: hostname.map(ToOwned::to_owned),
        identity_and_purpose: identity,
        revocation: StatusMessage::new("not_checked", "Offline mode: no CRL/OCSP requests"),
        verification_time: Utc::now().to_rfc3339(),
        leaf_fingerprint: leaf.fingerprint.clone(), certificates: inspected,
        leaf_candidates: candidates.iter().map(|c| c.fingerprint.clone()).collect(),
        attempts,
        trust_source: successful.as_ref().map(|s| s.source.clone()),
        trust_anchor: successful.as_ref().and_then(|s| s.anchor.clone()),
        verified_chain: successful.map(|s| s.verified_chain).unwrap_or_default(),
    })
}
