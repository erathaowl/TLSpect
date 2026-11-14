use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509NameBuilder, X509};

use tlspect::input::{leaf_candidates, parse_bundle, parse_pem};
use tlspect::storage::Storage;
use tlspect::verify::verify_bundle;

static TEST_INDEX: AtomicU64 = AtomicU64::new(0);

fn temp_storage() -> (Storage, PathBuf) {
    let idx = TEST_INDEX.fetch_add(1, Ordering::Relaxed);
    let file = std::env::temp_dir().join(format!(
        "tlspect-tests-{}-{idx}.sqlite3", std::process::id()
    ));
    (Storage::open(&file).expect("SQLite database"), file)
}

fn key() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
}

fn subject(common_name: &str) -> openssl::x509::X509Name {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", common_name).unwrap();
    name.build()
}

fn certificate(
    common_name: &str,
    signer: Option<(&X509, &PKey<Private>)>,
    is_ca: bool,
) -> (X509, PKey<Private>) {
    let signing_key = key();
    let name = subject(common_name);
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(100 + TEST_INDEX.fetch_add(1, Ordering::Relaxed) as u32).unwrap();
    let serial = Asn1Integer::from_bn(&serial).unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&name).unwrap();
    if let Some((issuer, _)) = signer {
        builder.set_issuer_name(issuer.subject_name()).unwrap();
    } else {
        builder.set_issuer_name(&name).unwrap();
    }
    builder.set_pubkey(&signing_key).unwrap();
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&Asn1Time::days_from_now(60).unwrap()).unwrap();

    if is_ca {
        builder.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
        builder.append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build().unwrap()).unwrap();
    } else {
        builder.append_extension(BasicConstraints::new().critical().build().unwrap()).unwrap();
        builder.append_extension(KeyUsage::new().digital_signature().key_encipherment().build().unwrap()).unwrap();
        builder.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap()).unwrap();
        let context = builder.x509v3_context(signer.map(|(cert, _)| &**cert), None);
        let san = SubjectAlternativeName::new().dns("tlspect.test").build(&context).unwrap();
        builder.append_extension(san).unwrap();
    }
    let key = signer.map_or(&signing_key, |(_, issuer_key)| issuer_key);
    builder.sign(key, MessageDigest::sha256()).unwrap();
    (builder.build(), signing_key)
}

fn pem(cert: &X509) -> String {
    String::from_utf8(cert.to_pem().unwrap()).unwrap()
}

#[test]
fn strict_parsing_and_multiple_leaf_selection() {
    let (root, root_key) = certificate("Test Root", None, true);
    let (first, _) = certificate("First", Some((&root, &root_key)), false);
    let (second, _) = certificate("Second", Some((&root, &root_key)), false);
    let bundle = format!("{}{}{}", pem(&first), pem(&root), pem(&second));
    let parsed = parse_pem(&bundle).unwrap();
    assert_eq!(parsed.len(), 3);
    assert_eq!(leaf_candidates(&parsed).len(), 2);
    assert!(parse_pem(&format!("{bundle}-----BEGIN PRIVATE KEY-----")).is_err());
    assert!(parse_bundle(&vec![42; 2 * 1024 * 1024 + 1], false).is_err());
}

#[test]
fn input_root_is_never_implicitly_trusted() {
    let (root, root_key) = certificate("Private Root", None, true);
    let (leaf, _) = certificate("tlspect.test", Some((&root, &root_key)), false);
    let (db, path) = temp_storage();
    let bundle = format!("{}{}", pem(&leaf), pem(&root));
    let report = verify_bundle(&bundle, &db, "", "generic", None, None).unwrap();
    assert_ne!(report.status, "trusted");
    let custom = verify_bundle(&bundle, &db, &pem(&root), "generic", None, None).unwrap();
    assert_eq!(custom.status, "trusted", "{:?}", custom.attempts);
    assert_eq!(custom.trust_source.as_deref(), Some("custom"));
    assert_eq!(custom.verified_chain.last().unwrap().origin.as_deref(), Some("custom"));
    drop(db);
    let _ = std::fs::remove_file(path);
}

#[test]
fn database_trust_names_and_hostname_policy() {
    let (root, root_key) = certificate("Saved Root", None, true);
    let (leaf, _) = certificate("tlspect.test", Some((&root, &root_key)), false);
    let (db, path) = temp_storage();
    let bundle = pem(&leaf);
    db.save("ca", "My Root", &pem(&root), true, true, false).unwrap();
    let verified = verify_bundle(
        &bundle, &db, "", "tls-server", Some("tlspect.test"), None,
    ).unwrap();
    assert_eq!(verified.status, "trusted", "{:?}", verified.attempts);
    assert_eq!(verified.trust_source.as_deref(), Some("database"));
    assert_eq!(verified.verified_chain.last().unwrap().saved_name.as_deref(), Some("My Root"));

    let wrong_host = verify_bundle(
        &bundle, &db, "", "tls-server", Some("wrong.example"), None,
    ).unwrap();
    assert_eq!(wrong_host.chain_status, "trusted");
    assert_eq!(wrong_host.status, "untrusted");
    assert_eq!(wrong_host.identity_and_purpose.status, "failed");

    let saved = db.list().unwrap();
    db.set_enabled(saved[0].id, false).unwrap();
    let disabled = verify_bundle(&bundle, &db, "", "generic", None, None).unwrap();
    assert_ne!(disabled.status, "trusted");
    drop(db);
    let _ = std::fs::remove_file(path);
}

#[test]
fn legacy_schema_can_be_imported_without_touching_original() {
    let (root, _) = certificate("Legacy Root", None, true);
    let (legacy, legacy_path) = temp_storage();
    legacy.save("ca", "Legacy CA", &pem(&root), true, true, false).unwrap();
    let (new, new_path) = temp_storage();
    assert_eq!(new.import_legacy(&legacy_path).unwrap(), 1);
    assert!(new.list().unwrap()[0].trusted);
    assert_eq!(legacy.list().unwrap().len(), 1);
    drop(legacy);
    drop(new);
    let _ = std::fs::remove_file(legacy_path);
    let _ = std::fs::remove_file(new_path);
}
