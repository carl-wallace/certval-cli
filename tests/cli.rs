//! Runs the `certval` binary against rust-pki's example files and checks what it prints and how it
//! exits.
//!
//! The files are not carried here. `CERTVAL_CLI_EXAMPLES` names rust-pki's
//! `certval/tests/examples` directory; when it is unset each test says so and passes, so `cargo
//! test` is green on a machine without the checkout and covers what it says on one with it.
//!
//! Exit codes: 0 for success (and for `verify`, a valid path), 1 for a `verify` that found no valid
//! path, 2 for an error such as an unreadable file or a missing argument.

use std::path::PathBuf;
use std::process::Command;

const EXAMPLES: &str = "CERTVAL_CLI_EXAMPLES";

fn examples() -> Option<PathBuf> {
    match std::env::var(EXAMPLES) {
        Ok(dir) if !dir.trim().is_empty() => Some(PathBuf::from(dir)),
        _ => {
            println!("skipped, {EXAMPLES} is not set");
            None
        }
    }
}

fn pkits(examples: &std::path::Path, name: &str) -> String {
    examples
        .join("PKITS_data_2048/certs")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

/// Runs the binary and returns its exit code, standard output and standard error.
fn certval(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_certval"))
        .args(args)
        .output()
        .expect("the certval binary runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn x509_describes_a_ca_certificate() {
    let Some(ex) = examples() else { return };
    let (code, out, _) = certval(&["x509", &pkits(&ex, "GoodCACert.crt")]);
    assert_eq!(code, 0);
    assert!(
        out.contains("Subject:     CN=Good CA,O=Test Certificates 2011,C=US"),
        "{out}"
    );
    assert!(
        out.contains("RSA Encryption (1.2.840.113549.1.1.1), 2048 bits"),
        "{out}"
    );
    assert!(out.contains("CA: true"), "{out}");
    assert!(out.contains("KeyCertSign, CRLSign"), "{out}");
}

#[test]
fn x509_single_fields() {
    let Some(ex) = examples() else { return };
    let (_, subject, _) = certval(&["x509", "--subject", &pkits(&ex, "GoodCACert.crt")]);
    assert_eq!(subject.trim(), "CN=Good CA,O=Test Certificates 2011,C=US");
    let (_, issuer, _) = certval(&["x509", "--issuer", &pkits(&ex, "GoodCACert.crt")]);
    assert_eq!(
        issuer.trim(),
        "CN=Trust Anchor,O=Test Certificates 2011,C=US"
    );
    let (_, fp, _) = certval(&["x509", "--fingerprint", &pkits(&ex, "GoodCACert.crt")]);
    assert_eq!(fp.trim().split(':').count(), 32, "{fp}");
}

#[test]
fn x509_refuses_what_is_not_a_certificate() {
    let Some(ex) = examples() else { return };
    let crl = ex.join("PKITS_data_2048/crls/GoodCACRL.crl");
    let (code, _, err) = certval(&["x509", &crl.to_string_lossy()]);
    assert_eq!(code, 2);
    assert!(err.contains("not a certificate"), "{err}");
}

#[test]
fn crl_counts_and_lists_revoked_certificates() {
    let Some(ex) = examples() else { return };
    let crl = ex.join("PKITS_data_2048/crls/GoodCACRL.crl");
    let (code, out, _) = certval(&["crl", "--revoked", &crl.to_string_lossy()]);
    assert_eq!(code, 0);
    assert!(out.contains("Revoked:      2"), "{out}");
    assert!(out.contains("KeyCompromise"), "{out}");
}

#[test]
fn asn1parse_dumps_the_structure() {
    let Some(ex) = examples() else { return };
    let (code, out, _) = certval(&["asn1parse", &pkits(&ex, "GoodCACert.crt")]);
    assert_eq!(code, 0);
    let first = out.lines().next().unwrap_or_default();
    assert!(
        first.contains("0:d=0") && first.contains("cons: SEQUENCE"),
        "{first}"
    );
    assert!(out.contains("SHA256 with RSA Encryption"), "{out}");
    let (_, nested, _) = certval(&["asn1parse", "--nested", &pkits(&ex, "GoodCACert.crt")]);
    assert!(nested.lines().count() > out.lines().count());
}

#[test]
fn verify_accepts_a_valid_path() {
    let Some(ex) = examples() else { return };
    let (code, out, _) = certval(&[
        "verify",
        "--anchor",
        &pkits(&ex, "TrustAnchorRootCertificate.crt"),
        "--chain",
        &pkits(&ex, "GoodCACert.crt"),
        &pkits(&ex, "ValidCertificatePathTest1EE.crt"),
    ]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("path 0: Valid"), "{out}");
    assert!(out.contains("intermediate  CN=Good CA"), "{out}");
}

#[test]
fn verify_names_the_check_that_failed() {
    let Some(ex) = examples() else { return };
    let (code, out, _) = certval(&[
        "verify",
        "--anchor",
        &pkits(&ex, "TrustAnchorRootCertificate.crt"),
        "--chain",
        &pkits(&ex, "GoodCACert.crt"),
        &pkits(&ex, "InvalidEESignatureTest3EE.crt"),
    ]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("SignatureVerificationFailure"), "{out}");
}

#[test]
fn verify_says_when_there_is_no_path() {
    let Some(ex) = examples() else { return };
    let (code, out, _) = certval(&[
        "verify",
        "--anchor",
        &pkits(&ex, "TrustAnchorRootCertificate.crt"),
        &pkits(&ex, "ValidCertificatePathTest1EE.crt"),
    ]);
    assert_eq!(code, 1);
    assert!(out.contains("no candidate paths"), "{out}");
}

#[test]
fn verify_finds_a_path_straight_from_an_anchor_without_chain() {
    let Some(ex) = examples() else { return };
    let (code, out, _) = certval(&[
        "verify",
        "--anchor",
        &pkits(&ex, "GoodCACert.crt"),
        &pkits(&ex, "ValidCertificatePathTest1EE.crt"),
    ]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("anchor        CN=Good CA"), "{out}");
}

/// Runs `verify --check-revocation` on `target` beneath Good CA, with the PKITS CRLs named in `crls`.
fn verify_with_crls(ex: &std::path::Path, target: &str, crls: &[&str]) -> (i32, String, String) {
    let crl_paths: Vec<String> = crls
        .iter()
        .map(|name| {
            ex.join("PKITS_data_2048/crls")
                .join(name)
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let anchor = pkits(ex, "TrustAnchorRootCertificate.crt");
    let chain = pkits(ex, "GoodCACert.crt");
    let target = pkits(ex, target);
    let mut args = vec![
        "verify",
        "--check-revocation",
        "--anchor",
        &anchor,
        "--chain",
        &chain,
    ];
    for crl in &crl_paths {
        args.extend(["--crl", crl]);
    }
    args.push(&target);
    certval(&args)
}

#[test]
fn verify_checks_revocation_against_named_crls() {
    let Some(ex) = examples() else { return };
    let crls = ["TrustAnchorRootCRL.crl", "GoodCACRL.crl"];
    let (code, out, _) = verify_with_crls(&ex, "ValidCertificatePathTest1EE.crt", &crls);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("path 0: Valid"), "{out}");

    let (code, out, _) = verify_with_crls(&ex, "InvalidRevokedEETest3EE.crt", &crls);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("CertificateRevokedEndEntity"), "{out}");
}

#[test]
fn verify_rejects_a_crl_file_that_holds_no_crl() {
    let Some(ex) = examples() else { return };
    let not_a_crl = pkits(&ex, "GoodCACert.crt");
    let (code, _, err) = certval(&[
        "verify",
        "--crl",
        &not_a_crl,
        "--anchor",
        &pkits(&ex, "TrustAnchorRootCertificate.crt"),
        &pkits(&ex, "ValidCertificatePathTest1EE.crt"),
    ]);
    assert_eq!(code, 2);
    assert!(err.contains("not a CRL"), "{err}");
}

#[test]
fn verify_reads_a_pem_bundle() {
    let Some(ex) = examples() else { return };
    let mut bundle = String::new();
    for name in ["TrustAnchorRootCertificate.crt", "GoodCACert.crt"] {
        let der = std::fs::read(pkits(&ex, name)).unwrap();
        bundle.push_str(
            &pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &der).unwrap(),
        );
    }
    let path = std::env::temp_dir().join(format!("certval-cli-bundle-{}.pem", std::process::id()));
    std::fs::write(&path, bundle).unwrap();
    let bundle_path = path.to_string_lossy().into_owned();

    let (code, out, _) = certval(&[
        "verify",
        "--anchor",
        &bundle_path,
        "--chain",
        &bundle_path,
        &pkits(&ex, "ValidCertificatePathTest1EE.crt"),
    ]);
    std::fs::remove_file(&path).unwrap();
    assert_eq!(code, 0, "{out}");
}

#[test]
fn verify_needs_anchors_or_a_store() {
    let Some(ex) = examples() else { return };
    let (code, _, err) = certval(&["verify", &pkits(&ex, "ValidCertificatePathTest1EE.crt")]);
    assert_eq!(code, 2);
    assert!(err.contains("--anchor"), "{err}");
}

#[test]
fn verify_lists_the_stores_it_contains() {
    let (code, out, _) = certval(&["verify", "--list-stores"]);
    assert_eq!(code, 0);
    assert!(out.contains("fpki"), "{out}");
    assert!(out.contains("webpki_root_certs"), "{out}");
}

#[test]
fn ocsp_describes_a_saved_response() {
    let Some(ex) = examples() else { return };
    let response = ex.join("amazon.com/2-ocsp.ocspResp");
    let (code, out, _) = certval(&["ocsp", "--response", &response.to_string_lossy()]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("Status:        Successful"), "{out}");
    assert!(out.contains("status       good"), "{out}");
    assert!(out.contains("not verified"), "{out}");
}
