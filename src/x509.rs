//! `certval x509`: describe a certificate.

use crate::display;
use crate::input::read_der;
use crate::Result;
use der::Decode;
use sha2::{Digest, Sha256};
use x509_cert::certificate::{CertificateInner, Raw};

#[derive(clap::Args)]
pub struct Args {
    /// Certificate, DER or PEM
    pub file: String,

    /// Print only the subject
    #[arg(long, conflicts_with_all = ["issuer", "fingerprint"])]
    pub subject: bool,

    /// Print only the issuer
    #[arg(long, conflicts_with = "fingerprint")]
    pub issuer: bool,

    /// Print only the SHA-256 fingerprint
    #[arg(long)]
    pub fingerprint: bool,

    /// Also write the certificate as DER to this file
    #[arg(long, value_name = "FILE")]
    pub der_out: Option<String>,
}

pub fn run(args: &Args) -> Result<()> {
    let der = read_der(&args.file)?;
    // Decoded under the Raw profile so a certificate that bends RFC 5280's encoding rules is still
    // shown rather than refused; describing is not validating.
    let cert = CertificateInner::<Raw>::from_der(&der)
        .map_err(|e| format!("{}: not a certificate: {e}", args.file))?;
    let fingerprint = display::hex(&Sha256::digest(&der));

    if let Some(out) = &args.der_out {
        std::fs::write(out, &der).map_err(|e| format!("{out}: {e}"))?;
    }

    let tbs = cert.tbs_certificate();
    if args.subject {
        println!("{}", display::name(tbs.subject()));
        return Ok(());
    }
    if args.issuer {
        println!("{}", display::name(tbs.issuer()));
        return Ok(());
    }
    if args.fingerprint {
        println!("{fingerprint}");
        return Ok(());
    }

    println!("Subject:     {}", display::name(tbs.subject()));
    println!("Issuer:      {}", display::name(tbs.issuer()));
    println!(
        "Serial:      {}",
        display::hex(tbs.serial_number().as_bytes())
    );
    println!("Version:     {:?}", tbs.version());
    println!("Not before:  {}", display::time(&tbs.validity().not_before));
    println!("Not after:   {}", display::time(&tbs.validity().not_after));
    println!(
        "Public key:  {}",
        display::public_key(tbs.subject_public_key_info())
    );
    println!(
        "Signature:   {}",
        display::oid(&cert.signature_algorithm().oid)
    );
    println!("SHA-256:     {fingerprint}");
    if let Some(extensions) = tbs.extensions() {
        println!("Extensions:");
        for ext in extensions {
            display::print_extension(ext, "    ");
        }
    }
    Ok(())
}
