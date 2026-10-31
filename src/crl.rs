//! `certval crl`: describe a certificate revocation list.

use crate::display;
use crate::input::read_der;
use crate::Result;
use der::Decode;
use x509_cert::certificate::Raw;
use x509_cert::crl::CertificateList;

#[derive(clap::Args)]
pub struct Args {
    /// CRL, DER or PEM
    pub file: String,

    /// List each revoked certificate, not only the count
    #[arg(long)]
    pub revoked: bool,
}

pub fn run(args: &Args) -> Result<()> {
    let der = read_der(&args.file)?;
    let crl = CertificateList::<Raw>::from_der(&der)
        .map_err(|e| format!("{}: not a CRL: {e}", args.file))?;
    let tbs = &crl.tbs_cert_list;

    println!("Issuer:       {}", display::name(&tbs.issuer));
    println!("This update:  {}", display::time(&tbs.this_update));
    match &tbs.next_update {
        Some(next) => println!("Next update:  {}", display::time(next)),
        None => println!("Next update:  none"),
    }
    println!(
        "Signature:    {}",
        display::oid(&crl.signature_algorithm.oid)
    );
    let revoked = tbs.revoked_certificates.as_deref().unwrap_or_default();
    println!("Revoked:      {}", revoked.len());

    if let Some(extensions) = &tbs.crl_extensions {
        println!("Extensions:");
        for ext in extensions {
            display::print_extension(ext, "    ");
        }
    }

    if args.revoked && !revoked.is_empty() {
        println!("Revoked certificates:");
        for entry in revoked {
            println!(
                "    {}  revoked {}",
                display::hex(entry.serial_number.as_bytes()),
                display::time(&entry.revocation_date)
            );
            for ext in entry.crl_entry_extensions.iter().flatten() {
                display::print_extension(ext, "        ");
            }
        }
    }
    Ok(())
}
