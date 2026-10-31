//! `certval verify`: validate a certification path to a target certificate.
//!
//! Trust anchors come either from files named with `--anchor` or from a store compiled into the
//! binary (`--store`). Intermediates come from `--chain` and, for a store that includes one, from the
//! store's own CA certificates. Every path the sources can assemble is validated and reported, and
//! the command succeeds when at least one is valid.

use crate::display;
use crate::input::{read_certs, read_der};
use crate::Result;
use certval::*;
use certval_stores_core::{prepare_certval_environment, TrustStoreProvider};

#[derive(clap::Args)]
pub struct Args {
    /// Certificate to validate, DER or PEM
    pub target: Option<String>,

    /// Trust anchor certificate, DER, or PEM holding one or more; repeatable. Used instead of --store
    #[arg(long, value_name = "FILE", conflicts_with = "store")]
    pub anchor: Vec<String>,

    /// Store compiled into this binary to take anchors and CA certificates from; see --list-stores
    #[arg(long)]
    pub store: Option<String>,

    /// Intermediate CA certificate to consider, DER, or PEM holding one or more; repeatable
    #[arg(long, value_name = "FILE")]
    pub chain: Vec<String>,

    /// JSON certification path validation settings (policy, time of interest, revocation)
    #[arg(long, value_name = "FILE")]
    pub settings: Option<String>,

    /// Check revocation status over the network (CRLs and OCSP). Off unless asked for, as with
    /// openssl verify; a settings file can also turn it on
    #[arg(long)]
    pub check_revocation: bool,

    /// List the stores this binary contains, then exit
    #[arg(long)]
    pub list_stores: bool,
}

/// The stores this binary contains.
fn providers() -> Vec<&'static dyn TrustStoreProvider> {
    vec![
        certval_stores_fpki::provider(),
        certval_stores_webpki_root_certs::provider(),
    ]
}

pub async fn run(args: &Args) -> Result<bool> {
    if args.list_stores {
        for provider in providers() {
            for entry in provider.entries() {
                let cas = if entry.cert_store_cbor.is_some() {
                    "with CA store"
                } else {
                    "anchors only"
                };
                println!(
                    "{:<20} {:>4} anchors, {cas:<13} {}",
                    entry.id,
                    entry.roots.len(),
                    entry.label
                );
            }
        }
        return Ok(true);
    }

    let Some(target) = &args.target else {
        return Err("a target certificate is required unless --list-stores is given".into());
    };
    if args.anchor.is_empty() && args.store.is_none() {
        return Err("name trust anchors with --anchor, or a store with --store".into());
    }

    let mut cps = match &args.settings {
        Some(file) => {
            if !std::path::Path::new(file).exists() {
                return Err(format!("settings file not found: {file}").into());
            }
            read_settings(&Some(file.clone()))?
        }
        None => {
            let mut cps = CertificationPathSettings::default();
            cps.set_check_revocation_status(false);
            cps
        }
    };
    if args.check_revocation {
        cps.set_check_revocation_status(true);
    }
    let toi = cps.get_time_of_interest();

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    let mut anchors_only = false;
    if let Some(store) = &args.store {
        let Some(entry) = providers()
            .iter()
            .flat_map(|p| p.entries())
            .find(|e| e.id == *store)
        else {
            return Err(format!("unknown store {store}; --list-stores prints the ids").into());
        };
        anchors_only = entry.cert_store_cbor.is_none();
        prepare_certval_environment(&providers(), &mut pe, store)?;
    } else {
        let mut ta_source = TaSource::new();
        for file in &args.anchor {
            for (i, bytes) in read_certs(file)?.into_iter().enumerate() {
                ta_source.push(CertFile {
                    filename: format!("{file}#{i}"),
                    bytes,
                });
            }
        }
        ta_source.initialize()?;
        pe.add_trust_anchor_source(Box::new(ta_source));
    }

    if !args.chain.is_empty() {
        let mut cert_source = CertSource::new();
        for file in &args.chain {
            for (i, bytes) in read_certs(file)?.into_iter().enumerate() {
                cert_source.push(CertFile {
                    filename: format!("{file}#{i}"),
                    bytes,
                });
            }
        }
        cert_source.initialize(&cps)?;
        cert_source.find_all_partial_paths(&pe, &cps);
        pe.add_certificate_source(Box::new(cert_source));
    }

    let mut target_cert = PDVCertificate::try_from(read_der(target)?.as_slice())
        .map_err(|e| format!("{target}: not a certificate: {e:?}"))?;
    target_cert.parse_extensions(EXTS_OF_INTEREST);

    // A threshold of 0 collects every path the sources can assemble. In a cross-certified
    // community there is often more than one, and they need not reach the same verdict.
    let mut paths = vec![];
    match pe.get_paths_for_target(&target_cert, &mut paths, 0, toi) {
        Ok(()) => {}
        // No certificate source at all (anchors and no --chain): the same outcome as one that
        // found nothing, for a target issued directly by an anchor or for one with no path.
        Err(certval::Error::Unrecognized) => {}
        Err(certval::Error::PathValidation(
            PathValidationStatus::InvalidNotAfterDate | PathValidationStatus::InvalidNotBeforeDate,
        )) => {
            println!("target is not valid at the time of interest ({toi})");
            return Ok(false);
        }
        Err(e) => return Err(format!("{e:?}").into()),
    }
    if paths.is_empty() {
        println!("no candidate paths to a trust anchor");
        if anchors_only && args.chain.is_empty() {
            println!("the store includes anchors only; name intermediates with --chain");
        }
        return Ok(false);
    }

    let mut any_valid = false;
    for (i, path) in paths.iter_mut().enumerate() {
        let mut cpr = CertificationPathResults::new();
        let result = validate_path_rfc5280(&pe, &cps, path, &mut cpr);
        if result.is_ok() && cps.get_check_revocation_status() {
            let _ = check_revocation(&pe, &cps, path, &mut cpr).await;
        }
        let status = cpr
            .get_validation_status()
            .map(|s| format!("{s:?}"))
            .unwrap_or_else(|| format!("{result:?}"));
        println!("path {i}: {status}");
        print_path(path);
        any_valid |= cpr.get_validation_status() == Some(PathValidationStatus::Valid);
    }
    Ok(any_valid)
}

/// Prints a path from its anchor down to the target, one subject per line.
fn print_path(path: &CertificationPath) {
    if let Ok(name) = get_trust_anchor_name(path.trust_anchor.decoded()) {
        println!("    anchor        {}", display::name(name));
    }
    for ca in &path.intermediates {
        println!(
            "    intermediate  {}",
            display::name(ca.decoded().tbs_certificate().subject())
        );
    }
    println!(
        "    target        {}",
        display::name(path.target.decoded().tbs_certificate().subject())
    );
}
