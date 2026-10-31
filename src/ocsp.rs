//! `certval ocsp`: query an OCSP responder about a certificate, or describe a saved response.
//!
//! The request is built by certval, sent by this tool, and the response decoded with the RFC 6960
//! types certval publishes as `certval::ocsp`. The response's signature is not verified: certval
//! verifies OCSP responses only as part of checking a certification path, and reports the result
//! into that path's results, so a standalone query has nothing to report it into. The output says
//! so rather than implying the status is authenticated; `certval verify --check-revocation` is the
//! command that does verify it.

use crate::display;
use crate::input::read_der;
use crate::Result;
use certval::ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId};
use const_oid::db::rfc5280::ID_AD_OCSP;
use der::Decode;
use x509_cert::certificate::{CertificateInner, Raw};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;

/// `id-pkix-ocsp-nonce`, RFC 8954.
const ID_PKIX_OCSP_NONCE: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");

#[derive(clap::Args)]
pub struct Args {
    /// Certificate to ask about, DER or PEM
    #[arg(required_unless_present = "response")]
    pub cert: Option<String>,

    /// Certificate of the CA that issued it, DER or PEM
    #[arg(long, value_name = "FILE", required_unless_present = "response")]
    pub issuer: Option<String>,

    /// Responder to ask; taken from the certificate's AIA extension when omitted
    #[arg(long)]
    pub url: Option<String>,

    /// Send a random nonce and check that the response echoes it
    #[arg(long)]
    pub nonce: bool,

    /// Also write the raw response to this file
    #[arg(long, value_name = "FILE")]
    pub out: Option<String>,

    /// Describe a saved DER response instead of querying a responder
    #[arg(long, value_name = "FILE", conflicts_with_all = ["cert", "issuer", "url", "nonce"])]
    pub response: Option<String>,
}

pub async fn run(args: &Args) -> Result<()> {
    if let Some(file) = &args.response {
        return describe(&read_der(file)?, None);
    }
    let (Some(cert_file), Some(issuer_file)) = (&args.cert, &args.issuer) else {
        return Err("a certificate and --issuer are required unless --response is given".into());
    };

    let cert = CertificateInner::<Raw>::from_der(&read_der(cert_file)?)
        .map_err(|e| format!("{cert_file}: not a certificate: {e}"))?;
    let issuer = CertificateInner::<Raw>::from_der(&read_der(issuer_file)?)
        .map_err(|e| format!("{issuer_file}: not a certificate: {e}"))?;

    let url = match &args.url {
        Some(url) => url.clone(),
        None => responder_from_aia(&cert)
            .ok_or("the certificate names no OCSP responder; give one with --url")?,
    };

    let nonce = if args.nonce {
        let mut bytes = vec![0u8; 16];
        getrandom::fill(&mut bytes).map_err(|e| format!("could not generate a nonce: {e}"))?;
        Some(bytes)
    } else {
        None
    };

    let request = certval::build_ocsp_request(&cert, &issuer, nonce.as_deref())
        .map_err(|e| format!("could not build the request: {e:?}"))?;

    println!("Responder URL: {url}");
    let response = reqwest::Client::new()
        .post(&url)
        .header("Content-Type", "application/ocsp-request")
        .body(request)
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("{url}: HTTP {}", response.status()).into());
    }
    let bytes = response.bytes().await.map_err(|e| format!("{url}: {e}"))?;

    if let Some(out) = &args.out {
        std::fs::write(out, &bytes).map_err(|e| format!("{out}: {e}"))?;
    }
    describe(&bytes, nonce.as_deref())
}

/// The first OCSP responder URI in the certificate's authority information access extension.
fn responder_from_aia(cert: &CertificateInner<Raw>) -> Option<String> {
    let (_, aia) = cert
        .tbs_certificate()
        .get_extension::<AuthorityInfoAccessSyntax>()
        .ok()??;
    aia.0
        .iter()
        .filter(|ad| ad.access_method == ID_AD_OCSP)
        .find_map(|ad| match &ad.access_location {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str().to_string()),
            _ => None,
        })
}

/// Prints a response. When `sent_nonce` is given, also reports whether the response echoed it.
fn describe(der: &[u8], sent_nonce: Option<&[u8]>) -> Result<()> {
    let response = OcspResponse::from_der(der).map_err(|e| format!("not an OCSP response: {e}"))?;
    println!("Status:        {:?}", response.response_status);
    if response.response_status != OcspResponseStatus::Successful {
        return Ok(());
    }
    let Some(bytes) = &response.response_bytes else {
        return Err("a successful response with no response bytes".into());
    };
    let basic = BasicOcspResponse::from_der(bytes.response.as_bytes())
        .map_err(|e| format!("not a basic OCSP response: {e}"))?;
    let data = &basic.tbs_response_data;

    match &data.responder_id {
        ResponderId::ByName(name) => println!("Responder ID:  {}", display::name(name)),
        ResponderId::ByKey(hash) => {
            println!("Responder ID:  key {}", display::hex(hash.as_bytes()))
        }
    }
    println!("Produced at:   {}", data.produced_at.0.to_date_time());
    println!(
        "Signature:     {}, not verified",
        display::oid(&basic.signature_algorithm.oid)
    );

    for single in &data.responses {
        println!(
            "Certificate:   serial {}",
            display::hex(single.cert_id.serial_number.as_bytes())
        );
        match &single.cert_status {
            CertStatus::Good(_) => println!("    status       good"),
            CertStatus::Revoked(info) => {
                let reason = info
                    .revocation_reason
                    .map(|r| format!(", reason {r:?}"))
                    .unwrap_or_default();
                println!(
                    "    status       revoked {}{reason}",
                    info.revocation_time.0.to_date_time()
                );
            }
            CertStatus::Unknown(_) => println!("    status       unknown"),
        }
        println!("    this update  {}", single.this_update.0.to_date_time());
        if let Some(next) = &single.next_update {
            println!("    next update  {}", next.0.to_date_time());
        }
    }

    if let Some(sent) = sent_nonce {
        let echoed = data
            .response_extensions
            .iter()
            .flatten()
            .find(|ext| ext.extn_id == ID_PKIX_OCSP_NONCE)
            .and_then(|ext| der::asn1::OctetString::from_der(ext.extn_value.as_bytes()).ok());
        match echoed {
            Some(n) if n.as_bytes() == sent => println!("Nonce:         echoed"),
            Some(_) => println!("Nonce:         DIFFERENT from the one sent"),
            None => println!("Nonce:         not echoed"),
        }
    }
    Ok(())
}
