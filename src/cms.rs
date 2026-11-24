//! `certval cms`: encrypt, decrypt, sign and verify CMS messages with certval-cms, with the
//! cryptographic operations performed by the implementation `--crypto` chooses.
//!
//! Messages are read as DER or PEM and written as DER, or with `--outform pem` as PEM labelled
//! `CMS`, which `openssl cms` reads with `-inform DER` or `-inform PEM`. S/MIME is neither read nor
//! written. Private keys are PKCS #8, DER or PEM, unencrypted, or with `--crypto
//! security-framework`, `cng` or `pkcs11`, may instead be the keychain's, the certificate store's
//! or a token's, chosen by the message's recipient identifiers to decrypt and by `--cert`,
//! `--email` or `--skid` to sign.

use certval_cms::{
    content_info, rsa_pss, AuthEnvelopedDataBuilder, CmsEnvironment, ContentEncryptionAlgorithm,
    DigestAlgorithm, EncryptedDataBuilder, IncludeCertificates, KdfAlgorithm, KemRecipient,
    KeyAgreeRecipient, KeyAgreementAlgorithm, KeyTransRecipient, KeyTransportAlgorithm,
    KeyWrapAlgorithm, SharedSigningCredential, SignedDataBuilder, Signer, SignerPolicy,
    SigningCredential, SigningCredentialLookup, Vetting,
};
use clap::ValueEnum;
use cms::builder::{EnvelopedDataBuilder, RecipientInfoBuilder};
use cms::cert::IssuerAndSerialNumber;
use cms::content_info::ContentInfo;
use cms::enveloped_data::RecipientIdentifier;
use cms::signed_data::SignerIdentifier;
use const_oid::db::fips203::{ID_ALG_ML_KEM_1024, ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768};
use const_oid::db::rfc5911::{ID_DATA, ID_ENVELOPED_DATA};
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION};
use der::asn1::OctetString;
use der::{Decode, Encode};
use getrandom::SysRng;
use rand_core::UnwrapErr;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::Certificate;

use crate::crypto::CryptoArgs;
use crate::display;
use crate::input::{read_certs, read_der};
use crate::trust;
use crate::Result;

#[derive(clap::Subcommand)]
pub enum Command {
    /// Encrypt a file to one or more recipients' certificates, or under a secret key
    Encrypt(EncryptArgs),
    /// Decrypt an EnvelopedData or AuthEnvelopedData with a recipient's key, or an EncryptedData
    /// with a secret key
    Decrypt(DecryptArgs),
    /// Sign a file
    Sign(SignArgs),
    /// Verify a SignedData, validating each signer's certificate when trust anchors are named
    Verify(VerifyArgs),
}

pub fn run(command: &Command) -> Result<bool> {
    match command {
        Command::Encrypt(args) => encrypt(args),
        Command::Decrypt(args) => decrypt(args),
        Command::Sign(args) => sign(args),
        Command::Verify(args) => verify(args),
    }
}

// ---- options

/// A content encryption algorithm; GCM makes an AuthEnvelopedData, CBC an EnvelopedData.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Content {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
}

impl From<Content> for ContentEncryptionAlgorithm {
    fn from(content: Content) -> Self {
        match content {
            Content::Aes128Cbc => ContentEncryptionAlgorithm::Aes128Cbc,
            Content::Aes192Cbc => ContentEncryptionAlgorithm::Aes192Cbc,
            Content::Aes256Cbc => ContentEncryptionAlgorithm::Aes256Cbc,
            Content::Aes128Gcm => ContentEncryptionAlgorithm::Aes128Gcm,
            Content::Aes192Gcm => ContentEncryptionAlgorithm::Aes192Gcm,
            Content::Aes256Gcm => ContentEncryptionAlgorithm::Aes256Gcm,
        }
    }
}

/// An RSA key transport algorithm.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum KeyTransport {
    Pkcs1v15,
    OaepSha1,
    OaepSha256,
    OaepSha384,
    OaepSha512,
}

impl From<KeyTransport> for KeyTransportAlgorithm {
    fn from(kt: KeyTransport) -> Self {
        match kt {
            KeyTransport::Pkcs1v15 => KeyTransportAlgorithm::RsaPkcs1v15,
            KeyTransport::OaepSha1 => KeyTransportAlgorithm::RsaOaepSha1,
            KeyTransport::OaepSha256 => KeyTransportAlgorithm::RsaOaepSha256,
            KeyTransport::OaepSha384 => KeyTransportAlgorithm::RsaOaepSha384,
            KeyTransport::OaepSha512 => KeyTransportAlgorithm::RsaOaepSha512,
        }
    }
}

/// A hash: the X9.63 KDF's for key agreement, HKDF's for a KEM, or the digest for signing.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn key_agreement(self) -> KeyAgreementAlgorithm {
        match self {
            Hash::Sha256 => KeyAgreementAlgorithm::EcdhSha256,
            Hash::Sha384 => KeyAgreementAlgorithm::EcdhSha384,
            Hash::Sha512 => KeyAgreementAlgorithm::EcdhSha512,
        }
    }

    fn kdf(self) -> KdfAlgorithm {
        match self {
            Hash::Sha256 => KdfAlgorithm::HkdfSha256,
            Hash::Sha384 => KdfAlgorithm::HkdfSha384,
            Hash::Sha512 => KdfAlgorithm::HkdfSha512,
        }
    }

    pub(crate) fn digest(self) -> DigestAlgorithm {
        match self {
            Hash::Sha256 => DigestAlgorithm::Sha256,
            Hash::Sha384 => DigestAlgorithm::Sha384,
            Hash::Sha512 => DigestAlgorithm::Sha512,
        }
    }
}

/// An AES key wrap.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Wrap {
    Aes128,
    Aes192,
    Aes256,
}

impl From<Wrap> for KeyWrapAlgorithm {
    fn from(wrap: Wrap) -> Self {
        match wrap {
            Wrap::Aes128 => KeyWrapAlgorithm::Aes128,
            Wrap::Aes192 => KeyWrapAlgorithm::Aes192,
            Wrap::Aes256 => KeyWrapAlgorithm::Aes256,
        }
    }
}

/// The encoding a message is written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Form {
    Der,
    Pem,
}

/// Which certificates a SignedData contains.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Include {
    /// Each signer's certificate
    Signer,
    /// None
    None,
}

/// Which signers must verify for a SignedData to be accepted.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Policy {
    /// Every signer
    All,
    /// At least one signer
    Any,
}

// ---- encrypt

#[derive(clap::Args)]
pub struct EncryptArgs {
    /// Recipient certificate, DER or PEM; repeatable. Its key decides the recipient type: key
    /// transport for RSA, key agreement for EC, a KEM for ML-KEM
    #[arg(
        long = "recip",
        value_name = "FILE",
        required_unless_present = "secret_key"
    )]
    pub recipients: Vec<String>,

    /// Write an EncryptedData under this key, as hex, which the parties already share, rather
    /// than an EnvelopedData or AuthEnvelopedData to recipients
    #[arg(long, value_name = "HEX", conflicts_with_all = ["recipients", "ukm"])]
    pub secret_key: Option<String>,

    /// File to encrypt
    #[arg(long = "in", value_name = "FILE")]
    pub input: String,

    /// File to write the message to
    #[arg(long, value_name = "FILE")]
    pub out: String,

    /// Content encryption algorithm; aes256-gcm by default, or aes256-cbc with --secret-key, as
    /// EncryptedData does not authenticate
    #[arg(long, value_enum)]
    pub content: Option<Content>,

    /// Key transport algorithm, for an RSA recipient
    #[arg(long, value_enum, default_value_t = KeyTransport::OaepSha256)]
    pub key_transport: KeyTransport,

    /// Hash of the KDF: the X9.63 KDF for an EC recipient, HKDF for an ML-KEM recipient
    #[arg(long, value_enum, default_value_t = Hash::Sha256)]
    pub kdf: Hash,

    /// Key wrap, for an EC or ML-KEM recipient
    #[arg(long, value_enum, default_value_t = Wrap::Aes256)]
    pub wrap: Wrap,

    /// User keying material, as hex, for an EC or ML-KEM recipient
    #[arg(long, value_name = "HEX")]
    pub ukm: Option<String>,

    /// Encoding of the message written
    #[arg(long, value_enum, default_value_t = Form::Der)]
    pub outform: Form,

    #[command(flatten)]
    pub crypto: CryptoArgs,
}

type Rng = UnwrapErr<SysRng>;

/// A recipient for each certificate, of the type the certificate's key calls for, with its
/// cryptography going through `env`.
fn recipients<'e>(
    env: &'e CmsEnvironment,
    args: &EncryptArgs,
    ukm: Option<Vec<u8>>,
) -> Result<Vec<Box<dyn RecipientInfoBuilder<Rng = Rng> + 'e>>> {
    let mut recipients: Vec<Box<dyn RecipientInfoBuilder<Rng = Rng> + 'e>> = vec![];
    for file in &args.recipients {
        let cert = read_certificate(file)?;
        match cert
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .oid
        {
            RSA_ENCRYPTION => recipients.push(Box::new(KeyTransRecipient::from_certificate(
                env,
                &cert,
                None,
                args.key_transport.into(),
            )?)),
            ID_EC_PUBLIC_KEY => recipients.push(Box::new(KeyAgreeRecipient::from_certificate(
                env,
                &cert,
                None,
                args.kdf.key_agreement(),
                args.wrap.into(),
                ukm.clone(),
            )?)),
            ID_ALG_ML_KEM_512 | ID_ALG_ML_KEM_768 | ID_ALG_ML_KEM_1024 => {
                recipients.push(Box::new(KemRecipient::from_certificate(
                    env,
                    &cert,
                    None,
                    args.kdf.kdf(),
                    args.wrap.into(),
                    ukm.clone(),
                )?))
            }
            oid => {
                return Err(
                    format!("{file}: no recipient type for a {} key", display::oid(&oid)).into(),
                )
            }
        }
    }
    Ok(recipients)
}

fn encrypt(args: &EncryptArgs) -> Result<bool> {
    let content = std::fs::read(&args.input).map_err(|e| format!("{}: {e}", args.input))?;
    let env = args.crypto.cms_environment(args.crypto.pki_environment()?);
    let mut rng: Rng = UnwrapErr(SysRng);
    let content_info = match &args.secret_key {
        Some(key) => {
            let key = secret_key(key)?;
            let alg = args.content.unwrap_or(Content::Aes256Cbc).into();
            EncryptedDataBuilder::new(&content, &key, env.content_encryptor(alg))
                .build_content_info(&mut rng)?
        }
        None => {
            let ukm = args.ukm.as_deref().map(from_hex).transpose()?;
            let recipients = recipients(&env, args, ukm)?;
            let alg: ContentEncryptionAlgorithm = args.content.unwrap_or(Content::Aes256Gcm).into();
            let encryptor = env.content_encryptor(alg);
            if alg.is_authenticated() {
                let mut builder = AuthEnvelopedDataBuilder::new(&content, encryptor);
                for recipient in recipients {
                    builder.add_recipient(recipient);
                }
                builder.build_content_info(&mut rng)?
            } else {
                let mut builder = EnvelopedDataBuilder::new(None, &content, encryptor, None)?;
                for recipient in recipients {
                    builder.add_recipient_info(recipient)?;
                }
                content_info(ID_ENVELOPED_DATA, &builder.build_with_rng(&mut rng)?)?
            }
        }
    };
    write_message(&args.out, &content_info, args.outform)?;
    Ok(true)
}

// ---- decrypt

#[derive(clap::Args)]
pub struct DecryptArgs {
    /// The message, DER or PEM
    #[arg(long = "in", value_name = "FILE")]
    pub input: String,

    /// The recipient's certificate, DER or PEM
    #[arg(long, value_name = "FILE", requires = "key")]
    pub cert: Option<String>,

    /// The recipient's private key, PKCS #8, DER or PEM. When absent, the key is the one the
    /// --crypto implementation holds for a recipient the message names
    #[arg(long, value_name = "FILE", requires = "cert")]
    pub key: Option<String>,

    /// Decrypt an EncryptedData with this key, as hex, which the parties share
    #[arg(long, value_name = "HEX", conflicts_with_all = ["cert", "key"])]
    pub secret_key: Option<String>,

    /// File to write the content to; standard output when absent
    #[arg(long, value_name = "FILE")]
    pub out: Option<String>,

    #[command(flatten)]
    pub crypto: CryptoArgs,
}

fn decrypt(args: &DecryptArgs) -> Result<bool> {
    let content_info = read_message(&args.input)?;
    let mut env = args.crypto.cms_environment(args.crypto.pki_environment()?);
    if let Some(key) = &args.secret_key {
        let (content_type, content) =
            env.decrypt_encrypted_data(&content_info, &secret_key(key)?)?;
        if content_type != ID_DATA {
            eprintln!("the content is of type {}", display::oid(&content_type));
        }
        write_content(args.out.as_deref(), &content)?;
        return Ok(true);
    }
    let decrypted = match (&args.cert, &args.key) {
        (Some(cert), Some(key)) => {
            let credential = args
                .crypto
                .recipient_credential(read_certificate(cert)?, &read_der(key)?)?;
            env.decrypt_enveloped_data(&content_info, Some(credential.as_ref()))?
        }
        _ => {
            let store = args.crypto.store()?;
            store.register(&mut env);
            let decrypted = env
                .decrypt_enveloped_data(&content_info, None)
                .map_err(|e| format!("with a key from {}: {e}", store.description()))?;
            eprintln!(
                "decrypted with the key from {} for {}",
                store.description(),
                recipient_identifier(&decrypted.recipient)
            );
            decrypted
        }
    };
    if decrypted.content_type != ID_DATA {
        eprintln!(
            "the content is of type {}",
            display::oid(&decrypted.content_type)
        );
    }
    write_content(args.out.as_deref(), &decrypted.content)?;
    Ok(true)
}

// ---- sign

#[derive(clap::Args)]
#[command(group(clap::ArgGroup::new("signer").required(true).multiple(false)))]
pub struct SignArgs {
    /// File to sign
    #[arg(long = "in", value_name = "FILE")]
    pub input: String,

    /// The signer's certificate, DER or PEM. Without --key, it chooses the key the --crypto
    /// implementation holds for it
    #[arg(long, value_name = "FILE", group = "signer")]
    pub cert: Option<String>,

    /// The signer's private key, PKCS #8, DER or PEM. When absent, the key is one the --crypto
    /// implementation holds, chosen by --cert, --email or --skid
    #[arg(long, value_name = "FILE", requires = "cert")]
    pub key: Option<String>,

    /// Sign with the key the --crypto implementation holds for a certificate containing this
    /// email address and permitting signing
    #[arg(long, value_name = "ADDRESS", group = "signer")]
    pub email: Option<String>,

    /// Sign with the key the --crypto implementation holds for the certificate with this subject
    /// key identifier, as hex, which `certval cred list` shows
    #[arg(long, value_name = "HEX", group = "signer")]
    pub skid: Option<String>,

    /// File to write the message to
    #[arg(long, value_name = "FILE")]
    pub out: String,

    /// Digest algorithm
    #[arg(long, value_enum, default_value_t = Hash::Sha256)]
    pub digest: Hash,

    /// Sign with RSASSA-PSS rather than PKCS #1 v1.5, for an RSA key
    #[arg(long)]
    pub pss: bool,

    /// Leave the content out of the message
    #[arg(long)]
    pub detached: bool,

    /// Leave out the signing-certificate-v2 attribute, which binds the signer's certificate
    #[arg(long)]
    pub no_ess_cert_id: bool,

    /// Which certificates the message contains
    #[arg(long, value_enum, default_value_t = Include::Signer)]
    pub include: Include,

    /// More certificates for the message to contain, e.g. intermediates, DER or PEM; repeatable
    #[arg(long, value_name = "FILE")]
    pub certfile: Vec<String>,

    /// Encoding of the message written
    #[arg(long, value_enum, default_value_t = Form::Der)]
    pub outform: Form,

    #[command(flatten)]
    pub crypto: CryptoArgs,
}

/// The signer's credential: from a key file, or held by the environment's sources.
enum SignerCredential {
    File(Box<dyn SigningCredential>),
    Held(SharedSigningCredential),
}

impl SignerCredential {
    fn credential(&self) -> &dyn SigningCredential {
        match self {
            SignerCredential::File(c) => c.as_ref(),
            SignerCredential::Held(c) => c.as_ref(),
        }
    }
}

/// The signing credential the arguments choose.
fn signer_credential(args: &SignArgs, env: &mut CmsEnvironment) -> Result<SignerCredential> {
    if let (Some(cert), Some(key)) = (&args.cert, &args.key) {
        return Ok(SignerCredential::File(
            args.crypto
                .signing_credential(read_certificate(cert)?, &read_der(key)?)?,
        ));
    }
    let store = args.crypto.store()?;
    store.register(env);
    let sid;
    let (lookup, what) = if let Some(cert) = &args.cert {
        let cert = read_certificate(cert)?;
        let tbs = cert.tbs_certificate();
        sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: tbs.issuer().clone(),
            serial_number: tbs.serial_number().clone(),
        });
        (
            SigningCredentialLookup::Identifier(&sid),
            format!("the certificate {}", display::name(tbs.subject())),
        )
    } else if let Some(skid) = &args.skid {
        sid = SignerIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(OctetString::new(
            from_hex(skid)?,
        )?));
        (
            SigningCredentialLookup::Identifier(&sid),
            format!("subject key identifier {skid}"),
        )
    } else if let Some(email) = &args.email {
        (
            SigningCredentialLookup::EmailAddress(email),
            format!("the email address {email}"),
        )
    } else {
        return Err("no signer: one of --cert, --email and --skid is required".into());
    };
    let mut found = env.find_signing_credentials(lookup)?;
    match found.len() {
        0 => Err(format!(
            "{} holds no key permitting signing for {what}",
            store.description()
        )
        .into()),
        1 => {
            let (credential, _) = found.remove(0);
            eprintln!(
                "signing with the key from {} for {}",
                store.description(),
                display::name(credential.certificate().tbs_certificate().subject())
            );
            Ok(SignerCredential::Held(credential))
        }
        n => {
            let mut message = format!(
                "{} holds {n} keys permitting signing for {what}; choose one with --skid:",
                store.description()
            );
            for (credential, _) in &found {
                message.push_str(&format!(
                    "\n    {}",
                    describe_briefly(credential.certificate())
                ));
            }
            Err(message.into())
        }
    }
}

/// A certificate's subject on one line and, as a list below it, its issuer, its notAfter, and its
/// subject key identifier, or serial number without one: enough to choose between certificates for
/// the same address.
fn describe_briefly(cert: &Certificate) -> String {
    let tbs = cert.tbs_certificate();
    let mut subject = display::name(tbs.subject());
    if subject.is_empty() {
        subject = String::from("(empty subject)");
    }
    let id = match certval_cms::signer_identifier(cert) {
        Ok(SignerIdentifier::SubjectKeyIdentifier(skid)) => {
            format!("subject key identifier {}", display::hex(skid.0.as_bytes()))
        }
        _ => format!("serial {}", display::hex(tbs.serial_number().as_bytes())),
    };
    format!(
        "{subject}\n        - issuer {}\n        - expires {}\n        - {id}",
        display::name(tbs.issuer()),
        display::time(&tbs.validity().not_after)
    )
}

fn sign(args: &SignArgs) -> Result<bool> {
    let content = std::fs::read(&args.input).map_err(|e| format!("{}: {e}", args.input))?;
    let mut env = args.crypto.cms_environment(args.crypto.pki_environment()?);
    let held = signer_credential(args, &mut env)?;
    let credential = held.credential();

    let digest = args.digest.digest();
    let mut signer = Signer::explicit(credential).digest(digest);
    if args.pss {
        signer = signer.signature_algorithm(rsa_pss(digest)?);
    }
    if args.no_ess_cert_id {
        signer = signer.without_ess_cert_id();
    }

    let mut builder = SignedDataBuilder::new(&content);
    builder.add_signer(signer);
    builder.include_certificates(match args.include {
        Include::Signer => IncludeCertificates::Signers,
        Include::None => IncludeCertificates::None,
    });
    for file in &args.certfile {
        for der in read_certs(file)? {
            builder
                .add_certificate(Certificate::from_der(&der).map_err(|e| format!("{file}: {e}"))?);
        }
    }
    if args.detached {
        builder.detached();
    }
    let built = builder.build(&env)?;
    write_message(&args.out, &built.content_info, args.outform)?;
    Ok(true)
}

// ---- verify

#[derive(clap::Args)]
pub struct VerifyArgs {
    /// The message, DER or PEM
    #[arg(long = "in", value_name = "FILE")]
    pub input: String,

    /// The content of a detached signature
    #[arg(long, value_name = "FILE")]
    pub content: Option<String>,

    /// File to write the content to
    #[arg(long, value_name = "FILE")]
    pub out: Option<String>,

    /// Which signers must verify
    #[arg(long, value_enum, default_value_t = Policy::All)]
    pub policy: Policy,

    /// Trust anchor certificate, DER, or PEM holding one or more; repeatable. With this or
    /// --store, each signer's certificate is validated; with neither, only the signatures are
    /// verified
    #[arg(long, value_name = "FILE", conflicts_with = "store")]
    pub anchor: Vec<String>,

    /// Store compiled into this binary to take anchors and CA certificates from; see
    /// `certval verify --list-stores`
    #[arg(long)]
    pub store: Option<String>,

    /// Intermediate CA certificate to consider, beyond those the message contains, DER, or PEM
    /// holding one or more; repeatable
    #[arg(long, value_name = "FILE")]
    pub chain: Vec<String>,

    /// JSON certification path validation settings (policy, time of interest, revocation).
    /// Revocation is checked against --crl only; nothing is fetched
    #[arg(long, value_name = "FILE")]
    pub settings: Option<String>,

    /// CRL to consult when the settings check revocation, DER or PEM; repeatable
    #[arg(long, value_name = "FILE")]
    pub crl: Vec<String>,

    #[command(flatten)]
    pub crypto: CryptoArgs,
}

fn verify(args: &VerifyArgs) -> Result<bool> {
    let content_info = read_message(&args.input)?;
    let detached = args
        .content
        .as_ref()
        .map(|file| std::fs::read(file).map_err(|e| format!("{file}: {e}")))
        .transpose()?;

    let vet = !args.anchor.is_empty() || args.store.is_some();
    let cps = trust::settings(args.settings.as_deref())?;
    let mut pe = args.crypto.pki_environment()?;
    if vet {
        trust::add_trust(
            &mut pe,
            &cps,
            &args.anchor,
            args.store.as_deref(),
            &args.chain,
            &args.crl,
        )?;
    }
    let env: CmsEnvironment = args.crypto.cms_environment(pe);
    let policy = match args.policy {
        Policy::All => SignerPolicy::All,
        Policy::Any => SignerPolicy::Any,
    };
    let verified = env.verify_signed_data(
        &content_info,
        detached.as_deref(),
        vet.then_some(&cps),
        policy,
    )?;

    for signer in &verified.signers {
        let validated = match &signer.vetting {
            Vetting::Validated(_) => "certificate validated",
            _ => "certificate not validated",
        };
        println!(
            "signer {}: signature verified, {validated}",
            display::name(signer.certificate.tbs_certificate().subject())
        );
        if !signer.message_ca_certificates.is_empty() {
            println!(
                "    the path used {} CA certificate(s) from the message",
                signer.message_ca_certificates.len()
            );
        }
    }
    for (sid, e) in &verified.failed {
        println!("signer {}: {e}", signer_identifier(sid));
    }
    if let Some(out) = &args.out {
        write_content(Some(out), &verified.content)?;
    }
    Ok(true)
}

// ---- files

pub(crate) fn read_certificate(file: &str) -> Result<Certificate> {
    Ok(Certificate::from_der(&read_der(file)?)
        .map_err(|e| format!("{file}: not a certificate: {e}"))?)
}

fn read_message(file: &str) -> Result<ContentInfo> {
    Ok(ContentInfo::from_ber(&read_der(file)?)
        .map_err(|e| format!("{file}: not a CMS message: {e}"))?)
}

fn write_message(file: &str, content_info: &ContentInfo, form: Form) -> Result<()> {
    let der = content_info.to_der()?;
    let bytes = match form {
        Form::Der => der,
        Form::Pem => pem_rfc7468::encode_string("CMS", pem_rfc7468::LineEnding::LF, &der)
            .map_err(|e| format!("{file}: {e}"))?
            .into_bytes(),
    };
    std::fs::write(file, bytes).map_err(|e| format!("{file}: {e}"))?;
    Ok(())
}

fn write_content(file: Option<&str>, content: &[u8]) -> Result<()> {
    match file {
        Some(file) => std::fs::write(file, content).map_err(|e| format!("{file}: {e}"))?,
        None => {
            use std::io::Write;
            std::io::stdout().write_all(content)?;
        }
    }
    Ok(())
}

/// Bytes from hex digits, which may be separated by colons, as `display::hex` writes them.
/// A `--secret-key`, as hex. Unlike [`from_hex`], an error does not repeat the input.
fn secret_key(hex: &str) -> Result<Vec<u8>> {
    from_hex(hex).map_err(|_| "--secret-key: not an even number of hex digits".into())
}

pub(crate) fn from_hex(hex: &str) -> Result<Vec<u8>> {
    let hex = &hex.replace(':', "");
    if !hex.len().is_multiple_of(2) {
        return Err(format!("{hex}: an odd number of hex digits").into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| format!("{hex}: not hex").into())
        })
        .collect()
}

fn recipient_identifier(rid: &RecipientIdentifier) -> String {
    match rid {
        RecipientIdentifier::IssuerAndSerialNumber(iasn) => format!(
            "issuer {}, serial {}",
            display::name(&iasn.issuer),
            display::hex(iasn.serial_number.as_bytes())
        ),
        RecipientIdentifier::SubjectKeyIdentifier(skid) => {
            format!("subject key identifier {}", display::hex(skid.0.as_bytes()))
        }
    }
}

fn signer_identifier(sid: &SignerIdentifier) -> String {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(iasn) => format!(
            "issuer {}, serial {}",
            display::name(&iasn.issuer),
            display::hex(iasn.serial_number.as_bytes())
        ),
        SignerIdentifier::SubjectKeyIdentifier(skid) => {
            format!("subject key identifier {}", display::hex(skid.0.as_bytes()))
        }
    }
}
