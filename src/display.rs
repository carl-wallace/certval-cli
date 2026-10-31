//! Turning decoded structures into readable lines: object identifiers, names, times, keys and
//! extensions.

use const_oid::db::rfc5280::{ID_AD_CA_ISSUERS, ID_AD_OCSP};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::Decode;
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{
    AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, BasicConstraints, CertificatePolicies,
    CrlDistributionPoints, CrlNumber, CrlReason, ExtendedKeyUsage, KeyUsage, SubjectAltName,
    SubjectInfoAccessSyntax, SubjectKeyIdentifier,
};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::time::Time;

/// Returns a readable name for an object identifier, followed by the dotted form.
///
/// certval's table is tried first, since it names the PKIX and post-quantum identifiers this tool
/// mostly meets, and const-oid's database after it.
pub fn oid(oid: &ObjectIdentifier) -> String {
    let dotted = oid.to_string();
    let name = certval::oid_lookup(oid)
        .ok()
        .filter(|n| *n != dotted)
        .or_else(|| const_oid::db::DB.by_oid(oid).map(str::to_string));
    match name {
        Some(name) => format!("{name} ({dotted})"),
        None => dotted,
    }
}

/// Formats bytes as colon-separated uppercase hex, as serial numbers and key identifiers are
/// conventionally shown.
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn name(name: &Name) -> String {
    certval::name_to_string(name)
}

pub fn time(time: &Time) -> String {
    time.to_date_time().to_string()
}

pub fn general_name(name: &GeneralName) -> String {
    match name {
        GeneralName::Rfc822Name(n) => format!("email:{}", n.as_str()),
        GeneralName::DnsName(n) => format!("DNS:{}", n.as_str()),
        GeneralName::UniformResourceIdentifier(n) => format!("URI:{}", n.as_str()),
        GeneralName::DirectoryName(n) => format!("dirName:{}", self::name(n)),
        GeneralName::IpAddress(ip) => match ip.as_bytes() {
            [a, b, c, d] => format!("IP:{a}.{b}.{c}.{d}"),
            bytes if bytes.len() == 16 => {
                let groups: Vec<String> = bytes
                    .chunks(2)
                    .map(|g| format!("{:x}", u16::from_be_bytes([g[0], g[1]])))
                    .collect();
                format!("IP:{}", groups.join(":"))
            }
            bytes => format!("IP:{}", hex(bytes)),
        },
        GeneralName::RegisteredId(id) => format!("RID:{}", oid(id)),
        GeneralName::OtherName(other) => format!("otherName:{}", oid(&other.type_id)),
        GeneralName::EdiPartyName(_) => "ediPartyName".to_string(),
    }
}

/// Describes a public key: its algorithm, and the size or curve where there is one to give.
pub fn public_key(spki: &SubjectPublicKeyInfoOwned) -> String {
    let algorithm = oid(&spki.algorithm.oid);
    let Some(bits) = spki.subject_public_key.as_bytes() else {
        return algorithm;
    };
    if let Ok(Some(curve)) = spki
        .algorithm
        .parameters
        .as_ref()
        .map(|p| p.decode_as::<ObjectIdentifier>())
        .transpose()
    {
        return format!("{algorithm}, curve {}", oid(&curve));
    }
    if let Ok(rsa) = RsaPublicKey::from_der(bits) {
        let modulus = rsa.modulus.as_bytes();
        let size = modulus.len() * 8 - modulus.first().map_or(0, |b| b.leading_zeros() as usize);
        return format!("{algorithm}, {size} bits");
    }
    format!("{algorithm}, {} bytes", bits.len())
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
#[derive(der::Sequence)]
struct RsaPublicKey<'a> {
    modulus: der::asn1::UintRef<'a>,
    public_exponent: der::asn1::UintRef<'a>,
}

/// Prints an extension: its name and criticality, then its decoded content indented beneath.
///
/// The extensions a certificate or CRL most often carries are decoded. Any other is shown by name
/// and length, so nothing is silently dropped.
pub fn print_extension(ext: &Extension, indent: &str) {
    let critical = if ext.critical { ", critical" } else { "" };
    println!("{indent}{}{critical}", oid(&ext.extn_id));
    let value = ext.extn_value.as_bytes();
    let inner = format!("{indent}    ");
    match describe_extension(&ext.extn_id, value) {
        Some(lines) => {
            for line in lines {
                println!("{inner}{line}");
            }
        }
        None => println!("{inner}{} bytes, not decoded", value.len()),
    }
}

fn describe_extension(id: &ObjectIdentifier, value: &[u8]) -> Option<Vec<String>> {
    let lines = match *id {
        BasicConstraints::OID => {
            let bc = BasicConstraints::from_der(value).ok()?;
            let mut line = format!("CA: {}", bc.ca);
            if let Some(len) = bc.path_len_constraint {
                line.push_str(&format!(", path length {len}"));
            }
            vec![line]
        }
        KeyUsage::OID => {
            let ku = KeyUsage::from_der(value).ok()?;
            let names: Vec<String> = ku.0.into_iter().map(|u| format!("{u:?}")).collect();
            vec![names.join(", ")]
        }
        ExtendedKeyUsage::OID => {
            let eku = ExtendedKeyUsage::from_der(value).ok()?;
            eku.0.iter().map(oid).collect()
        }
        SubjectKeyIdentifier::OID => {
            let skid = SubjectKeyIdentifier::from_der(value).ok()?;
            vec![hex(skid.0.as_bytes())]
        }
        AuthorityKeyIdentifier::OID => {
            let akid = AuthorityKeyIdentifier::from_der(value).ok()?;
            let mut lines = vec![];
            if let Some(kid) = &akid.key_identifier {
                lines.push(format!("key identifier {}", hex(kid.as_bytes())));
            }
            for issuer in akid.authority_cert_issuer.iter().flatten() {
                lines.push(format!("issuer {}", general_name(issuer)));
            }
            if let Some(serial) = &akid.authority_cert_serial_number {
                lines.push(format!("serial {}", hex(serial.as_bytes())));
            }
            lines
        }
        SubjectAltName::OID => {
            let san = SubjectAltName::from_der(value).ok()?;
            san.0.iter().map(general_name).collect()
        }
        CertificatePolicies::OID => {
            let policies = CertificatePolicies::from_der(value).ok()?;
            policies
                .0
                .iter()
                .map(|p| oid(&p.policy_identifier))
                .collect()
        }
        CrlDistributionPoints::OID => {
            let dps = CrlDistributionPoints::from_der(value).ok()?;
            let mut lines = vec![];
            for dp in &dps.0 {
                match &dp.distribution_point {
                    Some(DistributionPointName::FullName(names)) => {
                        lines.extend(names.iter().map(general_name));
                    }
                    Some(DistributionPointName::NameRelativeToCRLIssuer(_)) => {
                        lines.push("name relative to the CRL issuer".to_string());
                    }
                    None => {}
                }
            }
            lines
        }
        AuthorityInfoAccessSyntax::OID => {
            let aia = AuthorityInfoAccessSyntax::from_der(value).ok()?;
            aia.0
                .iter()
                .map(|ad| {
                    format!(
                        "{}: {}",
                        access_method(&ad.access_method),
                        general_name(&ad.access_location)
                    )
                })
                .collect()
        }
        SubjectInfoAccessSyntax::OID => {
            let sia = SubjectInfoAccessSyntax::from_der(value).ok()?;
            sia.0
                .iter()
                .map(|ad| {
                    format!(
                        "{}: {}",
                        oid(&ad.access_method),
                        general_name(&ad.access_location)
                    )
                })
                .collect()
        }
        CrlNumber::OID => {
            let number = CrlNumber::from_der(value).ok()?;
            vec![hex(number.0.as_bytes())]
        }
        CrlReason::OID => {
            let reason = CrlReason::from_der(value).ok()?;
            vec![format!("{reason:?}")]
        }
        _ => return None,
    };
    Some(lines)
}

fn access_method(method: &ObjectIdentifier) -> String {
    match *method {
        ID_AD_OCSP => "OCSP".to_string(),
        ID_AD_CA_ISSUERS => "CA issuers".to_string(),
        _ => oid(method),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_oids_are_named() {
        let sha256_rsa = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        let shown = oid(&sha256_rsa);
        assert!(shown.ends_with("(1.2.840.113549.1.1.11)"), "{shown}");
        assert!(shown.len() > "(1.2.840.113549.1.1.11)".len(), "{shown}");
    }

    #[test]
    fn unknown_oids_are_dotted() {
        let private = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1");
        assert_eq!(oid(&private), "1.3.6.1.4.1.99999.1");
    }

    #[test]
    fn hex_is_colon_separated() {
        assert_eq!(hex(&[0x01, 0xab, 0xff]), "01:AB:FF");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn ip_addresses_are_written_out() {
        let v4 = GeneralName::IpAddress(der::asn1::OctetString::new(vec![192, 0, 2, 1]).unwrap());
        assert_eq!(general_name(&v4), "IP:192.0.2.1");
        let mut bytes = vec![0u8; 16];
        bytes[0] = 0x20;
        bytes[1] = 0x01;
        bytes[15] = 1;
        let v6 = GeneralName::IpAddress(der::asn1::OctetString::new(bytes).unwrap());
        assert_eq!(general_name(&v6), "IP:2001:0:0:0:0:0:0:1");
    }
}
