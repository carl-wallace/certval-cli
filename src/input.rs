//! Reading the files the subcommands are pointed at.

use crate::Result;

/// Reads `path` as DER, decoding it first when the file holds PEM.
///
/// Every subcommand works on DER. PEM is accepted on input because that is the form most
/// certificates arrive in; the label is not checked against what the caller expects, since the
/// DER decode that follows says so more precisely.
pub fn read_der(path: &str) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let leading = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(0);
    if bytes[leading..].starts_with(b"-----BEGIN") {
        let (_label, der) =
            pem_rfc7468::decode_vec(&bytes[leading..]).map_err(|e| format!("{path}: {e}"))?;
        Ok(der)
    } else {
        Ok(bytes)
    }
}

/// Reads every certificate in `path`: the one certificate in a DER file, or each certificate in a
/// PEM file, so a bundle of CA certificates can be named once.
///
/// Each PEM block is base64-decoded and nothing more. Decoding to a certificate and encoding it
/// again would not be guaranteed to reproduce the bytes as issued, and the signature is over those.
pub fn read_certs(path: &str) -> Result<Vec<Vec<u8>>> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let leading = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(0);
    if !bytes[leading..].starts_with(b"-----BEGIN") {
        return Ok(vec![bytes]);
    }
    let text = std::str::from_utf8(&bytes).map_err(|e| format!("{path}: {e}"))?;
    let mut certs = vec![];
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let block = &rest[start..];
        let end_marker = block
            .find("-----END ")
            .ok_or(format!("{path}: unterminated PEM block"))?;
        let end = block[end_marker..]
            .find('\n')
            .map(|n| end_marker + n + 1)
            .unwrap_or(block.len());
        let (label, der) = pem_rfc7468::decode_vec(&block.as_bytes()[..end])
            .map_err(|e| format!("{path}: {e}"))?;
        if label == "CERTIFICATE" {
            certs.push(der);
        }
        rest = &block[end..];
    }
    if certs.is_empty() {
        return Err(format!("{path}: no CERTIFICATE blocks").into());
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, contents: &[u8]) -> String {
        let path = std::env::temp_dir().join(format!("certval-cli-{}-{name}", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn der_passes_through() {
        let path = temp_file("der", &[0x30, 0x03, 0x02, 0x01, 0x05]);
        assert_eq!(read_der(&path).unwrap(), vec![0x30, 0x03, 0x02, 0x01, 0x05]);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn pem_is_decoded() {
        let pem = "-----BEGIN DATA-----\nMAMCAQU=\n-----END DATA-----\n";
        let path = temp_file("pem", format!("\n{pem}").as_bytes());
        assert_eq!(read_der(&path).unwrap(), vec![0x30, 0x03, 0x02, 0x01, 0x05]);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_der_file_is_one_certificate() {
        let path = temp_file("one", &[0x30, 0x00]);
        assert_eq!(read_certs(&path).unwrap(), vec![vec![0x30, 0x00]]);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_missing_file_names_itself() {
        let err = read_der("/nonexistent/certval-cli").unwrap_err();
        assert!(err.to_string().contains("/nonexistent/certval-cli"));
    }
}
