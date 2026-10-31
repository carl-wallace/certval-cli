//! `certval asn1parse`: dump the DER structure of a file.
//!
//! The layout follows `openssl asn1parse`, whose format is well known enough to be worth keeping:
//! one line per element, giving its offset, depth, header length, content length, whether it is
//! constructed, its tag, and for a primitive element a readable form of its value.

use crate::display;
use crate::input::read_der;
use crate::Result;
use const_oid::ObjectIdentifier;

#[derive(clap::Args)]
pub struct Args {
    /// File to dump, DER or PEM
    pub file: String,

    /// Also descend into OCTET STRING and BIT STRING contents that are themselves DER
    #[arg(long)]
    pub nested: bool,
}

pub fn run(args: &Args) -> Result<()> {
    let der = read_der(&args.file)?;
    let mut lines = vec![];
    walk(&der, 0, 0, args.nested, &mut lines).map_err(|e| format!("{}: {e}", args.file))?;
    for line in lines {
        println!("{line}");
    }
    Ok(())
}

/// One element's header, as read from the input.
struct Header {
    class: u8,
    constructed: bool,
    number: u32,
    header_len: usize,
    content_len: usize,
}

/// Reads the identifier and length octets at the start of `input`.
fn header(input: &[u8]) -> std::result::Result<Header, String> {
    let first = *input.first().ok_or("unexpected end of input")?;
    let class = first >> 6;
    let constructed = first & 0x20 != 0;
    let mut pos = 1;
    let mut number = u32::from(first & 0x1f);
    if number == 0x1f {
        number = 0;
        loop {
            let b = *input.get(pos).ok_or("truncated tag")?;
            pos += 1;
            number = number
                .checked_mul(128)
                .and_then(|n| n.checked_add(u32::from(b & 0x7f)))
                .ok_or("tag number too large")?;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let len_byte = *input.get(pos).ok_or("truncated length")?;
    pos += 1;
    let content_len = if len_byte < 0x80 {
        usize::from(len_byte)
    } else if len_byte == 0x80 {
        return Err("indefinite length, which DER does not allow".into());
    } else {
        let count = usize::from(len_byte & 0x7f);
        if count > std::mem::size_of::<usize>() {
            return Err("length too large".into());
        }
        let mut len = 0usize;
        for _ in 0..count {
            let b = *input.get(pos).ok_or("truncated length")?;
            pos += 1;
            len = (len << 8) | usize::from(b);
        }
        len
    };
    if input.len() - pos < content_len {
        return Err(format!(
            "element claims {content_len} content bytes but {} remain",
            input.len() - pos
        ));
    }
    Ok(Header {
        class,
        constructed,
        number,
        header_len: pos,
        content_len,
    })
}

/// Walks every element in `input`, appending a line for each. `base` is the offset of `input`
/// within the file, so offsets are reported from the start of the file.
fn walk(
    input: &[u8],
    base: usize,
    depth: usize,
    nested: bool,
    lines: &mut Vec<String>,
) -> std::result::Result<(), String> {
    let mut pos = 0;
    while pos < input.len() {
        let h = header(&input[pos..]).map_err(|e| format!("at offset {}: {e}", base + pos))?;
        let start = pos + h.header_len;
        let content = &input[start..start + h.content_len];
        let form = if h.constructed { "cons" } else { "prim" };
        let mut line = format!(
            "{:5}:d={depth:<2} hl={} l={:4} {form}: {}",
            base + pos,
            h.header_len,
            h.content_len,
            tag_name(&h)
        );
        if h.constructed {
            lines.push(line);
            walk(content, base + start, depth + 1, nested, lines)?;
        } else {
            if let Some(value) = value(&h, content) {
                line.push_str(&format!("  :{value}"));
            }
            lines.push(line);
            if nested {
                descend(&h, content, base + start, depth, lines);
            }
        }
        pos = start + h.content_len;
    }
    Ok(())
}

/// Descends into an OCTET STRING or BIT STRING whose content parses as DER in full. Content that
/// does not parse is left alone; plenty of octet strings are just bytes.
fn descend(h: &Header, content: &[u8], offset: usize, depth: usize, lines: &mut Vec<String>) {
    let (inner, inner_offset) = match (h.class, h.number) {
        (0, 4) => (content, offset),
        // A BIT STRING's first content byte counts its unused bits; only a whole-byte string can
        // hold DER.
        (0, 3) if content.first() == Some(&0) => (&content[1..], offset + 1),
        _ => return,
    };
    if inner.is_empty() {
        return;
    }
    let mut nested_lines = vec![];
    if walk(inner, inner_offset, depth + 1, true, &mut nested_lines).is_ok() {
        lines.extend(nested_lines);
    }
}

fn tag_name(h: &Header) -> String {
    match h.class {
        0 => match h.number {
            1 => "BOOLEAN".into(),
            2 => "INTEGER".into(),
            3 => "BIT STRING".into(),
            4 => "OCTET STRING".into(),
            5 => "NULL".into(),
            6 => "OBJECT".into(),
            10 => "ENUMERATED".into(),
            12 => "UTF8String".into(),
            16 => "SEQUENCE".into(),
            17 => "SET".into(),
            19 => "PrintableString".into(),
            20 => "T61String".into(),
            22 => "IA5String".into(),
            23 => "UTCTime".into(),
            24 => "GeneralizedTime".into(),
            26 => "VisibleString".into(),
            30 => "BMPString".into(),
            n => format!("UNIVERSAL {n}"),
        },
        1 => format!("APPLICATION [{}]", h.number),
        2 => format!("cont [{}]", h.number),
        _ => format!("PRIVATE [{}]", h.number),
    }
}

/// A readable form of a primitive universal element's value, where one is worth showing.
fn value(h: &Header, content: &[u8]) -> Option<String> {
    if h.class != 0 {
        return Some(display::hex(content));
    }
    Some(match h.number {
        1 => (content.first().copied().unwrap_or(0) != 0).to_string(),
        2 | 10 => display::hex(content),
        3 => match content.split_first() {
            Some((unused, bits)) => format!("{} bytes, {unused} unused bits", bits.len()),
            None => "empty".into(),
        },
        4 => {
            if content.len() <= 32 {
                display::hex(content)
            } else {
                format!("{} bytes", content.len())
            }
        }
        5 => return None,
        6 => match ObjectIdentifier::from_bytes(content) {
            Ok(oid) => display::oid(&oid),
            Err(_) => format!("malformed: {}", display::hex(content)),
        },
        12 | 19 | 20 | 22 | 23 | 24 | 26 => String::from_utf8_lossy(content).into_owned(),
        30 => {
            let units: Vec<u16> = content
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        _ => display::hex(content),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dump(der: &[u8], nested: bool) -> Vec<String> {
        let mut lines = vec![];
        walk(der, 0, 0, nested, &mut lines).unwrap();
        lines
    }

    #[test]
    fn a_sequence_and_its_members() {
        // SEQUENCE { INTEGER 5, OBJECT 2.5.4.3, UTF8String "hi" }
        let der = [
            0x30, 0x0c, 0x02, 0x01, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x02, b'h', b'i',
        ];
        let lines = dump(&der, false);
        assert_eq!(lines.len(), 4);
        assert!(
            lines[0].contains("d=0") && lines[0].contains("cons: SEQUENCE"),
            "{}",
            lines[0]
        );
        assert!(
            lines[1].contains("d=1") && lines[1].ends_with(":05"),
            "{}",
            lines[1]
        );
        assert!(lines[2].contains("2.5.4.3"), "{}", lines[2]);
        assert!(lines[3].ends_with(":hi"), "{}", lines[3]);
    }

    #[test]
    fn offsets_count_from_the_start_of_the_file() {
        let der = [0x30, 0x03, 0x02, 0x01, 0x05];
        let lines = dump(&der, false);
        assert!(lines[1].trim_start().starts_with("2:"), "{}", lines[1]);
    }

    #[test]
    fn long_form_lengths_are_read() {
        let mut der = vec![0x04, 0x81, 0x80];
        der.extend(std::iter::repeat_n(0xaa, 0x80));
        let lines = dump(&der, false);
        assert!(
            lines[0].contains("hl=3") && lines[0].contains("l= 128"),
            "{}",
            lines[0]
        );
    }

    #[test]
    fn nested_der_is_opened_only_when_asked() {
        // OCTET STRING containing SEQUENCE { NULL }
        let der = [0x04, 0x04, 0x30, 0x02, 0x05, 0x00];
        assert_eq!(dump(&der, false).len(), 1);
        let lines = dump(&der, true);
        assert_eq!(lines.len(), 3);
        assert!(
            lines[1].contains("d=1") && lines[1].contains("SEQUENCE"),
            "{}",
            lines[1]
        );
    }

    #[test]
    fn indefinite_length_is_refused() {
        let mut lines = vec![];
        let err = walk(&[0x30, 0x80, 0x00, 0x00], 0, 0, false, &mut lines).unwrap_err();
        assert!(err.contains("indefinite"), "{err}");
    }

    #[test]
    fn a_length_past_the_end_is_refused() {
        let mut lines = vec![];
        let err = walk(&[0x04, 0x05, 0x00], 0, 0, false, &mut lines).unwrap_err();
        assert!(err.contains("5 content bytes"), "{err}");
    }

    #[test]
    fn context_tags_are_named() {
        let der = [0xa0, 0x03, 0x02, 0x01, 0x02];
        let lines = dump(&der, false);
        assert!(lines[0].contains("cont [0]"), "{}", lines[0]);
    }
}
