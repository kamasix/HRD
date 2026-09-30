//! Just enough DER to find a certificate's SubjectPublicKeyInfo.
//!
//! This is not an X.509 parser. It walks the fixed prefix of a certificate,
//! `Certificate { TBSCertificate { [0] version?, serial, signature, issuer,
//! validity, subject, subjectPublicKeyInfo ... } ... }`, without interpreting
//! any of it, and returns the bytes of the key. Every length is bounds-checked
//! against what is left, and indefinite lengths (BER) are refused, so a
//! malformed input can only produce `None`.

#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    /// The content octets, without the header.
    pub content: &'a [u8],
    /// Header and content together, exactly as they appear in the input.
    pub whole: &'a [u8],
}

/// Read one element from the front of `input`, returning it and the rest.
pub fn read(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *input.first()?;
    // Multi-byte tags (low five bits all set) do not occur in the structures
    // walked here and are refused rather than guessed at.
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *input.get(1)?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None; // indefinite, or longer than any real certificate
        }
        let bytes = input.get(2..2 + n)?;
        let len = bytes
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    if end > input.len() {
        return None;
    }
    Some((
        Tlv {
            tag,
            content: &input[header..end],
            whole: &input[..end],
        },
        &input[end..],
    ))
}

const SEQUENCE: u8 = 0x30;
const CONTEXT_0: u8 = 0xa0;

/// The DER of the certificate's SubjectPublicKeyInfo, header included.
pub fn subject_public_key_info(cert: &[u8]) -> Option<&[u8]> {
    let (cert, _) = read(cert)?;
    if cert.tag != SEQUENCE {
        return None;
    }
    let (tbs, _) = read(cert.content)?;
    if tbs.tag != SEQUENCE {
        return None;
    }
    let mut rest = tbs.content;
    let (mut el, mut after) = read(rest)?;
    if el.tag == CONTEXT_0 {
        // explicit version
        rest = after;
        (el, after) = read(rest)?;
    }
    // `el` is now the serial number (INTEGER); then signature, issuer,
    // validity, subject, and finally the key.
    if el.tag != 0x02 {
        return None;
    }
    rest = after;
    for _ in 0..4 {
        let (skipped, next) = read(rest)?;
        if skipped.tag != SEQUENCE {
            return None;
        }
        rest = next;
    }
    let (spki, _) = read(rest)?;
    (spki.tag == SEQUENCE).then_some(spki.whole)
}

#[cfg(test)]
pub(crate) mod build {
    //! Building DER for tests.

    pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else {
            let bytes = (content.len() as u32).to_be_bytes();
            let skip = bytes.iter().take_while(|b| **b == 0).count();
            out.push(0x80 | (4 - skip) as u8);
            out.extend_from_slice(&bytes[skip..]);
        }
        out.extend_from_slice(content);
        out
    }

    /// A structurally valid certificate around `spki`. Nothing in it is signed
    /// or meaningful; it has the shape the parser walks.
    pub fn certificate_with(spki: &[u8], cn: &str) -> Vec<u8> {
        let version = tlv(0xa0, &tlv(0x02, &[2]));
        let serial = tlv(0x02, &[1]);
        let sig_alg = tlv(
            0x30,
            &tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
        );
        let name = tlv(
            0x30,
            &tlv(
                0x31,
                &tlv(
                    0x30,
                    &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, cn.as_bytes())].concat(),
                ),
            ),
        );
        let validity = tlv(
            0x30,
            &[tlv(0x17, b"240101000000Z"), tlv(0x17, b"340101000000Z")].concat(),
        );
        let tbs = tlv(
            0x30,
            &[
                version,
                serial,
                sig_alg.clone(),
                name.clone(),
                validity,
                name,
                spki.to_vec(),
            ]
            .concat(),
        );
        tlv(0x30, &[tbs, sig_alg, tlv(0x03, &[0, 1, 2, 3])].concat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_key_in_a_well_formed_certificate() {
        let spki = build::tlv(
            0x30,
            &[
                build::tlv(0x30, &[0x05, 0x00]),
                build::tlv(0x03, &[0, 4, 4, 4]),
            ]
            .concat(),
        );
        let cert = build::certificate_with(&spki, "hrd-test");
        assert_eq!(subject_public_key_info(&cert), Some(&spki[..]));
    }

    #[test]
    fn works_without_the_optional_version() {
        let spki = build::tlv(0x30, &[1, 2, 3]);
        let mut cert = build::certificate_with(&spki, "x");
        // strip the [0] EXPLICIT version: rebuild manually
        let (outer, _) = read(&cert).unwrap();
        let (tbs, tail) = read(outer.content).unwrap();
        let (ver, rest) = read(tbs.content).unwrap();
        assert_eq!(ver.tag, 0xa0);
        let new_tbs = build::tlv(0x30, rest);
        cert = build::tlv(0x30, &[new_tbs, tail.to_vec()].concat());
        assert_eq!(subject_public_key_info(&cert), Some(&spki[..]));
    }

    #[test]
    fn malformed_input_yields_none_never_a_panic() {
        let spki = build::tlv(0x30, &[9; 40]);
        let cert = build::certificate_with(&spki, "x");
        // every truncation
        for n in 0..cert.len() {
            let _ = subject_public_key_info(&cert[..n]);
        }
        // every single-byte corruption
        for i in 0..cert.len() {
            let mut c = cert.clone();
            c[i] ^= 0xff;
            let _ = subject_public_key_info(&c);
        }
        assert_eq!(subject_public_key_info(&[]), None);
        assert_eq!(
            subject_public_key_info(&[0x30, 0x80, 0, 0]),
            None,
            "indefinite length"
        );
        assert_eq!(
            subject_public_key_info(&[0x30, 0x85, 1, 2, 3, 4, 5]),
            None,
            "length field too long"
        );
        assert_eq!(
            subject_public_key_info(&[0x30, 0x10, 0x30]),
            None,
            "length beyond the input"
        );
    }
}
