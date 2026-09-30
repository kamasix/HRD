//! Standard base64, exactly as WireGuard keys use it, and nothing else.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode padded, canonical base64. Rejects whitespace, missing or misplaced
/// padding, and non-zero trailing bits: a key has exactly one spelling, and an
/// alternative spelling of the same bytes is at best a typo.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (i, quad) in b.chunks(4).enumerate() {
        let last = (i + 1) * 4 == b.len();
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (j, &c) in quad.iter().enumerate() {
            let v = if j >= 4 - pad {
                if c != b'=' {
                    return None;
                }
                0
            } else {
                value(c)?
            };
            n = (n << 6) | v;
        }
        // Trailing bits that do not belong to any byte must be zero.
        if (pad == 1 && n & 0xff != 0) || (pad == 2 && n & 0xffff != 0) {
            return None;
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        for (raw, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(raw.as_bytes()), enc);
            if !enc.is_empty() {
                assert_eq!(decode(enc).unwrap(), raw.as_bytes());
            }
        }
    }

    #[test]
    fn non_canonical_and_malformed_input_is_refused() {
        for bad in [
            "",
            "Zg=",
            "Zg",
            "Zm9v=",
            "Zh==",
            "Zm9=",
            "Z===",
            "====",
            "Zm 9v",
            "Zm9v\n",
            "Zm9v=Zm9v",
            "Zm9-",
        ] {
            assert!(decode(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn a_wireguard_key_is_44_characters_and_32_bytes() {
        let k = encode(&[7u8; 32]);
        assert_eq!(k.len(), 44);
        assert_eq!(decode(&k).unwrap().len(), 32);
    }
}
