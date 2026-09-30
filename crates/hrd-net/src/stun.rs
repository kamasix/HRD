//! The smallest STUN client that answers "what address do you see me as, over
//! UDP?".
//!
//! This is how `network check` observes a group's exit. An HTTPS request to a
//! what's-my-IP page proves the TCP path; the game's transport is UDP, and a
//! tunnel can carry one and not the other (a provider that blocks UDP, a
//! gateway with only a TCP rule). A STUN binding request is one UDP datagram
//! each way, from inside the namespace, to a server the operator chose, and
//! the reply names the source address that server saw. That is the address the
//! game's UDP would appear from, at least as far as that server can tell, and
//! it is an observation, not a configuration.
//!
//! Only binding requests without authentication are built or parsed (RFC 5389).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAGIC: u32 = 0x2112_a442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

pub fn binding_request(txid: &[u8; 12]) -> [u8; 20] {
    let mut m = [0u8; 20];
    m[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // length 0
    m[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    m[8..20].copy_from_slice(txid);
    m
}

/// The mapped address in a binding success response to `txid`, or `None` for
/// anything else: another transaction, a truncated datagram, an error class.
pub fn parse_response(msg: &[u8], txid: &[u8; 12]) -> Option<(IpAddr, u16)> {
    if msg.len() < 20 || u16::from_be_bytes([msg[0], msg[1]]) != BINDING_SUCCESS {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([msg[2], msg[3]]));
    if u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]) != MAGIC
        || &msg[8..20] != txid
        || 20 + len > msg.len()
    {
        return None;
    }
    let mut attrs = &msg[20..20 + len];
    let mut plain = None;
    while attrs.len() >= 4 {
        let ty = u16::from_be_bytes([attrs[0], attrs[1]]);
        let alen = usize::from(u16::from_be_bytes([attrs[2], attrs[3]]));
        let padded = (alen + 3) & !3;
        if 4 + alen > attrs.len() {
            return None;
        }
        let value = &attrs[4..4 + alen];
        match ty {
            ATTR_XOR_MAPPED_ADDRESS => return decode_address(value, true, txid),
            ATTR_MAPPED_ADDRESS => plain = decode_address(value, false, txid),
            _ => {}
        }
        if 4 + padded > attrs.len() {
            break;
        }
        attrs = &attrs[4 + padded..];
    }
    plain
}

fn decode_address(v: &[u8], xor: bool, txid: &[u8; 12]) -> Option<(IpAddr, u16)> {
    if v.len() < 4 {
        return None;
    }
    let mut port = u16::from_be_bytes([v[2], v[3]]);
    if xor {
        port ^= (MAGIC >> 16) as u16;
    }
    match v[1] {
        1 if v.len() >= 8 => {
            let mut a = [v[4], v[5], v[6], v[7]];
            if xor {
                for (b, m) in a.iter_mut().zip(MAGIC.to_be_bytes()) {
                    *b ^= m;
                }
            }
            Some((IpAddr::V4(Ipv4Addr::from(a)), port))
        }
        2 if v.len() >= 20 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&v[4..20]);
            if xor {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&MAGIC.to_be_bytes());
                mask[4..].copy_from_slice(txid);
                for (b, m) in a.iter_mut().zip(mask) {
                    *b ^= m;
                }
            }
            Some((IpAddr::V6(Ipv6Addr::from(a)), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TXID: [u8; 12] = [
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ];

    /// RFC 5769 section 2.2, the sample IPv4 response.
    #[test]
    fn rfc_5769_ipv4_vector() {
        let resp: Vec<u8> = vec![
            0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
            0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, //
            0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f,
            0x72, 0x00, //
            0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43, //
            0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74,
            0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7, //
            0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96,
        ];
        assert_eq!(
            parse_response(&resp, &TXID),
            Some(("192.0.2.1".parse().unwrap(), 32853))
        );
    }

    /// RFC 5769 section 2.3, the sample IPv6 response (only the parts used).
    #[test]
    fn rfc_5769_ipv6_vector() {
        let txid = TXID;
        let resp: Vec<u8> = vec![
            0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
            0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, //
            0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f,
            0x72, 0x20, //
            0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3,
            0xf1, 0x79, 0xbc, 0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9, //
            0x00, 0x08, 0x00, 0x14, 0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6, 0x7b, 0xf1, 0x17, 0x84,
            0xc9, 0x7c, 0x82, 0x92, 0xc2, 0x75, 0xbf, 0xe3, 0xed, 0x41, //
            0x80, 0x28, 0x00, 0x04, 0xc8, 0xfb, 0x0b, 0x4c,
        ];
        assert_eq!(
            parse_response(&resp, &txid),
            Some((
                "2001:db8:1234:5678:11:2233:4455:6677".parse().unwrap(),
                32853
            ))
        );
    }

    #[test]
    fn a_reply_to_another_transaction_or_a_mangled_one_is_ignored() {
        let req = binding_request(&TXID);
        assert_eq!(&req[..4], &[0, 1, 0, 0]);
        assert_eq!(
            parse_response(&req, &TXID),
            None,
            "a request is not a response"
        );
        let mut wrong = [0u8; 12];
        wrong[0] = 1;
        let mut ok = vec![0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42];
        ok.extend_from_slice(&TXID);
        ok.extend_from_slice(&[
            0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
        ]);
        assert!(parse_response(&ok, &TXID).is_some());
        assert_eq!(parse_response(&ok, &wrong), None);
        for n in 0..ok.len() {
            let _ = parse_response(&ok[..n], &TXID);
        }
        for i in 0..ok.len() {
            let mut c = ok.clone();
            c[i] ^= 0xff;
            let _ = parse_response(&c, &TXID);
        }
    }
}
