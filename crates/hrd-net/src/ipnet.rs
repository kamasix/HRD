//! An address with a prefix length, without a dependency.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IpNet {
    pub fn max_prefix(addr: &IpAddr) -> u8 {
        if addr.is_ipv4() {
            32
        } else {
            128
        }
    }

    pub fn is_default_v4(&self) -> bool {
        self.addr == IpAddr::V4(Ipv4Addr::UNSPECIFIED) && self.prefix == 0
    }

    pub fn is_default_v6(&self) -> bool {
        self.addr == IpAddr::V6(Ipv6Addr::UNSPECIFIED) && self.prefix == 0
    }

    pub fn is_v6(&self) -> bool {
        self.addr.is_ipv6()
    }
}

impl FromStr for IpNet {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a.trim().parse().map_err(|_| format!("{s:?} is not an IP address"))?;
        let max = IpNet::max_prefix(&addr);
        let prefix = match p {
            None => max,
            Some(p) => {
                if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.len() > 3 {
                    return Err(format!("{s:?} has a malformed prefix length"));
                }
                p.parse::<u8>().map_err(|_| format!("{s:?} has a prefix length out of range"))?
            }
        };
        if prefix > max {
            return Err(format!("{s:?}: prefix length {prefix} exceeds {max}"));
        }
        Ok(IpNet { addr, prefix })
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl Serialize for IpNet {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for IpNet {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_prints() {
        let n: IpNet = "10.66.66.2/32".parse().unwrap();
        assert_eq!(n.to_string(), "10.66.66.2/32");
        assert_eq!("10.0.0.1".parse::<IpNet>().unwrap().prefix, 32);
        assert_eq!("fd42::2".parse::<IpNet>().unwrap().prefix, 128);
        assert!("0.0.0.0/0".parse::<IpNet>().unwrap().is_default_v4());
        assert!("::/0".parse::<IpNet>().unwrap().is_default_v6());
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["", "10.0.0.1/33", "::1/129", "10.0.0/24", "a.b.c.d", "10.0.0.1/", "10.0.0.1/-1", "10.0.0.1/ 24", "10.0.0.1/24/1", "10.0.0.1;ls", "1.2.3.4/0x10"] {
            assert!(bad.parse::<IpNet>().is_err(), "{bad:?}");
        }
    }
}
