//! Reading four attributes from a binary `AndroidManifest.xml`.
//!
//! An APK's manifest is Android's compiled XML (AXML): a string pool followed
//! by a flat list of node chunks. The importer wants exactly the root
//! `<manifest>` element's `package`, `versionCode`, `split` and `configForSplit`
//! so that a base APK and a split can be checked as belonging together (same
//! package and version). Nothing else in the format is interpreted.
//!
//! Every offset and length comes from the file, so every access is bounds
//! checked and any inconsistency yields `None`. A manifest this cannot read is
//! **not** an error for the importer, which records "consistency not checked"
//! and says why: the signature check (same signer, bound key) is the security
//! property, this is a check for operator mistakes such as mixing two builds.

const RES_XML: u16 = 0x0003;
const RES_STRING_POOL: u16 = 0x0001;
const RES_START_ELEMENT: u16 = 0x0102;
const UTF8_FLAG: u32 = 1 << 8;
const TYPE_STRING: u8 = 0x03;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const NO_INDEX: u32 = 0xffff_ffff;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestInfo {
    pub package: Option<String>,
    pub version_code: Option<u32>,
    pub split: Option<String>,
    pub config_for_split: Option<String>,
}

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn u8(&self, at: usize) -> Option<u8> {
        self.0.get(at).copied()
    }
    fn u16(&self, at: usize) -> Option<u16> {
        Some(u16::from_le_bytes(
            self.0.get(at..at.checked_add(2)?)?.try_into().ok()?,
        ))
    }
    fn u32(&self, at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            self.0.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    }
    fn slice(&self, at: usize, len: usize) -> Option<&'a [u8]> {
        self.0.get(at..at.checked_add(len)?)
    }
}

pub fn parse(data: &[u8]) -> Option<ManifestInfo> {
    let r = R(data);
    if r.u16(0)? != RES_XML || usize::from(r.u16(2)?) < 8 {
        return None;
    }
    let total = (r.u32(4)? as usize).min(data.len());
    let mut at = usize::from(r.u16(2)?);
    let mut pool: Option<Vec<String>> = None;

    while at + 8 <= total {
        let ty = r.u16(at)?;
        let header = usize::from(r.u16(at + 2)?);
        let size = r.u32(at + 4)? as usize;
        if size < 8 || header > size || at.checked_add(size)? > total {
            return None;
        }
        match ty {
            RES_STRING_POOL => pool = Some(read_pool(&R(r.slice(at, size)?))?),
            RES_START_ELEMENT => {
                let strings = pool.as_ref()?;
                return read_manifest_element(&R(r.slice(at, size)?), header, strings);
            }
            _ => {}
        }
        at += size;
    }
    None
}

fn read_pool(c: &R<'_>) -> Option<Vec<String>> {
    let count = c.u32(8)? as usize;
    let flags = c.u32(16)?;
    let strings_start = c.u32(20)? as usize;
    let header = usize::from(c.u16(2)?);
    // A pool larger than the chunk could hold is corrupt; this bound also stops
    // a hostile count from reserving gigabytes.
    if count > c.0.len() / 4 {
        return None;
    }
    let offsets_at = header;
    let mut out = Vec::with_capacity(count.min(4096));
    for i in 0..count {
        let off = c.u32(offsets_at.checked_add(i.checked_mul(4)?)?)? as usize;
        let s = strings_start.checked_add(off)?;
        out.push(if flags & UTF8_FLAG != 0 {
            utf8_string(c, s)?
        } else {
            utf16_string(c, s)?
        });
    }
    Some(out)
}

fn utf16_string(c: &R<'_>, at: usize) -> Option<String> {
    let first = usize::from(c.u16(at)?);
    let (len, data_at) = if first & 0x8000 != 0 {
        ((first & 0x7fff) << 16 | usize::from(c.u16(at + 2)?), at + 4)
    } else {
        (first, at + 2)
    };
    let bytes = c.slice(data_at, len.checked_mul(2)?)?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

fn utf8_string(c: &R<'_>, at: usize) -> Option<String> {
    // Two lengths: characters, then bytes; each one or two bytes.
    let (_, at) = utf8_len(c, at)?;
    let (n, at) = utf8_len(c, at)?;
    Some(String::from_utf8_lossy(c.slice(at, n)?).into_owned())
}

fn utf8_len(c: &R<'_>, at: usize) -> Option<(usize, usize)> {
    let b = usize::from(c.u8(at)?);
    if b & 0x80 != 0 {
        Some((((b & 0x7f) << 8) | usize::from(c.u8(at + 1)?), at + 2))
    } else {
        Some((b, at + 1))
    }
}

fn read_manifest_element(c: &R<'_>, header: usize, strings: &[String]) -> Option<ManifestInfo> {
    // header is 16: chunk header, line number, comment. The extension follows.
    let ext = header;
    let name_idx = c.u32(ext + 4)?;
    if strings.get(name_idx as usize).map(String::as_str) != Some("manifest") {
        return None;
    }
    let attr_start = usize::from(c.u16(ext + 8)?);
    let attr_size = usize::from(c.u16(ext + 10)?);
    let attr_count = usize::from(c.u16(ext + 12)?);
    if attr_size < 20 {
        return None;
    }
    let mut info = ManifestInfo::default();
    for i in 0..attr_count {
        let a = ext
            .checked_add(attr_start)?
            .checked_add(i.checked_mul(attr_size)?)?;
        let name = strings.get(c.u32(a + 4)? as usize)?;
        let raw = c.u32(a + 8)?;
        let data_type = c.u8(a + 15)?;
        let data = c.u32(a + 16)?;
        let string_value = || -> Option<String> {
            let idx = if raw != NO_INDEX {
                raw
            } else if data_type == TYPE_STRING {
                data
            } else {
                return None;
            };
            strings.get(idx as usize).cloned()
        };
        match name.as_str() {
            "package" => info.package = string_value(),
            "split" => info.split = string_value(),
            "configForSplit" => info.config_for_split = string_value(),
            "versionCode" if matches!(data_type, TYPE_INT_DEC | TYPE_INT_HEX) => {
                info.version_code = Some(data)
            }
            _ => {}
        }
    }
    Some(info)
}

#[cfg(test)]
pub(crate) fn build(utf8: bool, package: &str, version_code: u32, split: Option<&str>) -> Vec<u8> {
    fn pool(utf8: bool, strings: &[&str]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for s in strings {
            offsets.push(data.len() as u32);
            if utf8 {
                data.push(s.chars().count() as u8);
                data.push(s.len() as u8);
                data.extend_from_slice(s.as_bytes());
                data.push(0);
            } else {
                let u: Vec<u16> = s.encode_utf16().collect();
                data.extend_from_slice(&(u.len() as u16).to_le_bytes());
                for x in u {
                    data.extend_from_slice(&x.to_le_bytes());
                }
                data.extend_from_slice(&[0, 0]);
            }
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let header = 28usize;
        let strings_start = header + offsets.len() * 4;
        let size = strings_start + data.len();
        let mut out = Vec::new();
        out.extend_from_slice(&RES_STRING_POOL.to_le_bytes());
        out.extend_from_slice(&(header as u16).to_le_bytes());
        out.extend_from_slice(&(size as u32).to_le_bytes());
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(if utf8 { UTF8_FLAG } else { 0 }).to_le_bytes());
        out.extend_from_slice(&(strings_start as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        for o in offsets {
            out.extend_from_slice(&o.to_le_bytes());
        }
        out.extend_from_slice(&data);
        out
    }

    let mut strings = vec!["manifest", "package", "versionCode", "split", package];
    let split_idx = split.map(|s| {
        strings.push(s);
        (strings.len() - 1) as u32
    });
    let mut attrs: Vec<[u32; 5]> = vec![
        [NO_INDEX, 1, 4, u32::from(TYPE_STRING) << 24 | 8, 4],
        [
            NO_INDEX,
            2,
            NO_INDEX,
            u32::from(TYPE_INT_DEC) << 24 | 8,
            version_code,
        ],
    ];
    if let Some(i) = split_idx {
        attrs.push([NO_INDEX, 3, i, u32::from(TYPE_STRING) << 24 | 8, i]);
    }
    let mut el = Vec::new();
    let ext_len = 20 + attrs.len() * 20;
    el.extend_from_slice(&RES_START_ELEMENT.to_le_bytes());
    el.extend_from_slice(&16u16.to_le_bytes());
    el.extend_from_slice(&((16 + ext_len) as u32).to_le_bytes());
    el.extend_from_slice(&1u32.to_le_bytes());
    el.extend_from_slice(&NO_INDEX.to_le_bytes());
    el.extend_from_slice(&NO_INDEX.to_le_bytes()); // ns
    el.extend_from_slice(&0u32.to_le_bytes()); // name = "manifest"
    el.extend_from_slice(&20u16.to_le_bytes());
    el.extend_from_slice(&20u16.to_le_bytes());
    el.extend_from_slice(&(attrs.len() as u16).to_le_bytes());
    el.extend_from_slice(&[0; 6]);
    for a in &attrs {
        el.extend_from_slice(&a[0].to_le_bytes()); // ns
        el.extend_from_slice(&a[1].to_le_bytes()); // name
        el.extend_from_slice(&a[2].to_le_bytes()); // raw
                                                   // typed value: size u16 = 8, res0 u8 = 0, type u8, data u32
        el.extend_from_slice(&8u16.to_le_bytes());
        el.push(0);
        el.push((a[3] >> 24) as u8);
        el.extend_from_slice(&a[4].to_le_bytes());
    }
    let pool = pool(utf8, &strings);
    let total = 8 + pool.len() + el.len();
    let mut out = Vec::new();
    out.extend_from_slice(&RES_XML.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&(total as u32).to_le_bytes());
    out.extend_from_slice(&pool);
    out.extend_from_slice(&el);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_four_attributes_from_utf16_and_utf8_pools() {
        for utf8 in [false, true] {
            let m = parse(&build(utf8, "com.roblox.client", 738_001_397, None)).unwrap();
            assert_eq!(
                m.package.as_deref(),
                Some("com.roblox.client"),
                "utf8={utf8}"
            );
            assert_eq!(m.version_code, Some(738_001_397));
            assert_eq!(m.split, None);
            let s = parse(&build(utf8, "com.roblox.client", 7, Some("config.x86_64"))).unwrap();
            assert_eq!(s.split.as_deref(), Some("config.x86_64"));
        }
    }

    #[test]
    fn hostile_input_never_panics() {
        let good = build(false, "com.roblox.client", 7, Some("config.x86_64"));
        for n in 0..good.len() {
            let _ = parse(&good[..n]);
        }
        for i in 0..good.len() {
            for flip in [0xffu8, 0x01, 0x80] {
                let mut c = good.clone();
                c[i] ^= flip;
                let _ = parse(&c);
            }
        }
        assert_eq!(parse(&[]), None);
        assert_eq!(
            parse(&[0x03, 0x00, 0x08, 0x00, 0xff, 0xff, 0xff, 0xff]),
            None
        );
        let good8 = build(true, "a", 1, None);
        for n in 0..good8.len() {
            let _ = parse(&good8[..n]);
        }
    }

    #[test]
    fn a_root_element_that_is_not_manifest_is_not_a_manifest() {
        let mut m = build(false, "p", 1, None);
        // rename string 0 ("manifest") to something else of the same length
        let pos = m
            .windows(2 * 8)
            .position(|w| {
                w == "manifest"
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes())
                    .collect::<Vec<u8>>()
                    .as_slice()
            })
            .unwrap();
        m[pos] = b'X';
        assert_eq!(parse(&m), None);
    }
}
