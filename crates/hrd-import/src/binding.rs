//! Does the certificate that gets pinned belong to the key that signed?
//!
//! An APK signature block (scheme v2 or v3) holds, per signer, three things:
//! the *signed data* (digests, the signer's certificates, attributes), the
//! *signatures* over that data, and a *public key*. Android's own verifier
//! checks the signatures against the public key **and** that the public key is
//! the one inside the first certificate ("Public key mismatch between
//! certificate and signature record"); without the second check the
//! certificate is a label anyone can copy onto a block signed with a different
//! key.
//!
//! Upstream Cordial's `apk_signature::verify` (b0ee9f3) does the first check
//! and not the second: the signature is verified against the record's public
//! key, and the fingerprint it reports is the hash of the first certificate in
//! the signed data. Pinning that fingerprint, as `verify_signed_by` does, then
//! proves only that *some* block carrying Roblox's public certificate verified
//! against *some* key. The regression test at the bottom of this file builds
//! exactly such an archive and shows `verify_signed_by` accepting it while
//! [`check`] refuses it. BASELINE.md finding 8 is the written account.
//!
//! This module re-reads the signing block independently and compares the two.
//! It is deliberately stricter than upstream about what it looks at: it checks
//! **every** signer of the scheme upstream would use, not only the first.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::der;

const BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
const BLOCK_ID_V2: u32 = 0x7109_871a;
const BLOCK_ID_V3: u32 = 0xf053_68c0;
const MAX_BLOCK: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    NotAnArchive,
    NoSigningBlock,
    Malformed(&'static str),
    /// A signer's certificate does not contain the key that its signature
    /// record verifies against.
    KeyMismatch { signer: usize },
    Io(String),
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingError::NotAnArchive => f.write_str("not a zip archive"),
            BindingError::NoSigningBlock => f.write_str("no APK signing block (v1-only or unsigned)"),
            BindingError::Malformed(w) => write!(f, "malformed signing block: {w}"),
            BindingError::KeyMismatch { signer } => write!(
                f,
                "signer {signer}: the certificate does not contain the public key the signature was made with. \
                 The archive pairs a certificate with a key that is not its own; it is not what its certificate claims"
            ),
            BindingError::Io(e) => write!(f, "I/O: {e}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    pub scheme: u8,
    pub signers: usize,
}

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, at: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.at
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.buf.get(self.at..end)?;
        self.at = end;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn sized(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

fn io(e: std::io::Error) -> BindingError {
    BindingError::Io(e.to_string())
}

/// Check the binding in the archive at `path`.
pub fn check(path: &Path) -> Result<Binding, BindingError> {
    let mut f = File::open(path).map_err(io)?;
    let len = f.metadata().map_err(io)?.len();
    let block = signing_block(&mut f, len)?;
    check_block(&block)
}

fn signing_block(f: &mut File, len: u64) -> Result<Vec<u8>, BindingError> {
    if len < 22 + 24 {
        return Err(BindingError::NotAnArchive);
    }
    let window = len.min(22 + 65535) as usize;
    let start = len - window as u64;
    let mut tail = vec![0u8; window];
    f.seek(SeekFrom::Start(start)).map_err(io)?;
    f.read_exact(&mut tail).map_err(io)?;

    // The end-of-central-directory record, found from the back; a candidate
    // counts only if its comment length reaches exactly to the end of the file,
    // so bytes inside a comment cannot impersonate it.
    let eocd_rel = (0..=window - 22)
        .rev()
        .find(|&i| {
            tail[i..i + 4] == [0x50, 0x4b, 0x05, 0x06] && {
                let clen = usize::from(u16::from_le_bytes([tail[i + 20], tail[i + 21]]));
                i + 22 + clen == window
            }
        })
        .ok_or(BindingError::NotAnArchive)?;
    let cd_offset = u64::from(u32::from_le_bytes(tail[eocd_rel + 16..eocd_rel + 20].try_into().expect("4 bytes")));
    let eocd = start + eocd_rel as u64;
    if cd_offset == 0xffff_ffff || cd_offset >= eocd {
        return Err(BindingError::NotAnArchive);
    }
    if cd_offset < 24 {
        return Err(BindingError::NoSigningBlock);
    }
    let mut foot = [0u8; 24];
    f.seek(SeekFrom::Start(cd_offset - 24)).map_err(io)?;
    f.read_exact(&mut foot).map_err(io)?;
    if &foot[8..] != BLOCK_MAGIC {
        return Err(BindingError::NoSigningBlock);
    }
    let size = u64::from_le_bytes(foot[..8].try_into().expect("8 bytes"));
    if !(24..=MAX_BLOCK).contains(&size) {
        return Err(BindingError::Malformed("implausible block size"));
    }
    let block_start = cd_offset.checked_sub(size + 8).ok_or(BindingError::Malformed("the block is larger than the file"))?;
    let mut block = vec![0u8; (size + 8) as usize];
    f.seek(SeekFrom::Start(block_start)).map_err(io)?;
    f.read_exact(&mut block).map_err(io)?;
    Ok(block)
}

fn check_block(block: &[u8]) -> Result<Binding, BindingError> {
    let mut r = Reader::new(block);
    let declared = r.u64().ok_or(BindingError::Malformed("no leading size"))?;
    if declared + 8 != block.len() as u64 {
        return Err(BindingError::Malformed("the two size fields disagree"));
    }
    let (mut v2, mut v3): (Option<&[u8]>, Option<&[u8]>) = (None, None);
    while r.remaining() > 24 {
        let pair_len = r.u64().ok_or(BindingError::Malformed("truncated pair"))? as usize;
        if pair_len < 4 {
            return Err(BindingError::Malformed("pair shorter than its id"));
        }
        let id = r.u32().ok_or(BindingError::Malformed("pair without id"))?;
        let value = r.take(pair_len - 4).ok_or(BindingError::Malformed("pair longer than the block"))?;
        match id {
            BLOCK_ID_V2 => v2 = Some(value),
            BLOCK_ID_V3 => v3 = Some(value),
            _ => {}
        }
    }
    // The scheme upstream's verifier would use: v3 when present, else v2.
    let (scheme, value) = match (v3, v2) {
        (Some(v), _) => (3u8, v),
        (None, Some(v)) => (2u8, v),
        (None, None) => return Err(BindingError::NoSigningBlock),
    };
    let mut outer = Reader::new(value);
    let mut signers = Reader::new(outer.sized().ok_or(BindingError::Malformed("no signer sequence"))?);
    let mut n = 0usize;
    while signers.remaining() > 0 {
        let signer = signers.sized().ok_or(BindingError::Malformed("truncated signer"))?;
        let mut s = Reader::new(signer);
        let signed_data = s.sized().ok_or(BindingError::Malformed("no signed data"))?;
        if scheme == 3 {
            s.u32().ok_or(BindingError::Malformed("no minSdk"))?;
            s.u32().ok_or(BindingError::Malformed("no maxSdk"))?;
        }
        let _signatures = s.sized().ok_or(BindingError::Malformed("no signatures"))?;
        let public_key = s.sized().ok_or(BindingError::Malformed("no public key"))?;

        let mut sd = Reader::new(signed_data);
        let _digests = sd.sized().ok_or(BindingError::Malformed("no digests"))?;
        let mut certs = Reader::new(sd.sized().ok_or(BindingError::Malformed("no certificates"))?);
        let first = certs.sized().ok_or(BindingError::Malformed("no signing certificate"))?;
        let cert_key = der::subject_public_key_info(first).ok_or(BindingError::Malformed("the certificate does not parse"))?;
        if cert_key != public_key {
            return Err(BindingError::KeyMismatch { signer: n });
        }
        n += 1;
    }
    if n == 0 {
        return Err(BindingError::Malformed("no signers"));
    }
    Ok(Binding { scheme, signers: n })
}

// ---------------------------------------------------------------------------
// Test support: APKs signed with throwaway keys
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod testapk {
    //! Builds small archives with a genuine v2 signing block, signed with a key
    //! generated for the test. Nothing here is a credential: every key lives in
    //! memory for the length of one test.

    use std::io::Write;

    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    use sha2::{Digest, Sha256};

    use crate::der::build::{certificate_with, tlv};

    pub struct Signer {
        pair: EcdsaKeyPair,
        pub spki: Vec<u8>,
    }

    pub fn new_signer() -> Signer {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        // SubjectPublicKeyInfo for an EC P-256 key.
        let point = pair.public_key().as_ref().to_vec();
        let alg = tlv(0x30, &[tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]), tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])].concat());
        let mut bits = vec![0u8];
        bits.extend_from_slice(&point);
        let spki = tlv(0x30, &[alg, tlv(0x03, &bits)].concat());
        Signer { pair, spki }
    }

    /// A zip (stored, no compression) of the given entries.
    pub fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (name, data) in entries {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        buf.into_inner()
    }

    fn lp(b: &[u8]) -> Vec<u8> {
        let mut v = (b.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(b);
        v
    }

    fn chunk(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0xa5u8]);
        h.update((data.len() as u32).to_le_bytes());
        h.update(data);
        h.finalize().into()
    }

    /// Sign `zip` (v2). The signature is made by `record_key`, the record
    /// carries `record_key`'s public key, and the certificate embedded in the
    /// signed data wraps `cert_key_spki`, which is the same key for an honest
    /// archive and another key for the forgery the regression test builds.
    pub fn sign_v2(zip: &[u8], record_key: &Signer, cert_key_spki: &[u8], cn: &str) -> Vec<u8> {
        // split the zip
        let eocd = zip.len() - 22;
        assert_eq!(&zip[eocd..eocd + 4], &[0x50, 0x4b, 0x05, 0x06], "test zips have no comment");
        let cd_offset = u32::from_le_bytes(zip[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        let entries = &zip[..cd_offset];
        let cd = &zip[cd_offset..eocd];
        let mut eocd_bytes = zip[eocd..].to_vec();
        eocd_bytes[16..20].copy_from_slice(&(entries.len() as u32).to_le_bytes());

        let mut chunks: Vec<[u8; 32]> = Vec::new();
        for section in [entries, cd, &eocd_bytes[..]] {
            for c in section.chunks(1024 * 1024) {
                chunks.push(chunk(c));
            }
        }
        let mut top = Sha256::new();
        top.update([0x5au8]);
        top.update((chunks.len() as u32).to_le_bytes());
        for c in &chunks {
            top.update(c);
        }
        let digest: [u8; 32] = top.finalize().into();

        const ALG: u32 = 0x0201; // ECDSA with SHA-256
        let digests = lp(&lp(&[ALG.to_le_bytes().to_vec(), lp(&digest)].concat()));
        let cert = certificate_with(cert_key_spki, cn);
        let certs = lp(&lp(&cert));
        let attrs = lp(&[]);
        let signed_data = [digests, certs, attrs].concat();

        let sig = record_key.pair.sign(&SystemRandom::new(), &signed_data).unwrap();
        let signatures = lp(&lp(&[ALG.to_le_bytes().to_vec(), lp(sig.as_ref())].concat()));
        let signer = [lp(&signed_data), signatures, lp(&record_key.spki)].concat();
        let value = lp(&lp(&signer));

        let mut pairs = Vec::new();
        pairs.extend_from_slice(&((value.len() + 4) as u64).to_le_bytes());
        pairs.extend_from_slice(&0x7109_871au32.to_le_bytes());
        pairs.extend_from_slice(&value);
        let size = (pairs.len() + 24) as u64;
        let mut block = size.to_le_bytes().to_vec();
        block.extend_from_slice(&pairs);
        block.extend_from_slice(&size.to_le_bytes());
        block.extend_from_slice(b"APK Sig Block 42");

        let mut out = entries.to_vec();
        out.extend_from_slice(&block);
        out.extend_from_slice(cd);
        let mut eocd_final = zip[eocd..].to_vec();
        eocd_final[16..20].copy_from_slice(&((entries.len() + block.len()) as u32).to_le_bytes());
        out.extend_from_slice(&eocd_final);
        out
    }

    /// SHA-256 of the certificate `sign_v2` embeds, which is the fingerprint
    /// upstream reports and pins.
    pub fn fingerprint(cert_key_spki: &[u8], cn: &str) -> String {
        let cert = certificate_with(cert_key_spki, cn);
        Sha256::digest(&cert).iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::testapk::*;
    use super::*;

    fn write(tag: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("hrd-binding-{tag}-{}.apk", std::process::id()));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn sample_zip() -> Vec<u8> {
        zip_of(&[("AndroidManifest.xml", b"manifest"), ("lib/x86_64/libroblox.so", b"engine 2.738.0.1397 engine")])
    }

    #[test]
    fn an_honest_archive_verifies_upstream_and_binds() {
        let k = new_signer();
        let apk = write("honest", &sign_v2(&sample_zip(), &k, &k.spki, "honest"));
        let fp = cordial_update::apk_signature::verify(&apk).expect("upstream verify").certificate_sha256;
        assert_eq!(fp, fingerprint(&k.spki, "honest"));
        assert_eq!(check(&apk), Ok(Binding { scheme: 2, signers: 1 }));
        std::fs::remove_file(apk).ok();
    }

    /// **The regression test for BASELINE.md finding 8.**
    ///
    /// The forger signs with their own key but puts a certificate in the signed
    /// data that contains *someone else's* key, the way a copy of Roblox's
    /// public certificate would. Upstream accepts it against a pin of that
    /// certificate's fingerprint; this module refuses it.
    #[test]
    fn a_pinned_certificate_on_a_block_signed_by_another_key_passes_upstream_and_fails_here() {
        let roblox_like = new_signer();
        let forger = new_signer();
        // The certificate wraps roblox_like's key; the block is signed by, and
        // carries the public key of, the forger.
        let apk = write("forged", &sign_v2(&sample_zip(), &forger, &roblox_like.spki, "roblox-like"));
        let pinned = vec![fingerprint(&roblox_like.spki, "roblox-like")];

        let upstream = cordial_update::apk_signature::verify_signed_by(&apk, &pinned);
        assert!(upstream.is_ok(), "upstream is expected to ACCEPT the forgery (this is the defect): {upstream:?}");

        assert_eq!(check(&apk), Err(BindingError::KeyMismatch { signer: 0 }));
        std::fs::remove_file(apk).ok();
    }

    #[test]
    fn unsigned_and_damaged_archives_are_refused_without_panicking() {
        let unsigned = write("unsigned", &sample_zip());
        assert_eq!(check(&unsigned), Err(BindingError::NoSigningBlock));
        std::fs::remove_file(unsigned).ok();

        let k = new_signer();
        let signed = sign_v2(&sample_zip(), &k, &k.spki, "x");
        // truncate at every length and corrupt every byte of the signing block region
        for n in (0..signed.len()).step_by(7) {
            let p = write("trunc", &signed[..n]);
            let _ = check(&p);
            std::fs::remove_file(p).ok();
        }
        for i in (0..signed.len()).step_by(11) {
            let mut c = signed.clone();
            c[i] ^= 0x5a;
            let p = write("flip", &c);
            let _ = check(&p);
            std::fs::remove_file(p).ok();
        }
        let p = write("empty", b"");
        assert_eq!(check(&p), Err(BindingError::NotAnArchive));
        std::fs::remove_file(p).ok();
    }
}
