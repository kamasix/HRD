//! The import pipeline.
//!
//! Order matters and is the point:
//!
//! 1. **stage** private copies, so everything below reads bytes nobody else can
//!    change;
//! 2. **inspect** each archive (upstream's zip-slip, symlink, device, setuid and
//!    size refusals);
//! 3. **verify** each archive's signature against a pinned certificate *and*
//!    that the certificate contains the key that signed (`binding`);
//! 4. **classify by content**, not by file name, which archive holds the engine
//!    for this architecture and which holds the manifest and assets;
//! 5. **check the set belongs together** (same signer, same package, same
//!    version code, split for this architecture);
//! 6. **extract** the engine and the assets from the staged copies;
//! 7. **record** provenance;
//! 8. **publish** by one `rename`, then check the result the way `cordial-run`
//!    will, and take it back if that check fails.
//!
//! Nothing is written to the store proper before step 8.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cordial_update::apk::{self, Limits, HOST_ABI, LIBRARY_IN_APK};
use hrd_core::fsutil;
use hrd_core::{Error, Result};
use rustix::fs::OFlags;
use sha2::{Digest, Sha256};

use crate::axml::{self, ManifestInfo};
use crate::binding;
use crate::stage::{self, hex, Staged};
use crate::store::*;

/// The package every Roblox Android build declares.
pub const ROBLOX_PACKAGE: &str = "com.roblox.client";
const MAX_INPUTS: usize = 16;
const MAX_ASSET_ENTRY: u64 = 512 * 1024 * 1024;
const MAX_ASSET_TOTAL: u64 = 2 * 1024 * 1024 * 1024;
const MAX_MANIFEST: u64 = 4 * 1024 * 1024;

/// How an archive's signature is judged. A trait so the pipeline can be tested
/// with real signatures made by throwaway keys, and so that there is no
/// "skip verification" switch in the production type.
pub trait Verifier {
    /// The SHA-256 (hex) of the certificate that vouches for the archive, or
    /// the reason it was not accepted.
    fn fingerprint(&self, path: &Path) -> std::result::Result<String, String>;
}

/// Upstream's verification plus the key binding upstream lacks.
pub struct PinnedVerifier {
    pub trusted: Vec<String>,
}

impl PinnedVerifier {
    /// The pins compiled into upstream's `cordial-update`, plus any the
    /// operator named explicitly. `CORDIAL_TRUSTED_CERTIFICATES` is ignored: an
    /// environment variable must not be able to widen what an importer trusts.
    pub fn with_extra(extra: &[String]) -> PinnedVerifier {
        // Upstream's `pinned()` consults that variable; hide it from the call.
        let saved = std::env::var_os("CORDIAL_TRUSTED_CERTIFICATES");
        if saved.is_some() {
            std::env::remove_var("CORDIAL_TRUSTED_CERTIFICATES");
        }
        let mut trusted = cordial_update::apk_signature::pinned();
        if let Some(v) = saved {
            std::env::set_var("CORDIAL_TRUSTED_CERTIFICATES", v);
        }
        for e in extra {
            let e = e.trim().to_ascii_lowercase();
            if !trusted.contains(&e) {
                trusted.push(e);
            }
        }
        PinnedVerifier { trusted }
    }
}

impl Verifier for PinnedVerifier {
    fn fingerprint(&self, path: &Path) -> std::result::Result<String, String> {
        let signer = cordial_update::apk_signature::verify_signed_by(path, &self.trusted).map_err(|r| r.to_string())?;
        binding::check(path).map_err(|e| e.to_string())?;
        Ok(signer.certificate_sha256)
    }
}

pub struct Input {
    pub file: File,
    /// As the operator named it; provenance only.
    pub given_name: String,
}

pub struct Request<'a> {
    pub inputs: Vec<Input>,
    pub label: Option<String>,
    /// Make this build current even if another is.
    pub make_current: bool,
    pub verifier: &'a dyn Verifier,
    pub now: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Report {
    pub version: String,
    pub engine_sha256: String,
    pub signer_sha256: String,
    pub archives: Vec<ArchiveRecord>,
    pub unused: Vec<FileRecord>,
    pub already_present: bool,
    pub made_current: bool,
    pub split: bool,
    pub assets_files: u64,
    pub assets_bytes: u64,
    pub consistency: Consistency,
    pub warnings: Vec<String>,
}

/// Removes the staging areas however the import ends.
struct Cleanup(Vec<PathBuf>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = make_writable(p);
            let _ = fs::remove_dir_all(p);
        }
    }
}

fn refuse(what: impl std::fmt::Display) -> Error {
    Error::invalid(what.to_string())
}

struct Archive {
    path: PathBuf,
    given: String,
    staged: Staged,
    fingerprint: String,
    holds_engine: bool,
    has_manifest: bool,
    has_assets: bool,
    manifest: Option<ManifestInfo>,
}

/// Which of `lib/*/libroblox.so` an archive holds, for a useful refusal.
fn other_abis(path: &Path) -> Vec<String> {
    let Ok(f) = File::open(path) else { return vec![] };
    let Ok(z) = zip::ZipArchive::new(std::io::BufReader::new(f)) else { return vec![] };
    let mut v: Vec<String> = z
        .file_names()
        .filter_map(|n| n.strip_prefix("lib/")?.strip_suffix("/libroblox.so").map(String::from))
        .collect();
    v.sort();
    v
}

fn read_manifest_entry(path: &Path) -> Option<ManifestInfo> {
    let f = File::open(path).ok()?;
    let mut z = zip::ZipArchive::new(std::io::BufReader::new(f)).ok()?;
    let e = z.by_name("AndroidManifest.xml").ok()?;
    let mut buf = Vec::new();
    e.take(MAX_MANIFEST).read_to_end(&mut buf).ok()?;
    axml::parse(&buf)
}

fn zip_shape(path: &Path) -> Result<(bool, bool)> {
    let f = File::open(path).map_err(|e| Error::io(format!("open {}", path.display()), e))?;
    let z = zip::ZipArchive::new(std::io::BufReader::new(f)).map_err(|e| refuse(format!("{}: {e}", path.display())))?;
    let mut manifest = false;
    let mut assets = false;
    for n in z.file_names() {
        if n == "AndroidManifest.xml" {
            manifest = true;
        } else if n.starts_with("assets/") && !n.ends_with('/') {
            assets = true;
        }
        if manifest && assets {
            break;
        }
    }
    Ok((manifest, assets))
}

/// Run the import. `progress` receives one short line per step.
pub fn run(store: &Store, req: Request<'_>, progress: &mut dyn FnMut(&str)) -> Result<Report> {
    if req.inputs.is_empty() {
        return Err(refuse("no input files"));
    }
    if req.inputs.len() > MAX_INPUTS {
        return Err(refuse(format!("{} input files; at most {MAX_INPUTS} are accepted", req.inputs.len())));
    }
    store.ensure()?;
    progress("waiting for the runtime store lock");
    let _lock = store.lock(Duration::from_secs(600))?;

    // ---- space ----------------------------------------------------------
    let declared: u64 = req.inputs.iter().filter_map(|i| i.file.metadata().ok()).map(|m| m.len()).sum();
    let need = declared.saturating_mul(3).saturating_add(512 * 1024 * 1024);
    let free = stage::free_bytes(store.root())?;
    if free < need {
        return Err(Error::unavailable(format!(
            "not enough space for the runtime store: about {} MiB are needed while importing {} MiB of archives, {} MiB are free",
            need >> 20,
            declared >> 20,
            free >> 20
        )));
    }

    // ---- stage ----------------------------------------------------------
    let tag = format!("import-{}-{}", std::process::id(), req.now);
    let scratch = store.staging_dir().join(format!("{tag}.in"));
    let root = store.staging_dir().join(&tag);
    let mut cleanup = Cleanup(vec![scratch.clone(), root.clone()]);
    fsutil::ensure_private_dir(&scratch, 0o700)?;
    fsutil::ensure_private_dir(&root, 0o750)?;

    let mut archives: Vec<Archive> = Vec::new();
    for (i, mut input) in req.inputs.into_iter().enumerate() {
        progress(&format!("copying {} (private copy, hashing)", input.given_name));
        let dest = scratch.join(format!("{i}.apk"));
        let staged = stage::copy_hashing(&mut input.file, &dest, stage::MAX_INPUT)?;
        drop(input.file);
        archives.push(Archive {
            path: dest,
            given: input.given_name,
            staged,
            fingerprint: String::new(),
            holds_engine: false,
            has_manifest: false,
            has_assets: false,
            manifest: None,
        });
    }
    for (i, a) in archives.iter().enumerate() {
        if archives.iter().skip(i + 1).any(|b| b.staged.sha256 == a.staged.sha256) {
            return Err(refuse(format!("{} was given twice", a.given)));
        }
    }

    // ---- inspect, verify, classify ---------------------------------------
    let mut warnings = Vec::new();
    for a in archives.iter_mut() {
        progress(&format!("checking {}", a.given));
        apk::inspect(&a.path, Limits::default()).map_err(|r| refuse(format!("{}: {r}", a.given)))?;
        a.fingerprint = req.verifier.fingerprint(&a.path).map_err(|why| refuse(format!("{}: {why}", a.given)))?;
        a.holds_engine = apk::holds(&a.path, LIBRARY_IN_APK).map_err(|r| refuse(format!("{}: {r}", a.given)))?;
        (a.has_manifest, a.has_assets) = zip_shape(&a.path)?;
        a.manifest = if a.has_manifest { read_manifest_entry(&a.path) } else { None };
    }

    let signer = archives[0].fingerprint.clone();
    if let Some(other) = archives.iter().find(|a| a.fingerprint != signer) {
        return Err(refuse(format!(
            "these archives were not signed by the same certificate: {} is {} but {} is {}. A set is one build signed once",
            archives[0].given, signer, other.given, other.fingerprint
        )));
    }

    let engine_holders: Vec<usize> = (0..archives.len()).filter(|&i| archives[i].holds_engine).collect();
    let engine_idx = match engine_holders.as_slice() {
        [i] => *i,
        [] => {
            let mut why = format!("none of the archives holds {LIBRARY_IN_APK}, the engine for {HOST_ABI}.");
            let abis: Vec<String> = archives.iter().flat_map(|a| other_abis(&a.path)).collect();
            if !abis.is_empty() {
                why.push_str(&format!(" They do hold the engine for: {}. This build of the manager targets {HOST_ABI}; import the matching split.", abis.join(", ")));
            } else {
                why.push_str(" On a split build the engine is in split_config.x86_64.apk; include it.");
            }
            return Err(refuse(why));
        }
        many => {
            let names: Vec<&str> = many.iter().map(|&i| archives[i].given.as_str()).collect();
            return Err(refuse(format!("more than one archive holds the engine ({}); import one build at a time", names.join(", "))));
        }
    };
    let asset_holders: Vec<usize> = (0..archives.len()).filter(|&i| archives[i].has_manifest && archives[i].has_assets).collect();
    let (base_idx, monolithic) = if asset_holders.contains(&engine_idx) && asset_holders.len() == 1 {
        (engine_idx, true)
    } else if asset_holders.len() == 1 {
        (asset_holders[0], false)
    } else if asset_holders.is_empty() {
        return Err(refuse("none of the archives holds both AndroidManifest.xml and assets/: the base APK is missing"));
    } else {
        let names: Vec<&str> = asset_holders.iter().map(|&i| archives[i].given.as_str()).collect();
        return Err(refuse(format!("more than one archive looks like a base APK ({}); import one build at a time", names.join(", "))));
    };

    // ---- does the set belong together -----------------------------------
    let mut consistency = Consistency { status: "checked".into(), ..Default::default() };
    match archives[base_idx].manifest.clone() {
        None => {
            consistency.status = "unchecked".into();
            consistency.notes.push("the base APK's AndroidManifest.xml could not be read (format not understood); package and version code were not compared".into());
        }
        Some(base) => {
            consistency.package = base.package.clone();
            consistency.version_code = base.version_code;
            if let Some(p) = &base.package {
                if p != ROBLOX_PACKAGE {
                    return Err(refuse(format!("the base APK declares package {p:?}, not {ROBLOX_PACKAGE:?}")));
                }
            } else {
                consistency.status = "unchecked".into();
                consistency.notes.push("the base APK's manifest has no package attribute".into());
            }
            if !monolithic {
                match archives[engine_idx].manifest.clone() {
                    None => {
                        consistency.status = "unchecked".into();
                        consistency.notes.push("the engine split's AndroidManifest.xml could not be read; version code was not compared".into());
                    }
                    Some(split) => {
                        if split.package.is_some() && split.package != base.package {
                            return Err(refuse(format!(
                                "the engine split declares package {:?} but the base declares {:?}: these are different apps",
                                split.package, base.package
                            )));
                        }
                        match (base.version_code, split.version_code) {
                            (Some(a), Some(b)) if a != b => {
                                return Err(refuse(format!(
                                    "version codes differ: the base APK is {a} and the engine split is {b}. They are from different builds"
                                )));
                            }
                            (Some(_), Some(_)) => {}
                            _ => {
                                consistency.status = "unchecked".into();
                                consistency.notes.push("a version code was missing; base and split were not compared".into());
                            }
                        }
                        if let Some(s) = &split.split {
                            if !s.contains("x86_64") && HOST_ABI == "x86_64" {
                                return Err(refuse(format!("the engine split is named {s:?}, which is not for x86_64")));
                            }
                        }
                    }
                }
            }
        }
    }
    for (i, a) in archives.iter().enumerate() {
        if i != base_idx && i != engine_idx {
            warnings.push(format!("{} is signed correctly but holds neither the engine nor the assets; it is not stored", a.given));
        }
    }

    // ---- extract ---------------------------------------------------------
    progress("extracting the engine");
    let engine_dir = root.join("engine");
    fsutil::ensure_private_dir(&engine_dir, 0o750)?;
    let engine_path = apk::extract(&archives[engine_idx].path, LIBRARY_IN_APK, &engine_dir).map_err(|r| refuse(format!("extracting the engine: {r}")))?;
    let engine = stage::hash_file(&engine_path)?;
    let version = cordial_update::engine::version_of(&engine_path)
        .ok_or_else(|| refuse("could not read the engine's version out of libroblox.so; refusing to file a build under a guessed name"))?;
    if !valid_version(&version) {
        return Err(refuse(format!("the engine reports version {version:?}, which is not four numbers")));
    }
    // Write upstream's cache of the answer now, while the directory is ours, so
    // that every client finds it and none rescans 118 MB.
    match cordial_update::engine::installed_version(&engine_dir) {
        Some(v) if v == version => {}
        other => return Err(Error::Internal(format!("upstream's engine-version cache disagrees with the scan: {other:?} vs {version:?}"))),
    }

    progress("extracting assets");
    let assets_dir = root.join("assets");
    let (assets_files, assets_bytes, tree_sha256) = extract_assets(&archives[base_idx].path, &assets_dir)?;

    // ---- place archives ---------------------------------------------------
    let apk_dir = root.join("apk");
    fsutil::ensure_private_dir(&apk_dir, 0o750)?;
    let mut records = Vec::new();
    let split_name = cordial_update::install::SPLIT_APK;
    let base_final = apk_dir.join("base.apk");
    fs::rename(&archives[base_idx].path, &base_final).map_err(|e| Error::io("place base.apk", e))?;
    records.push(ArchiveRecord {
        role: if monolithic { "monolithic" } else { "base" }.into(),
        stored_as: "apk/base.apk".into(),
        given_as: archives[base_idx].given.clone(),
        size: archives[base_idx].staged.size,
        sha256: archives[base_idx].staged.sha256.clone(),
    });
    if !monolithic {
        fs::rename(&archives[engine_idx].path, apk_dir.join(split_name)).map_err(|e| Error::io("place the engine split", e))?;
        records.push(ArchiveRecord {
            role: "engine".into(),
            stored_as: format!("apk/{split_name}"),
            given_as: archives[engine_idx].given.clone(),
            size: archives[engine_idx].staged.size,
            sha256: archives[engine_idx].staged.sha256.clone(),
        });
    }
    let unused: Vec<FileRecord> = archives
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != base_idx && *i != engine_idx)
        .map(|(_, a)| FileRecord { path: a.given.clone(), size: a.staged.size, sha256: a.staged.sha256.clone() })
        .collect();

    // ---- stamp what cordial-run will compare ---------------------------------
    // The stamp names the APK by the path `cordial-run` will be given, which is
    // the final one, so it is built from the staged file's size and mtime and
    // the path it is about to have.
    let canonical_store = fs::canonicalize(store.root()).map_err(|e| Error::io("resolve the store path", e))?;
    let final_dir = canonical_store.join("builds").join(&version);
    let final_apk = final_dir.join("apk/base.apk");
    let stamp = {
        let md = fs::metadata(&base_final).map_err(|e| Error::io("stat base.apk", e))?;
        let mtime = md.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
        format!("{} {} {}", md.len(), mtime, final_apk.display())
    };
    fs::write(assets_dir.join(cordial_update::cache::STAMP), &stamp).map_err(|e| Error::io("write the assets stamp", e))?;

    // ---- provenance --------------------------------------------------------
    let manifest = BuildManifest {
        schema: SCHEMA,
        version: version.clone(),
        abi: HOST_ABI.into(),
        imported_at: req.now,
        tool: format!("hrd-import {}", env!("CARGO_PKG_VERSION")),
        upstream_commit: UPSTREAM_COMMIT.into(),
        label: req.label.clone(),
        signer_sha256: signer.clone(),
        engine: FileRecord { path: "engine/libroblox.so".into(), size: engine.size, sha256: engine.sha256.clone() },
        archives: records.clone(),
        unused: unused.clone(),
        assets: AssetsRecord { files: assets_files, bytes: assets_bytes, tree_sha256, stamp },
        consistency: consistency.clone(),
    };
    fsutil::write_json_atomic(&root.join("manifest.json"), &manifest, 0o640)?;

    // ---- seal, publish, re-check --------------------------------------------
    // Scratch copies go first; what is left is the build.
    let _ = fs::remove_dir_all(&scratch);
    progress("sealing and publishing");
    for entry in fs::read_dir(&root).map_err(|e| Error::io("read the staged build", e))?.flatten() {
        seal(&entry.path())?;
    }
    rustix::fs::syncfs(File::open(&root).map_err(|e| Error::io("open the staged build", e))?).map_err(|e| Error::io("sync", std::io::Error::from_raw_os_error(e.raw_os_error())))?;

    let target = store.build_dir(&version);
    let mut already = false;
    if target.exists() {
        let existing = store.manifest(&version)?;
        if existing.engine.sha256 == engine.sha256 && existing.signer_sha256 == signer {
            already = true;
        } else {
            return Err(Error::conflict(format!(
                "runtime {version} is already installed with a different engine ({} vs {}). Same version string, different bytes: remove the installed one first if you mean to replace it",
                &existing.engine.sha256[..12],
                &engine.sha256[..12]
            )));
        }
    }
    if !already {
        fs::rename(&root, &target).map_err(|e| Error::io(format!("publish {}", target.display()), e))?;
        // The top of the build stays writable until now because a directory
        // cannot be renamed into another parent without write permission on it.
        fs::set_permissions(&target, std::os::unix::fs::PermissionsExt::from_mode(DIR_MODE)).map_err(|e| Error::io("seal the build", e))?;
        File::open(store.builds_dir()).and_then(|d| d.sync_all()).map_err(|e| Error::io("sync builds/", e))?;

        let asset_ok = cordial_update::cache::is_current(&target.join("assets"), &target.join("apk/base.apk"));
        let via_canonical = cordial_update::cache::is_current(&target.join("assets"), &final_apk);
        let version_ok = cordial_update::engine::installed_version(&target.join("engine")).as_deref() == Some(version.as_str());
        if !via_canonical || !version_ok {
            // Take it back: nothing has started on it.
            let back = store.staging_dir().join(format!("unpublished-{tag}"));
            let _ = make_writable(&target);
            let _ = fs::rename(&target, &back);
            cleanup.0.push(back);
            return Err(Error::Internal(format!(
                "the published build failed the check cordial-run performs (assets stamp current via the canonical path: {via_canonical}, via the store path: {asset_ok}, version cache: {version_ok}); it was taken back. If the store is reached through a symlink or bind mount, use the canonical path"
            )));
        }
    }
    cleanup.0.retain(|p| p != &root || already);

    let mut made_current = false;
    if req.make_current || store.current().is_none() {
        store.use_version(&version)?;
        made_current = true;
    }

    Ok(Report {
        version,
        engine_sha256: engine.sha256,
        signer_sha256: signer,
        archives: records,
        unused,
        already_present: already,
        made_current,
        split: !monolithic,
        assets_files,
        assets_bytes,
        consistency,
        warnings,
    })
}

/// Write every `assets/*` entry of `apk` under `dest` (without the `assets/`
/// prefix), the way `cordial-run` would, and return file count, bytes and a
/// tree hash.
fn extract_assets(apk: &Path, dest: &Path) -> Result<(u64, u64, String)> {
    fsutil::ensure_private_dir(dest, 0o750)?;
    let f = File::open(apk).map_err(|e| Error::io(format!("open {}", apk.display()), e))?;
    let mut z = zip::ZipArchive::new(std::io::BufReader::new(f)).map_err(|e| refuse(format!("{}: {e}", apk.display())))?;
    let mut listing: Vec<(String, u64, String)> = Vec::new();
    let (mut files, mut total) = (0u64, 0u64);
    for i in 0..z.len() {
        let entry = z.by_index(i).map_err(|e| refuse(format!("entry {i}: {e}")))?;
        let Some(name) = entry.enclosed_name() else { continue };
        let Ok(rel) = name.strip_prefix("assets") else { continue };
        if entry.is_dir() || rel.as_os_str().is_empty() {
            continue;
        }
        if entry.size() > MAX_ASSET_ENTRY {
            return Err(refuse(format!("asset {} is {} bytes, more than the {MAX_ASSET_ENTRY} byte limit", rel.display(), entry.size())));
        }
        let out = dest.join(rel);
        if let Some(parent) = out.parent() {
            create_dirs_under(dest, parent)?;
        }
        let mut hasher = Sha256::new();
        let mut written = 0u64;
        {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o640)
                .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
                .open(&out)
                .map_err(|e| Error::io(format!("create {} (a duplicate entry name would fail here)", out.display()), e))?;
            let mut reader = entry.take(MAX_ASSET_ENTRY + 1);
            let mut buf = vec![0u8; 256 * 1024];
            loop {
                let n = reader.read(&mut buf).map_err(|e| Error::io(format!("inflate {}", rel.display()), e))?;
                if n == 0 {
                    break;
                }
                written += n as u64;
                if written > MAX_ASSET_ENTRY {
                    return Err(refuse(format!("asset {} inflates past {MAX_ASSET_ENTRY} bytes", rel.display())));
                }
                hasher.update(&buf[..n]);
                file.write_all(&buf[..n]).map_err(|e| Error::io(format!("write {}", out.display()), e))?;
            }
        }
        total += written;
        if total > MAX_ASSET_TOTAL {
            return Err(refuse(format!("assets inflate past {MAX_ASSET_TOTAL} bytes in total")));
        }
        files += 1;
        listing.push((rel.to_string_lossy().into_owned(), written, hex(&hasher.finalize())));
    }
    listing.sort();
    let mut tree = Sha256::new();
    for (p, s, h) in &listing {
        tree.update(p.as_bytes());
        tree.update([0]);
        tree.update(s.to_string().as_bytes());
        tree.update([0]);
        tree.update(h.as_bytes());
        tree.update(b"\n");
    }
    Ok((files, total, hex(&tree.finalize())))
}

/// `create_dir_all` that refuses to leave `root`, one component at a time, and
/// does not follow a symlink. The names are already `enclosed_name`d; this is
/// the second, independent reason a hostile name cannot write elsewhere.
fn create_dirs_under(root: &Path, dir: &Path) -> Result<()> {
    let rel = dir.strip_prefix(root).map_err(|_| Error::Internal("asset directory outside the staging root".into()))?;
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        match comp {
            std::path::Component::Normal(c) => cur.push(c),
            _ => return Err(refuse("asset path has a component that is not a plain name")),
        }
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(refuse(format!("{} exists and is not a directory", cur.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&cur).map_err(|e| Error::io(format!("create {}", cur.display()), e))?;
                fs::set_permissions(&cur, std::os::unix::fs::PermissionsExt::from_mode(0o750)).map_err(|e| Error::io("chmod", e))?;
            }
            Err(e) => return Err(Error::io(format!("stat {}", cur.display()), e)),
        }
    }
    Ok(())
}

/// Re-check an installed build against its manifest.
pub fn verify_build(store: &Store, version: &str) -> Result<Vec<String>> {
    let m = store.manifest(version)?;
    let dir = store.build_dir(version);
    let mut problems = Vec::new();
    let eng = stage::hash_file(&dir.join(&m.engine.path)).ok();
    if eng.as_ref().map(|e| e.sha256.as_str()) != Some(m.engine.sha256.as_str()) {
        problems.push("engine/libroblox.so does not match its recorded hash".to_string());
    }
    for a in &m.archives {
        let h = stage::hash_file(&dir.join(&a.stored_as)).ok();
        if h.as_ref().map(|x| x.sha256.as_str()) != Some(a.sha256.as_str()) {
            problems.push(format!("{} does not match its recorded hash", a.stored_as));
        }
    }
    let assets = dir.join("assets");
    let base = dir.join("apk/base.apk");
    let canonical = fs::canonicalize(&base).unwrap_or(base);
    if !cordial_update::cache::is_current(&assets, &canonical) {
        problems.push("the assets stamp does not match the APK as cordial-run will see it; it would try to re-extract into a read-only directory".to_string());
    }
    if cordial_update::engine::installed_version(&dir.join("engine")).as_deref() != Some(version) {
        problems.push("the engine-version cache is missing or wrong; every start would rescan the engine".to_string());
    }
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(&dir).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
    if mode & 0o222 != 0 {
        problems.push(format!("the build directory is writable (mode {mode:o}); it should be sealed"));
    }
    Ok(problems)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::testapk::*;

    const ENGINE_BYTES: &[u8] = b"\0\0 fake engine 2.738.0.1397 \0\0";

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hrd-import-{tag}-{}", std::process::id()));
        let _ = make_writable(&d);
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn input(dir: &Path, name: &str, bytes: &[u8]) -> Input {
        let p = dir.join(name);
        fs::write(&p, bytes).unwrap();
        Input { file: File::open(p).unwrap(), given_name: name.into() }
    }

    fn base_zip(version_code: u32) -> Vec<u8> {
        zip_of(&[
            ("AndroidManifest.xml", &axml::build(false, ROBLOX_PACKAGE, version_code, None)),
            ("assets/content/fonts/a.ttf", b"font-a"),
            ("assets/ssl/cacert.pem", b"-----BEGIN CERTIFICATE-----"),
            ("assets/android/x.json", b"{}"),
        ])
    }

    fn split_zip(version_code: u32, engine: &[u8]) -> Vec<u8> {
        zip_of(&[
            ("AndroidManifest.xml", &axml::build(true, ROBLOX_PACKAGE, version_code, Some("config.x86_64"))),
            ("lib/x86_64/libroblox.so", engine),
        ])
    }

    fn mono_zip() -> Vec<u8> {
        zip_of(&[
            ("AndroidManifest.xml", &axml::build(false, ROBLOX_PACKAGE, 7, None)),
            ("assets/content/fonts/a.ttf", b"font-a"),
            ("lib/x86_64/libroblox.so", ENGINE_BYTES),
            ("lib/arm64-v8a/libroblox.so", b"arm engine"),
        ])
    }

    fn run_import(store: &Store, inputs: Vec<Input>, v: &dyn Verifier, now: u64) -> Result<Report> {
        run(store, Request { inputs, label: Some("test".into()), make_current: false, verifier: v, now }, &mut |_| {})
    }

    fn trusting(k: &Signer) -> PinnedVerifier {
        PinnedVerifier { trusted: vec![fingerprint(&k.spki, "t")] }
    }

    #[test]
    fn a_split_set_imports_publishes_and_passes_the_check_cordial_run_makes() {
        let d = scratch("split");
        let store = Store::new(d.join("runtime"));
        let k = new_signer();
        let inputs = vec![
            input(&d, "base.apk", &sign_v2(&base_zip(77), &k, &k.spki, "t")),
            input(&d, "split_config.x86_64.apk", &sign_v2(&split_zip(77, ENGINE_BYTES), &k, &k.spki, "t")),
            input(&d, "split_config.en.apk", &sign_v2(&zip_of(&[("res/x", b"1")]), &k, &k.spki, "t")),
        ];
        let r = run_import(&store, inputs, &trusting(&k), 1000).unwrap();
        assert_eq!(r.version, "2.738.0.1397");
        assert!(r.split && r.made_current && !r.already_present);
        assert_eq!(r.consistency.status, "checked");
        assert_eq!(r.consistency.version_code, Some(77));
        assert_eq!(r.unused.len(), 1);
        assert_eq!(r.assets_files, 3);

        let b = store.build_dir("2.738.0.1397");
        assert!(b.join("engine/libroblox.so").is_file());
        assert!(b.join("apk/base.apk").is_file() && b.join("apk/split_config.x86_64.apk").is_file());
        assert_eq!(fs::read(b.join("assets/content/fonts/a.ttf")).unwrap(), b"font-a");
        assert_eq!(store.current().as_deref(), Some("2.738.0.1397"));
        assert_eq!(verify_build(&store, "2.738.0.1397").unwrap(), Vec::<String>::new());
        // what cordial-run asks, asked directly
        let canon = fs::canonicalize(b.join("apk/base.apk")).unwrap();
        assert!(cordial_update::cache::is_current(&b.join("assets"), &canon));
        // nothing left behind in staging
        assert_eq!(fs::read_dir(store.staging_dir()).unwrap().count(), 0);
        let _ = make_writable(&d);
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn a_monolithic_apk_imports_and_the_other_architecture_is_not_what_was_extracted() {
        let d = scratch("mono");
        let store = Store::new(d.join("runtime"));
        let k = new_signer();
        let r = run_import(&store, vec![input(&d, "roblox.apk", &sign_v2(&mono_zip(), &k, &k.spki, "t"))], &trusting(&k), 1).unwrap();
        assert!(!r.split);
        assert_eq!(r.archives[0].role, "monolithic");
        let engine = fs::read(store.build_dir(&r.version).join("engine/libroblox.so")).unwrap();
        assert_eq!(engine, ENGINE_BYTES, "the x86_64 engine, not the arm64 one");
        let _ = make_writable(&d);
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn importing_the_same_build_twice_is_idempotent() {
        let d = scratch("twice");
        let store = Store::new(d.join("runtime"));
        let k = new_signer();
        let apk = sign_v2(&mono_zip(), &k, &k.spki, "t");
        run_import(&store, vec![input(&d, "a.apk", &apk)], &trusting(&k), 1).unwrap();
        let again = run_import(&store, vec![input(&d, "b.apk", &apk)], &trusting(&k), 2).unwrap();
        assert!(again.already_present);
        assert_eq!(fs::read_dir(store.staging_dir()).unwrap().count(), 0);
        assert_eq!(store.list().len(), 1);
        let _ = make_writable(&d);
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn same_version_different_bytes_is_a_conflict_not_a_replacement() {
        let d = scratch("conflict");
        let store = Store::new(d.join("runtime"));
        let k = new_signer();
        run_import(&store, vec![input(&d, "a.apk", &sign_v2(&mono_zip(), &k, &k.spki, "t"))], &trusting(&k), 1).unwrap();
        let other = zip_of(&[
            ("AndroidManifest.xml", &axml::build(false, ROBLOX_PACKAGE, 7, None)),
            ("assets/content/x", b"x"),
            ("lib/x86_64/libroblox.so", b"\0 tampered 2.738.0.1397 \0"),
        ]);
        let e = run_import(&store, vec![input(&d, "b.apk", &sign_v2(&other, &k, &k.spki, "t"))], &trusting(&k), 2).unwrap_err();
        assert!(matches!(e, Error::Conflict(_)), "{e}");
        let _ = make_writable(&d);
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn a_split_from_another_build_is_refused() {
        let d = scratch("mismatch");
        let store = Store::new(d.join("runtime"));
        let k = new_signer();
        let inputs = vec![
            input(&d, "base.apk", &sign_v2(&base_zip(77), &k, &k.spki, "t")),
            input(&d, "split.apk", &sign_v2(&split_zip(78, ENGINE_BYTES), &k, &k.spki, "t")),
        ];
        let e = run_import(&store, inputs, &trusting(&k), 1).unwrap_err().to_string();
        assert!(e.contains("version codes differ"), "{e}");
        assert!(store.list().is_empty());
        let _ = make_writable(&d);
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn archives_signed_by_different_certificates_are_not_a_set() {
        let d = scratch("signers");
        let store = Store::new(d.join("runtime"));
        let (k1, k2) = (new_signer(), new_signer());
        let v = PinnedVerifier { trusted: vec![fingerprint(&k1.spki, "t"), fingerprint(&k2.spki, "t")] };
        let inputs = vec![
            input(&d, "base.apk", &sign_v2(&base_zip(77), &k1, &k1.spki, "t")),
            input(&d, "split.apk", &sign_v2(&split_zip(77, ENGINE_BYTES), &k2, &k2.spki, "t")),
        ];
        let e = run_import(&store, inputs, &v, 1).unwrap_err().to_string();
        assert!(e.contains("not signed by the same certificate"), "{e}");
        let _ = make_writable(&d);
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn an_untrusted_signer_is_refused_and_named() {
        let d = scratch("untrusted");
        let store = Store::new(d.join("runtime"));
        let (k, other) = (new_signer(), new_signer());
        let e = run_import(&store, vec![input(&d, "a.apk", &sign_v2(&mono_zip(), &k, &k.spki, "t"))], &trusting(&other), 1).unwrap_err().to_string();
        assert!(e.to_ascii_lowercase().contains("certificate") || e.contains(&fingerprint(&k.spki, "t")), "{e}");
        let _ = make_writable(&d);
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn the_forged_key_pairing_is_refused_by_the_pipeline() {
        let d = scratch("forged");
        let store = Store::new(d.join("runtime"));
        let (roblox_like, forger) = (new_signer(), new_signer());
        let v = PinnedVerifier { trusted: vec![fingerprint(&roblox_like.spki, "t")] };
        let apk = sign_v2(&mono_zip(), &forger, &roblox_like.spki, "t");
        let e = run_import(&store, vec![input(&d, "a.apk", &apk)], &v, 1).unwrap_err().to_string();
        assert!(e.contains("does not contain the public key"), "{e}");
        assert!(store.list().is_empty());
        let _ = make_writable(&d);
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn a_build_without_this_architectures_engine_says_which_it_does_hold() {
        let d = scratch("abi");
        let store = Store::new(d.join("runtime"));
        let k = new_signer();
        let arm = zip_of(&[("AndroidManifest.xml", &axml::build(false, ROBLOX_PACKAGE, 1, None)), ("assets/a", b"a"), ("lib/arm64-v8a/libroblox.so", b"x")]);
        let e = run_import(&store, vec![input(&d, "a.apk", &sign_v2(&arm, &k, &k.spki, "t"))], &trusting(&k), 1).unwrap_err().to_string();
        assert!(e.contains("arm64-v8a") && e.contains("x86_64"), "{e}");
        let _ = make_writable(&d);
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn a_wrong_package_is_refused_even_if_correctly_signed() {
        let d = scratch("pkg");
        let store = Store::new(d.join("runtime"));
        let k = new_signer();
        let z = zip_of(&[("AndroidManifest.xml", &axml::build(false, "com.example.notroblox", 1, None)), ("assets/a", b"a"), ("lib/x86_64/libroblox.so", ENGINE_BYTES)]);
        let e = run_import(&store, vec![input(&d, "a.apk", &sign_v2(&z, &k, &k.spki, "t"))], &trusting(&k), 1).unwrap_err().to_string();
        assert!(e.contains("com.example.notroblox"), "{e}");
        let _ = make_writable(&d);
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn traversal_and_symlink_entries_are_refused_before_anything_is_extracted() {
        let d = scratch("slip");
        let store = Store::new(d.join("runtime"));
        let k = new_signer();
        let z = zip_of(&[
            ("AndroidManifest.xml", &axml::build(false, ROBLOX_PACKAGE, 1, None)),
            ("assets/../../escape.txt", b"boom"),
            ("lib/x86_64/libroblox.so", ENGINE_BYTES),
        ]);
        let e = run_import(&store, vec![input(&d, "a.apk", &sign_v2(&z, &k, &k.spki, "t"))], &trusting(&k), 1).unwrap_err().to_string();
        assert!(e.contains(".."), "{e}");
        assert!(!d.join("escape.txt").exists() && !d.join("runtime/escape.txt").exists());
        let _ = make_writable(&d);
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn non_regular_inputs_and_duplicates_are_refused() {
        let d = scratch("inputs");
        let store = Store::new(d.join("runtime"));
        let k = new_signer();
        let dev = Input { file: File::open("/dev/zero").unwrap(), given_name: "zero".into() };
        assert!(run_import(&store, vec![dev], &trusting(&k), 1).is_err());
        let apk = sign_v2(&mono_zip(), &k, &k.spki, "t");
        let e = run_import(&store, vec![input(&d, "a.apk", &apk), input(&d, "b.apk", &apk)], &trusting(&k), 2).unwrap_err().to_string();
        assert!(e.contains("given twice"), "{e}");
        assert!(run_import(&store, vec![], &trusting(&k), 3).is_err());
        let _ = make_writable(&d);
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn verify_notices_a_tampered_engine() {
        let d = scratch("tamper");
        let store = Store::new(d.join("runtime"));
        let k = new_signer();
        let r = run_import(&store, vec![input(&d, "a.apk", &sign_v2(&mono_zip(), &k, &k.spki, "t"))], &trusting(&k), 1).unwrap();
        let eng = store.build_dir(&r.version).join("engine/libroblox.so");
        make_writable(&store.build_dir(&r.version)).unwrap();
        fs::write(&eng, b"different").unwrap();
        let problems = verify_build(&store, &r.version).unwrap();
        assert!(problems.iter().any(|p| p.contains("recorded hash")), "{problems:?}");
        let _ = make_writable(&d);
        fs::remove_dir_all(d).ok();
    }
}
