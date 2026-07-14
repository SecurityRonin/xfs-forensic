//! P4 directory tests — short-form + block dirs, and the read-by-path capstone.
//!
//! Three tiers, all oracle-gated where an image is needed:
//! - **Listing Tier-1 (independent oracle):** `read_dir` on the v5 root / `sf/` /
//!   `block/` returns exactly the `{name -> inode}` set that `mount -o ro` +
//!   `ls -i` reported (a from-scratch parse cross-checked against the kernel's
//!   own directory walk — a genuinely independent reader, since TSK has no XFS
//!   on this host). The name->inode ground truth is recorded verbatim in
//!   `tests/data/README.md` (P4 directory oracle section).
//! - **Capstone Tier-1:** `read_by_path("/sf/file1.txt")` reconstructs the file
//!   THROUGH directory navigation (root short-form -> descend into `sf` ->
//!   name-match `file1.txt` -> read_file) and the sha256 EQUALS the committed
//!   mount-ro content oracle. This proves P1+P2+P3+P4 compose into the real
//!   forensic read-file-by-path entrypoint.
//! - **v4 no-ftype branch:** the dedicated `v4dir.img` (mkfs `-n ftype=0`, so the
//!   short-form entries carry NO ftype byte — `sfdir2`) lists correctly, proving
//!   the per-feature-bit ftype branch (NOT a v4-vs-v5 branch).
//! - **Unsupported (fail loud):** a leaf/node directory (`leaf/`, inode 655488 —
//!   `format == Extents` but `size != blocksize`) returns a loud `Unsupported`
//!   error that NAMES the format, never a silent empty listing.
//! - **Robustness:** truncated / malformed directory data does not panic.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use sha2::{Digest, Sha256};
use xfs::{read_by_path, read_dir, DirEntry, Superblock, XfsError};

/// Resolve an image path from an env var, falling back to `tests/data/<name>`.
fn image_path(env: &str, default_name: &str) -> Option<PathBuf> {
    let p = std::env::var(env).map_or_else(
        |_| {
            let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            d.pop(); // core/ -> repo root
            d.push("tests/data");
            d.push(default_name);
            d
        },
        PathBuf::from,
    );
    p.exists().then_some(p)
}

fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut h = Sha256::new();
    h.update(data);
    let mut s = String::with_capacity(64);
    for b in h.finalize() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Collect `read_dir` output into a `{name -> inode}` map for set comparison
/// (dropping any implicit `.`/`..` a format may surface — they are not in the
/// `ls -i` non-`-a` oracle).
fn name_inode_map(entries: &[DirEntry]) -> BTreeMap<String, u64> {
    entries
        .iter()
        .filter(|e| e.name != b"." && e.name != b"..")
        .map(|e| (String::from_utf8_lossy(&e.name).into_owned(), e.inode))
        .collect()
}

// -------------------------------------------------------------------------
// Short-form listing (v5 root + sf/) vs mount-ro `ls -i`
// -------------------------------------------------------------------------

#[test]
fn read_dir_v5_root_shortform_matches_ls_i() {
    let Some(path) = image_path("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).unwrap();
    let root = sb.read_inode(&img, sb.rootino).unwrap();
    let entries = read_dir(&img, &sb, &root).expect("root short-form dir lists");

    let got = name_inode_map(&entries);
    // mount -o ro; ls -i mnt  (tests/data/README.md P4 oracle)
    let want: BTreeMap<String, u64> = [
        ("sf".to_string(), 131u64),
        ("block".to_string(), 262272),
        ("leaf".to_string(), 655488),
        ("big.bin".to_string(), 135),
    ]
    .into_iter()
    .collect();
    assert_eq!(got, want, "root {{name->inode}} must equal `ls -i mnt`");
}

#[test]
fn read_dir_v5_sf_shortform_matches_ls_i() {
    let Some(path) = image_path("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).unwrap();
    let sf = sb.read_inode(&img, 131).unwrap();
    let entries = read_dir(&img, &sb, &sf).expect("sf/ short-form dir lists");

    let got = name_inode_map(&entries);
    let want: BTreeMap<String, u64> = [
        ("file1.txt".to_string(), 132u64),
        ("file2.txt".to_string(), 133),
        ("file3.txt".to_string(), 134),
    ]
    .into_iter()
    .collect();
    assert_eq!(got, want, "sf/ {{name->inode}} must equal `ls -i mnt/sf`");

    // v5 short-form entries carry an ftype byte: file* are regular files (1).
    for e in &entries {
        assert_eq!(e.ftype, Some(1), "v5 sf entries carry ftype = 1 (regular)");
    }
}

// -------------------------------------------------------------------------
// Block-directory listing (v5 block/) vs mount-ro `ls -i`
// -------------------------------------------------------------------------

#[test]
fn read_dir_v5_block_dir_matches_ls_i() {
    let Some(path) = image_path("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).unwrap();
    let block = sb.read_inode(&img, 262272).unwrap();
    let entries = read_dir(&img, &sb, &block).expect("block/ block dir lists");

    let got = name_inode_map(&entries);
    // ls -i mnt/block: e01..e40 -> 262273..262312.
    let want: BTreeMap<String, u64> = (1..=40u64)
        .map(|i| (format!("e{i:02}"), 262272 + i))
        .collect();
    assert_eq!(got.len(), 40, "block dir has 40 named entries (e01..e40)");
    assert_eq!(
        got, want,
        "block/ {{name->inode}} must equal `ls -i mnt/block`"
    );
}

// -------------------------------------------------------------------------
// THE capstone: read_by_path -> sha256 == mount-ro content oracle
// -------------------------------------------------------------------------

#[test]
fn read_by_path_sf_file1_sha256_matches_mount_oracle() {
    let Some(path) = image_path("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).unwrap();

    let content = read_by_path(&img, &sb, "/sf/file1.txt").expect("read /sf/file1.txt by path");
    assert_eq!(&content, b"content-1\n", "literal content of /sf/file1.txt");
    assert_eq!(
        sha256_hex(&content),
        "1894d80da16dd47db42e2a47e33e709254908a30d4a5985df4bf6e1ba18ce350",
        "read_by_path content sha256 MUST equal the mount-ro oracle (capstone)"
    );
}

#[test]
fn read_by_path_reaches_all_three_sf_files() {
    let Some(path) = image_path("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).unwrap();

    // Each sf/ file reached through directory navigation matches its oracle hash.
    for (name, want) in [
        (
            "/sf/file2.txt",
            "e581112dc8525e865b0896be01d082082c32a2633701321438e1efdd4137f05b",
        ),
        (
            "/sf/file3.txt",
            "9302e07efd6bac7fe50f8e310f5392128577100c46a3ef6a4ccecf64047d92e9",
        ),
    ] {
        let content = read_by_path(&img, &sb, name).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(sha256_hex(&content), want, "{name} sha256 vs mount oracle");
    }
}

#[test]
fn read_by_path_missing_component_errors_not_panics() {
    let Some(path) = image_path("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).unwrap();

    let res = read_by_path(&img, &sb, "/sf/nope.txt");
    assert!(
        matches!(res, Err(XfsError::PathNotFound { .. })),
        "missing name -> PathNotFound, got {res:?}"
    );
}

// -------------------------------------------------------------------------
// v4 no-ftype short-form (sfdir2) — the per-feature-bit ftype branch
// -------------------------------------------------------------------------

#[test]
fn read_dir_v4_noftype_shortform_matches_ls_i() {
    let Some(path) = image_path("XFS_ORACLE_V4DIR_IMG", "v4dir.img") else {
        eprintln!("skip: v4dir (no-ftype) image absent");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).unwrap();
    assert!(!sb.has_ftype(), "v4dir.img was minted with -n ftype=0");

    // root: 131 sf
    let root = sb.read_inode(&img, sb.rootino).unwrap();
    let root_entries = read_dir(&img, &sb, &root).expect("v4 root sfdir2 lists");
    assert_eq!(
        name_inode_map(&root_entries),
        [("sf".to_string(), 131u64)].into_iter().collect()
    );

    // sf: 132/133/134 file1/2/3.txt, and NO ftype byte -> ftype is None.
    let sf = sb.read_inode(&img, 131).unwrap();
    let entries = read_dir(&img, &sb, &sf).expect("v4 sf sfdir2 lists");
    let want: BTreeMap<String, u64> = [
        ("file1.txt".to_string(), 132u64),
        ("file2.txt".to_string(), 133),
        ("file3.txt".to_string(), 134),
    ]
    .into_iter()
    .collect();
    assert_eq!(name_inode_map(&entries), want, "v4 sf {{name->inode}}");
    for e in &entries {
        assert_eq!(e.ftype, None, "no-ftype image -> DirEntry.ftype is None");
    }
}

#[test]
fn read_by_path_v4_noftype_reaches_file1() {
    let Some(path) = image_path("XFS_ORACLE_V4DIR_IMG", "v4dir.img") else {
        eprintln!("skip: v4dir image absent");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).unwrap();

    // Identical content bytes to the v5 file1.txt -> same sha256.
    let content = read_by_path(&img, &sb, "/sf/file1.txt").expect("v4 read-by-path");
    assert_eq!(
        sha256_hex(&content),
        "1894d80da16dd47db42e2a47e33e709254908a30d4a5985df4bf6e1ba18ce350",
        "v4 no-ftype read_by_path content sha256 vs oracle"
    );
}

// -------------------------------------------------------------------------
// Unsupported (fail LOUD, name the format) — leaf/node dir
// -------------------------------------------------------------------------

#[test]
fn read_dir_leaf_dir_is_unsupported_and_names_format() {
    let Some(path) = image_path("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).unwrap();
    // Inode 655488 = the leaf dir: format == Extents but size (49152) != blocksize.
    let leaf = sb.read_inode(&img, 655488).unwrap();
    let res = read_dir(&img, &sb, &leaf);
    match res {
        Err(XfsError::UnsupportedDir { detail }) => {
            // The error must NAME what it can't handle (fail loud with the value).
            assert!(
                detail.contains("leaf")
                    || detail.contains("multi-block")
                    || detail.contains("49152"),
                "Unsupported error must name the format/size, got: {detail}"
            );
        }
        other => panic!("leaf dir must fail loud as UnsupportedDir, got {other:?}"),
    }
}

// -------------------------------------------------------------------------
// Robustness (crafted, no image) — no panic on malformed input
// -------------------------------------------------------------------------

/// Build a minimal v5 superblock buffer (blocksize 4096, inodesize 512, v5).
fn min_sb_bytes() -> Vec<u8> {
    let blocksize = 4096u32;
    let mut img = vec![0u8; 512];
    img[0..4].copy_from_slice(&0x5846_5342u32.to_be_bytes());
    img[4..8].copy_from_slice(&blocksize.to_be_bytes());
    img[56..64].copy_from_slice(&128u64.to_be_bytes());
    img[84..88].copy_from_slice(&32768u32.to_be_bytes());
    img[88..92].copy_from_slice(&1u32.to_be_bytes());
    img[100..102].copy_from_slice(&0xb4a5u16.to_be_bytes()); // v5
    img[104..106].copy_from_slice(&512u16.to_be_bytes());
    img[106..108].copy_from_slice(&8u16.to_be_bytes());
    img[120] = 12;
    img[122] = 9;
    img[123] = 3;
    img[124] = 15;
    img[216..220].copy_from_slice(&1u32.to_be_bytes()); // features_incompat FTYPE
    img
}

#[test]
fn read_shortform_truncated_fork_does_not_panic() {
    let img = min_sb_bytes();
    let sb = Superblock::parse(&img).unwrap();
    // A short-form header claiming 5 entries but a fork with only a few bytes:
    // must stop at the fork bound, never panic or over-read.
    let entries = xfs::read_shortform_dir(&[5, 0, 0, 0, 0, 128, 9, 0], sb.has_ftype());
    assert!(
        entries.len() < 5,
        "truncated fork yields only entries that fit"
    );
}
