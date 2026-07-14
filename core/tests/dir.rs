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
//!   name-match `file1.txt` -> `read_file`) and the sha256 EQUALS the committed
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
        ("block".to_string(), 262_272),
        ("leaf".to_string(), 655_488),
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
    let block = sb.read_inode(&img, 262_272).unwrap();
    let entries = read_dir(&img, &sb, &block).expect("block/ block dir lists");

    let got = name_inode_map(&entries);
    // ls -i mnt/block: e01..e40 -> 262273..262312.
    let want: BTreeMap<String, u64> = (1..=40u64)
        .map(|i| (format!("e{i:02}"), 262_272 + i))
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

// The P4 leaf-dir "fail loud, unsupported" test is superseded by P5 Part 2,
// which reads leaf directories via the multi-block data-block walk. Its success
// gate (read_dir(leaf/) == ls -i, ~2000 entries) lives in `tests/dir_leaf.rs`.
// The remaining loud-fail path (Btree-format directory) is still covered above
// by `read_dir_btree_format_is_unsupported_and_names_format`.

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

#[test]
fn read_shortform_stops_when_inum_runs_past_fork() {
    // Header (count=1, i8count=0, parent=128) + one entry whose name is present
    // but the fork ends before the 4-byte inode number: the reader must break
    // (drop the incomplete entry) rather than read a partial/garbage inum.
    // count(1) i8count(1) parent(4) | namelen(1)=2 offset(2) name(2)="ab" | <cut>
    let fork = [1u8, 0, 0, 0, 0, 128, 2, 0, 0x40, b'a', b'b'];
    let entries = xfs::read_shortform_dir(&fork, false);
    assert!(entries.is_empty(), "entry with no room for inum is dropped");
}

#[test]
fn read_shortform_i8count_uses_8byte_inums() {
    // i8count != 0 -> parent and every inode number are 8 bytes (exercises the
    // read_inum 8-byte arm and the 8-byte parent skip). One entry "z" -> inode 9.
    // count(1)=1 i8count(1)=1 parent(8) | namelen(1)=1 offset(2) name(1)="z"
    // ftype(1)=1 inumber(8)=9
    let mut fork = vec![1u8, 1];
    fork.extend_from_slice(&128u64.to_be_bytes()); // parent (8 bytes)
    fork.push(1); // namelen
    fork.extend_from_slice(&[0x00, 0x60]); // offset
    fork.push(b'z'); // name
    fork.push(1); // ftype
    fork.extend_from_slice(&9u64.to_be_bytes()); // inumber (8 bytes)
    let entries = xfs::read_shortform_dir(&fork, true);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, b"z");
    assert_eq!(entries[0].inode, 9, "8-byte inode number decoded");
    assert_eq!(entries[0].ftype, Some(1));
}

#[test]
fn read_block_dir_v4_magic_xd2b_and_noftype() {
    // A crafted v4 (XD2B) block dir with a 16-byte header, one entry "a" -> ino 7
    // (no ftype byte), then a block tail with count=0 (no leaf array). Exercises
    // the XD2B header-length arm and the has_ftype=false block path.
    let blocksize = 64usize; // small but valid: hdr(16) + entry(16) + ... + tail(8)
    let mut block = vec![0u8; blocksize];
    block[0..4].copy_from_slice(&xfs::XFS_DIR2_BLOCK_MAGIC.to_be_bytes());
    // entry at offset 16: inumber(8)=7 namelen(1)=1 name="a" tag(2) -> aligned 16.
    let off = 16;
    block[off..off + 8].copy_from_slice(&7u64.to_be_bytes());
    block[off + 8] = 1; // namelen
    block[off + 9] = b'a'; // name
                           // tag at off+10..12 (ignored); rest zero.
                           // block tail (last 8 bytes): count=0, stale=0 -> leaf_start = blocksize-8.
                           // (count already zero.)
    let entries = xfs::read_block_dir(&block, false).expect("v4 block dir parses");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, b"a");
    assert_eq!(entries[0].inode, 7);
    assert_eq!(entries[0].ftype, None, "no-ftype block entry -> None");
}

#[test]
fn read_block_dir_unrecognized_magic_fails_loud() {
    // A block whose data-block magic is neither XDB3 nor XD2B must fail LOUD and
    // NAME the offending magic bytes (never a silent empty listing).
    let mut block = vec![0u8; 64];
    block[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let res = xfs::read_block_dir(&block, true);
    match res {
        Err(XfsError::UnsupportedDir { detail }) => {
            assert!(
                detail.contains("0xdeadbeef") && detail.contains("magic"),
                "must name the offending magic, got: {detail}"
            );
        }
        other => panic!("unrecognized magic must fail loud, got {other:?}"),
    }
}

#[test]
fn read_block_dir_tiny_block_no_tail_is_empty() {
    // A block smaller than the 8-byte tail: leaf_start falls to 0, region_end
    // clamps to hdr_len, the walk runs zero iterations -> empty (no panic).
    let mut block = vec![0u8; 4];
    block[0..4].copy_from_slice(&xfs::XFS_DIR3_BLOCK_MAGIC.to_be_bytes());
    let entries = xfs::read_block_dir(&block, true).expect("tiny block parses empty");
    assert!(entries.is_empty(), "no room for entries -> empty listing");
}

#[test]
fn read_block_dir_entry_past_block_stops() {
    // A v5 block whose last entry claims a namelen running past the block end:
    // the reader must break rather than over-read. hdr(64) + a valid entry then a
    // truncated one.
    let blocksize = 128usize;
    let mut block = vec![0u8; blocksize];
    block[0..4].copy_from_slice(&xfs::XFS_DIR3_BLOCK_MAGIC.to_be_bytes());
    // count=0 in tail so leaf_start = blocksize - 8 = 120; entries region 64..120.
    let off = 64;
    // entry claims namelen=250 (way past the block) -> name slice is None -> break.
    block[off..off + 8].copy_from_slice(&5u64.to_be_bytes());
    block[off + 8] = 250; // namelen past end
    let entries = xfs::read_block_dir(&block, true).expect("must not panic");
    assert!(entries.is_empty(), "entry running past block is dropped");
}

#[test]
fn read_block_dir_skips_unused_free_records() {
    // A v5 block with a leading unused record (freetag 0xFFFF, length 16) then a
    // real entry "b" -> ino 3. Exercises the free-record skip branch.
    let blocksize = 128usize;
    let mut block = vec![0u8; blocksize];
    block[0..4].copy_from_slice(&xfs::XFS_DIR3_BLOCK_MAGIC.to_be_bytes());
    let off = 64;
    // unused record: freetag(2)=0xFFFF, length(2)=16.
    block[off..off + 2].copy_from_slice(&0xFFFFu16.to_be_bytes());
    block[off + 2..off + 4].copy_from_slice(&16u16.to_be_bytes());
    // real entry at off+16.
    let e = off + 16;
    block[e..e + 8].copy_from_slice(&3u64.to_be_bytes());
    block[e + 8] = 1; // namelen
    block[e + 9] = b'b'; // name
    block[e + 10] = 2; // ftype
    let entries = xfs::read_block_dir(&block, true).expect("parses past the free record");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, b"b");
    assert_eq!(entries[0].inode, 3);
    assert_eq!(entries[0].ftype, Some(2));
}

#[test]
fn read_block_dir_zero_length_free_record_makes_progress() {
    // A malformed unused record with length 0 must not stall the loop: the reader
    // enforces forward progress of at least one 8-byte grain.
    let blocksize = 128usize;
    let mut block = vec![0u8; blocksize];
    block[0..4].copy_from_slice(&xfs::XFS_DIR3_BLOCK_MAGIC.to_be_bytes());
    let off = 64;
    block[off..off + 2].copy_from_slice(&0xFFFFu16.to_be_bytes()); // freetag
                                                                   // length stays 0 -> the reader must still advance and terminate.
    let entries = xfs::read_block_dir(&block, true).expect("must terminate, not hang");
    assert!(entries.is_empty());
}

#[test]
fn read_dir_btree_format_is_unsupported_and_names_format() {
    // A directory inode reported as Btree format is not yet supported: read_dir
    // must fail loud naming the format (the InodeFormat::Btree/other arm).
    use xfs::{Inode, InodeFormat};
    let img = min_sb_bytes();
    let sb = Superblock::parse(&img).unwrap();
    // Craft a v3 directory inode with di_format = 3 (BTREE).
    let mut ib = vec![0u8; 512];
    ib[0..2].copy_from_slice(&0x494eu16.to_be_bytes()); // "IN"
    ib[2..4].copy_from_slice(&0o040_700u16.to_be_bytes()); // dir mode
    ib[4] = 3; // di_version = v3
    ib[5] = 3; // di_format = BTREE
    let inode = Inode::parse(&ib).unwrap();
    assert_eq!(inode.format, InodeFormat::Btree);
    match read_dir(&img, &sb, &inode) {
        Err(XfsError::UnsupportedDir { detail }) => {
            assert!(detail.contains("Btree"), "must name Btree, got: {detail}");
        }
        other => panic!("btree dir must fail loud, got {other:?}"),
    }
}

#[test]
fn read_by_path_non_dir_intermediate_component_errors() {
    // Descending THROUGH a component that is a regular file (not a directory)
    // must error, not try to list a file as a directory.
    let Some(path) = image_path("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).unwrap();
    // big.bin is a regular file; treating it as a dir component must fail.
    let res = read_by_path(&img, &sb, "/big.bin/whatever");
    assert!(
        matches!(res, Err(XfsError::PathNotFound { .. })),
        "a file used as an intermediate dir component -> PathNotFound, got {res:?}"
    );
}

#[test]
fn read_by_path_empty_path_is_not_found() {
    // An empty path resolves to the root directory, which is not a file: the
    // reader reports PathNotFound rather than trying to read a directory's bytes.
    let Some(path) = image_path("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).unwrap();
    let res = read_by_path(&img, &sb, "/");
    assert!(
        matches!(res, Err(XfsError::PathNotFound { .. })),
        "empty path -> PathNotFound, got {res:?}"
    );
}
