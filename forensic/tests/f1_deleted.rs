//! F1 deleted-inode recovery tests.
//!
//! Fixtures (see `tests/data/v5del.ground-truth.txt`):
//!   - `v5del.freed_inode.bin` (committed, 512 B) — the freed inode 132 from a
//!     minted extent-format deletion case: `di_mode==0`, `di_nextents==0`, but
//!     the residual extent record `[startoff=0, startblock=32, blockcount=8]`
//!     survives at offset 176. Proves residual-extent decode with no full image.
//!   - `xfs_dfvfs.raw` (committed, 16 MiB, Apache-2.0) — the always-on Tier-1 v5
//!     image, used purely as a real v5 geometry host: the committed freed inode
//!     is spliced into an inode slot in a *copy* of it and `recover_deleted`
//!     recovers it (its residual extent points within the 16 MiB image). This
//!     carries the CI coverage path with no env-gated oracle.
//!   - `del.img` via `XFS_DEL_ORACLE` (512 MiB, gitignored) — the full image;
//!     the carve-and-hash gate: the recovered inode's carved bytes' sha256 MUST
//!     equal the original `DELETED_target.bin` sha256.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::format_collect
)]

use std::path::PathBuf;

use sha2::{Digest, Sha256};
use xfs_forensic::recover_deleted;

/// Ground-truth sha256 of the deleted `DELETED_target.bin` (32768 bytes).
const DELETED_TARGET_SHA256: &str =
    "e34be105623327ff457b879a66d110ce877d3b754f0e1a704537598d42d61b98";

fn data_path(name: &str) -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.push("tests/data");
    d.push(name);
    d
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The committed always-on Tier-1 v5 image (`xfs_dfvfs.raw`, 16 MiB), used here
/// only as a real v5 geometry host for the freed-inode splice (its 4096 blocks
/// comfortably contain the freed inode's `startblock 32 + count 8` extent).
fn dfvfs() -> Vec<u8> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("tests/data/xfs_dfvfs.raw");
    std::fs::read(&p).unwrap_or_else(|e| panic!("read committed Tier-1 image {}: {e}", p.display()))
}

// ── residual-extent decode from the committed 512-byte freed-inode fixture ────
//
// Splice the committed freed inode into an inode slot of a *copy* of the
// always-on dfvfs v5 image (both have inodesize 512). `recover_deleted` then
// finds it via its `IN` magic + `di_mode == 0` and decodes the surviving
// residual extent. This is always-on (committed data only), so it carries the CI
// coverage path for the recovery decode without an env-gated oracle.

#[test]
fn recovers_freed_inode_residual_extent_from_fixture() {
    let freed = std::fs::read(data_path("v5del.freed_inode.bin")).unwrap();
    assert_eq!(freed.len(), 512, "fixture is one 512-byte inode");

    let mut img = dfvfs();
    let sb = xfs::Superblock::parse(&img).unwrap();
    assert_eq!(sb.inodesize, 512, "dfvfs inodesize matches the fixture");
    // Splice the freed inode at a block-aligned inode slot (block 2048) — well
    // clear of the real inodes near the root, and block-aligned so it sits at a
    // genuine inode-chunk boundary the sweep steps onto.
    let off = 2048usize * sb.blocksize as usize;
    img[off..off + 512].copy_from_slice(&freed);

    let recovered = recover_deleted(&img, &sb);
    let hit = recovered
        .iter()
        .find(|d| {
            d.residual_extents
                .first()
                .is_some_and(|e| e.startblock == 32)
        })
        .expect("freed inode with residual extent recovered");

    assert_eq!(
        hit.residual_extents.len(),
        1,
        "one residual extent survived"
    );
    let e = &hit.residual_extents[0];
    assert_eq!(e.startoff, 0);
    assert_eq!(e.startblock, 32);
    assert_eq!(e.blockcount, 8);
    // ctime = deletion time (2026-07-13 05:46:56 UTC = 1783892816).
    assert_eq!(hit.ctime.secs, 1_783_892_816);
    // 8 blocks * 4096 = 32768 bytes.
    assert_eq!(hit.recovered_size_estimate, 32768);
}

// ── carve-and-hash gate (env-gated full image) ────────────────────────────────

#[test]
fn carves_deleted_content_matching_original_sha256() {
    let Ok(path) = std::env::var("XFS_DEL_ORACLE") else {
        eprintln!("skip: XFS_DEL_ORACLE not set (512 MiB deletion image absent)");
        return;
    };
    let img = std::fs::read(&path).expect("read XFS_DEL_ORACLE image");
    let sb = xfs::Superblock::parse(&img).unwrap();

    let recovered = recover_deleted(&img, &sb);
    let hit = recovered
        .iter()
        .find(|d| d.inode_number == 132)
        .expect("deleted inode 132 recovered from oracle image");

    // THE gate: carved bytes reproduce the original content hash.
    assert_eq!(
        sha256_hex(&hit.carved),
        DELETED_TARGET_SHA256,
        "carved deleted-file content sha256 must equal the original"
    );
    assert_eq!(hit.recovered_size_estimate, 32768);
}

// ── degenerate geometry short-circuits before the sweep ───────────────────────

#[test]
fn recover_deleted_tiny_inode_size_returns_empty() {
    let mut img = dfvfs();
    img[104..106].copy_from_slice(&128u16.to_be_bytes()); // sb_inodesize = 128 (< 176)
    let sb = xfs::Superblock::parse(&img).unwrap();
    // A sub-core inode size can hold no v3 fork extents → early return, no work.
    assert!(recover_deleted(&img, &sb).is_empty());
}

// ── no-panic on malformed input ───────────────────────────────────────────────

#[test]
fn recover_deleted_malformed_input_does_not_panic() {
    let sb = xfs::Superblock::parse(&dfvfs()).unwrap();
    // A tiny image slice must not panic.
    assert!(recover_deleted(&[], &sb).is_empty());
    assert!(recover_deleted(&[0u8; 32], &sb).is_empty());
}
