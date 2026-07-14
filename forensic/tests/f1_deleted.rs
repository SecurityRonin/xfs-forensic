//! F1 deleted-inode recovery tests (oracle-gated).
//!
//! Fixtures (see `tests/data/v5del.ground-truth.txt`):
//!   - `v5del.freed_inode.bin` (committed, 512 B) — the freed inode 132 from a
//!     minted extent-format deletion case: `di_mode==0`, `di_nextents==0`, but
//!     the residual extent record `[startoff=0, startblock=32, blockcount=8]`
//!     survives at offset 176. Proves residual-extent decode with no full image.
//!   - `del.img` via `XFS_DEL_ORACLE` (512 MiB, gitignored) — the full image;
//!     the carve-and-hash gate: the recovered inode's carved bytes' sha256 MUST
//!     equal the original `DELETED_target.bin` sha256.

#![allow(clippy::unwrap_used, clippy::expect_used)]

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

// ── residual-extent decode from the committed 512-byte freed-inode fixture ────
//
// This does not need the full image: it constructs a minimal single-AG geometry
// matching the mint (isize=512, bsize=4096, agblocks=32768, inopblock=8) and
// places the one freed inode at inode 132's slot, then asserts recover_deleted
// finds it with the surviving residual extent.

#[test]
fn recovers_freed_inode_residual_extent_from_fixture() {
    let freed = std::fs::read(data_path("v5del.freed_inode.bin")).unwrap();
    assert_eq!(freed.len(), 512, "fixture is one 512-byte inode");

    // Build a synthetic image large enough to hold inode 132 at its computed
    // byte offset, with a real v5 superblock copied from v5.img geometry so the
    // reader's inode_to_location matches the mint. We reuse v5.img's SB sector
    // (identical geometry) and splice the freed inode into inode 132's slot.
    let mut img = std::fs::read(data_path("v5.img")).unwrap_or_default();
    if img.is_empty() {
        eprintln!("skip: v5 image absent (needed for geometry)");
        return;
    }
    let sb = xfs::Superblock::parse(&img).unwrap();
    let loc = sb.inode_to_location(132);
    let off = loc.byte_offset as usize;
    img[off..off + 512].copy_from_slice(&freed);

    let recovered = recover_deleted(&img, &sb);
    let hit = recovered
        .iter()
        .find(|d| d.inode_number == 132)
        .expect("freed inode 132 recovered");

    assert_eq!(hit.agno, 0, "inode 132 is in AG0");
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

// ── no-panic on malformed input ───────────────────────────────────────────────

#[test]
fn recover_deleted_malformed_input_does_not_panic() {
    let img = std::fs::read(data_path("v5.img")).unwrap_or_default();
    if img.is_empty() {
        return;
    }
    let sb = xfs::Superblock::parse(&img).unwrap();
    // A tiny image slice must not panic.
    assert!(recover_deleted(&[], &sb).is_empty());
    assert!(recover_deleted(&[0u8; 32], &sb).is_empty());
}
