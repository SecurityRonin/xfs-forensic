//! F3 structural-integrity auditor tests.
//!
//! Fixtures:
//!   - `tests/data/v5.img` (env `XFS_ORACLE_V5_IMG`) — clean v5 image; MUST emit
//!     no CRC / mirror / geometry / orphan findings (clean-image-is-clean, the
//!     success criterion).
//!   - crafted corruption over a copy of the clean image (byte-flip an inode
//!     block → `XFS-CRC-MISMATCH`; craft an AGI unlinked bucket →
//!     `XFS-ORPHANED-INODE`; craft SB-mirror divergence + impossible geometry).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use xfs_forensic::{audit_findings, audit_image, AnomalyKind, Severity};

fn image_bytes(env: &str, default_name: &str) -> Option<Vec<u8>> {
    let p = std::env::var(env).map_or_else(
        |_| {
            let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            d.pop();
            d.push("tests/data");
            d.push(default_name);
            d
        },
        PathBuf::from,
    );
    p.exists().then(|| std::fs::read(&p).unwrap())
}

fn v5_image() -> Option<Vec<u8>> {
    image_bytes("XFS_ORACLE_V5_IMG", "v5.img")
}

// ── clean-image-is-clean (THE success criterion) ─────────────────────────────

#[test]
fn clean_v5_image_emits_no_anomalies() {
    let Some(img) = v5_image() else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let anomalies = audit_image(&img);
    assert!(
        anomalies.is_empty(),
        "clean v5 image must be clean, got: {anomalies:?}"
    );
    assert!(audit_findings(&img, "volume: v5").is_empty());
}

// ── XFS-CRC-MISMATCH: byte-flip an inode block ───────────────────────────────

#[test]
fn byte_flipped_inode_block_flags_crc_mismatch() {
    let Some(mut img) = v5_image() else {
        eprintln!("skip: v5 image absent");
        return;
    };
    // Flip a byte inside the root inode (ino 128) core region. Its byte offset is
    // inodesize*... — for v5.img: inodesize=512, inode 128 is the first inode of
    // AG0's inode chunk. Locate it via the reader.
    let sb = xfs::Superblock::parse(&img).unwrap();
    let loc = sb.inode_to_location(128);
    let off = loc.byte_offset as usize;
    // Flip a byte in the middle of the inode (not the magic) so the CRC breaks
    // but the inode still parses.
    img[off + 40] ^= 0xFF;

    let anomalies = audit_image(&img);
    assert!(
        anomalies
            .iter()
            .any(|a| matches!(&a.kind, AnomalyKind::CrcMismatch { structure, .. } if *structure == "inode")),
        "expected XFS-CRC-MISMATCH for the flipped inode, got: {anomalies:?}"
    );
    let crc = anomalies
        .iter()
        .find(|a| matches!(a.kind, AnomalyKind::CrcMismatch { .. }))
        .unwrap();
    assert_eq!(crc.code, "XFS-CRC-MISMATCH");
    assert_eq!(crc.severity, Severity::High);
}

// ── XFS-ORPHANED-INODE: craft a non-null AGI unlinked bucket ──────────────────

#[test]
fn crafted_agi_unlinked_bucket_flags_orphaned_inode() {
    let Some(mut img) = v5_image() else {
        eprintln!("skip: v5 image absent");
        return;
    };
    // AGI is at sector 2 of AG0. `agi_unlinked[64]` starts at offset 40 within the
    // AGI (0xffffffff = null). Set bucket 0 to a plausible agino, then fix the CRC
    // so the ORPHANED finding is not masked by a CRC finding. We craft over a copy
    // and re-verify the AGI CRC using xfs-core's verifier by zeroing the CRC field
    // is not possible here; instead assert the orphan fires regardless.
    let sb = xfs::Superblock::parse(&img).unwrap();
    let sectsize = 512usize; // v5.img sectsize
    let agi_off = 2 * sectsize; // AG0 AGI at sector 2
    let unlinked0 = agi_off + 40;
    img[unlinked0..unlinked0 + 4].copy_from_slice(&0x0000_0085u32.to_be_bytes()); // agino 133

    let anomalies = audit_image(&img);
    let orphan = anomalies.iter().find(|a| {
        matches!(&a.kind, AnomalyKind::OrphanedInode { agno: 0, bucket: 0, agino } if *agino == 0x85)
    });
    assert!(
        orphan.is_some(),
        "expected XFS-ORPHANED-INODE for crafted bucket, got: {anomalies:?}"
    );
    assert_eq!(orphan.unwrap().severity, Severity::Medium);
    assert_eq!(orphan.unwrap().code, "XFS-ORPHANED-INODE");
    // silence unused
    let _ = sb.agcount;
}

// ── XFS-SB-MIRROR-DIVERGENCE: diverge a secondary superblock ─────────────────

#[test]
fn diverged_secondary_superblock_flags_mirror_divergence() {
    let Some(mut img) = v5_image() else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let sb = xfs::Superblock::parse(&img).unwrap();
    // Secondary SB for AG1 sits at agno * agblocks * blocksize.
    let sec_off = (sb.agblocks as usize) * (sb.blocksize as usize);
    // sb_agblocks is at offset 84 in the SB (be_u32). Corrupt AG1's copy.
    let agb_off = sec_off + 84;
    let bogus = (sb.agblocks + 7).to_be_bytes();
    img[agb_off..agb_off + 4].copy_from_slice(&bogus);

    let anomalies = audit_image(&img);
    assert!(
        anomalies.iter().any(|a| matches!(
            &a.kind,
            AnomalyKind::SbMirrorDivergence { agno: 1, field, .. } if *field == "agblocks"
        )),
        "expected XFS-SB-MIRROR-DIVERGENCE for AG1, got: {anomalies:?}"
    );
    let d = anomalies
        .iter()
        .find(|a| matches!(a.kind, AnomalyKind::SbMirrorDivergence { .. }))
        .unwrap();
    assert_eq!(d.severity, Severity::High);
    assert_eq!(d.code, "XFS-SB-MIRROR-DIVERGENCE");
}

// ── XFS-IMPOSSIBLE-GEOMETRY: absurd agcount in the primary SB ─────────────────

#[test]
fn impossible_geometry_agcount_flags_finding() {
    let Some(mut img) = v5_image() else {
        eprintln!("skip: v5 image absent");
        return;
    };
    // sb_agcount is at offset 88 (be_u32). Set it absurdly large vs image size.
    img[88..92].copy_from_slice(&0x00FF_FFFFu32.to_be_bytes());
    let anomalies = audit_image(&img);
    assert!(
        anomalies.iter().any(|a| matches!(
            &a.kind,
            AnomalyKind::ImpossibleGeometry { field, .. } if *field == "agcount"
        )),
        "expected XFS-IMPOSSIBLE-GEOMETRY for agcount, got: {anomalies:?}"
    );
}

// ── no-panic on malformed input ───────────────────────────────────────────────

#[test]
fn audit_malformed_input_does_not_panic() {
    assert!(audit_image(&[]).is_empty());
    assert!(audit_image(&[0u8; 16]).is_empty());
    assert!(audit_image(b"not an XFS image at all").is_empty());
    assert!(audit_findings(&[0u8; 8], "x").is_empty());
}
