//! F3 structural-integrity auditor tests.
//!
//! Two fixture tiers, per the fleet two-path model:
//!
//!   - **CI-coverage path (always-on):** the committed Tier-1 image
//!     `tests/data/xfs_dfvfs.raw` (dfvfs `test_data/xfs.raw`, Apache-2.0) is a
//!     clean single-AG v5 filesystem — it drives the whole clean audit walk and,
//!     via crafted corruptions over a *copy*, every push branch (CRC / orphan /
//!     geometry / inode-CRC). A tiny self-contained `two_ag_v5()` crafted image
//!     supplies the one branch a single-AG image cannot reach: the secondary
//!     (AG 1..n) superblock divergence walk. Neither needs an env-gated oracle,
//!     so CI runners with only committed data cover 100% of the auditor.
//!   - **Tier-1 correctness path (env-gated, unchanged):** the large minted
//!     `v5.img` / `v4.img` (`XFS_ORACLE_V5_IMG` / `XFS_ORACLE_V4_IMG`) — when
//!     present, the same corruptions are re-run against a genuine `mkfs.xfs`
//!     image; absent, those tests skip cleanly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use xfs_forensic::{audit_findings, audit_image, AnomalyKind, Severity};

// ── committed always-on Tier-1 image (drives the CI coverage path) ────────────

/// The committed clean v5 image (`xfs_dfvfs.raw`, 16 `MiB`, Apache-2.0). Always
/// present in the checkout, so — unlike the env-gated `v5.img` — these tests do
/// not skip on CI. It is a single-AG (`agcount == 1`) clean filesystem:
/// `audit_image` returns no anomalies over it.
fn dfvfs() -> Vec<u8> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // core/ -> repo root
    p.push("tests/data/xfs_dfvfs.raw");
    std::fs::read(&p).unwrap_or_else(|e| panic!("read committed Tier-1 image {}: {e}", p.display()))
}

/// dfvfs geometry (from `xfs_db sb 0 print`, see `tier1_dfvfs.rs`): 512-byte
/// sectors, 4096-byte blocks, 512-byte inodes, single AG, root inode 11072.
const DFVFS_SECT: usize = 512;

// ── env-gated minted images (Tier-1 correctness path, unchanged) ──────────────

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

fn v4_image() -> Option<Vec<u8>> {
    image_bytes("XFS_ORACLE_V4_IMG", "v4.img")
}

// ── clean-image-is-clean (THE success criterion) ─────────────────────────────

#[test]
fn clean_v5_image_emits_no_anomalies() {
    let img = dfvfs();
    let anomalies = audit_image(&img);
    assert!(
        anomalies.is_empty(),
        "clean v5 image must be clean, got: {anomalies:?}"
    );
    assert!(audit_findings(&img, "volume: dfvfs").is_empty());
}

// ── XFS-CRC-MISMATCH: byte-flip an inode block ───────────────────────────────

#[test]
fn byte_flipped_inode_block_flags_crc_mismatch() {
    let mut img = dfvfs();
    // Flip a byte inside the root inode (11072) core region, away from the magic,
    // so the CRC breaks but the inode still parses and its di_ino self-reference
    // still matches — the audit's inode sweep then flags it.
    let sb = xfs::Superblock::parse(&img).unwrap();
    let off = sb.inode_to_location(sb.rootino).byte_offset as usize;
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
        .find(|a| matches!(a.kind, AnomalyKind::CrcMismatch { structure, .. } if structure == "inode"))
        .unwrap();
    assert_eq!(crc.code, "XFS-CRC-MISMATCH");
    assert_eq!(crc.severity, Severity::High);
}

// ── XFS-CRC-MISMATCH: byte-flip the primary superblock ───────────────────────

#[test]
fn byte_flipped_primary_superblock_flags_crc_mismatch() {
    let mut img = dfvfs();
    // Flip a byte inside the SB sector, away from the magic (bytes 0..4) and the
    // geometry fields the audit re-reads, so only the CRC breaks.
    img[200] ^= 0xFF;
    let anomalies = audit_image(&img);
    assert!(
        anomalies.iter().any(|a| matches!(
            &a.kind,
            AnomalyKind::CrcMismatch { structure, offset } if *structure == "superblock" && *offset == 0
        )),
        "expected primary-superblock XFS-CRC-MISMATCH, got: {anomalies:?}"
    );
}

// ── XFS-ORPHANED-INODE: craft a non-null AGI unlinked bucket ──────────────────

#[test]
fn crafted_agi_unlinked_bucket_flags_orphaned_inode() {
    let mut img = dfvfs();
    // AGI is at sector 2 of AG0. `agi_unlinked[64]` starts at offset 40 within
    // the AGI (0xffffffff = null). Set bucket 0 to a plausible agino. The CRC
    // will now also break (an expected companion finding); the assertion targets
    // the orphan.
    let agi_off = 2 * DFVFS_SECT;
    let unlinked0 = agi_off + 40;
    img[unlinked0..unlinked0 + 4].copy_from_slice(&0x0000_2b41u32.to_be_bytes()); // agino 11073

    let anomalies = audit_image(&img);
    let orphan = anomalies.iter().find(|a| {
        matches!(&a.kind, AnomalyKind::OrphanedInode { agno: 0, bucket: 0, agino } if *agino == 0x2b41)
    });
    assert!(
        orphan.is_some(),
        "expected XFS-ORPHANED-INODE for crafted bucket, got: {anomalies:?}"
    );
    assert_eq!(orphan.unwrap().severity, Severity::Medium);
    assert_eq!(orphan.unwrap().code, "XFS-ORPHANED-INODE");
}

// ── XFS-CRC-MISMATCH: corrupt an AGF sector ───────────────────────────────────

#[test]
fn corrupt_agf_flags_crc_mismatch() {
    let mut img = dfvfs();
    // AG0 AGF is at sector 1 (byte 512). Flip a root field (offset 24 within the
    // AGF, not the magic) so the sector CRC breaks but the header still parses.
    img[DFVFS_SECT + 24] ^= 0xFF;
    let anomalies = audit_image(&img);
    assert!(
        anomalies.iter().any(
            |a| matches!(&a.kind, AnomalyKind::CrcMismatch { structure, .. } if *structure == "AGF")
        ),
        "expected XFS-CRC-MISMATCH for the corrupt AGF, got: {anomalies:?}"
    );
}

// ── XFS-CRC-MISMATCH: corrupt the AGI sector (without touching a bucket) ──────

#[test]
fn corrupt_agi_flags_crc_mismatch() {
    let mut img = dfvfs();
    // Flip an AGI field (offset 16 = agi_count, not the magic, not a bucket) so
    // the sector CRC breaks and the AGI still parses with all buckets null.
    img[2 * DFVFS_SECT + 16] ^= 0xFF;
    let anomalies = audit_image(&img);
    assert!(
        anomalies.iter().any(
            |a| matches!(&a.kind, AnomalyKind::CrcMismatch { structure, .. } if *structure == "AGI")
        ),
        "expected XFS-CRC-MISMATCH for the corrupt AGI, got: {anomalies:?}"
    );
}

// ── XFS-IMPOSSIBLE-GEOMETRY: absurd agcount in the primary SB ─────────────────

#[test]
fn impossible_geometry_agcount_flags_finding() {
    let mut img = dfvfs();
    // sb_agcount is at offset 88 (be_u32). Set it absurdly large vs image size.
    img[88..92].copy_from_slice(&0x00FF_FFFFu32.to_be_bytes());
    let anomalies = audit_image(&img);
    assert!(
        anomalies.iter().any(|a| matches!(
            &a.kind,
            AnomalyKind::ImpossibleGeometry { field, value, .. } if *field == "agcount" && *value == 0x00FF_FFFF
        )),
        "expected XFS-IMPOSSIBLE-GEOMETRY for agcount, got: {anomalies:?}"
    );
}

// ── XFS-IMPOSSIBLE-GEOMETRY: agcount == 0 ─────────────────────────────────────

#[test]
fn zero_agcount_flags_impossible_geometry() {
    let mut img = dfvfs();
    img[88..92].copy_from_slice(&0u32.to_be_bytes()); // sb_agcount = 0
    let anomalies = audit_image(&img);
    assert!(
        anomalies.iter().any(|a| matches!(
            &a.kind,
            AnomalyKind::ImpossibleGeometry { field, value, .. } if *field == "agcount" && *value == 0
        )),
        "expected XFS-IMPOSSIBLE-GEOMETRY for agcount==0, got: {anomalies:?}"
    );
}

// ── XFS-SB-MIRROR-DIVERGENCE: a crafted 2-AG image with a diverged secondary ──
//
// A single-AG image cannot reach the `agno >= 1` secondary-superblock walk, so
// this uses a tiny self-contained crafted v5 image (`two_ag_v5`) whose AG-1
// backup superblock has each geometry field diverged from the AG-0 primary. That
// drives both the secondary-SB CRC-mismatch push and every arm of
// `push_sb_divergence`.

#[test]
fn diverged_secondary_superblock_flags_mirror_divergence() {
    let img = two_ag_v5();
    let anomalies = audit_image(&img);
    for want in ["agblocks", "agcount", "blocksize", "inodesize"] {
        assert!(
            anomalies.iter().any(|a| matches!(
                &a.kind,
                AnomalyKind::SbMirrorDivergence { agno: 1, field, .. } if *field == want
            )),
            "expected XFS-SB-MIRROR-DIVERGENCE for AG1 field {want}, got: {anomalies:?}"
        );
    }
    let d = anomalies
        .iter()
        .find(|a| matches!(a.kind, AnomalyKind::SbMirrorDivergence { .. }))
        .unwrap();
    assert_eq!(d.severity, Severity::High);
    assert_eq!(d.code, "XFS-SB-MIRROR-DIVERGENCE");
    // The secondary SB's broken CRC also surfaces (offset == AG1 base).
    assert!(
        anomalies.iter().any(|a| matches!(
            &a.kind,
            AnomalyKind::CrcMismatch { structure, offset } if *structure == "superblock" && *offset != 0
        )),
        "expected a secondary-superblock CRC mismatch, got: {anomalies:?}"
    );
}

// ── audit_findings converts every anomaly kind to a graded report::Finding ────
//
// Drives the `to_finding` path so each kind's Observation impl (severity/code/
// note/evidence) is exercised. Three crafted images together produce all four
// codes: an absurd agcount (ImpossibleGeometry + primary-SB CRC), a crafted AGI
// bucket + flipped inode (OrphanedInode + inode CRC), and the 2-AG mirror image
// (SbMirrorDivergence).

#[test]
fn audit_findings_convert_every_anomaly_kind() {
    let base = dfvfs();

    let mut a = base.clone();
    a[88..92].copy_from_slice(&0x00FF_FFFFu32.to_be_bytes());

    let mut b = base.clone();
    let sb = xfs::Superblock::parse(&b).unwrap();
    let agi_bucket0 = 2 * DFVFS_SECT + 40;
    b[agi_bucket0..agi_bucket0 + 4].copy_from_slice(&0x0000_2b41u32.to_be_bytes());
    let ioff = sb.inode_to_location(sb.rootino).byte_offset as usize;
    b[ioff + 40] ^= 0xFF;

    let c = two_ag_v5();

    let mut codes = std::collections::BTreeSet::new();
    for img in [&a, &b, &c] {
        let findings = audit_findings(img, "volume: xfs");
        assert!(!findings.is_empty());
        for f in &findings {
            assert!(!f.note.is_empty());
            assert!(!f.evidence.is_empty());
            assert!(f.severity.is_some());
            assert_eq!(f.source.analyzer, "xfs-forensic");
            assert_eq!(f.source.scope, "volume: xfs");
            codes.insert(f.code.as_ref().to_string());
        }
    }
    for want in [
        "XFS-CRC-MISMATCH",
        "XFS-SB-MIRROR-DIVERGENCE",
        "XFS-ORPHANED-INODE",
        "XFS-IMPOSSIBLE-GEOMETRY",
    ] {
        assert!(codes.contains(want), "missing {want}; got {codes:?}");
    }
}

// ── robustness: malformed geometry / headers degrade, never panic ─────────────

#[test]
fn v4_image_audits_without_crc_findings() {
    let Some(img) = v4_image() else {
        eprintln!("skip: v4 image absent");
        return;
    };
    // v4 carries no CRCs: no CRC-mismatch findings, and the is_v5-gated inode
    // CRC sweep is skipped — all without panicking.
    let anomalies = audit_image(&img);
    assert!(
        !anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::CrcMismatch { .. })),
        "v4 image must not yield CRC findings, got: {anomalies:?}"
    );
}

#[test]
fn crafted_v4_image_skips_crc_and_inode_sweep() {
    // A crafted v4 (`versionnum` low nibble 4) image: the audit walks the AG
    // headers but the v5-gated CRC checks and inode CRC sweep are all skipped —
    // a clean v4 emits nothing, exercising the `is_v5 == false` branches.
    let img = two_ag_v4();
    let anomalies = audit_image(&img);
    assert!(
        !anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::CrcMismatch { .. })),
        "v4 image must not yield CRC findings, got: {anomalies:?}"
    );
}

#[test]
fn zero_blocksize_degrades_without_panic() {
    let mut img = dfvfs();
    img[4..8].copy_from_slice(&0u32.to_be_bytes()); // sb_blocksize = 0
    let _ = audit_image(&img);
}

#[test]
fn corrupt_ag_header_magics_are_skipped() {
    let mut img = two_ag_v5();
    let ag1 = ag_bytes_of(&img); // AG1 base
    img[ag1] ^= 0xFF; // secondary superblock magic
    img[DFVFS_SECT] ^= 0xFF; // AG0 AGF magic (sector 1)
    img[2 * DFVFS_SECT] ^= 0xFF; // AG0 AGI magic (sector 2)
                                 // Each header now fails to parse and is skipped (the parse-Err paths); no
                                 // panic, and the corrupt AGI is not read for orphan buckets.
    let _ = audit_image(&img);
}

#[test]
fn truncated_image_skips_partial_ag_headers() {
    let img = two_ag_v5();
    // Cut just past AG1's base so its secondary SB / AGF / AGI slices fall off
    // the end of the image (the `image.get(..)` None paths).
    let cut = (ag_bytes_of(&img) + 100).min(img.len());
    let _ = audit_image(&img[..cut]);
}

#[test]
fn absurd_sector_size_falls_back_to_512() {
    let mut img = dfvfs();
    img[102..104].copy_from_slice(&13u16.to_be_bytes()); // not a power of two
                                                         // The clamp falls back to a 512-byte sector rather than mis-slicing.
    let _ = audit_image(&img);
}

#[test]
fn tiny_inode_size_skips_inode_sweep() {
    let mut img = dfvfs();
    img[104..106].copy_from_slice(&128u16.to_be_bytes()); // sb_inodesize = 128 (< 176)
                                                          // The inode CRC sweep needs a v3 core; a sub-core inode size skips it.
    let _ = audit_image(&img);
}

// ── no-panic on malformed input ───────────────────────────────────────────────

#[test]
fn audit_malformed_input_does_not_panic() {
    assert!(audit_image(&[]).is_empty());
    assert!(audit_image(&[0u8; 16]).is_empty());
    assert!(audit_image(b"not an XFS image at all").is_empty());
    assert!(audit_findings(&[0u8; 8], "x").is_empty());
}

// ── crafted minimal multi-AG images ───────────────────────────────────────────
//
// A hand-built v5 (or v4) image just large enough for the auditor to walk two
// allocation groups. Geometry is intentionally tiny (512-byte sectors and
// blocks, `agblocks == 1` so each AG is one sector-and-block region) so the whole
// image is a few kilobytes. Every AG opens with a valid-magic SB / AGF / AGI so
// the headers parse; the AG-1 backup SB has each geometry field diverged so
// `push_sb_divergence` fires. CRC fields are left arbitrary (they do not gate a
// parse), so the v5 image's secondary SB / headers additionally surface an
// expected CRC-mismatch — the coverage target is the walk, not clean CRCs.

const XFSB: u32 = 0x5846_5342;
const XAGF: u32 = 0x5841_4746;
const XAGI: u32 = 0x5841_4749;

/// Absolute byte base of AG1 (`agblocks * blocksize`) for a crafted image.
fn ag_bytes_of(img: &[u8]) -> usize {
    let sb = xfs::Superblock::parse(img).unwrap();
    (sb.agblocks as usize) * (sb.blocksize as usize)
}

/// Write a minimal superblock at `img[base..]` with the given geometry. Only the
/// fields the auditor reads are set; everything else stays zero.
fn write_sb(
    img: &mut [u8],
    base: usize,
    versionnum: u16,
    blocksize: u32,
    agblocks: u32,
    agcount: u32,
    inodesize: u16,
) {
    img[base..base + 4].copy_from_slice(&XFSB.to_be_bytes());
    img[base + 4..base + 8].copy_from_slice(&blocksize.to_be_bytes());
    img[base + 84..base + 88].copy_from_slice(&agblocks.to_be_bytes());
    img[base + 88..base + 92].copy_from_slice(&agcount.to_be_bytes());
    img[base + 100..base + 102].copy_from_slice(&versionnum.to_be_bytes());
    img[base + 104..base + 106].copy_from_slice(&inodesize.to_be_bytes());
}

/// Stamp valid-magic AGF (sector 1) and AGI (sector 2) headers at AG base
/// `base`, with all AGI unlinked buckets null so a clean walk finds no orphans.
fn write_ag_headers(img: &mut [u8], base: usize, sect: usize) {
    let agf = base + sect;
    img[agf..agf + 4].copy_from_slice(&XAGF.to_be_bytes());
    let agi = base + 2 * sect;
    img[agi..agi + 4].copy_from_slice(&XAGI.to_be_bytes());
    // agi_unlinked[64] @ offset 40: fill with the null sentinel 0xffffffff.
    for i in 0..64 {
        let o = agi + 40 + i * 4;
        img[o..o + 4].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
    }
}

/// Build the shared 2-AG image body for `versionnum` (0xb4b5 → v5, 0xb4b4 → v4).
/// AG-0 primary is coherent (`agcount == 2`); AG-1 backup diverges on every
/// geometry field. Geometry is coherent and tiny: sect = block = 512,
/// agblocks = 4 → each AG is 2048 bytes, comfortably holding its SB/AGF/AGI
/// header sectors (0,1,2) without either AG's headers colliding with the next.
fn two_ag(versionnum: u16) -> Vec<u8> {
    let sect = 512usize;
    let agblocks = 4u32;
    let blocksize = 512u32;
    let ag_bytes = agblocks as usize * blocksize as usize; // 2048 = 4 sectors
                                                           // Two AGs back to back; AG1 base = ag_bytes. Its three header sectors
                                                           // (SB/AGF/AGI) fit within [ag_bytes, ag_bytes + 3*sect).
    let mut img = vec![0u8; 2 * ag_bytes];

    // AG-0 primary superblock (the truth), plus its AGF/AGI.
    write_sb(&mut img, 0, versionnum, blocksize, agblocks, 2, 512);
    write_ag_headers(&mut img, 0, sect);

    // AG-1 backup superblock at ag_bytes, every geometry field diverged.
    let base1 = ag_bytes;
    write_sb(
        &mut img,
        base1,
        versionnum,
        blocksize + 1,
        agblocks + 1,
        3,
        256,
    );
    write_ag_headers(&mut img, base1, sect);
    img
}

/// A crafted 2-AG **v5** image (versionnum low nibble 5).
fn two_ag_v5() -> Vec<u8> {
    two_ag(0xb4b5)
}

/// A crafted 2-AG **v4** image (versionnum low nibble 4): the v5-gated CRC / inode
/// checks are all skipped, so a clean walk emits nothing.
fn two_ag_v4() -> Vec<u8> {
    two_ag(0xb4b4)
}
