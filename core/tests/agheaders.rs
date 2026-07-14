//! P1 AG-header tests (AGF / AGI / AGFL).
//!
//! Oracle-gated (Tier-1): read AG 0's three headers from the real minted
//! images and assert every field equals the committed `xfs_db` dumps:
//!   - `tests/data/v5.agf0.txt`  / `v4.agf0.txt`  (`xfs_db agf 0 print`)
//!   - `tests/data/v5.agi0.txt`  / `v4.agi0.txt`  (`xfs_db agi 0 print`)
//!   - `tests/data/v5.agfl0.txt` / `v4.agfl0.txt` (`xfs_db agfl 0 print`)
//!
//! Confirmed layout (sectorsize 512): SB at sector 0, AGF at sector 1,
//! AGI at sector 2, AGFL at sector 3 — the AG base byte is
//! `agno * agblocks * blocksize` (0 for AG 0).
//!
//! Plus robustness: bad magic fails loud with the offending value; a truncated
//! buffer returns `Truncated`, never panics.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use xfs::{Agf, Agfl, Agi, XFS_AGFL_MAGIC, XFS_AGF_MAGIC, XFS_AGI_MAGIC};

const SECTOR: usize = 512;

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

/// Slice one sector (`SECTOR` bytes) at `sector` from an AG-0-based image.
fn sect(img: &[u8], sector: usize) -> &[u8] {
    &img[sector * SECTOR..(sector + 1) * SECTOR]
}

#[test]
fn v5_agf0_matches_oracle() {
    let Some(img) = image_bytes("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let agf = Agf::parse(sect(&img, 1)).expect("AGF parses");

    // Ground truth: tests/data/v5.agf0.txt.
    assert_eq!(agf.magicnum, XFS_AGF_MAGIC, "magicnum");
    assert_eq!(agf.versionnum, 1, "versionnum");
    assert_eq!(agf.seqno, 0, "seqno");
    assert_eq!(agf.length, 32768, "length");
    assert_eq!(agf.bno_root, 1, "bnoroot");
    assert_eq!(agf.cnt_root, 2, "cntroot");
    assert_eq!(agf.rmap_root, 5, "rmaproot");
    assert_eq!(agf.bno_level, 1, "bnolevel");
    assert_eq!(agf.cnt_level, 1, "cntlevel");
    assert_eq!(agf.rmap_level, 1, "rmaplevel");
    assert_eq!(agf.flfirst, 1, "flfirst");
    assert_eq!(agf.fllast, 6, "fllast");
    assert_eq!(agf.flcount, 6, "flcount");
    assert_eq!(agf.freeblks, 28648, "freeblks");
    assert_eq!(agf.longest, 28648, "longest");
    assert_eq!(agf.btreeblks, 0, "btreeblks");
    assert_eq!(agf.rmap_blocks, 1, "rmapblocks");
    assert_eq!(agf.refcount_blocks, 1, "refcntblocks");
    assert_eq!(agf.refcount_root, 6, "refcntroot");
    assert_eq!(agf.refcount_level, 1, "refcntlevel");
}

#[test]
fn v4_agf0_matches_oracle() {
    let Some(img) = image_bytes("XFS_ORACLE_V4_IMG", "v4.img") else {
        eprintln!("skip: v4 image absent");
        return;
    };
    let agf = Agf::parse(sect(&img, 1)).expect("AGF parses");

    // Ground truth: tests/data/v4.agf0.txt (no rmap/refcount btrees on v4).
    assert_eq!(agf.magicnum, XFS_AGF_MAGIC, "magicnum");
    assert_eq!(agf.versionnum, 1, "versionnum");
    assert_eq!(agf.length, 32768, "length");
    assert_eq!(agf.bno_root, 1, "bnoroot");
    assert_eq!(agf.cnt_root, 2, "cntroot");
    assert_eq!(agf.bno_level, 1, "bnolevel");
    assert_eq!(agf.cnt_level, 1, "cntlevel");
    assert_eq!(agf.rmap_level, 0, "rmaplevel (v4: no rmapbt)");
    assert_eq!(agf.flfirst, 1, "flfirst");
    assert_eq!(agf.fllast, 4, "fllast");
    assert_eq!(agf.flcount, 4, "flcount");
    assert_eq!(agf.freeblks, 32756, "freeblks");
    assert_eq!(agf.longest, 32756, "longest");
    assert_eq!(agf.btreeblks, 0, "btreeblks");
    assert_eq!(agf.rmap_blocks, 0, "rmapblocks (v4)");
    assert_eq!(agf.refcount_blocks, 0, "refcntblocks (v4)");
}

#[test]
fn v5_agi0_matches_oracle_incl_unlinked() {
    let Some(img) = image_bytes("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let agi = Agi::parse(sect(&img, 2)).expect("AGI parses");

    // Ground truth: tests/data/v5.agi0.txt.
    assert_eq!(agi.magicnum, XFS_AGI_MAGIC, "magicnum");
    assert_eq!(agi.versionnum, 1, "versionnum");
    assert_eq!(agi.seqno, 0, "seqno");
    assert_eq!(agi.length, 32768, "length");
    assert_eq!(agi.count, 64, "count");
    assert_eq!(agi.root, 3, "root");
    assert_eq!(agi.level, 1, "level");
    assert_eq!(agi.freecount, 56, "freecount");
    assert_eq!(agi.newino, 128, "newino");
    assert_eq!(agi.dirino, 0xffff_ffff, "dirino = null");
    // v5.agi0.txt shows 'unlinked[0-63] =' with no entries -> all null (-1).
    assert!(
        agi.unlinked.iter().all(|&b| b == 0xffff_ffff),
        "all unlinked buckets null"
    );
    assert_eq!(agi.unlinked.len(), 64, "64 unlinked buckets");
    // v5 tail (finobt + inobtcount):
    assert_eq!(agi.free_root, 4, "free_root");
    assert_eq!(agi.free_level, 1, "free_level");
    assert_eq!(agi.ino_blocks, 1, "ino_blocks");
    assert_eq!(agi.fino_blocks, 1, "fino_blocks");
}

#[test]
fn v4_agi0_matches_oracle() {
    let Some(img) = image_bytes("XFS_ORACLE_V4_IMG", "v4.img") else {
        eprintln!("skip: v4 image absent");
        return;
    };
    let agi = Agi::parse(sect(&img, 2)).expect("AGI parses");

    // Ground truth: tests/data/v4.agi0.txt.
    assert_eq!(agi.magicnum, XFS_AGI_MAGIC, "magicnum");
    assert_eq!(agi.count, 64, "count");
    assert_eq!(agi.root, 3, "root");
    assert_eq!(agi.level, 1, "level");
    assert_eq!(agi.freecount, 61, "freecount");
    assert_eq!(agi.newino, 128, "newino");
    assert_eq!(agi.dirino, 0xffff_ffff, "dirino = null");
    assert!(
        agi.unlinked.iter().all(|&b| b == 0xffff_ffff),
        "all unlinked buckets null"
    );
    // v4 has no finobt/inobtcount -> tail fields read 0.
    assert_eq!(agi.free_root, 0, "free_root (v4)");
    assert_eq!(agi.ino_blocks, 0, "ino_blocks (v4)");
}

#[test]
fn v5_agfl0_matches_oracle() {
    let Some(img) = image_bytes("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let agfl = Agfl::parse_v5(sect(&img, 3), SECTOR as u32).expect("AGFL parses");

    // Ground truth: tests/data/v5.agfl0.txt.
    assert_eq!(agfl.magicnum, Some(XFS_AGFL_MAGIC), "magicnum XAFL");
    assert_eq!(agfl.seqno, Some(0), "seqno");
    // v5 ring = (512 - 36) / 4 = 119 slots.
    assert_eq!(agfl.bno.len(), 119, "v5 AGFL slot count");
    // bno[0]=null, bno[1..=6] = 7..12 (matches agf.flfirst=1, fllast=6), rest null.
    assert_eq!(agfl.bno[0], 0xffff_ffff, "bno[0] null");
    assert_eq!(
        &agfl.bno[1..7],
        &[7, 8, 9, 10, 11, 12],
        "bno[1..=6] free ring"
    );
    assert!(
        agfl.bno[7..].iter().all(|&b| b == 0xffff_ffff),
        "bno[7..] all null"
    );
}

#[test]
fn v4_agfl0_matches_oracle() {
    let Some(img) = image_bytes("XFS_ORACLE_V4_IMG", "v4.img") else {
        eprintln!("skip: v4 image absent");
        return;
    };
    let agfl = Agfl::parse_v4(sect(&img, 3), SECTOR as u32);

    // Ground truth: tests/data/v4.agfl0.txt — bare ring, no header.
    assert_eq!(agfl.magicnum, None, "v4 AGFL has no header magic");
    assert_eq!(agfl.seqno, None, "v4 AGFL has no header seqno");
    // v4 ring = 512 / 4 = 128 slots.
    assert_eq!(agfl.bno.len(), 128, "v4 AGFL slot count");
    assert_eq!(agfl.bno[0], 0xffff_ffff, "bno[0] null");
    assert_eq!(&agfl.bno[1..5], &[4, 5, 6, 7], "bno[1..=4] free ring");
    assert!(
        agfl.bno[5..].iter().all(|&b| b == 0xffff_ffff),
        "bno[5..] all null"
    );
}

// ---- robustness ----

#[test]
fn agf_bad_magic_fails_loud() {
    let mut d = vec![0u8; SECTOR];
    d[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    match Agf::parse(&d).unwrap_err() {
        xfs::XfsError::BadMagic { found, bytes } => {
            assert_eq!(found, 0xDEAD_BEEF);
            assert_eq!(bytes, [0xDE, 0xAD, 0xBE, 0xEF]);
        }
        other => panic!("expected BadMagic, got {other:?}"),
    }
}

#[test]
fn agi_bad_magic_fails_loud() {
    let mut d = vec![0u8; SECTOR];
    d[0..4].copy_from_slice(&[0x00, 0x11, 0x22, 0x33]);
    match Agi::parse(&d).unwrap_err() {
        xfs::XfsError::BadMagic { found, .. } => assert_eq!(found, 0x0011_2233),
        other => panic!("expected BadMagic, got {other:?}"),
    }
}

#[test]
fn agfl_v5_bad_magic_fails_loud() {
    let mut d = vec![0u8; SECTOR];
    d[0..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    match Agfl::parse_v5(&d, SECTOR as u32).unwrap_err() {
        xfs::XfsError::BadMagic { found, .. } => assert_eq!(found, 0xAABB_CCDD),
        other => panic!("expected BadMagic, got {other:?}"),
    }
}

#[test]
fn truncated_headers_do_not_panic() {
    // Valid magics but far too short.
    let mut agf = vec![0u8; 8];
    agf[0..4].copy_from_slice(&XFS_AGF_MAGIC.to_be_bytes());
    assert!(matches!(
        Agf::parse(&agf).unwrap_err(),
        xfs::XfsError::Truncated { .. }
    ));

    let mut agi = vec![0u8; 8];
    agi[0..4].copy_from_slice(&XFS_AGI_MAGIC.to_be_bytes());
    assert!(matches!(
        Agi::parse(&agi).unwrap_err(),
        xfs::XfsError::Truncated { .. }
    ));

    let mut agfl = vec![0u8; 8];
    agfl[0..4].copy_from_slice(&XFS_AGFL_MAGIC.to_be_bytes());
    assert!(matches!(
        Agfl::parse_v5(&agfl, SECTOR as u32).unwrap_err(),
        xfs::XfsError::Truncated { .. }
    ));

    // v4 AGFL is infallible (bare ring); a short buffer just yields fewer /
    // zero-padded slots without panicking.
    let short = vec![0u8; 6];
    let a = Agfl::parse_v4(&short, SECTOR as u32);
    assert_eq!(a.bno.len(), 128, "slot count fixed by sectorsize");
}

/// The minted images have an empty `unlinked[64]` (no orphaned inodes), so the
/// oracle asserts only exercise the all-null case. This hand-built AGI puts a
/// non-null AG-inode number in a specific bucket to prove the array is indexed
/// at the right offset/stride (bucket i at byte `40 + i*4`) — the forensically
/// load-bearing decode when a real image DOES carry orphaned-open inodes.
#[test]
fn agi_unlinked_bucket_indexing() {
    let mut d = vec![0xffu8; SECTOR]; // all buckets null by default
    d[0..4].copy_from_slice(&XFS_AGI_MAGIC.to_be_bytes());
    // Bucket 5 -> AG-relative inode 0x1234; bucket 63 -> 0x00AB_CDEF.
    d[40 + 5 * 4..40 + 5 * 4 + 4].copy_from_slice(&0x0000_1234u32.to_be_bytes());
    d[40 + 63 * 4..40 + 63 * 4 + 4].copy_from_slice(&0x00AB_CDEFu32.to_be_bytes());

    let agi = Agi::parse(&d).expect("parses");
    assert_eq!(agi.unlinked[5], 0x0000_1234, "bucket 5 decoded at 40+5*4");
    assert_eq!(
        agi.unlinked[63], 0x00AB_CDEF,
        "last bucket decoded at 40+63*4"
    );
    assert_eq!(agi.unlinked[0], 0xffff_ffff, "untouched buckets stay null");
    assert_eq!(agi.unlinked[4], 0xffff_ffff);
    assert_eq!(agi.unlinked[6], 0xffff_ffff);
}
