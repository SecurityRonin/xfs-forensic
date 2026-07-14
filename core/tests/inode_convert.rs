//! P1 inode-number decode tests.
//!
//! `Superblock::inode_to_location` MUST reproduce `xfs_db convert` exactly — a
//! Tier-1 structural check. The ground-truth cases below are grepped verbatim
//! from the committed oracle dumps:
//!
//! - `tests/data/v5.convert_root.txt` — ino 128 (rootino)
//! - `tests/data/v5.convert_big.txt`  — ino 135 (big.bin)
//! - `tests/data/v5.convert_agspan.txt` — ino 262272 (AG 1), ino 655488 (AG 2)
//!
//! The oracle prints, in order, `agno / agino / agblock / offset [/ fsblock]`.
//! Byte position is derived from the same geometry
//! (`fsblock * blocksize + offset * inodesize`) and cross-checked against the
//! inode dumps (`xfs_db inode N print` reads exactly those bytes).
//!
//! Env-gated on the image path so the oracle assertions run when the minted
//! corpus is present and skip cleanly when it is absent (mirrors the P0 style).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use xfs::{InodeLocation, Superblock};

/// Resolve the image path from an env var, falling back to `tests/data/<name>`.
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

fn read_sb(env: &str, default_name: &str) -> Option<Superblock> {
    let path = image_path(env, default_name)?;
    let data = std::fs::read(&path).unwrap();
    Some(Superblock::parse(&data[..512.min(data.len())]).expect("superblock parses"))
}

/// Assert a full decode against the oracle's five convert fields plus the
/// derived byte position.
#[allow(clippy::too_many_arguments)]
fn assert_loc(
    sb: &Superblock,
    ino: u64,
    agno: u64,
    agino: u64,
    agblock: u64,
    offset: u64,
    fsblock: u64,
) {
    let want = InodeLocation {
        agno,
        agino,
        agblock,
        offset,
        fsblock,
        byte_offset: fsblock * u64::from(sb.blocksize) + offset * u64::from(sb.inodesize),
    };
    assert_eq!(sb.inode_to_location(ino), want, "decode of ino {ino}");
}

#[test]
fn v5_convert_matches_oracle() {
    let Some(sb) = read_sb("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent (set XFS_ORACLE_V5_IMG or mint tests/data/v5.img)");
        return;
    };

    // v5.convert_root.txt:  agno 0, agino 64, agblock 8, offset 0
    //   (root file has no fsblock line; fsblock = 0*32768 + 8 = 8).
    assert_loc(&sb, 128, 0, 64, 8, 0, 8);

    // v5.convert_big.txt:   agno 0, agino 135, agblock 16, offset 7, fsblock 16.
    assert_loc(&sb, 135, 0, 135, 16, 7, 16);

    // v5.convert_agspan.txt (ino 262272): agno 1, agino 128, agblock 16,
    //   offset 0, fsblock 32784.
    assert_loc(&sb, 262272, 1, 128, 16, 0, 32784);

    // v5.convert_agspan.txt (ino 655488): agno 2, agino 131200, agblock 16400,
    //   offset 0, fsblock 81936.
    assert_loc(&sb, 655488, 2, 131200, 16400, 0, 81936);
}

#[test]
fn v4_root_decode() {
    // v4 shift fields: agblklog=15, inopblog=4 -> shift 19; agblocks=32768,
    // blocksize=4096, inodesize=256. rootino=128:
    //   agno = 128 >> 19 = 0
    //   agino = 128 & 0x7ffff = 128
    //   agblock = 128 >> 4 = 8
    //   offset  = 128 & 0xf = 0
    //   fsblock = 0*32768 + 8 = 8
    //   byte    = 8*4096 + 0*256 = 32768
    let Some(sb) = read_sb("XFS_ORACLE_V4_IMG", "v4.img") else {
        eprintln!("skip: v4 image absent (set XFS_ORACLE_V4_IMG or mint tests/data/v4.img)");
        return;
    };
    assert_eq!(sb.inopblog, 4, "v4 inopblog (16 inodes/block)");
    assert_loc(&sb, 128, 0, 128, 8, 0, 8);
}

// ---- robustness: hostile/edge inode numbers must never panic ----

/// A hand-built superblock with the v5 minted geometry, for edge tests that
/// do not need the image on disk.
fn synthetic_v5_geometry() -> Superblock {
    // Build the minimum bytes and parse, so the test exercises the real ctor.
    let mut d = vec![0u8; 512];
    d[0..4].copy_from_slice(&xfs::XFS_SB_MAGIC.to_be_bytes());
    d[4..8].copy_from_slice(&4096u32.to_be_bytes()); // blocksize
    d[56..64].copy_from_slice(&128u64.to_be_bytes()); // rootino
    d[84..88].copy_from_slice(&32768u32.to_be_bytes()); // agblocks
    d[88..92].copy_from_slice(&4u32.to_be_bytes()); // agcount
    d[100..102].copy_from_slice(&0xb4a5u16.to_be_bytes()); // versionnum v5
    d[104..106].copy_from_slice(&512u16.to_be_bytes()); // inodesize
    d[106..108].copy_from_slice(&8u16.to_be_bytes()); // inopblock
    d[120] = 12; // blocklog
    d[122] = 9; // inodelog
    d[123] = 3; // inopblog
    d[124] = 15; // agblklog
    Superblock::parse(&d).expect("synthetic superblock parses")
}

#[test]
fn ino_zero_decodes_to_origin() {
    let sb = synthetic_v5_geometry();
    let loc = sb.inode_to_location(0);
    assert_eq!(
        loc,
        InodeLocation {
            agno: 0,
            agino: 0,
            agblock: 0,
            offset: 0,
            fsblock: 0,
            byte_offset: 0,
        }
    );
}

#[test]
fn huge_ino_does_not_panic() {
    let sb = synthetic_v5_geometry();
    // u64::MAX must not overflow the fsblock/byte multiplies.
    let loc = sb.inode_to_location(u64::MAX);
    // shift = 15 + 3 = 18; agno = MAX >> 18; agino = low 18 bits (all set).
    assert_eq!(loc.agno, u64::MAX >> 18);
    assert_eq!(loc.agino, (1u64 << 18) - 1);
    // fsblock = agno*32768 + agblock would overflow u64 -> saturates.
    assert_eq!(loc.fsblock, u64::MAX, "fsblock saturates rather than wraps");
    assert_eq!(loc.byte_offset, u64::MAX, "byte_offset saturates");
}

#[test]
fn absurd_shift_fields_do_not_panic() {
    // A malformed image can carry shift fields >= 64. The decode must clamp,
    // never trigger a shift-overflow panic.
    let mut d = vec![0u8; 512];
    d[0..4].copy_from_slice(&xfs::XFS_SB_MAGIC.to_be_bytes());
    d[4..8].copy_from_slice(&4096u32.to_be_bytes());
    d[84..88].copy_from_slice(&32768u32.to_be_bytes());
    d[104..106].copy_from_slice(&512u16.to_be_bytes());
    d[120] = 255; // blocklog
    d[122] = 255; // inodelog
    d[123] = 200; // inopblog >= 64
    d[124] = 200; // agblklog >= 64
    let sb = Superblock::parse(&d).expect("parses");
    // Must return without panicking; values are clamped, we only assert no UB.
    let _ = sb.inode_to_location(0xDEAD_BEEF_1234_5678);
    let _ = sb.inode_to_location(0);
}
