//! P6 — v5 CRC32c self-describing-metadata verification tests.
//!
//! Two tiers, both anchored on the real minted images (`xfsprogs` is the
//! independent CRC author — the oracle):
//!
//! - **Positive (Tier-1):** every metadata block read from the UNMODIFIED
//!   `v5.img` / `v5frag.img` verifies `crc_valid == Some(true)` — superblock,
//!   AG-0 AGF/AGI/AGFL, root inode 128, a directory data block, and a `BMA3`
//!   bmbt block. A wrong offset / coverage / polynomial fails here, so this test
//!   IS the oracle proving the computation matches what `xfsprogs` wrote.
//! - **Negative + v4 + bounds (robustness):** flipping one byte flips
//!   `crc_valid` to `Some(false)`; a v4 structure reports `None` (no CRC); a
//!   too-short buffer verifies as `false` without panicking.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use xfs::{
    crc_status, verify_bmbt_block_crc, verify_crc, verify_dir_block_crc, Agf, Agfl, Agi, Inode,
    Superblock,
};

const SECTOR: usize = 512;

/// v5.img geometry (from `tests/data/README.md` / the P0 oracle): blocksize
/// 4096, inodesize 512, root inode 128.
const V5_BLOCKSIZE: usize = 4096;

/// v5frag.img holds the `BMA3` bmbt leaf at filesystem block 64 (its inode 131
/// is `btree`-format with three leaf blocks at fsblocks 64 / 558 / 1101).
const V5FRAG_BMBT_FSBLOCK: usize = 64;

fn data_path(name: &str) -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // core/ -> repo root
    d.push("tests/data");
    d.push(name);
    d
}

fn image_bytes(env: &str, default_name: &str) -> Option<Vec<u8>> {
    let p = std::env::var(env).map_or_else(|_| data_path(default_name), PathBuf::from);
    p.exists().then(|| std::fs::read(&p).unwrap())
}

/// Slice one sector at `sector` from an AG-0-based image.
fn sect(img: &[u8], sector: usize) -> &[u8] {
    &img[sector * SECTOR..(sector + 1) * SECTOR]
}

/// Slice one filesystem block (`V5_BLOCKSIZE`) at `fsblock`.
fn block(img: &[u8], fsblock: usize) -> &[u8] {
    &img[fsblock * V5_BLOCKSIZE..(fsblock + 1) * V5_BLOCKSIZE]
}

/// Scan a v5 image for the first block whose 32-bit magic at offset 0 equals
/// `magic` (used to find a real `XDD3` dir data block or `XDB3` single block).
fn find_block_by_magic(img: &[u8], magic: u32) -> Option<&[u8]> {
    let mut b = 0;
    while b + V5_BLOCKSIZE <= img.len() {
        if u32::from_be_bytes([img[b], img[b + 1], img[b + 2], img[b + 3]]) == magic {
            return Some(&img[b..b + V5_BLOCKSIZE]);
        }
        b += V5_BLOCKSIZE;
    }
    None
}

// ---------------------------------------------------------------------------
// Positive: every UNMODIFIED v5 metadata block verifies Some(true) (the oracle)
// ---------------------------------------------------------------------------

#[test]
fn v5_superblock_crc_verifies() {
    let Some(img) = image_bytes("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let sb = Superblock::parse(sect(&img, 0)).expect("v5 sb parses");
    assert_eq!(
        sb.crc_valid,
        Some(true),
        "unmodified v5 superblock CRC must verify (oracle: xfsprogs wrote it)"
    );
}

#[test]
fn v5_agf_agi_agfl_crc_verify() {
    let Some(img) = image_bytes("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let agf = Agf::parse_verified(sect(&img, 1), true).expect("AGF parses");
    assert_eq!(agf.crc_valid, Some(true), "v5 AGF CRC must verify");

    let agi = Agi::parse_verified(sect(&img, 2), true).expect("AGI parses");
    assert_eq!(agi.crc_valid, Some(true), "v5 AGI CRC must verify");

    let agfl = Agfl::parse_v5(sect(&img, 3), SECTOR as u32).expect("AGFL parses");
    assert_eq!(agfl.crc_valid, Some(true), "v5 AGFL CRC must verify");
}

#[test]
fn v5_root_inode_crc_verifies() {
    let Some(img) = image_bytes("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let sb = Superblock::parse(sect(&img, 0)).expect("sb parses");
    let inode = sb.read_inode(&img, 128).expect("root inode 128 reads");
    assert_eq!(
        inode.crc_valid,
        Some(true),
        "unmodified v5 root inode 128 CRC must verify"
    );
    // The raw stored value is also surfaced (P2 already exposed `crc`).
    assert!(inode.crc.is_some(), "v3 inode carries a stored di_crc");
}

#[test]
fn v5_dir_data_block_crc_verifies() {
    let Some(img) = image_bytes("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    // A leaf directory's DATA block carries magic XDD3 (0x58444433).
    let blk = find_block_by_magic(&img, 0x5844_4433).expect("an XDD3 dir data block exists");
    assert_eq!(
        verify_dir_block_crc(blk),
        Some(true),
        "unmodified v5 XDD3 dir data block CRC must verify"
    );
}

#[test]
fn v5_dir_leaf_node_block_crc_verifies() {
    let Some(img) = image_bytes("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    // A v5 dir leaf / node / freeindex block carries `xfs_da3_blkinfo` with a
    // 16-bit magic at block offset 8 (0x3df1 leaf1 / 0x3dff leafn / 0x3ebe node)
    // and its CRC at offset 12. Find the first such block and verify it.
    let mut b = 0;
    let mut checked = false;
    while b + V5_BLOCKSIZE <= img.len() {
        let blk = &img[b..b + V5_BLOCKSIZE];
        let magic16 = u16::from_be_bytes([blk[8], blk[9]]);
        if matches!(magic16, 0x3df1 | 0x3dff | 0x3ebe) {
            assert_eq!(
                verify_dir_block_crc(blk),
                Some(true),
                "unmodified v5 dir leaf/node block (magic {magic16:#06x}) CRC must verify"
            );
            checked = true;
            break;
        }
        b += V5_BLOCKSIZE;
    }
    assert!(
        checked,
        "the leaf directory yields at least one da3 leaf/node block"
    );
}

#[test]
fn v4_dir_data_block_reports_none() {
    // A v4 single-block dir header (`XD2B`, 0x58443242) carries no CRC -> None.
    // (The v4 oracle uses short-form dirs, so this is a crafted header — the
    // point is only that a recognized v4 magic yields None, not a false
    // mismatch.)
    let mut blk = vec![0u8; V5_BLOCKSIZE];
    blk[0..4].copy_from_slice(&0x5844_3242u32.to_be_bytes()); // "XD2B"
    assert_eq!(
        verify_dir_block_crc(&blk),
        None,
        "v4 XD2B dir block -> None"
    );
    // And the v4 multi-block data magic `XD2D` (0x58443244) likewise.
    blk[0..4].copy_from_slice(&0x5844_3244u32.to_be_bytes()); // "XD2D"
    assert_eq!(
        verify_dir_block_crc(&blk),
        None,
        "v4 XD2D dir block -> None"
    );
}

#[test]
fn v5_bmbt_block_crc_verifies() {
    let Some(img) = image_bytes("XFS_ORACLE_V5FRAG_IMG", "v5frag.img") else {
        eprintln!("skip: v5frag image absent");
        return;
    };
    let blk = block(&img, V5FRAG_BMBT_FSBLOCK);
    // Sanity: this really is a BMA3 leaf.
    assert_eq!(
        &blk[0..4],
        &[0x42, 0x4d, 0x41, 0x33],
        "fsblock 64 is a BMA3 bmbt block"
    );
    assert_eq!(
        verify_bmbt_block_crc(blk),
        Some(true),
        "unmodified v5 BMA3 bmbt block CRC must verify"
    );
}

// ---------------------------------------------------------------------------
// Negative: a single flipped byte makes the CRC fail (detection works)
// ---------------------------------------------------------------------------

#[test]
fn flipped_byte_breaks_superblock_crc() {
    let Some(img) = image_bytes("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let mut sector = sect(&img, 0).to_vec();
    // Flip a byte OUTSIDE the CRC field (e.g. byte 0x20, part of sb_uuid) so the
    // covered data changes while the stored CRC stays put -> mismatch.
    sector[0x20] ^= 0xff;
    let sb = Superblock::parse(&sector).expect("still parses (bad CRC is non-fatal)");
    assert_eq!(
        sb.crc_valid,
        Some(false),
        "a flipped data byte must make the superblock CRC fail"
    );
}

#[test]
fn flipped_byte_breaks_inode_crc() {
    let Some(img) = image_bytes("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    // Root inode 128 lives at byte 65536 (agblock 16 * blocksize 4096).
    let mut ino = img[65536..65536 + SECTOR].to_vec();
    ino[0x18] ^= 0x01; // flip a byte in the covered region (di_nlink area)
    let inode = Inode::parse(&ino).expect("still parses (non-fatal)");
    assert_eq!(
        inode.crc_valid,
        Some(false),
        "a flipped byte must make the inode CRC fail"
    );
}

#[test]
fn flipped_byte_breaks_bmbt_crc() {
    let Some(img) = image_bytes("XFS_ORACLE_V5FRAG_IMG", "v5frag.img") else {
        eprintln!("skip: v5frag image absent");
        return;
    };
    let mut blk = block(&img, V5FRAG_BMBT_FSBLOCK).to_vec();
    blk[100] ^= 0xff; // a byte well inside the covered block, past the header
    assert_eq!(
        verify_bmbt_block_crc(&blk),
        Some(false),
        "a flipped byte must make the bmbt block CRC fail"
    );
}

// ---------------------------------------------------------------------------
// v4: no CRC -> None everywhere
// ---------------------------------------------------------------------------

#[test]
fn v4_superblock_and_inode_report_none() {
    let Some(img) = image_bytes("XFS_ORACLE_V4_IMG", "v4.img") else {
        eprintln!("skip: v4 image absent");
        return;
    };
    let sb = Superblock::parse(sect(&img, 0)).expect("v4 sb parses");
    assert!(!sb.is_v5(), "the v4 oracle image is v4");
    assert_eq!(sb.crc_valid, None, "v4 superblock has no CRC -> None");

    // v4 root inode 128: v4 inodesize is 256, agblock = 128 >> inopblog(4) = 8,
    // byte = 8 * 4096 = 32768.
    let inode = sb.read_inode(&img, 128).expect("v4 root inode reads");
    assert_eq!(inode.version, 2, "v4 uses v2 inode core");
    assert_eq!(inode.crc_valid, None, "v2 inode has no CRC -> None");
    assert_eq!(inode.crc, None, "v2 inode has no stored di_crc");
}

#[test]
fn v4_ag_headers_report_none() {
    let Some(img) = image_bytes("XFS_ORACLE_V4_IMG", "v4.img") else {
        eprintln!("skip: v4 image absent");
        return;
    };
    // parse_verified with is_v5=false must report None (no false-positive
    // bad-CRC on a v4 header whose "crc offset" is reserved/spare bytes).
    let agf = Agf::parse_verified(sect(&img, 1), false).expect("v4 AGF parses");
    assert_eq!(agf.crc_valid, None, "v4 AGF -> None");
    let agi = Agi::parse_verified(sect(&img, 2), false).expect("v4 AGI parses");
    assert_eq!(agi.crc_valid, None, "v4 AGI -> None");
    // v4 AGFL is a bare ring with no header/CRC.
    let agfl = Agfl::parse_v4(sect(&img, 3), SECTOR as u32);
    assert_eq!(agfl.crc_valid, None, "v4 AGFL -> None");
}

#[test]
fn version_agnostic_parse_leaves_crc_none() {
    let Some(img) = image_bytes("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    // The plain (version-agnostic) AGF/AGI parse does not claim a CRC status.
    let agf = Agf::parse(sect(&img, 1)).expect("AGF parses");
    assert_eq!(agf.crc_valid, None, "plain parse() leaves crc_valid None");
    let agi = Agi::parse(sect(&img, 2)).expect("AGI parses");
    assert_eq!(agi.crc_valid, None, "plain parse() leaves crc_valid None");
}

// ---------------------------------------------------------------------------
// Bounds / robustness: short buffers and unknown magics never panic
// ---------------------------------------------------------------------------

#[test]
fn verify_crc_short_buffer_is_false_not_panic() {
    // Buffer too short to hold the CRC field at the given offset -> false.
    assert!(!verify_crc(&[0u8; 4], 224), "224+4 > 4 -> false");
    assert!(!verify_crc(&[], 0), "empty buffer -> false");
    // A hostile offset near usize::MAX must not overflow-panic -> false.
    assert!(
        !verify_crc(&[0u8; 512], usize::MAX),
        "usize::MAX offset -> false, no panic"
    );
    assert!(
        !verify_crc(&[0u8; 512], usize::MAX - 2),
        "offset whose +4 overflows -> false"
    );
    // crc_status wraps it: v5 + short -> Some(false); v4 -> None regardless.
    assert_eq!(crc_status(true, &[0u8; 2], 224), Some(false));
    assert_eq!(crc_status(false, &[0u8; 2], 224), None);
}

#[test]
fn verify_dir_and_bmbt_crc_unknown_magic_is_none() {
    // A block with a magic matching neither v5 nor v4 dir/bmbt magic -> None
    // (no CRC claim, never a false mismatch).
    let junk = vec![0xAAu8; V5_BLOCKSIZE];
    assert_eq!(verify_dir_block_crc(&junk), None, "unknown magic -> None");
    assert_eq!(verify_bmbt_block_crc(&junk), None, "unknown magic -> None");
    // A v4 (BMAP) bmbt block -> None.
    let mut v4bmbt = vec![0u8; V5_BLOCKSIZE];
    v4bmbt[0..4].copy_from_slice(&[0x42, 0x4d, 0x41, 0x50]); // "BMAP"
    assert_eq!(verify_bmbt_block_crc(&v4bmbt), None, "v4 BMAP -> None");
}
