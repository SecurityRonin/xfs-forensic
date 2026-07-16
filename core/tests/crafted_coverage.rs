//! Always-on crafted-fixture coverage tests.
//!
//! These exercise reader paths that the genuine Tier-1 images reach only when
//! the large env-gated oracles (`XFS_ORACLE_V5_IMG` / `…_V4_IMG` / `…_V5FRAG_IMG`)
//! are present — the v5 self-describing-metadata CRC verifiers on real block
//! magics, the v5 AGFL (`XAFL`) parse, the block / multi-block / btree directory
//! `read_dir` dispatch, the btree-format `read_file` arm, the `read_by_path`
//! not-found arms, and two inode accessors. On a CI runner with only committed
//! data those oracle tests skip, leaving these lines uncovered; the crafted
//! fixtures below (and the always-on committed `xfs_dfvfs.raw`) drive them
//! directly so the 100%-line gate holds without an external oracle.
//!
//! The structures are crafted VALID (correct magics and coherent geometry) so
//! the reader genuinely walks into each line — never a special case in the
//! reader to reach it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use xfs::{
    read_by_path, verify_bmbt_block_crc, verify_dir_block_crc, Agfl, Inode, InodeFormat,
    Superblock, XfsError, XFS_AGFL_MAGIC, XFS_BMAP_CRC_MAGIC, XFS_DIR3_BLOCK_MAGIC,
    XFS_DIR3_DATA_MAGIC,
};

// ── shared crafted geometry ───────────────────────────────────────────────────

const BLOCKSIZE: u32 = 4096;
const XFSB: u32 = 0x5846_5342;

/// A minimal v5 superblock at offset 0 (blocksize 4096, inodesize 512, single
/// AG, `has_ftype`). Mirrors the geometry the other crafted core tests use.
fn v5_sb(img: &mut [u8]) {
    img[0..4].copy_from_slice(&XFSB.to_be_bytes());
    img[4..8].copy_from_slice(&BLOCKSIZE.to_be_bytes());
    img[56..64].copy_from_slice(&128u64.to_be_bytes()); // rootino
    img[84..88].copy_from_slice(&32768u32.to_be_bytes()); // agblocks
    img[88..92].copy_from_slice(&1u32.to_be_bytes()); // agcount
    img[100..102].copy_from_slice(&0xb4a5u16.to_be_bytes()); // v5
    img[104..106].copy_from_slice(&512u16.to_be_bytes()); // inodesize
    img[106..108].copy_from_slice(&8u16.to_be_bytes()); // inopblock
    img[120] = 12; // blocklog
    img[122] = 9; // inodelog
    img[123] = 3; // inopblog
    img[124] = 15; // agblklog
    img[216..220].copy_from_slice(&1u32.to_be_bytes()); // features_incompat FTYPE
}

/// Pack a 16-byte `xfs_bmbt_rec` (kernel layout), unwritten = false.
fn pack(startoff: u64, startblock: u64, blockcount: u64) -> [u8; 16] {
    let sb_hi = (startblock >> 43) & ((1 << 9) - 1);
    let sb_lo = startblock & ((1 << 43) - 1);
    let l0 = ((startoff & ((1 << 54) - 1)) << 9) | sb_hi;
    let l1 = (sb_lo << 21) | (blockcount & ((1 << 21) - 1));
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&l0.to_be_bytes());
    out[8..].copy_from_slice(&l1.to_be_bytes());
    out
}

/// Stamp a v3 inode core at `img[off..]` with the given mode / format / size and
/// an inline data fork (the packed extents) starting at the v3 fork offset 176.
fn stamp_inode(
    img: &mut [u8],
    off: usize,
    mode: u16,
    format: u8,
    size: u64,
    nextents: u32,
    fork: &[u8],
) {
    img[off..off + 2].copy_from_slice(&0x494eu16.to_be_bytes()); // "IN"
    img[off + 2..off + 4].copy_from_slice(&mode.to_be_bytes());
    img[off + 4] = 3; // di_version = v3
    img[off + 5] = format; // di_format
    img[off + 56..off + 64].copy_from_slice(&size.to_be_bytes()); // di_size
    img[off + 76..off + 80].copy_from_slice(&nextents.to_be_bytes()); // di_nextents
    let fork_off = off + 176;
    img[fork_off..fork_off + fork.len()].copy_from_slice(fork);
}

// ── v5 CRC verifiers on real block magics (btree.rs:89, dir.rs:302/313) ────────

#[test]
fn verify_bmbt_block_crc_on_bma3_block_returns_some() {
    // A v5 `BMA3` bmbt block: the verifier must take the CRC-claim arm (not the
    // `_ => None` non-bmbt arm). The stored CRC is arbitrary, so it verifies as
    // Some(false) — the point is that a v5 magic yields Some(_), never None.
    let mut block = vec![0u8; 512];
    block[0..4].copy_from_slice(&XFS_BMAP_CRC_MAGIC.to_be_bytes());
    assert_eq!(
        verify_bmbt_block_crc(&block),
        Some(false),
        "a BMA3 block carries a CRC claim (Some), arbitrary CRC -> false"
    );
}

#[test]
fn verify_dir_block_crc_on_v5_data_and_leaf_magics_returns_some() {
    // v5 data / single-block magic (32-bit @0) -> Some (CRC claim).
    let mut data = vec![0u8; 512];
    data[0..4].copy_from_slice(&XFS_DIR3_BLOCK_MAGIC.to_be_bytes());
    assert_eq!(
        verify_dir_block_crc(&data),
        Some(false),
        "XDB3 -> CRC claim"
    );

    let mut d2 = vec![0u8; 512];
    d2[0..4].copy_from_slice(&XFS_DIR3_DATA_MAGIC.to_be_bytes());
    assert_eq!(verify_dir_block_crc(&d2), Some(false), "XDD3 -> CRC claim");

    // v5 leaf magic (16-bit @8: 0x3df1 = XFS_DIR3_LEAF1_MAGIC) -> Some (CRC claim).
    let mut leaf = vec![0u8; 512];
    leaf[8..10].copy_from_slice(&0x3df1u16.to_be_bytes());
    assert_eq!(
        verify_dir_block_crc(&leaf),
        Some(false),
        "v5 leaf magic -> CRC claim"
    );
}

// ── v5 AGFL (XAFL) parse (agheaders.rs:341-355) ────────────────────────────────

#[test]
fn agfl_v5_parse_reads_header_and_ring() {
    // A crafted v5 AGFL sector: XAFL magic @0, seqno @4, then the bno[] ring at
    // offset 36. Parsing must read the header, size the ring from the sector, and
    // return a CRC status (arbitrary CRC -> Some(false)).
    let sectorsize = 512u32;
    let mut sect = vec![0u8; sectorsize as usize];
    sect[0..4].copy_from_slice(&XFS_AGFL_MAGIC.to_be_bytes());
    sect[4..8].copy_from_slice(&0u32.to_be_bytes()); // seqno 0
                                                     // bno[0] = 42, rest zero.
    sect[36..40].copy_from_slice(&42u32.to_be_bytes());

    let agfl = Agfl::parse_v5(&sect, sectorsize).expect("v5 AGFL parses");
    assert_eq!(agfl.magicnum, Some(XFS_AGFL_MAGIC));
    assert_eq!(agfl.seqno, Some(0));
    assert_eq!(agfl.bno.len(), (512 - 36) / 4, "ring sized from the sector");
    assert_eq!(agfl.bno[0], 42, "first ring slot decoded");
    assert_eq!(agfl.crc_valid, Some(false), "v5 AGFL carries a CRC claim");
}

// ── inode accessors (inode.rs:363-365 is_reg, 378-384 data_fork_offset) ────────

#[test]
fn inode_is_reg_and_data_fork_offset() {
    // A crafted v3 regular-file inode: is_reg() true, data_fork_offset() == 176.
    let mut ib = vec![0u8; 512];
    ib[0..2].copy_from_slice(&0x494eu16.to_be_bytes()); // "IN"
    ib[2..4].copy_from_slice(&0o100_644u16.to_be_bytes()); // S_IFREG
    ib[4] = 3; // v3
    let v3 = Inode::parse(&ib).unwrap();
    assert!(v3.is_reg(), "regular-file inode -> is_reg()");
    assert_eq!(v3.data_fork_offset(), 176, "v3 fork offset");

    // A v2 inode: data_fork_offset() == 100 (the else arm of data_fork_offset).
    let mut v2b = vec![0u8; 128];
    v2b[0..2].copy_from_slice(&0x494eu16.to_be_bytes());
    v2b[2..4].copy_from_slice(&0o100_644u16.to_be_bytes());
    v2b[4] = 2; // v2
    let v2 = Inode::parse(&v2b).unwrap();
    assert!(v2.is_reg());
    assert_eq!(v2.data_fork_offset(), 100, "v2 fork offset");
}

// ── v4 has_ftype via features2 (superblock.rs:148) ─────────────────────────────

#[test]
fn v4_has_ftype_reads_features2_bit() {
    // A crafted v4 superblock (low nibble 4) with the features2 FTYPE bit (0x200)
    // at offset 200 set: has_ftype() must take the v4 branch and read features2.
    let mut img = vec![0u8; 512];
    img[0..4].copy_from_slice(&XFSB.to_be_bytes());
    img[4..8].copy_from_slice(&BLOCKSIZE.to_be_bytes());
    img[100..102].copy_from_slice(&0xb4a4u16.to_be_bytes()); // v4
    img[200..204].copy_from_slice(&0x0000_0200u32.to_be_bytes()); // features2 FTYPE
    let sb = Superblock::parse(&img).unwrap();
    assert!(!sb.is_v5(), "crafted as v4");
    assert!(sb.has_ftype(), "v4 features2 FTYPE bit -> has_ftype()");

    // And a v4 SB without the bit takes the same branch, returns false.
    img[200..204].copy_from_slice(&0u32.to_be_bytes());
    let sb0 = Superblock::parse(&img).unwrap();
    assert!(!sb0.has_ftype(), "v4 without FTYPE bit -> false");
}

// ── block-format directory via read_dir -> read_file -> read_block_dir ─────────
//   (dir.rs:406-407)

#[test]
fn read_dir_block_format_via_read_file() {
    // An Extents-format directory whose di_size == blocksize is a single-block
    // (block) directory: read_dir reads its one extent via read_file, then walks
    // the XDB3 data block. Build a 2-block image: block 0 holds the SB/inode,
    // block 1 holds the XDB3 directory block the inode's extent points at.
    let bs = BLOCKSIZE as usize;
    let mut img = vec![0u8; 3 * bs];
    v5_sb(&mut img);

    // The XDB3 block at fsblock 1 with one entry "f" -> inode 200.
    let blk = bs; // fsblock 1
    img[blk..blk + 4].copy_from_slice(&XFS_DIR3_BLOCK_MAGIC.to_be_bytes());
    let e = blk + 64; // past the 64-byte v5 hdr; tail count=0 -> region ends at bs-8
    img[e..e + 8].copy_from_slice(&200u64.to_be_bytes());
    img[e + 8] = 1; // namelen
    img[e + 9] = b'f'; // name
    img[e + 10] = 1; // ftype

    // A dir inode at fsblock 2 (byte 2*bs): Extents format, size == blocksize,
    // one extent [startoff 0, startblock 1, count 1].
    let ino_off = 2 * bs;
    let fork = pack(0, 1, 1);
    stamp_inode(
        &mut img,
        ino_off,
        0o040_755,
        2, /* EXTENTS */
        u64::from(BLOCKSIZE),
        1,
        &fork,
    );

    let sb = Superblock::parse(&img).unwrap();
    let inode = Inode::parse(&img[ino_off..ino_off + 512]).unwrap();
    assert_eq!(inode.format, InodeFormat::Extents);
    let entries = sb.read_dir(&img, &inode).expect("block dir lists");
    assert_eq!(entries.len(), 1, "one entry in the block dir");
    assert_eq!(entries[0].name, b"f");
    assert_eq!(entries[0].inode, 200);
}

// ── multi-block directory via read_dir -> read_multiblock_dir ──────────────────
//   (dir.rs:457 skip-leaf-extent, 471-473 data-block append)

#[test]
fn read_dir_multiblock_format_walks_data_and_skips_leaf() {
    // An Extents-format directory whose di_size > blocksize is a leaf/node
    // directory: read_multiblock_dir walks each DATA extent's blocks (XDD3) and
    // skips any extent at/above the XFS_DIR2_LEAF_OFFSET boundary. Two extents:
    //   - a DATA extent [startoff 0, startblock 1, count 1] (an XDD3 block) →
    //     entries appended;
    //   - a leaf extent at the boundary block [startoff = 1<<35 / blocksize] →
    //     skipped (the `startoff >= leaf_boundary_block` continue).
    let bs = BLOCKSIZE as usize;
    let mut img = vec![0u8; 4 * bs];
    v5_sb(&mut img);

    // DATA block (XDD3) at fsblock 1 with one entry "g" -> inode 201.
    let blk = bs;
    img[blk..blk + 4].copy_from_slice(&XFS_DIR3_DATA_MAGIC.to_be_bytes());
    let e = blk + 64;
    img[e..e + 8].copy_from_slice(&201u64.to_be_bytes());
    img[e + 8] = 1;
    img[e + 9] = b'g';
    img[e + 10] = 1;

    // The leaf-extent logical block: XFS_DIR2_LEAF_OFFSET (1<<35) / blocksize.
    let leaf_startoff = (1u64 << 35) / u64::from(BLOCKSIZE);
    let mut fork = Vec::new();
    fork.extend_from_slice(&pack(0, 1, 1)); // data extent
    fork.extend_from_slice(&pack(leaf_startoff, 2, 1)); // leaf extent -> skipped

    // Dir inode at fsblock 3: size = 2*blocksize (> blocksize -> multi-block).
    let ino_off = 3 * bs;
    stamp_inode(
        &mut img,
        ino_off,
        0o040_755,
        2, // EXTENTS
        u64::from(BLOCKSIZE) * 2,
        2,
        &fork,
    );

    let sb = Superblock::parse(&img).unwrap();
    let inode = Inode::parse(&img[ino_off..ino_off + 512]).unwrap();
    let entries = sb.read_dir(&img, &inode).expect("multi-block dir lists");
    assert_eq!(entries.len(), 1, "only the DATA-block entry (leaf skipped)");
    assert_eq!(entries[0].name, b"g");
    assert_eq!(entries[0].inode, 201);
}

// ── btree-format regular file via read_file (extent.rs:244-245) ────────────────

#[test]
fn read_file_btree_format_walks_bmbt() {
    // A Btree-format regular file: read_file must take the Btree arm
    // (read_btree_extents + assemble_extents), not the Extents arm. A degenerate
    // empty btree root (bb_level 0 / bb_numrecs 0 inline) maps no leaf blocks, so
    // the file assembles as a di_size-length zero fill — the arm is exercised
    // without needing a full multi-level tree.
    let mut img = vec![0u8; 4096];
    v5_sb(&mut img);
    let sb = Superblock::parse(&img).unwrap();

    let mut ib = vec![0u8; 512];
    ib[0..2].copy_from_slice(&0x494eu16.to_be_bytes()); // "IN"
    ib[2..4].copy_from_slice(&0o100_644u16.to_be_bytes()); // regular file
    ib[4] = 3; // v3
    ib[5] = 3; // di_format = BTREE
    ib[56..64].copy_from_slice(&8u64.to_be_bytes()); // di_size = 8 bytes
                                                     // fork (offset 176) stays zero: bb_level 0, bb_numrecs 0 -> no leaf ptrs.
    let inode = Inode::parse(&ib).unwrap();
    assert_eq!(inode.format, InodeFormat::Btree);

    let bytes = sb
        .read_file(&img, &inode)
        .expect("btree read_file assembles");
    assert_eq!(bytes.len(), 8, "di_size-length output");
    assert_eq!(bytes, vec![0u8; 8], "empty btree maps no data -> zero fill");
}

// ── read_by_path not-found arms, always-on via the committed dfvfs image ───────
//   (dir.rs:514-517 missing component, 527-530 non-dir intermediate, 537-540 empty)

/// The committed always-on Tier-1 v5 image (`xfs_dfvfs.raw`).
fn dfvfs() -> Vec<u8> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // core/ -> repo root
    p.push("tests/data/xfs_dfvfs.raw");
    std::fs::read(&p).unwrap_or_else(|e| panic!("read committed Tier-1 image {}: {e}", p.display()))
}

#[test]
fn read_by_path_missing_component_is_not_found() {
    let img = dfvfs();
    let sb = Superblock::parse(&img).unwrap();
    // A name that does not exist in the root directory.
    let res = read_by_path(&img, &sb, "/no_such_entry");
    assert!(
        matches!(res, Err(XfsError::PathNotFound { .. })),
        "missing component -> PathNotFound, got {res:?}"
    );
}

#[test]
fn read_by_path_non_dir_intermediate_is_not_found() {
    let img = dfvfs();
    let sb = Superblock::parse(&img).unwrap();
    // passwords.txt is a regular file; using it as an intermediate dir component
    // must fail with PathNotFound (the non-dir intermediate arm).
    let res = read_by_path(&img, &sb, "/passwords.txt/whatever");
    assert!(
        matches!(res, Err(XfsError::PathNotFound { .. })),
        "file used as an intermediate component -> PathNotFound, got {res:?}"
    );
}

#[test]
fn read_by_path_empty_path_is_not_found() {
    let img = dfvfs();
    let sb = Superblock::parse(&img).unwrap();
    // The root path resolves to the root directory (no components), which is not
    // a file -> the final not-found arm.
    let res = read_by_path(&img, &sb, "/");
    assert!(
        matches!(res, Err(XfsError::PathNotFound { .. })),
        "empty path -> PathNotFound, got {res:?}"
    );
}
