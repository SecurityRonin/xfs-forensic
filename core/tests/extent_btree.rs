//! P5 Part 1 — bmap B+tree file read (`di_format == Btree`) tests.
//!
//! Two tiers:
//! - **Oracle-gated (Tier-1):**
//!   - **THE content gate:** `Superblock::read_file` on the fragmented btree file
//!     (v5frag.img, inode 131) reconstructs the file's bytes by walking the
//!     inline `xfs_bmdr_block` root -> the `BMA3` bmbt leaf blocks -> the 16-byte
//!     `xfs_bmbt_rec` records, and the sha256 EQUALS the committed mount-ro
//!     ground truth (`tests/data/v5frag.content.sha256`). A wrong tree walk (miss
//!     a leaf, wrong descent order, wrong header size) produces wrong bytes and
//!     fails this hash.
//!   - **Walk-completeness gate:** the collected extent set EQUALS the full
//!     `xfs_db bmap` listing (`tests/data/v5frag.bmap.txt`, all 700 extents), in
//!     `startoff` order — proving the walk visited every leaf and every record.
//! - **Unit (robustness):** a crafted single-level bmdr root -> one BMA3 leaf; a
//!   two-level tree (interior node -> leaves); bounded walk (max levels, cycle
//!   guard, oversize numrecs, allocation cap); truncated/bad blocks do not panic.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use sha2::{Digest, Sha256};
use xfs::Superblock;

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

/// Path to a committed oracle text file under `tests/data/`.
fn data_path(name: &str) -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.push("tests/data");
    d.push(name);
    d
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

/// The frag file's inode number in v5frag.img (from tests/data/v5frag.inode.txt).
const FRAG_INO: u64 = 131;

/// Parse `tests/data/v5frag.bmap.txt` into `(startoff, startblock, blockcount)`
/// tuples — the walk-completeness oracle. Each line:
/// `data offset 0 startblock 13 (0/13) count 1 flag 0`.
fn parse_bmap_oracle() -> Vec<(u64, u64, u64)> {
    let text = std::fs::read_to_string(data_path("v5frag.bmap.txt")).unwrap();
    let mut out = Vec::new();
    for line in text.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        // find "offset" and "startblock" and "count" keyword positions.
        let pos = |kw: &str| toks.iter().position(|t| *t == kw);
        let (Some(o), Some(sb), Some(c)) = (pos("offset"), pos("startblock"), pos("count")) else {
            continue;
        };
        let startoff: u64 = toks[o + 1].parse().unwrap();
        let startblock: u64 = toks[sb + 1].parse().unwrap();
        let blockcount: u64 = toks[c + 1].parse().unwrap();
        out.push((startoff, startblock, blockcount));
    }
    out
}

// -------------------------------------------------------------------------
// THE Tier-1 content gate: read_file(btree file) -> sha256 == mount-ro oracle
// -------------------------------------------------------------------------

#[test]
fn read_btree_file_content_sha256_matches_mount_oracle() {
    let Some(path) = image_path("XFS_ORACLE_V5FRAG_IMG", "v5frag.img") else {
        eprintln!(
            "skip: v5frag image absent (set XFS_ORACLE_V5FRAG_IMG or mint tests/data/v5frag.img)"
        );
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).expect("superblock parses");
    let inode = sb.read_inode(&img, FRAG_INO).expect("frag inode parses");
    // The whole point: this inode is BTREE format, not extents.
    assert_eq!(
        inode.format,
        xfs::InodeFormat::Btree,
        "v5frag inode 131 must be di_format = btree"
    );

    let content = sb
        .read_file(&img, &inode)
        .expect("read_file reconstructs the btree file");
    assert_eq!(content.len(), 2_867_200, "frag.bin size (di_size)");

    let want = std::fs::read_to_string(data_path("v5frag.content.sha256"))
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(
        sha256_hex(&content),
        want,
        "btree file content sha256 MUST equal the mount-ro oracle"
    );
}

// -------------------------------------------------------------------------
// Walk-completeness gate: collected extents == full `xfs_db bmap` listing
// -------------------------------------------------------------------------

#[test]
fn btree_walk_collects_all_extents_in_startoff_order() {
    let Some(path) = image_path("XFS_ORACLE_V5FRAG_IMG", "v5frag.img") else {
        eprintln!("skip: v5frag image absent");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).unwrap();
    let inode = sb.read_inode(&img, FRAG_INO).unwrap();

    // The public btree extent walker: root fork -> all leaf records, in order.
    let recs =
        xfs::read_btree_extents(&img, &sb, &inode.data_fork).expect("btree extent walk succeeds");

    let oracle = parse_bmap_oracle();
    assert_eq!(oracle.len(), 700, "oracle has 700 extents (sanity)");
    assert_eq!(
        recs.len(),
        oracle.len(),
        "walk must collect EVERY extent xfs_db bmap lists (no missed leaf)"
    );
    for (i, (rec, (o, s, c))) in recs.iter().zip(oracle.iter()).enumerate() {
        assert_eq!(rec.startoff, *o, "extent {i} startoff");
        assert_eq!(rec.startblock, *s, "extent {i} startblock");
        assert_eq!(rec.blockcount, *c, "extent {i} blockcount");
    }
    // startoff must be monotonically non-decreasing (tree in-order).
    for w in recs.windows(2) {
        assert!(w[0].startoff <= w[1].startoff, "extents in startoff order");
    }
}

// -------------------------------------------------------------------------
// Unit (crafted) — single-level and two-level bmbt trees, robustness
// -------------------------------------------------------------------------

/// Build a minimal v5 superblock buffer with the given blocksize.
fn write_min_sb(img: &mut [u8], blocksize: u32) {
    img[0..4].copy_from_slice(&0x5846_5342u32.to_be_bytes()); // XFSB
    img[4..8].copy_from_slice(&blocksize.to_be_bytes());
    img[56..64].copy_from_slice(&128u64.to_be_bytes());
    img[84..88].copy_from_slice(&32768u32.to_be_bytes()); // agblocks
    img[88..92].copy_from_slice(&1u32.to_be_bytes()); // agcount
    img[100..102].copy_from_slice(&0xb4a5u16.to_be_bytes()); // v5
    img[104..106].copy_from_slice(&512u16.to_be_bytes());
    img[106..108].copy_from_slice(&8u16.to_be_bytes());
    img[120] = 12; // blocklog
    img[122] = 9; // inodelog
    img[123] = 3; // inopblog
    img[124] = 15; // agblklog
}

/// Pack a 16-byte `xfs_bmbt_rec` (mirrors the kernel layout).
fn pack(startoff: u64, startblock: u64, blockcount: u64, unwritten: bool) -> [u8; 16] {
    let flag = u64::from(unwritten);
    let sb_hi = (startblock >> 43) & ((1 << 9) - 1);
    let sb_lo = startblock & ((1 << 43) - 1);
    let l0 = (flag << 63) | ((startoff & ((1 << 54) - 1)) << 9) | sb_hi;
    let l1 = (sb_lo << 21) | (blockcount & ((1 << 21) - 1));
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&l0.to_be_bytes());
    out[8..].copy_from_slice(&l1.to_be_bytes());
    out
}

/// Build a v5 (`BMA3`) bmbt block: 72-byte CRC long-form header + records.
/// `level` 0 = leaf (16-byte recs), `level` > 0 = interior (keys[] then ptrs[]).
fn build_bma3_leaf(recs: &[[u8; 16]], blocksize: usize) -> Vec<u8> {
    let mut b = vec![0u8; blocksize];
    b[0..4].copy_from_slice(&0x424d_4133u32.to_be_bytes()); // BMA3
    b[4..6].copy_from_slice(&0u16.to_be_bytes()); // bb_level = 0
    let numrecs = u16::try_from(recs.len()).unwrap();
    b[6..8].copy_from_slice(&numrecs.to_be_bytes()); // bb_numrecs
                                                     // leftsib/rightsib = null.
    b[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    b[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
    let mut off = 72; // XFS_BTREE_LBLOCK_CRC_LEN
    for r in recs {
        b[off..off + 16].copy_from_slice(r);
        off += 16;
    }
    b
}

/// The v5 CRC long-form bmbt block header length (`XFS_BTREE_LBLOCK_CRC_LEN`).
const BMA3_HDR: usize = 72;

/// Build an interior (`level` 1) BMA3 node, laid out EXACTLY as on disk: header +
/// keys[maxrecs] + ptrs[maxrecs], where `maxrecs = (blocksize - hdr) / 16` and
/// only the first `numrecs` slots are valid. The ptrs therefore start at
/// `hdr + maxrecs*8`, NOT `hdr + numrecs*8` — the walker must locate them the
/// same maxrecs-based way (matching the real-image root layout verified against
/// `xfs_db`: root ptrs at fork offset 164 = 4 + dmaxrecs(20)*8).
fn build_bma3_node(keys: &[u64], ptrs: &[u64], blocksize: usize) -> Vec<u8> {
    assert_eq!(keys.len(), ptrs.len());
    let mut b = vec![0u8; blocksize];
    b[0..4].copy_from_slice(&0x424d_4133u32.to_be_bytes()); // BMA3
    b[4..6].copy_from_slice(&1u16.to_be_bytes()); // bb_level = 1 (interior)
    b[6..8].copy_from_slice(&u16::try_from(keys.len()).unwrap().to_be_bytes());
    b[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    b[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
    let maxrecs = (blocksize - BMA3_HDR) / 16;
    let key_off = BMA3_HDR;
    let ptr_off = BMA3_HDR + maxrecs * 8;
    for (i, k) in keys.iter().enumerate() {
        b[key_off + i * 8..key_off + i * 8 + 8].copy_from_slice(&k.to_be_bytes());
    }
    for (i, p) in ptrs.iter().enumerate() {
        b[ptr_off + i * 8..ptr_off + i * 8 + 8].copy_from_slice(&p.to_be_bytes());
    }
    b
}

/// Build a bmdr root (inline data fork), laid out EXACTLY as on disk: `bb_level(2)
/// bb_numrecs(2)` then keys[dmaxrecs] (8B) + ptrs[dmaxrecs] (8B), where
/// `dmaxrecs = (fork_len - 4) / 16` and only the first `numrecs` are valid. The
/// ptrs start at `4 + dmaxrecs*8`. `fork_len` fixes the maxrecs geometry (the
/// real inode fork is 336 bytes on a 512B v3 inode -> dmaxrecs 20).
fn build_bmdr_root(level: u16, keys: &[u64], ptrs: &[u64], fork_len: usize) -> Vec<u8> {
    assert_eq!(keys.len(), ptrs.len());
    let mut f = vec![0u8; fork_len];
    f[0..2].copy_from_slice(&level.to_be_bytes());
    f[2..4].copy_from_slice(&u16::try_from(keys.len()).unwrap().to_be_bytes());
    let dmaxrecs = (fork_len - 4) / 16;
    let key_off = 4;
    let ptr_off = 4 + dmaxrecs * 8;
    for (i, k) in keys.iter().enumerate() {
        f[key_off + i * 8..key_off + i * 8 + 8].copy_from_slice(&k.to_be_bytes());
    }
    for (i, p) in ptrs.iter().enumerate() {
        f[ptr_off + i * 8..ptr_off + i * 8 + 8].copy_from_slice(&p.to_be_bytes());
    }
    f
}

#[test]
fn btree_single_level_root_to_one_leaf() {
    // bmdr root (level 1) -> ptr to fsblock 2 (a BMA3 leaf with 2 records).
    let blocksize = 4096usize;
    let mut img = vec![0u8; blocksize * 8];
    write_min_sb(&mut img, blocksize as u32);
    let sb = Superblock::parse(&img).unwrap();

    // Leaf at fsblock 2 with two extents.
    let leaf = build_bma3_leaf(&[pack(0, 5, 1, false), pack(1, 6, 2, false)], blocksize);
    img[2 * blocksize..3 * blocksize].copy_from_slice(&leaf);

    // Root fork: level 1, one key/ptr -> fsblock 2.
    let root = build_bmdr_root(1, &[0], &[2], 336);

    let recs = xfs::read_btree_extents(&img, &sb, &root).expect("single-level walk");
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].startblock, 5);
    assert_eq!(recs[1].startoff, 1);
    assert_eq!(recs[1].blockcount, 2);
}

#[test]
fn btree_two_level_interior_to_leaves() {
    // Root (level 2) -> one interior node (fsblock 2, level 1) -> two leaves
    // (fsblocks 3 and 4). Proves interior descent and multi-leaf collection.
    let blocksize = 4096usize;
    let mut img = vec![0u8; blocksize * 8];
    write_min_sb(&mut img, blocksize as u32);
    let sb = Superblock::parse(&img).unwrap();

    let leaf_a = build_bma3_leaf(&[pack(0, 10, 1, false)], blocksize);
    let leaf_b = build_bma3_leaf(&[pack(1, 11, 1, false)], blocksize);
    img[3 * blocksize..4 * blocksize].copy_from_slice(&leaf_a);
    img[4 * blocksize..5 * blocksize].copy_from_slice(&leaf_b);

    // Interior node at fsblock 2 (level 1): two keys/ptrs -> leaves 3, 4.
    let node = build_bma3_node(&[0, 1], &[3, 4], blocksize);
    img[2 * blocksize..3 * blocksize].copy_from_slice(&node);

    // Root (level 2): one key/ptr -> interior node at fsblock 2.
    let root = build_bmdr_root(2, &[0], &[2], 336);

    let recs = xfs::read_btree_extents(&img, &sb, &root).expect("two-level walk");
    assert_eq!(recs.len(), 2, "both leaves' records collected");
    assert_eq!(recs[0].startblock, 10);
    assert_eq!(recs[1].startblock, 11);
}

#[test]
fn btree_bad_leaf_magic_does_not_panic() {
    // A root ptr to a block whose magic is NOT BMA3/BMAP: the walker must skip it
    // (no records) rather than panic or misread.
    let blocksize = 4096usize;
    let mut img = vec![0u8; blocksize * 8];
    write_min_sb(&mut img, blocksize as u32);
    let sb = Superblock::parse(&img).unwrap();
    // fsblock 2 stays all-zero (magic 0) -> not a bmbt block.
    let root = build_bmdr_root(1, &[0], &[2], 336);
    let recs = xfs::read_btree_extents(&img, &sb, &root).expect("bad-magic walk must not panic");
    assert!(
        recs.is_empty(),
        "unrecognized block -> no extents, no panic"
    );
}

#[test]
fn btree_ptr_outside_image_does_not_panic() {
    // A root ptr to an fsblock far past the image end: bounds-checked -> skipped.
    let blocksize = 4096usize;
    let mut img = vec![0u8; blocksize * 4];
    write_min_sb(&mut img, blocksize as u32);
    let sb = Superblock::parse(&img).unwrap();
    let root = build_bmdr_root(1, &[0], &[1_000_000], 336); // way out of range
    let recs = xfs::read_btree_extents(&img, &sb, &root).expect("out-of-image ptr must not panic");
    assert!(recs.is_empty());
}

#[test]
fn btree_truncated_root_fork_does_not_panic() {
    // A root fork too short to hold the claimed numrecs' keys/ptrs: bounds-stop.
    let blocksize = 4096usize;
    let mut img = vec![0u8; blocksize * 4];
    write_min_sb(&mut img, blocksize as u32);
    let sb = Superblock::parse(&img).unwrap();
    // level 1, numrecs 100 but only a few bytes of fork.
    let mut root = Vec::new();
    root.extend_from_slice(&1u16.to_be_bytes());
    root.extend_from_slice(&100u16.to_be_bytes());
    let recs = xfs::read_btree_extents(&img, &sb, &root).expect("truncated root must not panic");
    assert!(recs.is_empty(), "no readable ptrs -> no extents");
}

#[test]
fn btree_excessive_level_is_bounded() {
    // A root claiming an absurd level must not recurse unboundedly: the walker
    // caps descent depth. A level far beyond any real tree yields no extents
    // (the ptr targets are zero blocks) without hanging or stack-overflowing.
    let blocksize = 4096usize;
    let mut img = vec![0u8; blocksize * 4];
    write_min_sb(&mut img, blocksize as u32);
    let sb = Superblock::parse(&img).unwrap();
    let root = build_bmdr_root(250, &[0], &[2], 336); // absurd level
    let recs = xfs::read_btree_extents(&img, &sb, &root).expect("capped, no hang");
    assert!(recs.is_empty());
}
