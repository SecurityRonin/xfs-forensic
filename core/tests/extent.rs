//! P3 extent-list file-read tests.
//!
//! Two tiers:
//! - **Oracle-gated (Tier-1):**
//!   - `BmbtRec::unpack` reproduces the `xfs_db bmap` fields for big.bin (ino
//!     135) and file1.txt (ino 132): `tests/data/v5.bmap_big.txt` /
//!     `v5.bmap_small.txt`.
//!   - **THE content gate:** `Superblock::read_file` reconstructs each file's
//!     bytes through the extent decoder and the sha256 EQUALS the committed
//!     mount-ro ground truth (`tests/data/content.sha256`). A wrong bit-split
//!     produces plausible-but-wrong bytes that fail this hash (the LZNT1-trap
//!     this phase exists to catch).
//! - **Unit (robustness):** the l0/l1 startblock split proven bit-by-bit on a
//!   crafted record; the unwritten flag; a sparse-hole zero-fill; a truncated
//!   fork does not panic; an absurd size is refused.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use sha2::{Digest, Sha256};
use xfs::{BmbtRec, Superblock};

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

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let digest = h.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

// -------------------------------------------------------------------------
// BmbtRec::unpack — bit-split correctness (crafted, no image needed)
// -------------------------------------------------------------------------

/// Pack the four logical fields into the on-disk 16-byte record, mirroring the
/// kernel layout so the test proves the *decoder* inverts a known encoding:
///   l0 = [flag:1 | startoff:54 | startblock_hi:9]  (bits 63 | 62..9 | 8..0)
///   l1 = [startblock_lo:43 | blockcount:21]        (bits 63..21 | 20..0)
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

#[test]
fn unpack_big_bin_extent_matches_bmap_oracle() {
    // Oracle v5.bmap_big.txt: "data offset 0 startblock 24 count 4096 flag 0".
    let raw = pack(0, 24, 4096, false);
    let rec = BmbtRec::unpack(&raw);
    assert_eq!(rec.startoff, 0, "startoff");
    assert_eq!(rec.startblock, 24, "startblock");
    assert_eq!(rec.blockcount, 4096, "blockcount");
    assert!(!rec.unwritten, "flag 0 -> normal (written)");
}

#[test]
fn unpack_small_file_extent_matches_bmap_oracle() {
    // Oracle v5.bmap_small.txt: "data offset 0 startblock 13 count 1 flag 0".
    let raw = pack(0, 13, 1, false);
    let rec = BmbtRec::unpack(&raw);
    assert_eq!(rec.startoff, 0);
    assert_eq!(rec.startblock, 13);
    assert_eq!(rec.blockcount, 1);
    assert!(!rec.unwritten);
}

#[test]
fn unpack_proves_startblock_split_across_both_words() {
    // A startblock whose value straddles the l0:0-8 / l1:21-63 boundary: the
    // top 9 bits are non-zero AND the low 43 bits are non-zero, so an inverted
    // split (swapping hi/lo) yields a *different* number and fails here.
    // startblock = (0x1AB << 43) | 0x1234_5678_9AB
    let hi: u64 = 0x1AB; // 9 bits
    let lo: u64 = 0x1234_5678_9AB & ((1 << 43) - 1); // 43 bits
    let startblock = (hi << 43) | lo;
    let startoff = 0x2A_BCDE; // an arbitrary 54-bit-range value
    let blockcount = 0x0015_5555; // 21-bit value
    let raw = pack(startoff, startblock, blockcount, true);

    let rec = BmbtRec::unpack(&raw);
    assert_eq!(rec.startoff, startoff, "startoff (l0:9-62)");
    assert_eq!(
        rec.startblock, startblock,
        "startblock reassembled from l0:0-8 + l1:21-63"
    );
    assert_eq!(rec.blockcount, blockcount, "blockcount (l1:0-20)");
    assert!(rec.unwritten, "flag 1 -> unwritten/preallocated");

    // Guard against an inverted split: the hi/lo swapped value must NOT match.
    let swapped = (lo << 43) | hi;
    assert_ne!(rec.startblock, swapped, "hi/lo must not be swapped");
}

#[test]
fn unpack_max_fields_do_not_overflow() {
    // Every field at its width maximum — panic-free, values isolated correctly.
    let startoff = (1u64 << 54) - 1;
    let startblock = (1u64 << 52) - 1;
    let blockcount = (1u64 << 21) - 1;
    let raw = pack(startoff, startblock, blockcount, true);
    let rec = BmbtRec::unpack(&raw);
    assert_eq!(rec.startoff, startoff);
    assert_eq!(rec.startblock, startblock);
    assert_eq!(rec.blockcount, blockcount);
    assert!(rec.unwritten);
}

// -------------------------------------------------------------------------
// THE Tier-1 content gate: read_file -> sha256 == mount-ro ground truth
// -------------------------------------------------------------------------

#[test]
fn read_big_bin_content_sha256_matches_mount_oracle() {
    let Some(path) = image_path("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent (set XFS_ORACLE_V5_IMG or mint tests/data/v5.img)");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).expect("superblock parses");
    let inode = sb.read_inode(&img, 135).expect("big.bin inode parses");

    let content = sb
        .read_file(&img, &inode)
        .expect("read_file reconstructs big.bin");
    assert_eq!(content.len(), 16_777_216, "big.bin size (di_size)");

    // Ground truth: content.sha256 / content.ro.sha256 (mount -o ro sha256sum).
    assert_eq!(
        sha256_hex(&content),
        "1c473b2dfaef2727826973b231b3076185c2eca46a2db7ba12b8259a772abe7c",
        "big.bin content sha256 MUST equal the mount-ro oracle"
    );
}

#[test]
fn read_small_file_content_sha256_matches_mount_oracle() {
    let Some(path) = image_path("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).expect("superblock parses");
    let inode = sb.read_inode(&img, 132).expect("file1.txt inode parses");

    let content = sb
        .read_file(&img, &inode)
        .expect("read_file reconstructs file1.txt");
    // di_size = 10: the final block's tail is slack and must be truncated away.
    assert_eq!(
        content.len(),
        10,
        "file1.txt size (di_size, truncated from 1 block)"
    );
    assert_eq!(&content, b"content-1\n", "file1.txt literal content");

    assert_eq!(
        sha256_hex(&content),
        "1894d80da16dd47db42e2a47e33e709254908a30d4a5985df4bf6e1ba18ce350",
        "file1.txt content sha256 MUST equal the mount-ro oracle"
    );
}

// -------------------------------------------------------------------------
// read_extents iterator + sparse-hole + robustness (crafted)
// -------------------------------------------------------------------------

#[test]
fn read_extents_reads_all_records_in_order() {
    // Two consecutive records in a fork slice.
    let mut fork = Vec::new();
    fork.extend_from_slice(&pack(0, 24, 4096, false));
    fork.extend_from_slice(&pack(4096, 128, 8, true));
    let recs = xfs::read_extents(&fork, 2);
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].startblock, 24);
    assert_eq!(recs[0].blockcount, 4096);
    assert_eq!(recs[1].startoff, 4096);
    assert_eq!(recs[1].startblock, 128);
    assert!(recs[1].unwritten);
}

#[test]
fn read_extents_stops_at_fork_bounds() {
    // Claim 4 extents but only 1 record's worth of bytes: reader must not
    // over-read; it returns only the records that fully fit.
    let fork = pack(0, 24, 1, false).to_vec();
    let recs = xfs::read_extents(&fork, 4);
    assert_eq!(
        recs.len(),
        1,
        "only the one fully-present record is returned"
    );
}

#[test]
fn read_file_sparse_hole_zero_fills() {
    // A file with a hole: block 0 has data, block 1 is a hole, block 2 has data.
    // Build a tiny synthetic image: blocksize 4096, one AG. We only need the
    // superblock geometry fields read_file uses (blocksize) plus the extent
    // block bytes at the right offsets.
    let blocksize = 4096usize;
    // startblock 1 -> byte 4096 (data A); startblock 3 -> byte 12288 (data C).
    let total_blocks = 4usize;
    let mut img = vec![0u8; blocksize * (total_blocks + 4)];

    // Write a minimal valid v5 superblock so Superblock::parse succeeds and
    // reports blocksize 4096, inodesize 512.
    write_min_sb(&mut img, blocksize as u32);

    let data_a = vec![0xAAu8; blocksize];
    let data_c = vec![0xCCu8; blocksize];
    img[1 * blocksize..2 * blocksize].copy_from_slice(&data_a);
    img[3 * blocksize..4 * blocksize].copy_from_slice(&data_c);

    let sb = Superblock::parse(&img).expect("min sb parses");

    // Extent map: [startoff 0 -> startblock 1, count 1], hole at logical block 1,
    // [startoff 2 -> startblock 3, count 1]. size = 3 blocks.
    let mut fork = Vec::new();
    fork.extend_from_slice(&pack(0, 1, 1, false));
    fork.extend_from_slice(&pack(2, 3, 1, false));

    let out =
        xfs::read_file_from_fork(&img, &sb, &fork, 2, (3 * blocksize) as u64).expect("sparse read");
    assert_eq!(out.len(), 3 * blocksize);
    assert_eq!(&out[0..blocksize], &data_a[..], "logical block 0 = data A");
    assert!(
        out[blocksize..2 * blocksize].iter().all(|&b| b == 0),
        "logical block 1 = hole (zeros)"
    );
    assert_eq!(
        &out[2 * blocksize..3 * blocksize],
        &data_c[..],
        "logical block 2 = data C"
    );
}

#[test]
fn read_file_refuses_absurd_size() {
    // A size claiming far more than the image could hold must be refused, not
    // allocated (allocation-bomb guard).
    let blocksize = 4096usize;
    let mut img = vec![0u8; blocksize * 8];
    write_min_sb(&mut img, blocksize as u32);
    let sb = Superblock::parse(&img).expect("min sb parses");

    let fork = pack(0, 1, 1, false).to_vec();
    let absurd = u64::MAX; // way past the image
    let res = xfs::read_file_from_fork(&img, &sb, &fork, 1, absurd);
    assert!(
        res.is_err(),
        "an absurd size must be refused, not allocated"
    );
}

#[test]
fn read_file_truncated_fork_does_not_panic() {
    let blocksize = 4096usize;
    let mut img = vec![0u8; blocksize * 8];
    write_min_sb(&mut img, blocksize as u32);
    let sb = Superblock::parse(&img).expect("min sb parses");

    // Claim 3 extents but hand only 4 bytes of fork: must not panic; it reads
    // the extents that fit (none) and yields a zero-filled file of `size`.
    let fork = vec![0u8; 4];
    let out = xfs::read_file_from_fork(&img, &sb, &fork, 3, blocksize as u64);
    // No records -> nothing to place -> a hole -> `size` zero bytes.
    assert!(out.is_ok(), "truncated fork must not panic");
    assert_eq!(out.unwrap().len(), blocksize);
}

/// Write the minimal set of superblock fields `Superblock::parse` reads so the
/// geometry needed by `read_file` (blocksize/inodesize/version) is valid.
fn write_min_sb(img: &mut [u8], blocksize: u32) {
    // magic "XFSB"
    img[0..4].copy_from_slice(&0x5846_5342u32.to_be_bytes());
    img[4..8].copy_from_slice(&blocksize.to_be_bytes()); // sb_blocksize
    img[56..64].copy_from_slice(&128u64.to_be_bytes()); // sb_rootino
    img[84..88].copy_from_slice(&32768u32.to_be_bytes()); // sb_agblocks
    img[88..92].copy_from_slice(&1u32.to_be_bytes()); // sb_agcount
    img[100..102].copy_from_slice(&0xb4a5u16.to_be_bytes()); // sb_versionnum (v5)
    img[104..106].copy_from_slice(&512u16.to_be_bytes()); // sb_inodesize
    img[106..108].copy_from_slice(&8u16.to_be_bytes()); // sb_inopblock
    img[120] = 12; // sb_blocklog
    img[122] = 9; // sb_inodelog
    img[123] = 3; // sb_inopblog
    img[124] = 15; // sb_agblklog
}
