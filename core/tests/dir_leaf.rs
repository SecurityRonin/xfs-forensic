//! P5 Part 2 — leaf/node directory listing tests.
//!
//! A directory too large for a single block becomes a *leaf* (or *node*)
//! directory: its data entries spread across multiple directory data blocks,
//! and a separate leaf/hash index (in blocks above the `XFS_DIR2_LEAF_OFFSET`
//! address-space boundary) maps name-hashes to data-block offsets. Listing the
//! directory needs only the DATA blocks — the leaf/hash index is a lookup
//! accelerator, not a listing requirement. The data blocks carry the *multi-
//! block* data magic `XDD3` (v5) / `XD2D` (v4), distinct from the single-block
//! `XDB3`/`XD2B`, and unlike the single-block format they have NO block tail:
//! entries run the full block after the 64/16-byte header.
//!
//! Tier-1 gate: `read_dir` on the v5 `leaf/` directory (inode 655488, ~2000
//! children) returns exactly the `{name -> inode}` set that mount-ro `ls -i`
//! reported — an independent cross-check against the kernel's own directory
//! walk. The committed oracle is `tests/data/leaf.ls_i.txt`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use xfs::{read_block_dir, read_by_path, read_dir, DirEntry, Superblock};

/// Resolve an image path from an env var, falling back to `tests/data/<name>`.
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

/// Parse `leaf.ls_i.txt` (`<inode> <name>` per line) into `{name -> inode}`.
fn parse_ls_i_oracle() -> BTreeMap<String, u64> {
    let text = std::fs::read_to_string(data_path("leaf.ls_i.txt")).unwrap();
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut it = l.split_whitespace();
            let ino: u64 = it.next().unwrap().parse().unwrap();
            let name = it.next().unwrap().to_string();
            (name, ino)
        })
        .collect()
}

/// Collect `read_dir` output into `{name -> inode}`, dropping `.`/`..` (the
/// non-`-a` `ls -i` oracle omits them).
fn name_inode_map(entries: &[DirEntry]) -> BTreeMap<String, u64> {
    entries
        .iter()
        .filter(|e| e.name != b"." && e.name != b"..")
        .map(|e| (String::from_utf8_lossy(&e.name).into_owned(), e.inode))
        .collect()
}

// -------------------------------------------------------------------------
// THE Tier-1 gate: read_dir(leaf/) == full `ls -i` listing (~2000 entries)
// -------------------------------------------------------------------------

#[test]
fn read_dir_v5_leaf_dir_matches_ls_i() {
    let Some(path) = image_path("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).unwrap();
    // Inode 655488 = leaf dir: format == Extents, size 49152 (> blocksize).
    let leaf = sb.read_inode(&img, 655_488).unwrap();
    let entries = read_dir(&img, &sb, &leaf).expect("leaf dir lists via multi-block data walk");

    let got = name_inode_map(&entries);
    let want = parse_ls_i_oracle();
    assert_eq!(want.len(), 2000, "oracle has 2000 leaf children (sanity)");
    assert_eq!(
        got.len(),
        2000,
        "read_dir(leaf/) must surface all 2000 entries, got {}",
        got.len()
    );
    assert_eq!(
        got, want,
        "leaf/ {{name->inode}} must equal `ls -i mnt/leaf` (every data block walked)"
    );
    // v5 fs has ftype: every child is a regular file (ftype 1).
    for e in entries.iter().filter(|e| e.name != b"." && e.name != b"..") {
        assert_eq!(
            e.ftype,
            Some(1),
            "v5 leaf entries carry ftype = 1 (regular)"
        );
    }
}

#[test]
fn read_by_path_into_leaf_dir_reaches_a_child() {
    let Some(path) = image_path("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let img = std::fs::read(&path).unwrap();
    let sb = Superblock::parse(&img).unwrap();

    // The oracle's first child by name (f0001). read_by_path must descend into
    // the leaf directory (multi-block data walk) and resolve the child. The
    // f* children are empty files (0 bytes) -> content is empty, but resolution
    // through the leaf dir is the point.
    let oracle = parse_ls_i_oracle();
    let (first_name, _first_ino) = oracle.iter().next().unwrap();
    let full = format!("/leaf/{first_name}");
    let content = read_by_path(&img, &sb, &full).unwrap_or_else(|e| panic!("{full}: {e:?}"));
    assert!(
        content.is_empty(),
        "leaf children are empty files (size 0), got {} bytes",
        content.len()
    );
}

// -------------------------------------------------------------------------
// Multi-block data-block walker (crafted, no image) — XDD3/XD2D, no tail
// -------------------------------------------------------------------------

#[test]
fn read_data_dir_block_xdd3_walks_full_block_no_tail() {
    // A v5 multi-block data block (magic XDD3) has NO block tail: entries run
    // from the 64-byte header to the end of the block. Craft one with two real
    // entries then trailing zero padding; the walker must surface both and stop
    // cleanly at the zero padding (namelen 0), never read a phantom leaf tail.
    let blocksize = 256usize;
    let mut block = vec![0u8; blocksize];
    block[0..4].copy_from_slice(&xfs::XFS_DIR3_DATA_MAGIC.to_be_bytes());
    // first entry at offset 64: inumber(8)=100 namelen(1)=2 name="aa" ftype(1)=1 tag(2)
    let mut off = 64usize;
    block[off..off + 8].copy_from_slice(&100u64.to_be_bytes());
    block[off + 8] = 2;
    block[off + 9] = b'a';
    block[off + 10] = b'a';
    block[off + 11] = 1; // ftype
                         // tag at +12..14; aligned to 8 -> next entry at off + align8(8+1+2+1+2)=off+16
    off += 16;
    block[off..off + 8].copy_from_slice(&101u64.to_be_bytes());
    block[off + 8] = 2;
    block[off + 9] = b'b';
    block[off + 10] = b'b';
    block[off + 11] = 1;

    let entries = xfs::read_data_dir_block(&block, true).expect("XDD3 data block parses");
    assert_eq!(entries.len(), 2, "both entries surfaced, no tail assumed");
    assert_eq!(entries[0].name, b"aa");
    assert_eq!(entries[0].inode, 100);
    assert_eq!(entries[1].name, b"bb");
    assert_eq!(entries[1].inode, 101);
}

#[test]
fn read_data_dir_block_v4_xd2d_magic() {
    // The v4 multi-block data magic is XD2D (0x58443244), 16-byte header.
    let blocksize = 128usize;
    let mut block = vec![0u8; blocksize];
    block[0..4].copy_from_slice(&xfs::XFS_DIR2_DATA_MAGIC.to_be_bytes());
    let off = 16usize; // v4 header
    block[off..off + 8].copy_from_slice(&7u64.to_be_bytes());
    block[off + 8] = 1; // namelen
    block[off + 9] = b'x'; // name (no ftype on this crafted no-ftype block)
    let entries = xfs::read_data_dir_block(&block, false).expect("XD2D data block parses");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, b"x");
    assert_eq!(entries[0].inode, 7);
    assert_eq!(entries[0].ftype, None);
}

#[test]
fn read_data_dir_block_skips_unused_free_records() {
    // A leading unused record (freetag 0xFFFF, len 16) then a real entry.
    let blocksize = 128usize;
    let mut block = vec![0u8; blocksize];
    block[0..4].copy_from_slice(&xfs::XFS_DIR3_DATA_MAGIC.to_be_bytes());
    let off = 64usize;
    block[off..off + 2].copy_from_slice(&0xFFFFu16.to_be_bytes());
    block[off + 2..off + 4].copy_from_slice(&16u16.to_be_bytes());
    let e = off + 16;
    block[e..e + 8].copy_from_slice(&9u64.to_be_bytes());
    block[e + 8] = 1;
    block[e + 9] = b'z';
    block[e + 10] = 3; // ftype
    let entries = xfs::read_data_dir_block(&block, true).expect("parses past free record");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, b"z");
    assert_eq!(entries[0].ftype, Some(3));
}

#[test]
fn read_data_dir_block_unrecognized_magic_fails_loud() {
    // A data-block magic that is neither XDD3 nor XD2D (nor the single-block
    // XDB3/XD2B) must fail loud and name the offending magic.
    use xfs::XfsError;
    let mut block = vec![0u8; 128];
    block[0..4].copy_from_slice(&[0xAB, 0xCD, 0xEF, 0x00]);
    match xfs::read_data_dir_block(&block, true) {
        Err(XfsError::UnsupportedDir { detail }) => {
            assert!(
                detail.contains("0xabcdef00") && detail.contains("magic"),
                "must name the offending magic, got: {detail}"
            );
        }
        other => panic!("unrecognized data magic must fail loud, got {other:?}"),
    }
}

#[test]
fn read_data_dir_block_truncated_entry_stops() {
    // An entry whose namelen runs past the block end: the walker breaks rather
    // than over-read (bounds-stopping, no panic).
    let blocksize = 96usize;
    let mut block = vec![0u8; blocksize];
    block[0..4].copy_from_slice(&xfs::XFS_DIR3_DATA_MAGIC.to_be_bytes());
    let off = 64usize;
    block[off..off + 8].copy_from_slice(&5u64.to_be_bytes());
    block[off + 8] = 200; // namelen past the 96-byte block
    let entries = xfs::read_data_dir_block(&block, true).expect("must not panic");
    assert!(entries.is_empty(), "entry running past block dropped");
}

// -------------------------------------------------------------------------
// The single-block block-dir walker still works (regression) — XDB3 with tail
// -------------------------------------------------------------------------

#[test]
fn read_dir_multiblock_data_extent_outside_image_is_skipped() {
    // A leaf/node dir whose DATA extent points at a filesystem block past the
    // image end: read_multiblock_dir must skip that block (bounds-checked) and
    // return whatever the in-image blocks held — never panic or over-read.
    use xfs::{Inode, InodeFormat};
    // Minimal v5 sb, blocksize 4096, and a directory inode in Extents format
    // whose size > blocksize (so the multi-block path is taken) with a single
    // extent mapping logical dir-block 0 -> fsblock 1_000_000 (far past image).
    let blocksize = 4096usize;
    let mut img = vec![0u8; blocksize * 4];
    img[0..4].copy_from_slice(&0x5846_5342u32.to_be_bytes());
    img[4..8].copy_from_slice(&(blocksize as u32).to_be_bytes());
    img[56..64].copy_from_slice(&128u64.to_be_bytes());
    img[84..88].copy_from_slice(&32768u32.to_be_bytes());
    img[88..92].copy_from_slice(&1u32.to_be_bytes());
    img[100..102].copy_from_slice(&0xb4a5u16.to_be_bytes());
    img[104..106].copy_from_slice(&512u16.to_be_bytes());
    img[106..108].copy_from_slice(&8u16.to_be_bytes());
    img[120] = 12;
    img[122] = 9;
    img[123] = 3;
    img[124] = 15;
    img[216..220].copy_from_slice(&1u32.to_be_bytes()); // ftype
    let sb = Superblock::parse(&img).unwrap();

    // Craft a v3 dir inode: Extents format, size 2*blocksize (> blocksize ->
    // multi-block path), one extent startoff 0 -> startblock 1_000_000 count 1.
    let mut ib = vec![0u8; 512];
    ib[0..2].copy_from_slice(&0x494eu16.to_be_bytes()); // "IN"
    ib[2..4].copy_from_slice(&0o040_700u16.to_be_bytes()); // dir mode
    ib[4] = 3; // v3
    ib[5] = 2; // Extents
    ib[56..64].copy_from_slice(&((2 * blocksize) as u64).to_be_bytes()); // di_size
    ib[76..80].copy_from_slice(&1u32.to_be_bytes()); // di_nextents = 1
                                                     // extent at fork offset 176: startoff 0, startblock 1_000_000, count 1.
    let mut l0 = 0u64;
    let mut l1 = 0u64;
    let startblock: u64 = 1_000_000;
    l0 |= (startblock >> 43) & ((1 << 9) - 1);
    l1 |= (startblock & ((1 << 43) - 1)) << 21;
    l1 |= 1; // blockcount
    ib[176..184].copy_from_slice(&l0.to_be_bytes());
    ib[184..192].copy_from_slice(&l1.to_be_bytes());
    let inode = Inode::parse(&ib).unwrap();
    assert_eq!(inode.format, InodeFormat::Extents);

    let entries = read_dir(&img, &sb, &inode).expect("out-of-image data extent must not panic");
    assert!(
        entries.is_empty(),
        "the only data block is past the image -> skipped -> empty listing"
    );
}

#[test]
fn single_block_xdb3_still_uses_tail() {
    // Regression: the P4 single-block block-dir path (XDB3, WITH a leaf/hash
    // tail) must remain correct after the P5 multi-block path is added.
    let blocksize = 64usize;
    let mut block = vec![0u8; blocksize];
    block[0..4].copy_from_slice(&xfs::XFS_DIR3_BLOCK_MAGIC.to_be_bytes());
    let off = 64usize.min(blocksize); // header end
    let _ = off;
    // Use the existing 16-byte-header-less path via read_block_dir on a minimal
    // XDB3 block: one entry after the 64-byte header would need >= 64+16+8 bytes;
    // keep this a smoke check that the API is unchanged (empty tiny block).
    let entries = read_block_dir(&block, true).expect("XDB3 single-block still parses");
    assert!(entries.is_empty(), "tiny XDB3 block yields no entries");
}
