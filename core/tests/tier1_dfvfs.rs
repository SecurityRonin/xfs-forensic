//! **Tier-1 validation** — our `xfs-core` reader against a genuine, third-party
//! XFS image.
//!
//! The image `tests/data/xfs_dfvfs.raw` is `test_data/xfs.raw` from
//! [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) (Joachim Metz),
//! Apache-2.0 — the same image `libfsxfs` uses as its own oracle. Unlike our
//! self-minted `mkfs.xfs` fixtures (Tier-2), neither the image nor its answer
//! key was authored by us: the ground truth below was captured from three
//! **independent** oracles on a controlled Linux VM (xfsprogs 6.6.0):
//!
//! - `xfs_db -r -c 'sb 0' -c print`   — superblock geometry
//! - `xfs_db -r -c 'inode N' -c print` — inode cores + short-form dir entries
//! - `mount -o ro,loop` + `ls -iR` + `sha256sum` — the Linux kernel's own walk
//!   and file-content hashes (a wholly separate implementation from `xfs_db`).
//!
//! The image is 16 `MiB` and committed (Apache-2.0), so this test is **always
//! on** in CI — it is not env-gated. It is the load-bearing correctness proof
//! for the reader; the self-minted `v5.img`/`v4.img` tests are regression
//! backstops beneath it.
//!
//! ## Real-world geometry this exercises that our self-mint does not
//!
//! Our `mkfs.xfs` images have `agcount = 4`, `agblklog = 15`, `rootino = 128`.
//! This dfvfs image has **`agcount = 1`, `agblklog = 12`, `rootino = 11072`**
//! (sparse-inode geometry, `spino_align = 4`). The inode-number decode
//! (`inode_to_location`) is therefore driven by a different `agblklog` shift and
//! a large root inode number no self-mint here ever produced — a genuine
//! real-world quirk the Tier-1 image surfaces.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::path::PathBuf;

use sha2::{Digest, Sha256};
use xfs::{read_by_path, read_dir, FileType, Superblock, XFS_SB_MAGIC};

/// The committed Tier-1 image, resolved relative to this crate (repo-root
/// `tests/data`). Always present (committed), so — unlike the self-mint tests —
/// this does not skip.
fn dfvfs_image() -> Vec<u8> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // core/ -> repo root
    p.push("tests/data/xfs_dfvfs.raw");
    std::fs::read(&p).unwrap_or_else(|e| panic!("read committed Tier-1 image {}: {e}", p.display()))
}

fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in Sha256::digest(data) {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Superblock fields must equal the `xfs_db -r -c 'sb 0' -c print` ground truth.
#[test]
fn superblock_matches_xfs_db() {
    let img = dfvfs_image();
    // The v5 `sb_crc` covers exactly the sector (`sectsize = 512`), so the CRC
    // check must parse the sector-sized slice a real caller reads — parsing over
    // the whole image would CRC the wrong length. Field values are identical
    // either way (they all lie in the first 220 bytes).
    let sb = Superblock::parse(&img[..512]).expect("dfvfs superblock parses");

    // Verbatim from `xfs_db sb 0 print` (see tests/data/README.md).
    assert_eq!(sb.magic, XFS_SB_MAGIC, "magicnum 0x58465342");
    assert_eq!(sb.blocksize, 4096, "blocksize");
    assert_eq!(sb.inodesize, 512, "inodesize");
    assert_eq!(sb.inopblock, 8, "inopblock");
    assert_eq!(sb.versionnum, 0xb4b5, "versionnum (v5)");
    assert_eq!(
        sb.rootino, 11072,
        "rootino (NOT 128 — sparse-inode geometry)"
    );
    assert_eq!(sb.agblocks, 4096, "agblocks");
    assert_eq!(sb.agcount, 1, "agcount");
    assert_eq!(sb.blocklog, 12, "blocklog");
    assert_eq!(sb.inodelog, 9, "inodelog");
    assert_eq!(sb.inopblog, 3, "inopblog");
    assert_eq!(sb.agblklog, 12, "agblklog");

    assert_eq!(sb.version(), 5, "low nibble -> v5");
    assert!(sb.is_v5());
    // v5 superblock CRC verifies (`crc = 0x7a195fb4 (correct)`).
    assert_eq!(sb.crc_valid, Some(true), "sb_crc verifies");
}

/// The root directory listing must equal the kernel's `ls -iR` (an oracle wholly
/// independent of `xfs_db`): the exact names, inode numbers, and ftype bytes.
#[test]
fn root_listing_matches_kernel_ls() {
    let img = dfvfs_image();
    let sb = Superblock::parse(&img).unwrap();
    let root = sb.read_inode(&img, sb.rootino).unwrap();
    assert_eq!(root.file_type(), FileType::Directory, "root is a directory");

    let entries = read_dir(&img, &sb, &root).unwrap();
    let mut got: Vec<(String, u64, Option<u8>)> = entries
        .iter()
        .map(|e| {
            (
                String::from_utf8_lossy(&e.name).into_owned(),
                e.inode,
                e.ftype,
            )
        })
        .collect();
    got.sort();

    // Ground truth: `mount -o ro` + `ls -i` and `xfs_db inode 11072 print`.
    //   a_directory -> 11075 (ftype 2 = dir)
    //   passwords.txt -> 11077 (ftype 1 = regular)
    //   a_link -> 11079 (ftype 7 = symlink)
    let mut want = vec![
        ("a_directory".to_string(), 11075u64, Some(2u8)),
        ("passwords.txt".to_string(), 11077, Some(1)),
        ("a_link".to_string(), 11079, Some(7)),
    ];
    want.sort();
    assert_eq!(got, want, "root listing == kernel ls -i");
}

/// The nested `a_directory/` listing must match the kernel walk too — proves the
/// large-inode-number decode descends correctly into a child short-form dir.
#[test]
fn nested_directory_listing_matches_kernel_ls() {
    let img = dfvfs_image();
    let sb = Superblock::parse(&img).unwrap();
    let root = sb.read_inode(&img, sb.rootino).unwrap();
    let a_directory_ino = read_dir(&img, &sb, &root)
        .unwrap()
        .into_iter()
        .find(|e| e.name == b"a_directory")
        .expect("a_directory present")
        .inode;

    let a_directory = sb.read_inode(&img, a_directory_ino).unwrap();
    let mut got: Vec<(String, u64)> = read_dir(&img, &sb, &a_directory)
        .unwrap()
        .into_iter()
        .map(|e| (String::from_utf8_lossy(&e.name).into_owned(), e.inode))
        .collect();
    got.sort();

    // `ls -i mnt/a_directory`: a_file -> 11076, another_file -> 11078.
    assert_eq!(
        got,
        vec![
            ("a_file".to_string(), 11076u64),
            ("another_file".to_string(), 11078),
        ],
        "a_directory listing == kernel ls -i"
    );
}

/// A file's reconstructed bytes must hash to the kernel's `sha256sum` — the
/// strongest Tier-1 gate (extent decode + block read reproduce the exact file).
///
/// `passwords.txt` (inode 11077) is size 116, a single extent (startblock 1379,
/// count 1), and — a real-world quirk — carries an attribute fork (a SELinux
/// `security.selinux` xattr) our self-mint files do not.
#[test]
fn file_content_matches_kernel_sha256() {
    let img = dfvfs_image();
    let sb = Superblock::parse(&img).unwrap();

    let bytes = read_by_path(&img, &sb, "/passwords.txt").unwrap();
    assert_eq!(bytes.len(), 116, "di_size");
    // `sha256sum mnt/passwords.txt` under a read-only kernel mount.
    assert_eq!(
        sha256_hex(&bytes),
        "02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252",
        "reconstructed content == kernel sha256sum"
    );
    // The first line is the CSV header (a stable literal cross-check).
    assert!(
        bytes.starts_with(b"place,user,password\n"),
        "content leads with the CSV header"
    );

    // A nested file too: a_directory/another_file (inode 11078).
    let nested = read_by_path(&img, &sb, "/a_directory/another_file").unwrap();
    assert_eq!(
        sha256_hex(&nested),
        "c7fbc0e821c0871805a99584c6a384533909f68a6bbe9a2a687d28d9f3b10c16",
        "nested file content == kernel sha256sum"
    );
}

/// The inode-number decode for the large sparse-geometry root inode must land on
/// the byte offset `xfs_db` would compute — a direct check of the `agblklog=12`,
/// `rootino=11072` path our `rootino=128` self-mint never exercised.
#[test]
fn root_inode_location_decodes_under_sparse_geometry() {
    let img = dfvfs_image();
    let sb = Superblock::parse(&img).unwrap();
    // agcount=1 so agno must be 0; the whole inode number is the agino.
    let loc = sb.inode_to_location(sb.rootino);
    assert_eq!(loc.agno, 0, "single-AG image -> agno 0");
    assert_eq!(loc.agino, 11072, "agino == rootino for a single-AG fs");
    // agino 11072 = agblock (11072 >> 3 = 1384), slot (11072 & 7 = 0).
    assert_eq!(loc.agblock, 1384, "agblock = agino >> inopblog");
    assert_eq!(loc.offset, 0, "inode slot within its block");
    // byte = fsblock*bs + slot*isize = 1384*4096 = 5_668_864.
    assert_eq!(loc.byte_offset, 1384 * 4096, "absolute byte offset");
    // And the inode actually parses at that location with di_ino self-consistent.
    let root = sb.read_inode(&img, sb.rootino).unwrap();
    assert_eq!(root.di_ino, Some(11072), "di_ino self-reference matches");
}
