//! 64-bit extent counters (`XFS_SB_FEAT_INCOMPAT_NREXT64`) move two inode
//! fields, and reading the old offsets returns plausible, wrong data.
//!
//! xfsprogs 6.x sets this feature BY DEFAULT, so it is the normal case on any
//! recently made XFS filesystem rather than an exotic option. It relocates both
//! extent counters:
//!
//! | | without `NREXT64` | with `NREXT64` |
//! |---|---|---|
//! | data-fork extents | `di_nextents` be32 @76 | `di_big_nextents` be64 @**24** |
//! | attr-fork extents | `di_anextents` be16 @80 | `di_anextents` be32 @**76** |
//!
//! ## Why this is worth a test of its own
//!
//! Reading the legacy offsets on such an image does not error. Offset 76 still
//! holds a small plausible number — it is just the ATTRIBUTE count sitting where
//! the DATA count is expected. The reader then walks that many extents.
//!
//! On this fixture the effect was measured, not theorised:
//!
//! ```text
//! ino 131 sf.txt: size=10  nextents(read)=0  bytes_read=10  content="\0\0\0\0\0\0\0\0\0\0"
//! ```
//!
//! `sf.txt` contains `"shortform\n"`. It has one data extent and no attributes,
//! so the misread count was 0, no extents were walked, and the reader returned
//! the right NUMBER of bytes, all zero, with no error and nothing in any log.
//! Files with more attribute extents than data extents read correctly by
//! coincidence, which is why the defect survives casual testing.
//!
//! Silent substitution of an artifact's contents is the worst failure mode
//! available to a forensic reader, so this is pinned separately from the
//! extended-attribute tests that exposed it.

#![cfg(feature = "vfs")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Read;

use xfs::Superblock;

fn image() -> Vec<u8> {
    let gz = include_bytes!("../../tests/data/xfs_xattr.img.gz");
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut out)
        .expect("fixture must decompress");
    out
}

/// The fixture must actually exercise the feature, or every assertion below is
/// about a code path it never takes.
#[test]
fn the_fixture_really_has_nrext64_set() {
    let img = image();
    let sb = Superblock::parse(&img).unwrap();
    assert!(
        sb.has_nrext64(),
        "mkfs.xfs 6.x sets NREXT64 by default; without it this file tests nothing"
    );
}

/// The counters must match what `xfs_db` reports for these inodes.
///
/// Both counters are checked together because they were BOTH wrong, in a way
/// that partially cancelled: `nextents` read the attribute count and `aextents`
/// read padding. Checking only one would have looked like a single-field slip.
#[test]
fn both_extent_counters_match_xfs_db() {
    let img = image();
    let sb = Superblock::parse(&img).unwrap();

    // xfs_db -c "inode N" -c "p core.nextents core.naextents", run on this image:
    //
    //   ino 131: core.nextents = 1   core.naextents = 0
    //   ino 132: core.nextents = 1   core.naextents = 1
    //   ino 133: core.nextents = 1   core.naextents = 2
    //
    // Note nextents is 1 for ALL THREE while naextents varies. That is what
    // makes the two fields distinguishable here; in an image where they happen
    // to agree, a swap is invisible.
    for (ino, nextents, aextents) in [(131u64, 1u64, 0u32), (132, 1, 1), (133, 1, 2)] {
        let node = sb.read_inode(&img, ino).unwrap();
        assert_eq!(
            node.nextents, nextents,
            "inode {ino} data-fork extent count (di_big_nextents @24)"
        );
        assert_eq!(
            node.aextents, aextents,
            "inode {ino} attr-fork extent count (di_anextents @76 under NREXT64)"
        );
    }
}

/// The consequence, stated as content rather than as a field value.
///
/// This is the assertion that would have caught the defect without anyone
/// knowing what `NREXT64` is: read a file and compare it to what was written.
#[test]
fn file_contents_are_not_silently_replaced_by_zeros() {
    let img = image();
    let sb = Superblock::parse(&img).unwrap();

    for (ino, want) in [
        (131u64, &b"shortform\n"[..]),
        (132, b"leaf\n"),
        (133, b"remote\n"),
    ] {
        let node = sb.read_inode(&img, ino).unwrap();
        let got = sb.read_file(&img, &node).expect("file must read");
        assert_eq!(
            got,
            want,
            "inode {ino} read back as {:?}",
            String::from_utf8_lossy(&got)
        );
        // Explicit, because the failure being guarded is specifically
        // "right length, all zero" rather than "wrong length".
        assert!(
            got.iter().any(|&b| b != 0),
            "inode {ino} read as all-zero bytes of the correct length -- the \
             signature of a misread extent count"
        );
    }
}
