//! XFS extended attributes — the attribute fork, in all three of its shapes.
//!
//! Nothing in this crate read the attribute fork before this test. `di_forkoff`
//! and `di_aformat` were parsed and then unused, so every XFS image presented
//! files with no attributes — indistinguishable from files that have none. On
//! Linux that silently drops `SELinux` labels, capabilities and POSIX `ACLs`.
//!
//! ## The oracle is the Linux XFS driver
//!
//! `tests/data/xfs_xattr.img.gz` was made by `mkfs.xfs` and populated through a
//! real mount; the kernel wrote every attribute and `getfattr` read them all
//! back before the filesystem was unmounted. `SELinux` was active, so it added
//! its own `security.selinux` label to each file — unplanned, and kept: it is
//! exactly the attribute a forensic reader must not lose.
//!
//! ## Three storage shapes, one per test file
//!
//! `xfs_db` reports the attribute-fork format (`core.aformat`) directly, so
//! which shape each inode uses is observed rather than inferred:
//!
//! | inode | file | `aformat` | shape |
//! |---|---|---|---|
//! | 131 | `sf.txt` | 1 (local) | **shortform**, in the inode's literal area |
//! | 132 | `leaf.txt` | 2 (extents) | **leaf**, value held *local* in the leaf block |
//! | 133 | `remote.txt` | 2 (extents) | **leaf**, value *remote* in its own blocks |
//! | 134 | `ns.txt` | 1 (local) | shortform, all three namespaces |
//! | 135 | `adir` | 1 (local) | shortform, on a directory |
//!
//! ## Layout facts, read out of these bytes rather than recalled
//!
//! Every constant the decoder depends on was confirmed against this image
//! before a line was written:
//!
//! - the shortform header is **4 bytes** (`totsize` be16, `count`, `padding`),
//!   derived from arithmetic that had to close: entries of `3 + namelen +
//!   valuelen` sum to 93 while `hdr.totsize` reads 97.
//! - a shortform entry is `namelen`, `valuelen`, `flags`, then name and value.
//! - the namespace lives in those flags: `0x00` user, `0x02` root (`trusted.`),
//!   `0x04` secure (`security.`) — observed on `user.u`, `trusted.t` and
//!   `security.s` in `ns.txt`.
//! - a v5 leaf block starts with magic `0x3BEE` at offset **8**, and its header
//!   is **80** bytes. 76 was tried first and produced garbage entries; the
//!   block's own `freemap[0].base = 96`, with two 8-byte entries, puts the
//!   header end at 80. The v5 header carries a trailing `__be32 pad2`.
//! - `XFS_ATTR_LOCAL` is `0x01` in a leaf entry's flags, choosing between the
//!   local and remote name/value records.

#![cfg(feature = "vfs")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Read;

use xfs::xattr::{list_xattrs, XattrStorage};
use xfs::{Inode, Superblock};

const SF_INO: u64 = 131;
const LEAF_LOCAL_INO: u64 = 132;
const LEAF_REMOTE_INO: u64 = 133;
const NS_INO: u64 = 134;
const DIR_INO: u64 = 135;

/// The minted image. Committed gzipped: XFS refuses to make a filesystem under
/// 300 MB, and 320 MB of mostly-zero image is 338 KB compressed.
fn image() -> Vec<u8> {
    let gz = include_bytes!("../../tests/data/xfs_xattr.img.gz");
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut out)
        .expect("fixture must decompress");
    out
}

fn sb(img: &[u8]) -> Superblock {
    Superblock::parse(img).expect("fixture must parse as XFS")
}

fn inode(img: &[u8], sb: &Superblock, ino: u64) -> Inode {
    sb.read_inode(img, ino).expect("inode must parse")
}

/// `(name, len, storage)` for every attribute on `ino`.
fn attrs(img: &[u8], ino: u64) -> Vec<(String, usize, XattrStorage)> {
    let sb = sb(img);
    let node = inode(img, &sb, ino);
    list_xattrs(img, &sb, &node)
        .expect("listing must not error")
        .into_iter()
        .map(|x| (x.full_name(), x.value.len(), x.storage))
        .collect()
}

/// Shortform: the attributes live in the inode's own literal area.
#[test]
fn shortform_attributes_are_listed() {
    let img = image();
    let a = attrs(&img, SF_INO);

    // Non-zero baseline before any per-name assertion, or an empty list would
    // satisfy every `find` below vacuously.
    assert_eq!(a.len(), 3, "getfattr listed 3 attributes on sf.txt: {a:?}");

    let names: Vec<&str> = a.iter().map(|(n, _, _)| n.as_str()).collect();
    for want in ["user.small", "user.comment", "security.selinux"] {
        assert!(names.contains(&want), "missing {want}; got {names:?}");
    }
    assert!(
        a.iter().all(|(_, _, s)| *s == XattrStorage::Shortform),
        "aformat is 1 (local) for inode 131, so every attribute is shortform: {a:?}"
    );
}

/// The namespace is carried in three flag bits, not in the stored name.
#[test]
fn namespaces_come_from_the_entry_flags() {
    let img = image();
    let a = attrs(&img, NS_INO);
    let names: Vec<&str> = a.iter().map(|(n, _, _)| n.as_str()).collect();

    assert_eq!(a.len(), 4, "ns.txt carries 4 attributes: {a:?}");
    // XFS stores the bare name plus a flag. Reporting `t` rather than
    // `trusted.t` would lose which namespace the attribute belongs to, and
    // reporting it in the WRONG namespace would rename the artifact.
    for want in ["user.u", "trusted.t", "security.s", "security.selinux"] {
        assert!(names.contains(&want), "missing {want}; got {names:?}");
    }
}

/// Leaf format, value held inside the leaf block.
#[test]
fn leaf_local_values_are_read_byte_exact() {
    let img = image();
    let sb = sb(&img);
    let node = inode(&img, &sb, LEAF_LOCAL_INO);
    let list = list_xattrs(&img, &sb, &node).expect("leaf listing");

    let big = list
        .iter()
        .find(|x| x.full_name() == "user.big")
        .expect("user.big must be listed");
    assert_eq!(big.storage, XattrStorage::LeafLocal);
    // Byte-exact over all 3000: a wrong nameidx or header size yields the right
    // LENGTH from the entry and the wrong bytes.
    assert_eq!(big.value, vec![b'B'; 3000], "3000 bytes of 'B'");
}

/// Leaf format, value pushed out to its own blocks.
///
/// This is the shape most likely to be got wrong and never noticed: the value
/// is addressed by a LOGICAL block offset inside the attribute fork, so it must
/// be mapped through the fork's extents, and on v5 every remote block carries a
/// 56-byte `xfs_attr3_rmt_hdr` that is not part of the value.
#[test]
fn leaf_remote_values_are_read_byte_exact() {
    let img = image();
    let sb = sb(&img);
    let node = inode(&img, &sb, LEAF_REMOTE_INO);
    let list = list_xattrs(&img, &sb, &node).expect("remote listing");

    let huge = list
        .iter()
        .find(|x| x.full_name() == "user.huge")
        .expect("user.huge must be listed");
    assert!(
        matches!(huge.storage, XattrStorage::LeafRemote { .. }),
        "20000 bytes cannot fit a 4096-byte leaf block: {:?}",
        huge.storage
    );
    assert_eq!(
        huge.value.len(),
        20000,
        "getfattr read 20000 bytes back from this attribute"
    );
    // The whole value, not a prefix: a reader that failed to strip the per-block
    // remote headers would return the right total length with 56 bytes of
    // header spliced in at every block boundary.
    assert_eq!(huge.value, vec![b'H'; 20000]);
}

/// Directories carry attributes too.
#[test]
fn directories_carry_attributes() {
    let img = image();
    let a = attrs(&img, DIR_INO);
    let names: Vec<&str> = a.iter().map(|(n, _, _)| n.as_str()).collect();
    assert!(
        names.contains(&"user.ondir"),
        "adir must carry user.ondir; got {names:?}"
    );
}

/// An inode with no attribute fork is not an error, and not a guess.
#[test]
fn an_inode_without_an_attribute_fork_lists_nothing() {
    let img = image();
    let sb = sb(&img);
    // The root directory was never given an attribute.
    let node = inode(&img, &sb, sb.rootino);
    let list = list_xattrs(&img, &sb, &node).expect("no attr fork is not an error");
    assert!(
        list.iter().all(|x| x.full_name() != "user.small"),
        "the root must not inherit another inode's attributes: {list:?}"
    );
}
