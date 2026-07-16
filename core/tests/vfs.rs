//! forensic-vfs adapter tests for `xfs::vfs::XfsFs` (behind the `vfs` feature).
//!
//! These drive the [`forensic_vfs::FileSystem`] trait object over the real
//! oracle image `tests/data/v5.img` and check it against the *reader's own*
//! `read_dir` / `read_by_path` output (a self-consistency oracle: the adapter
//! must surface exactly what the underlying `xfs-core` reader surfaces), plus
//! the probe (v5.img sniffs as an XFS candidate; random bytes do not).
//!
//! Env-gated on `XFS_ORACLE_V5_IMG` (the 512 `MiB` image is gitignored — see
//! `tests/data/README.md`); the tests skip cleanly when the image is absent.

#![cfg(feature = "vfs")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;

use forensic_vfs::{
    Confidence, DynSource, FileSystem, FsKind, ImageSource, NodeKind, SniffWindow, StreamId,
    VfsResult,
};
use xfs::vfs::{xfs_probe, XfsFs};
use xfs::{read_by_path, read_dir, Superblock};

/// An in-memory [`ImageSource`] over a whole image (the way a carved region or a
/// decoded container hands bytes to a filesystem adapter).
struct MemSource(Vec<u8>);
impl ImageSource for MemSource {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let off = usize::try_from(offset).unwrap_or(usize::MAX);
        let Some(src) = self.0.get(off..) else {
            return Ok(0);
        };
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        Ok(n)
    }
}

fn mem(bytes: Vec<u8>) -> DynSource {
    Arc::new(MemSource(bytes))
}

/// Resolve the v5 oracle image path from `XFS_ORACLE_V5_IMG`, else the repo-root
/// `tests/data/v5.img`; `None` (skip) when the gitignored image is absent.
fn v5_image() -> Option<Vec<u8>> {
    let p = std::env::var("XFS_ORACLE_V5_IMG").map_or_else(
        |_| {
            let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            d.pop(); // core/ -> repo root
            d.push("tests/data");
            d.push("v5.img");
            d
        },
        PathBuf::from,
    );
    p.exists().then(|| std::fs::read(&p).unwrap())
}

#[test]
fn probe_recognizes_v5_and_declines_random_bytes() {
    // The XFSB magic at byte 0 makes the probe a definite Yes.
    let mut xfsb = vec![0u8; 4096];
    xfsb[0..4].copy_from_slice(b"XFSB");
    assert!(matches!(
        xfs_probe(&SniffWindow::new(0, &xfsb)),
        Confidence::Yes { .. }
    ));
    // Random / empty bytes decline.
    assert_eq!(xfs_probe(&SniffWindow::new(0, &[])), Confidence::No);
    assert_eq!(
        xfs_probe(&SniffWindow::new(0, &[0u8; 4096])),
        Confidence::No
    );
}

#[test]
fn kind_root_and_zone() {
    let Some(img) = v5_image() else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let fs = XfsFs::open(&mem(img.clone())).expect("mount xfs");
    let vfs: &dyn FileSystem = &fs;
    assert_eq!(vfs.kind(), FsKind::XFS);
    // The root maps to the superblock's root inode number.
    let sb = Superblock::parse(&img).unwrap();
    let meta = vfs.meta(vfs.root()).unwrap();
    assert_eq!(meta.ino, sb.rootino);
    assert_eq!(meta.kind, NodeKind::Dir);
}

#[test]
fn read_dir_root_matches_reader() {
    let Some(img) = v5_image() else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let fs = XfsFs::open(&mem(img.clone())).expect("mount xfs");
    let vfs: &dyn FileSystem = &fs;

    // The adapter's listing must equal the reader's own read_dir on the root.
    let sb = Superblock::parse(&img).unwrap();
    let root_inode = sb.read_inode(&img, sb.rootino).unwrap();
    let mut reader_names: Vec<String> = read_dir(&img, &sb, &root_inode)
        .unwrap()
        .into_iter()
        .map(|e| String::from_utf8_lossy(&e.name).into_owned())
        .collect();
    reader_names.sort();

    let mut vfs_names: Vec<String> = vfs
        .read_dir(vfs.root())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.name != b"." && e.name != b"..")
        .map(|e| String::from_utf8_lossy(&e.name).into_owned())
        .collect();
    vfs_names.sort();

    assert_eq!(vfs_names, reader_names, "adapter listing == reader listing");
    // The known v5.img root entries (tests/data/README.md P4 oracle).
    for known in ["sf", "block", "leaf", "big.bin"] {
        assert!(vfs_names.iter().any(|n| n == known), "missing {known}");
    }
}

#[test]
fn lookup_read_matches_read_by_path() {
    let Some(img) = v5_image() else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let fs = XfsFs::open(&mem(img.clone())).expect("mount xfs");
    let vfs: &dyn FileSystem = &fs;

    // Navigate root -> sf -> file1.txt through the trait object.
    let sf = vfs.lookup(vfs.root(), b"sf").unwrap().expect("sf dir");
    assert_eq!(vfs.meta(sf).unwrap().kind, NodeKind::Dir);
    let file1 = vfs.lookup(sf, b"file1.txt").unwrap().expect("file1.txt");
    let meta = vfs.meta(file1).unwrap();
    assert_eq!(meta.kind, NodeKind::File);

    let mut buf = vec![0u8; meta.size as usize];
    let n = vfs.read_at(file1, StreamId::Default, 0, &mut buf).unwrap();
    buf.truncate(n);

    // Self-consistency oracle: the adapter's bytes == the reader's read_by_path.
    let sb = Superblock::parse(&img).unwrap();
    let expected = read_by_path(&img, &sb, "/sf/file1.txt").unwrap();
    assert_eq!(buf, expected, "adapter read_at == reader read_by_path");
    assert_eq!(buf, b"content-1\n", "literal content of /sf/file1.txt");

    // Extents cover a non-empty run for a real file.
    let runs: Vec<_> = vfs
        .extents(file1, StreamId::Default)
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(!runs.is_empty(), "file1.txt has at least one run");
}

#[test]
fn missing_child_is_none_and_foreign_id_is_refused() {
    let Some(img) = v5_image() else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let fs = XfsFs::open(&mem(img)).expect("mount xfs");
    let vfs: &dyn FileSystem = &fs;
    assert!(vfs.lookup(vfs.root(), b"does-not-exist").unwrap().is_none());
    // A non-XFS FileId identity is a caller error, surfaced loud.
    let foreign = forensic_vfs::FileId::NtfsRef { entry: 5, seq: 1 };
    assert!(vfs.meta(foreign).is_err());
    assert!(vfs.read_dir(foreign).is_err());
}

#[test]
fn open_on_garbage_fails_loud() {
    // No XFSB magic -> Superblock::parse fails -> loud error, never a silent mount.
    assert!(XfsFs::open(&mem(vec![0u8; 4096])).is_err());
}

#[test]
fn deleted_unallocated_readlink_defaults() {
    let Some(img) = v5_image() else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let fs = XfsFs::open(&mem(img)).expect("mount xfs");
    let vfs: &dyn FileSystem = &fs;
    assert_eq!(vfs.deleted().unwrap().count(), 0);
    assert_eq!(vfs.unallocated().unwrap().count(), 0);
    // read_link on a non-symlink (the root dir) reads as an empty target.
    assert_eq!(vfs.read_link(vfs.root(), 4096).unwrap(), Vec::<u8>::new());
}

#[test]
fn geometry_and_zone_reported() {
    let Some(img) = v5_image() else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let fs = XfsFs::open(&mem(img.clone())).expect("mount xfs");
    let vfs: &dyn FileSystem = &fs;
    let sizes = vfs.sector_sizes();
    assert_eq!(sizes.logical, 512);
    // v5.img blocksize is 4096 (SGI XFS file(1) header).
    let sb = Superblock::parse(&img).unwrap();
    assert_eq!(sizes.cluster_or_block, sb.blocksize);
    assert_eq!(vfs.timestamp_zone(), forensic_vfs::TimeZonePolicy::Utc);
}

#[test]
fn extents_on_a_directory_is_empty_and_named_stream_refused() {
    let Some(img) = v5_image() else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let fs = XfsFs::open(&mem(img)).expect("mount xfs");
    let vfs: &dyn FileSystem = &fs;
    // The root is a short-form (Local) directory -> no inline extent array, so
    // extents() takes the non-Extents arm and yields nothing.
    let runs: Vec<_> = vfs
        .extents(vfs.root(), StreamId::Default)
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(
        runs.is_empty(),
        "a Local-format dir has no data-fork extents"
    );

    // A named/slack stream is refused loud on both extents and read_at.
    assert!(vfs.extents(vfs.root(), StreamId::Slack).is_err());
    assert!(vfs
        .read_at(vfs.root(), StreamId::Named(1), 0, &mut [0u8; 4])
        .is_err());
}

#[test]
fn read_at_past_eof_reads_zero() {
    let Some(img) = v5_image() else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let fs = XfsFs::open(&mem(img.clone())).expect("mount xfs");
    let vfs: &dyn FileSystem = &fs;
    let sf = vfs.lookup(vfs.root(), b"sf").unwrap().unwrap();
    let file1 = vfs.lookup(sf, b"file1.txt").unwrap().unwrap();
    let size = vfs.meta(file1).unwrap().size;
    // A start at/after EOF yields zero bytes, never a panic.
    let mut buf = [0u8; 16];
    assert_eq!(
        vfs.read_at(file1, StreamId::Default, size + 100, &mut buf)
            .unwrap(),
        0
    );
}

#[test]
fn out_of_image_inode_maps_to_out_of_range() {
    let Some(img) = v5_image() else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let fs = XfsFs::open(&mem(img)).expect("mount xfs");
    let vfs: &dyn FileSystem = &fs;
    // An inode number whose located byte window lies past the image end -> the
    // reader's Truncated error, mapped to VfsError::OutOfRange (not Decode).
    let bogus = forensic_vfs::FileId::Opaque(u64::MAX / 2);
    assert!(matches!(
        vfs.meta(bogus),
        Err(forensic_vfs::VfsError::OutOfRange { .. })
    ));
}
