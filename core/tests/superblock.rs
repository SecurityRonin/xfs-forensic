//! P0 superblock tests.
//!
//! Two tiers:
//! - **Oracle-gated (Tier-1):** parse the real minted v5/v4 images and assert
//!   every field equals the `xfs_db sb 0 print` ground truth captured in
//!   `tests/data/README.md`. Gated on the image path; skip cleanly when absent.
//! - **Unit (robustness):** bad-magic fails loud with the offending bytes; a
//!   truncated buffer returns `Truncated`, never panics.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use xfs::{Superblock, XFS_SB_MAGIC};

/// Resolve the image path from an env var, falling back to `tests/data/<name>`.
/// Returns `None` (→ test skips) when the file is not present.
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

/// Read the primary superblock (AG 0, offset 0) — first 512 bytes suffice.
fn read_sb(path: &PathBuf) -> Vec<u8> {
    let data = std::fs::read(path).unwrap();
    data[..512.min(data.len())].to_vec()
}

#[test]
fn v5_superblock_matches_oracle() {
    let Some(path) = image_path("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent (set XFS_ORACLE_V5_IMG or mint tests/data/v5.img)");
        return;
    };
    let sb = Superblock::parse(&read_sb(&path)).expect("v5 superblock parses");

    // Ground truth: tests/data/v5.sb0.txt (xfs_db sb 0 print).
    assert_eq!(sb.magic, XFS_SB_MAGIC, "magicnum");
    assert_eq!(sb.blocksize, 4096, "blocksize");
    assert_eq!(sb.inodesize, 512, "inodesize");
    assert_eq!(sb.inopblock, 8, "inopblock");
    assert_eq!(sb.agblocks, 32768, "agblocks");
    assert_eq!(sb.agcount, 4, "agcount");
    assert_eq!(sb.rootino, 128, "rootino");
    assert_eq!(sb.versionnum, 0xb4a5, "versionnum");
    assert_eq!(sb.blocklog, 12, "blocklog");
    assert_eq!(sb.inodelog, 9, "inodelog");
    assert_eq!(sb.inopblog, 3, "inopblog");
    assert_eq!(sb.agblklog, 15, "agblklog");

    assert_eq!(sb.version(), 5, "low nibble of versionnum -> v5");
    assert!(sb.is_v5());
}

#[test]
fn v4_superblock_matches_oracle() {
    let Some(path) = image_path("XFS_ORACLE_V4_IMG", "v4.img") else {
        eprintln!("skip: v4 image absent (set XFS_ORACLE_V4_IMG or mint tests/data/v4.img)");
        return;
    };
    let sb = Superblock::parse(&read_sb(&path)).expect("v4 superblock parses");

    // Ground truth: tests/data/v4.sb0.txt (xfs_db sb 0 print).
    assert_eq!(sb.magic, XFS_SB_MAGIC, "magicnum");
    assert_eq!(sb.blocksize, 4096, "blocksize");
    assert_eq!(sb.inodesize, 256, "inodesize"); // v4 default inode size
    assert_eq!(sb.inopblock, 16, "inopblock");
    assert_eq!(sb.agblocks, 32768, "agblocks");
    assert_eq!(sb.agcount, 4, "agcount");
    assert_eq!(sb.rootino, 128, "rootino");
    assert_eq!(sb.versionnum, 0xb4a4, "versionnum");
    assert_eq!(sb.blocklog, 12, "blocklog");
    assert_eq!(sb.inodelog, 8, "inodelog");
    assert_eq!(sb.inopblog, 4, "inopblog");
    assert_eq!(sb.agblklog, 15, "agblklog");

    assert_eq!(sb.version(), 4, "low nibble of versionnum -> v4");
    assert!(!sb.is_v5());
}

#[test]
fn bad_magic_fails_loud_with_offending_bytes() {
    // A 512-byte buffer whose first four bytes are NOT "XFSB".
    let mut data = vec![0u8; 512];
    data[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let err = Superblock::parse(&data).unwrap_err();
    match err {
        xfs::XfsError::BadMagic { found, bytes } => {
            assert_eq!(found, 0xDEAD_BEEF);
            assert_eq!(bytes, [0xDE, 0xAD, 0xBE, 0xEF]);
        }
        other => panic!("expected BadMagic, got {other:?}"),
    }
}

#[test]
fn truncated_buffer_does_not_panic() {
    // Valid magic but far too short to hold the whole superblock.
    let mut data = vec![0u8; 8];
    data[0..4].copy_from_slice(&XFS_SB_MAGIC.to_be_bytes());

    let err = Superblock::parse(&data).unwrap_err();
    assert!(
        matches!(err, xfs::XfsError::Truncated { .. }),
        "short buffer must yield Truncated, got {err:?}"
    );
}

#[test]
fn empty_buffer_does_not_panic() {
    let err = Superblock::parse(&[]).unwrap_err();
    assert!(matches!(err, xfs::XfsError::Truncated { .. }));
}
