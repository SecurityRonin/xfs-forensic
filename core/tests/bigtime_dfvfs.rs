//! **Tier-1 (env-gated)** — the bigtime timestamp path against a genuine dfvfs
//! image whose inodes carry `XFS_DIFLAG2_BIGTIME`.
//!
//! `xfs-bigtime.raw` is `test_data/xfs_bigtime.raw` from
//! [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) (Apache-2.0). It
//! is a v5 image made after 2486 became reachable, so every inode's timestamps
//! use the 64-bit **bigtime** counter (`sec = raw/1e9 - 2^31`) rather than the
//! legacy `(sec:i32, nsec:i32)` packing — the branch our default `mkfs.xfs`
//! images (legacy timestamps) never exercise.
//!
//! Unlike the always-on `xfs_dfvfs.raw` Tier-1 image, this second 16 `MiB` blob
//! is **not committed** (one committed 16 MiB image is enough; a second would
//! bloat the repo). It is gitignored and **env-gated** on `XFS_BIGTIME_ORACLE`;
//! the test skips cleanly when the image is absent, so CI without it stays green
//! while a local run with it validates the bigtime decode.
//!
//! Ground truth (xfsprogs 6.6.0, `TZ=UTC xfs_db -r -c 'inode 16128' -c print`):
//!   - rootino = 16128, versionnum 0xb4b5 (v5)
//!   - root inode `v3.bigtime = 1`, `di_flags2 = 0x18` (BIGTIME | … )
//!   - mtime  = 2026-07-01 13:32:33 UTC = epoch 1_782_912_753, nsec 497_950_218
//!   - crtime = 2026-07-01 13:32:33 UTC = epoch 1_782_912_753, nsec  68_099_000

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use xfs::{Superblock, XFS_DIFLAG2_BIGTIME};

/// Read the bigtime oracle image from `XFS_BIGTIME_ORACLE`; `None` (→ skip) when
/// the env var is unset (the gitignored image is not present).
fn bigtime_image() -> Option<Vec<u8>> {
    let path = std::env::var("XFS_BIGTIME_ORACLE").ok()?;
    std::fs::read(&path).ok()
}

#[test]
fn bigtime_root_timestamps_decode_against_oracle() {
    let Some(img) = bigtime_image() else {
        eprintln!("skip: bigtime image absent (set XFS_BIGTIME_ORACLE=/path/to/xfs-bigtime.raw)");
        return;
    };
    let sb = Superblock::parse(&img).expect("bigtime superblock parses");
    assert_eq!(sb.rootino, 16128, "bigtime image rootino");
    assert!(sb.is_v5());

    let root = sb.read_inode(&img, sb.rootino).unwrap();

    // The inode must be flagged bigtime, and the reader must take the bigtime
    // decode branch because of it (not the legacy path).
    assert!(root.is_bigtime(), "root inode carries XFS_DIFLAG2_BIGTIME");
    assert_eq!(
        root.flags2.unwrap() & XFS_DIFLAG2_BIGTIME,
        XFS_DIFLAG2_BIGTIME,
        "BIGTIME bit set in di_flags2"
    );

    // The load-bearing assertion: the decoded post-epoch nanosecond counter must
    // reproduce the kernel/xfs_db UTC ground truth. A legacy decode of the same
    // raw __be64 would yield a wildly different (far-future/garbage) value, so
    // this pins the bigtime math, not merely "some timestamp".
    assert_eq!(root.mtime.secs, 1_782_912_753, "mtime seconds (bigtime)");
    assert_eq!(root.mtime.nsecs, 497_950_218, "mtime nanoseconds");

    let crtime = root.crtime.expect("v5 inode has crtime");
    assert_eq!(crtime.secs, 1_782_912_753, "crtime seconds (bigtime)");
    assert_eq!(crtime.nsecs, 68_099_000, "crtime nanoseconds");
}
