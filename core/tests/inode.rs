//! P2 inode-core tests.
//!
//! `Inode::parse` MUST reproduce `xfs_db -c 'inode N' -c print` exactly — a
//! Tier-1 structural check. The ground-truth values below are grepped verbatim
//! from the committed oracle dumps:
//!
//! - `tests/data/v5.inode128.txt` — v5 root dir (ino 128, v3 core, bigtime)
//! - `tests/data/v5.inode_big.txt` — v5 `big.bin` (ino 135, extents, `16 MiB`)
//! - `tests/data/v4.inode128.txt` — v4 root dir (ino 128, v2 core, legacy time)
//!
//! Timestamps: the oracle prints the minting VM's local time (HKT/+0800), which
//! is timezone-fragile to reparse. We instead anchor on the timezone-independent
//! facts — `atime` is the Unix epoch (`0`), the nanosecond fields (which carry
//! no timezone), and `mtime`/`ctime`/`crtime` seconds against the Unix value
//! `1783879768` (the oracle's `Mon Jul 13 02:09:28 2026 HKT` == `2026-07-12
//! 18:09:28 UTC`, cross-checked under `TZ=UTC xfs_db`). The bigtime-vs-legacy
//! decode branch is the load-bearing thing under test, so we assert the decoded
//! Unix value directly.
//!
//! Env-gated on the image path so the oracle assertions run when the minted
//! corpus is present and skip cleanly when it is absent (mirrors P0/P1 style).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use xfs::{FileType, Inode, InodeFormat, Superblock};

/// Every `InodeFormat` decode arm — the oracle images only exercise Local and
/// Extents, so the Dev/Btree/Other arms need explicit coverage (each is a real
/// selector a hostile or unusual image can carry, not a dead arm).
#[test]
fn inode_format_all_arms() {
    assert_eq!(InodeFormat::from_raw(0), InodeFormat::Dev);
    assert_eq!(InodeFormat::from_raw(1), InodeFormat::Local);
    assert_eq!(InodeFormat::from_raw(2), InodeFormat::Extents);
    assert_eq!(InodeFormat::from_raw(3), InodeFormat::Btree);
    assert_eq!(InodeFormat::from_raw(4), InodeFormat::Other(4));
    assert_eq!(InodeFormat::from_raw(255), InodeFormat::Other(255));
}

/// Every `FileType` `S_IFMT` decode arm — the oracle images only carry
/// directories and regular files, so fifo/char/block/symlink/socket/other need
/// explicit coverage.
#[test]
fn file_type_all_arms() {
    assert_eq!(FileType::from_mode(0o010_000), FileType::Fifo);
    assert_eq!(FileType::from_mode(0o020_000), FileType::CharDevice);
    assert_eq!(FileType::from_mode(0o040_000), FileType::Directory);
    assert_eq!(FileType::from_mode(0o060_000), FileType::BlockDevice);
    assert_eq!(FileType::from_mode(0o100_000), FileType::Regular);
    assert_eq!(FileType::from_mode(0o120_000), FileType::Symlink);
    assert_eq!(FileType::from_mode(0o140_000), FileType::Socket);
    // 0 has no S_IFMT type bits set -> an unnamed type, carried verbatim.
    assert_eq!(FileType::from_mode(0o000_644), FileType::Other(0));
}

/// Unix seconds for the minted corpus's `Mon Jul 13 02:09:28 2026 HKT`
/// (== `2026-07-12 18:09:28 UTC`), the mtime/ctime/crtime.sec of the root and
/// big.bin inodes. Timezone-pinned via `TZ=UTC xfs_db` at capture time.
const MINT_UNIX_SECS: i64 = 1_783_879_768;

fn image_bytes(env: &str, default_name: &str) -> Option<Vec<u8>> {
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
    p.exists().then(|| std::fs::read(&p).unwrap())
}

fn sb_of(img: &[u8]) -> Superblock {
    Superblock::parse(&img[..512.min(img.len())]).expect("superblock parses")
}

#[test]
fn v5_root_inode_matches_oracle() {
    let Some(img) = image_bytes("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent (set XFS_ORACLE_V5_IMG or mint tests/data/v5.img)");
        return;
    };
    let sb = sb_of(&img);
    // rootino = 128 (see P1 oracle). Read + parse via the reader convenience.
    assert_eq!(sb.rootino, 128, "minted rootino");
    let inode = sb.read_inode(&img, sb.rootino).expect("root inode parses");

    // tests/data/v5.inode128.txt
    assert_eq!(inode.magic, 0x494e, "di_magic 'IN'");
    assert_eq!(inode.version, 3, "v5 -> v3 core");
    assert_eq!(inode.format, InodeFormat::Local, "core.format = 1 (local)");
    assert_eq!(inode.mode, 0o040_755, "core.mode");
    assert_eq!(
        inode.file_type(),
        FileType::Directory,
        "root is a directory"
    );
    assert!(inode.is_dir());
    assert_eq!(inode.size, 56, "core.size");
    assert_eq!(inode.nblocks, 0, "core.nblocks");
    assert_eq!(inode.nextents, 0, "core.nextents");
    assert_eq!(inode.aformat, 2, "core.aformat = extents");

    // v3 extras.
    assert_eq!(inode.di_ino, Some(128), "v3.inumber self-reference == ino");
    assert_eq!(inode.flags2, Some(0x8), "v3.flags2 (BIGTIME bit set)");
    assert!(inode.is_bigtime(), "v5 root uses bigtime encoding");
    assert_eq!(inode.cowextsize, Some(0), "v3.cowextsize");
    assert_eq!(
        inode.uuid,
        Some([
            0x05, 0x6b, 0xaa, 0xec, 0x66, 0xa5, 0x49, 0xb1, 0xa0, 0xcc, 0x03, 0xa0, 0x02, 0xf6,
            0x2c, 0x18
        ]),
        "v3.uuid 056baaec-66a5-49b1-a0cc-03a002f62c18"
    );
    assert_eq!(
        inode.crc,
        Some(0x0a97_c0f5),
        "v3.crc exposed (not verified)"
    );
    assert!(inode.crtime.is_some(), "v3 has crtime");

    // Timestamps (bigtime decode). atime is the Unix epoch.
    assert_eq!(inode.atime.secs, 0, "atime = Unix epoch");
    assert_eq!(inode.atime.nsecs, 0, "atime.nsec");
    assert_eq!(inode.mtime.secs, MINT_UNIX_SECS, "mtime.sec (bigtime)");
    assert_eq!(inode.mtime.nsecs, 258_024_354, "mtime.nsec");
    assert_eq!(inode.ctime.secs, MINT_UNIX_SECS, "ctime.sec (bigtime)");
    assert_eq!(inode.ctime.nsecs, 258_024_354, "ctime.nsec");
    let crtime = inode.crtime.expect("v3 crtime");
    assert_eq!(crtime.secs, MINT_UNIX_SECS, "crtime.sec (bigtime)");
    assert_eq!(crtime.nsecs, 27_423_000, "crtime.nsec");

    // v3 data fork starts at inode offset 176 (P3/P4 branch on this).
    assert_eq!(inode.data_fork_offset(), 176, "v3 data fork offset");
}

#[test]
fn v5_big_bin_inode_matches_oracle() {
    let Some(img) = image_bytes("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let sb = sb_of(&img);
    // big.bin is ino 135 (see v5.inodes.txt / v5.inode_big.txt).
    let inode = sb.read_inode(&img, 135).expect("big.bin inode parses");

    // tests/data/v5.inode_big.txt
    assert_eq!(inode.magic, 0x494e, "di_magic");
    assert_eq!(inode.version, 3, "v3 core");
    assert_eq!(
        inode.format,
        InodeFormat::Extents,
        "core.format = 2 (extents)"
    );
    assert_eq!(inode.mode, 0o100_600, "core.mode (regular file)");
    assert_eq!(inode.file_type(), FileType::Regular, "regular file");
    assert!(inode.is_reg());
    assert_eq!(inode.size, 16_777_216, "core.size == 16 MiB");
    assert_eq!(inode.nblocks, 4096, "core.nblocks");
    // Oracle ground truth: this 16 MiB file landed in ONE contiguous extent.
    assert_eq!(
        inode.nextents, 1,
        "core.nextents (single contiguous extent)"
    );
    assert_eq!(inode.di_ino, Some(135), "v3.inumber self-reference");
    assert!(inode.is_bigtime(), "bigtime");
    assert_eq!(inode.data_fork_offset(), 176, "v3 data fork offset");
}

#[test]
fn v4_root_inode_matches_oracle() {
    let Some(img) = image_bytes("XFS_ORACLE_V4_IMG", "v4.img") else {
        eprintln!("skip: v4 image absent (set XFS_ORACLE_V4_IMG or mint tests/data/v4.img)");
        return;
    };
    let sb = sb_of(&img);
    assert_eq!(sb.rootino, 128, "minted rootino");
    let inode = sb
        .read_inode(&img, sb.rootino)
        .expect("v4 root inode parses");

    // tests/data/v4.inode128.txt
    assert_eq!(inode.magic, 0x494e, "di_magic");
    assert_eq!(inode.version, 2, "v4 -> v2 core (256-byte inode)");
    assert_eq!(inode.format, InodeFormat::Local, "core.format = 1 (local)");
    assert_eq!(inode.mode, 0o040_755, "core.mode");
    assert_eq!(inode.file_type(), FileType::Directory, "root directory");
    assert_eq!(inode.size, 6, "core.size");
    assert_eq!(inode.nextents, 0, "core.nextents");

    // v2 has no v3 tail.
    assert_eq!(inode.di_ino, None, "v2 has no self-reference");
    assert_eq!(inode.flags2, None, "v2 has no di_flags2");
    assert_eq!(inode.crtime, None, "v2 has no crtime");
    assert_eq!(inode.uuid, None, "v2 has no di_uuid");
    assert_eq!(inode.crc, None, "v2 has no di_crc");
    assert!(
        !inode.is_bigtime(),
        "v2 always uses the legacy timestamp path"
    );

    // Legacy (sec:i32, nsec:i32) decode. atime is the Unix epoch.
    assert_eq!(inode.atime.secs, 0, "atime = Unix epoch (legacy)");
    assert_eq!(inode.atime.nsecs, 0, "atime.nsec");
    assert_eq!(inode.mtime.secs, MINT_UNIX_SECS, "mtime.sec (legacy)");
    assert_eq!(inode.mtime.nsecs, 71_649_000, "mtime.nsec");
    assert_eq!(inode.ctime.secs, MINT_UNIX_SECS, "ctime.sec (legacy)");
    assert_eq!(inode.ctime.nsecs, 71_649_000, "ctime.nsec");

    // v2 data fork starts at inode offset 100 (right after di_next_unlinked).
    assert_eq!(inode.data_fork_offset(), 100, "v2 data fork offset");
}

// ---- unit: bigtime vs legacy decode branch (crafted, documented) ----

/// Build a minimal v3 inode buffer with a chosen flags2 and one timestamp, to
/// exercise both decode branches independent of the image. Offsets follow
/// `struct xfs_dinode`: `di_atime` @32, `di_flags2` @120 (v3 tail).
fn craft_inode(version: u8, flags2: u64, atime_raw: u64) -> Vec<u8> {
    let mut d = vec![0u8; 512];
    d[0..2].copy_from_slice(&0x494eu16.to_be_bytes()); // magic
    d[2..4].copy_from_slice(&0o100_644_u16.to_be_bytes()); // mode: regular file
    d[4] = version;
    d[5] = 2; // format = extents
    d[32..40].copy_from_slice(&atime_raw.to_be_bytes()); // di_atime
    if version == 3 {
        d[120..128].copy_from_slice(&flags2.to_be_bytes()); // di_flags2
    }
    d
}

#[test]
fn bigtime_decode_branch() {
    // XFS_DIFLAG2_BIGTIME = 1 << 3 = 0x8. bigtime raw is an unsigned 64-bit
    // nanosecond counter from the 1901-12-13 epoch:
    //   ondisk_sec = raw / 1e9 ; nsec = raw % 1e9
    //   unix_sec   = ondisk_sec - XFS_BIGTIME_EPOCH_OFFSET (2^31)
    // Encode Unix (1783879768 s, 258024354 ns):
    //   ondisk_sec = 1783879768 + 2147483648 = 3931363416
    //   raw = 3931363416 * 1e9 + 258024354
    let raw: u64 = 3_931_363_416u64 * 1_000_000_000 + 258_024_354;
    let d = craft_inode(3, 0x8, raw);
    let inode = Inode::parse(&d).expect("crafted v3 bigtime inode parses");
    assert!(inode.is_bigtime());
    assert_eq!(inode.atime.secs, 1_783_879_768, "bigtime seconds");
    assert_eq!(inode.atime.nsecs, 258_024_354, "bigtime nanos");
}

#[test]
fn legacy_decode_branch_v3_without_bigtime() {
    // A v3 inode WITHOUT the bigtime flag takes the legacy (sec:i32, nsec:i32)
    // path: high 32 bits = signed seconds, low 32 = nanoseconds.
    // High 32 = seconds, low 32 = nanoseconds (disjoint fields, so `+` == `|`).
    let raw: u64 = (1_783_879_768_u64 << 32) + 71_649_000_u64;
    let d = craft_inode(3, 0x0, raw);
    let inode = Inode::parse(&d).expect("crafted v3 legacy inode parses");
    assert!(!inode.is_bigtime());
    assert_eq!(inode.atime.secs, 1_783_879_768, "legacy seconds");
    assert_eq!(inode.atime.nsecs, 71_649_000, "legacy nanos");
}

#[test]
fn legacy_negative_seconds_pre_epoch() {
    // Legacy seconds are SIGNED i32 — a pre-1970 timestamp must decode negative,
    // not as a huge unsigned value.
    let secs: i32 = -100;
    let raw: u64 = (u64::from(secs as u32) << 32) + 500_u64;
    let d = craft_inode(2, 0, raw);
    let inode = Inode::parse(&d).expect("parses");
    assert_eq!(inode.atime.secs, -100, "negative legacy seconds");
    assert_eq!(inode.atime.nsecs, 500);
}

// ---- robustness: bad magic, truncation, self-reference mismatch ----

#[test]
fn bad_magic_fails_loud() {
    let mut d = vec![0u8; 512];
    d[0..2].copy_from_slice(&0xDEADu16.to_be_bytes());
    match Inode::parse(&d).unwrap_err() {
        xfs::XfsError::BadMagic { found, bytes } => {
            // di_magic is a be16 promoted to the be32 error (high half zero).
            assert_eq!(found & 0xffff, 0xDEAD, "offending magic surfaced");
            assert_eq!(&bytes[2..4], &[0xDE, 0xAD], "raw magic bytes surfaced");
        }
        other => panic!("expected BadMagic, got {other:?}"),
    }
}

#[test]
fn truncated_inode_does_not_panic() {
    // Valid magic but far too short for even the v2 core.
    let mut d = vec![0u8; 8];
    d[0..2].copy_from_slice(&0x494eu16.to_be_bytes());
    assert!(matches!(
        Inode::parse(&d).unwrap_err(),
        xfs::XfsError::Truncated { .. }
    ));
}

#[test]
fn read_inode_out_of_range_does_not_panic() {
    // A hostile inode number whose byte offset lands past the image must not
    // panic; it surfaces Truncated (the sliced window is empty/short).
    let Some(img) = image_bytes("XFS_ORACLE_V5_IMG", "v5.img") else {
        eprintln!("skip: v5 image absent");
        return;
    };
    let sb = sb_of(&img);
    let err = sb.read_inode(&img, u64::MAX).unwrap_err();
    assert!(matches!(err, xfs::XfsError::Truncated { .. }));
}

#[test]
fn unknown_format_is_preserved() {
    // A di_format the enum does not name (e.g. 5 = UUID, unused) must round-trip
    // as Other(value), never be silently coerced — show the unrecognized value.
    let mut d = vec![0u8; 512];
    d[0..2].copy_from_slice(&0x494eu16.to_be_bytes());
    d[4] = 3; // version
    d[5] = 5; // di_format = UUID (unused / unnamed)
    let inode = Inode::parse(&d).expect("parses");
    assert_eq!(
        inode.format,
        InodeFormat::Other(5),
        "unknown format preserved"
    );
}
