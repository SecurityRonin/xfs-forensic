//! XFS inode core (`di_core`) parse — v2 (v4 image) and v3 (v5 image).
//!
//! Reads a single inode from its inode-sized slice and decodes the core fields
//! a forensic tool needs: identity/mode/format selector, size/extent counts,
//! and the timestamps (with the v3 **bigtime** vs legacy branch). Field offsets
//! follow `struct xfs_dinode` in `fs/xfs/libxfs/xfs_format.h`; the data-fork
//! union ("u") begins at **offset 176** on v3 and **offset 100** on v2 — the
//! offset P3/P4 use to find the extent array / short-form directory.
//!
//! ## Timestamp encoding (the load-bearing branch)
//!
//! Every timestamp is a `__be64` on disk. Two decodings, selected by the v3
//! `di_flags2` BIGTIME bit:
//!
//! - **Legacy** (v2 always; v3 without BIGTIME): high 32 bits = signed seconds
//!   from the Unix epoch, low 32 = nanoseconds. Seconds are *signed* so a
//!   pre-1970 stamp decodes negative.
//! - **Bigtime** (v3 with `XFS_DIFLAG2_BIGTIME`): an *unsigned* 64-bit
//!   nanosecond counter from the epoch `1901-12-13 20:45:52 UTC`. Decode is
//!   `sec = raw / 1e9 - 2^31`, `nsec = raw % 1e9` (the kernel's
//!   `xfs_inode_decode_bigtime` / `xfs_bigtime_to_unix`).

use crate::bytes::{be_u16, be_u32, be_u64, u8_at};
use crate::crc::{crc_status, DINODE_CRC_OFF};
use crate::error::XfsError;

/// The XFS inode magic number, ASCII `"IN"` at byte 0 (`XFS_DINODE_MAGIC`).
pub const XFS_DINODE_MAGIC: u16 = 0x494e;

/// `XFS_DIFLAG2_BIGTIME` (bit 3) — set in v3 `di_flags2` when timestamps use the
/// 64-bit bigtime counter instead of the legacy `(sec:i32, nsec:i32)` pair.
pub const XFS_DIFLAG2_BIGTIME: u64 = 1 << 3;

/// Difference between the Unix epoch and the bigtime epoch, in seconds
/// (`XFS_BIGTIME_EPOCH_OFFSET = -(int64_t)S32_MIN = 2^31`).
const XFS_BIGTIME_EPOCH_OFFSET: i64 = 1 << 31;

/// Nanoseconds per second.
const NSEC_PER_SEC: u64 = 1_000_000_000;

/// Data-fork ("u" union) start offset within the inode.
const V2_LITINO_OFFSET: usize = 100;
const V3_LITINO_OFFSET: usize = 176;

/// Minimum bytes to parse a v2 inode core (through the data-fork start at 100).
const V2_MIN_LEN: usize = V2_LITINO_OFFSET;
/// Minimum bytes to parse a v3 inode core (through `di_uuid`, ending at 176).
const V3_MIN_LEN: usize = V3_LITINO_OFFSET;

/// The `S_IFMT` file-type mask and the type values (POSIX; XFS reuses them
/// verbatim in `di_mode`).
const S_IFMT: u16 = 0o170_000;
const S_IFIFO: u16 = 0o010_000;
const S_IFCHR: u16 = 0o020_000;
const S_IFDIR: u16 = 0o040_000;
const S_IFBLK: u16 = 0o060_000;
const S_IFREG: u16 = 0o100_000;
const S_IFLNK: u16 = 0o120_000;
const S_IFSOCK: u16 = 0o140_000;

/// The data-fork format selector (`di_format` / `di_aformat`).
///
/// P3/P4 branch on this to interpret the fork: [`InodeFormat::Local`] is inline
/// data (short-form dir / symlink), [`InodeFormat::Extents`] is an inline
/// `xfs_bmbt_rec` array, [`InodeFormat::Btree`] is an inline bmap-btree root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InodeFormat {
    /// `XFS_DINODE_FMT_DEV` (0) — device number in the fork.
    Dev,
    /// `XFS_DINODE_FMT_LOCAL` (1) — inline data (short-form dir / symlink).
    Local,
    /// `XFS_DINODE_FMT_EXTENTS` (2) — inline `xfs_bmbt_rec` extent array.
    Extents,
    /// `XFS_DINODE_FMT_BTREE` (3) — inline bmap-btree root header.
    Btree,
    /// Any other value (e.g. 5 = the unused `UUID` format) — carried verbatim so
    /// an unrecognized selector shows its value rather than being coerced.
    Other(u8),
}

impl InodeFormat {
    /// Decode a raw `di_format` / `di_aformat` byte, preserving unknowns.
    #[must_use]
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => Self::Dev,
            1 => Self::Local,
            2 => Self::Extents,
            3 => Self::Btree,
            other => Self::Other(other),
        }
    }
}

/// The `S_IFMT` file type decoded from `di_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileType {
    /// FIFO / named pipe (`S_IFIFO`).
    Fifo,
    /// Character device (`S_IFCHR`).
    CharDevice,
    /// Directory (`S_IFDIR`).
    Directory,
    /// Block device (`S_IFBLK`).
    BlockDevice,
    /// Regular file (`S_IFREG`).
    Regular,
    /// Symbolic link (`S_IFLNK`).
    Symlink,
    /// Unix-domain socket (`S_IFSOCK`).
    Socket,
    /// A type field not matching any known `S_IFMT` value — carried verbatim.
    Other(u16),
}

impl FileType {
    /// Decode the `S_IFMT` type bits of a `di_mode`.
    #[must_use]
    pub fn from_mode(mode: u16) -> Self {
        match mode & S_IFMT {
            S_IFIFO => Self::Fifo,
            S_IFCHR => Self::CharDevice,
            S_IFDIR => Self::Directory,
            S_IFBLK => Self::BlockDevice,
            S_IFREG => Self::Regular,
            S_IFLNK => Self::Symlink,
            S_IFSOCK => Self::Socket,
            other => Self::Other(other),
        }
    }
}

/// A decoded inode timestamp: signed Unix seconds + nanoseconds.
///
/// Stored as `(secs: i64, nsecs: u32)` rather than a calendar type so the core
/// stays free of any date/time dependency (a consumer converts as it wishes).
/// `secs` is signed because legacy timestamps carry a signed 32-bit seconds
/// field (pre-1970 stamps are negative).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XfsTimestamp {
    /// Seconds from the Unix epoch (signed).
    pub secs: i64,
    /// Nanoseconds within the second (`0..1_000_000_000`).
    pub nsecs: u32,
}

impl XfsTimestamp {
    /// Decode a raw `__be64` timestamp using the legacy `(sec:i32, nsec:i32)`
    /// packing: high 32 bits = signed seconds, low 32 = nanoseconds.
    #[must_use]
    fn from_legacy(raw: u64) -> Self {
        let secs = i64::from((raw >> 32) as i32);
        let nsecs = (raw & 0xffff_ffff) as u32;
        Self { secs, nsecs }
    }

    /// Decode a raw `__be64` bigtime counter (unsigned nanoseconds from the
    /// 1901 epoch): `sec = raw/1e9 - 2^31`, `nsec = raw%1e9`.
    #[must_use]
    fn from_bigtime(raw: u64) -> Self {
        let ondisk_secs = raw / NSEC_PER_SEC;
        let nsecs = (raw % NSEC_PER_SEC) as u32;
        // ondisk_secs fits in i64 (raw is u64, /1e9), so the subtraction is
        // exact; a hostile raw at the u64 ceiling stays within i64 range.
        let secs = ondisk_secs as i64 - XFS_BIGTIME_EPOCH_OFFSET;
        Self { secs, nsecs }
    }

    /// Decode with the branch chosen by `bigtime`.
    #[must_use]
    fn decode(raw: u64, bigtime: bool) -> Self {
        if bigtime {
            Self::from_bigtime(raw)
        } else {
            Self::from_legacy(raw)
        }
    }
}

/// A parsed XFS inode core (`di_core`), v2 or v3.
///
/// Carries the subset of `struct xfs_dinode` a forensic reader needs; the v3
/// tail fields (`crtime`/`di_ino`/`uuid`/`crc`/`flags2`/`cowextsize`) are
/// `Option` — `None` on a v2 inode where they do not exist. `#[non_exhaustive]`
/// so later phases add fields without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Inode {
    /// `di_magic` (offset 0) — validated to equal [`XFS_DINODE_MAGIC`].
    pub magic: u16,
    /// `di_mode` (offset 2) — file type (`S_IFMT`) + permission bits.
    pub mode: u16,
    /// `di_version` (offset 4) — inode format version (1 / 2 / 3).
    pub version: u8,
    /// `di_format` (offset 5) — the **data-fork** format selector P3/P4 use.
    pub format: InodeFormat,
    /// `di_aformat` (offset 83) — the attribute-fork format selector.
    pub aformat: u8,
    /// `di_size` (offset 56) — logical size in bytes.
    pub size: u64,
    /// `di_nblocks` (offset 64) — data + btree blocks used.
    pub nblocks: u64,
    /// `di_nextents` (offset 76) — number of data-fork extents.
    pub nextents: u32,
    /// `di_anextents` (offset 80) — number of attribute-fork extents.
    pub aextents: u16,
    /// `di_forkoff` (offset 82) — attr-fork offset (in 8-byte units).
    pub forkoff: u8,
    /// `di_atime` (offset 32) — last-access time (decoded).
    pub atime: XfsTimestamp,
    /// `di_mtime` (offset 40) — last-modification time (decoded).
    pub mtime: XfsTimestamp,
    /// `di_ctime` (offset 48) — inode-change time (decoded).
    pub ctime: XfsTimestamp,
    /// `di_crtime` (offset 144) — creation time; `None` on v2.
    pub crtime: Option<XfsTimestamp>,
    /// `di_flags2` (offset 120) — extended flags (BIGTIME/…); `None` on v2.
    pub flags2: Option<u64>,
    /// `di_cowextsize` (offset 128) — copy-on-write extent-size hint; `None` v2.
    pub cowextsize: Option<u32>,
    /// `di_ino` (offset 152) — the inode's self-reference; `None` on v2. A nice
    /// integrity check: it must equal the number used to locate the inode.
    pub di_ino: Option<u64>,
    /// `di_uuid` (offset 160) — owning filesystem UUID; `None` on v2.
    pub uuid: Option<[u8; 16]>,
    /// `di_crc` (offset 100, little-endian) — inode CRC32c; `None` on v2.
    /// The raw stored value; [`Self::crc_valid`] carries the verification result.
    pub crc: Option<u32>,
    /// The v5 CRC32c status of this inode: `Some(true)` if `di_crc` (offset 100)
    /// verifies over the whole inode-sized slice, `Some(false)` if it does not
    /// (corrupt/tampered), or `None` on a v2 inode (no CRC). **Non-fatal** — a
    /// bad CRC does not fail the parse; the `-forensic` layer turns it into a
    /// Finding. Computed only when [`Self::parse`] receives the full inode; a
    /// short slice (< inodesize) verifies as `Some(false)`.
    pub crc_valid: Option<bool>,
    /// The raw data-fork ("u" union) bytes — everything from
    /// [`Self::data_fork_offset`] to the end of the inode-sized slice. For an
    /// [`InodeFormat::Extents`] inode this holds the inline `xfs_bmbt_rec`
    /// array P3 decodes; for [`InodeFormat::Local`] it holds the short-form
    /// dir/symlink (P4). Empty when the slice was exactly the core length.
    pub data_fork: Vec<u8>,
}

impl Inode {
    /// Parse an inode core from `data` (the inode-sized slice at the byte offset
    /// [`crate::Superblock::inode_to_location`] yields).
    ///
    /// # Errors
    ///
    /// - [`XfsError::BadMagic`] if bytes 0..2 are not `IN` — the offending value
    ///   is carried (as a `be32` with the high half zero, matching the shared
    ///   error type).
    /// - [`XfsError::Truncated`] if `data` is shorter than the core for its
    ///   version (v2: 100 bytes; v3: 176 bytes).
    pub fn parse(data: &[u8]) -> Result<Self, XfsError> {
        // Identity before length so a wrong-slice error names the bytes read.
        let magic = be_u16(data, 0);
        if magic != XFS_DINODE_MAGIC {
            let bytes = [0, 0, u8_at(data, 0), u8_at(data, 1)];
            return Err(XfsError::BadMagic {
                found: u32::from(magic),
                bytes,
            });
        }

        let version = u8_at(data, 4);
        let is_v3 = version >= 3;
        let need = if is_v3 { V3_MIN_LEN } else { V2_MIN_LEN };
        if data.len() < need {
            return Err(XfsError::Truncated {
                structure: "inode core",
                need,
                have: data.len(),
            });
        }

        // v3 timestamps use bigtime iff the flag is set in di_flags2; v2 never
        // has di_flags2, so it always takes the legacy path.
        let flags2 = if is_v3 { Some(be_u64(data, 120)) } else { None };
        let bigtime = flags2.is_some_and(|f| f & XFS_DIFLAG2_BIGTIME != 0);

        let atime = XfsTimestamp::decode(be_u64(data, 32), bigtime);
        let mtime = XfsTimestamp::decode(be_u64(data, 40), bigtime);
        let ctime = XfsTimestamp::decode(be_u64(data, 48), bigtime);

        let (crtime, cowextsize, di_ino, uuid, crc) = if is_v3 {
            let mut u = [0u8; 16];
            if let Some(s) = data.get(160..176) {
                u.copy_from_slice(s);
            }
            (
                Some(XfsTimestamp::decode(be_u64(data, 144), bigtime)),
                Some(be_u32(data, 128)),
                Some(be_u64(data, 152)),
                Some(u),
                // di_crc is stored little-endian (the only LE field in the core).
                Some(u32::from_le_bytes([
                    u8_at(data, 100),
                    u8_at(data, 101),
                    u8_at(data, 102),
                    u8_at(data, 103),
                ])),
            )
        } else {
            (None, None, None, None, None)
        };

        // The data fork ("u" union) begins at 176 (v3) / 100 (v2). Capture the
        // remainder of the inode slice so P3/P4 can decode the inline extent
        // array / short-form dir without re-slicing the image.
        let fork_off = if is_v3 {
            V3_LITINO_OFFSET
        } else {
            V2_LITINO_OFFSET
        };
        let data_fork = data.get(fork_off..).unwrap_or(&[]).to_vec();

        // A v3 (v5-filesystem) inode carries a CRC32c over the whole inode-sized
        // slice; a v2 inode has none. Non-fatal — surfaced, never fails parse.
        let crc_valid = crc_status(is_v3, data, DINODE_CRC_OFF);

        Ok(Self {
            magic,
            mode: be_u16(data, 2),
            version,
            format: InodeFormat::from_raw(u8_at(data, 5)),
            aformat: u8_at(data, 83),
            size: be_u64(data, 56),
            nblocks: be_u64(data, 64),
            nextents: be_u32(data, 76),
            aextents: be_u16(data, 80),
            forkoff: u8_at(data, 82),
            atime,
            mtime,
            ctime,
            crtime,
            flags2,
            cowextsize,
            di_ino,
            uuid,
            crc,
            crc_valid,
            data_fork,
        })
    }

    /// The `S_IFMT` file type from [`Self::mode`].
    #[must_use]
    pub fn file_type(&self) -> FileType {
        FileType::from_mode(self.mode)
    }

    /// True if this inode is a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.file_type() == FileType::Directory
    }

    /// True if this inode is a regular file.
    #[must_use]
    pub fn is_reg(&self) -> bool {
        self.file_type() == FileType::Regular
    }

    /// True if the timestamps were decoded with the bigtime encoding (a v3
    /// inode carrying `XFS_DIFLAG2_BIGTIME`).
    #[must_use]
    pub fn is_bigtime(&self) -> bool {
        self.flags2.is_some_and(|f| f & XFS_DIFLAG2_BIGTIME != 0)
    }

    /// Byte offset of the data-fork ("u" union) within the inode: **176** on a
    /// v3 inode, **100** on a v2 inode. P3/P4 read the extent array / short-form
    /// directory starting here.
    #[must_use]
    pub fn data_fork_offset(&self) -> usize {
        if self.version >= 3 {
            V3_LITINO_OFFSET
        } else {
            V2_LITINO_OFFSET
        }
    }
}
