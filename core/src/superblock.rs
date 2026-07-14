//! XFS superblock (`xfs_dsb`) parse and geometry.
//!
//! One superblock sits at **offset 0** of every allocation group (AG 0 primary;
//! secondaries are backups). Field offsets follow the kernel on-disk struct
//! `struct xfs_dsb` in `fs/xfs/libxfs/xfs_format.h`; `XFSLABEL_MAX = 12`.

use crate::bytes::{be_u16, be_u32, be_u64, u8_at};
use crate::crc::{crc_status, SB_CRC_OFF};
use crate::error::XfsError;
use crate::inode::Inode;

/// The XFS superblock magic number, ASCII `"XFSB"` at byte 0.
pub const XFS_SB_MAGIC: u32 = 0x5846_5342;

/// Minimum bytes required to parse every field this reader extracts
/// (through `sb_features_incompat` at offset 216, +4 = 220).
const SB_MIN_LEN: usize = 220;

/// `XFS_SB_VERSION2_FTYPE` — the v4 `sb_features2` bit that turns on the
/// directory-entry `ftype` field.
const XFS_SB_VERSION2_FTYPE: u32 = 0x0000_0200;

/// `XFS_SB_FEAT_INCOMPAT_FTYPE` — the v5 `sb_features_incompat` bit for the same
/// per-dirent `ftype` field.
const XFS_SB_FEAT_INCOMPAT_FTYPE: u32 = 0x0000_0001;

/// Parsed XFS superblock — geometry and the log2 shift fields the inode-number
/// decode (P1) needs.
///
/// This carries the subset of `xfs_dsb` the reader currently uses; it is
/// `#[non_exhaustive]` so later phases add fields without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Superblock {
    /// `sb_magicnum` (offset 0) — validated to equal [`XFS_SB_MAGIC`].
    pub magic: u32,
    /// `sb_blocksize` (offset 4) — logical block size in bytes.
    pub blocksize: u32,
    /// `sb_rootino` (offset 56) — root inode number.
    pub rootino: u64,
    /// `sb_agblocks` (offset 84) — blocks per allocation group.
    pub agblocks: u32,
    /// `sb_agcount` (offset 88) — number of allocation groups.
    pub agcount: u32,
    /// `sb_versionnum` (offset 100) — low nibble = format version (4 vs 5).
    pub versionnum: u16,
    /// `sb_inodesize` (offset 104) — inode size in bytes.
    pub inodesize: u16,
    /// `sb_inopblock` (offset 106) — inodes per block.
    pub inopblock: u16,
    /// `sb_blocklog` (offset 120) — log2 of `blocksize`.
    pub blocklog: u8,
    /// `sb_inodelog` (offset 122) — log2 of `inodesize`.
    pub inodelog: u8,
    /// `sb_inopblog` (offset 123) — log2 of `inopblock`.
    pub inopblog: u8,
    /// `sb_agblklog` (offset 124) — log2 of `agblocks` (rounded up).
    pub agblklog: u8,
    /// `sb_features2` (offset 200) — v4 extended feature flags; the FTYPE bit
    /// (`0x200`) here says v4 directory entries carry the trailing `ftype` byte.
    pub features2: u32,
    /// `sb_features_incompat` (offset 216) — v5 incompatible feature flags; the
    /// FTYPE bit (`0x1`) here is the v5 equivalent of the `features2` FTYPE bit.
    pub features_incompat: u32,
    /// The v5 CRC32c status of the superblock sector: `Some(true)` if `sb_crc`
    /// (offset 224) verifies over the whole sector, `Some(false)` if it does not
    /// (corrupt/tampered), or `None` on a v4 filesystem (no CRC). **Non-fatal**:
    /// a bad CRC does not fail the parse — the `-forensic` layer turns it into a
    /// Finding. Computed only when [`Self::parse`] receives the full sector; a
    /// short buffer (< sector) verifies as `Some(false)`.
    pub crc_valid: Option<bool>,
}

impl Superblock {
    /// Parse a superblock from the start of `data`.
    ///
    /// # Errors
    ///
    /// - [`XfsError::Truncated`] if `data` is shorter than the fields read.
    /// - [`XfsError::BadMagic`] if byte 0 is not `XFSB` — the four offending
    ///   bytes are carried in the error.
    pub fn parse(data: &[u8]) -> Result<Self, XfsError> {
        // Validate magic before length so a wrong-image identity error names the
        // offending bytes even on a short buffer (fail loud with the value).
        let bytes = [
            u8_at(data, 0),
            u8_at(data, 1),
            u8_at(data, 2),
            u8_at(data, 3),
        ];
        let magic = u32::from_be_bytes(bytes);
        if magic != XFS_SB_MAGIC {
            return Err(XfsError::BadMagic {
                found: magic,
                bytes,
            });
        }

        // All parsed fields lie within the first SB_MIN_LEN bytes; range-check
        // once so the bounds-checked readers below never mask a short image.
        if data.len() < SB_MIN_LEN {
            return Err(XfsError::Truncated {
                structure: "superblock",
                need: SB_MIN_LEN,
                have: data.len(),
            });
        }

        // Offsets from `struct xfs_dsb` (fs/xfs/libxfs/xfs_format.h),
        // XFSLABEL_MAX = 12.
        let versionnum = be_u16(data, 100);
        // v5 iff the low nibble of sb_versionnum is 5. The CRC covers the whole
        // sector `data`; on v4 there is no CRC field so the status is `None`.
        let is_v5 = versionnum & 0x000f == 5;
        let crc_valid = crc_status(is_v5, data, SB_CRC_OFF);
        Ok(Self {
            magic,
            blocksize: be_u32(data, 4),
            rootino: be_u64(data, 56),
            agblocks: be_u32(data, 84),
            agcount: be_u32(data, 88),
            versionnum,
            inodesize: be_u16(data, 104),
            inopblock: be_u16(data, 106),
            blocklog: u8_at(data, 120),
            inodelog: u8_at(data, 122),
            inopblog: u8_at(data, 123),
            agblklog: u8_at(data, 124),
            features2: be_u32(data, 200),
            features_incompat: be_u32(data, 216),
            crc_valid,
        })
    }

    /// True if the filesystem's `ftype` feature is enabled — i.e. every
    /// directory entry (short-form and block) carries a trailing `ftype` byte.
    ///
    /// The bit lives in a different field per format: v5 uses
    /// `sb_features_incompat & XFS_SB_FEAT_INCOMPAT_FTYPE`; v4 uses
    /// `sb_features2 & XFS_SB_VERSION2_FTYPE`. Modern `mkfs.xfs` enables it by
    /// default even on v4, so a directory reader MUST branch on this feature bit
    /// rather than on the v4/v5 version (the classic off-by-one source).
    #[must_use]
    pub fn has_ftype(&self) -> bool {
        if self.is_v5() {
            self.features_incompat & XFS_SB_FEAT_INCOMPAT_FTYPE != 0
        } else {
            self.features2 & XFS_SB_VERSION2_FTYPE != 0
        }
    }

    /// The on-disk format version: `4` (legacy) or `5` (self-describing/CRC),
    /// taken from the low nibble of `sb_versionnum`.
    #[must_use]
    pub fn version(&self) -> u8 {
        (self.versionnum & 0x000f) as u8
    }

    /// True for a v5 (CRC / self-describing metadata) filesystem.
    #[must_use]
    pub fn is_v5(&self) -> bool {
        self.version() == 5
    }

    /// Decode an inode number into its allocation-group location and absolute
    /// byte position — the exact split `xfs_db convert` performs.
    ///
    /// The math (from the XFS on-disk format, using the superblock's log2 shift
    /// fields):
    ///
    /// ```text
    /// shift   = agblklog + inopblog          (bits held by agino)
    /// agno    = ino >> shift
    /// agino   = ino & ((1 << shift) - 1)
    /// agblock = agino >> inopblog
    /// offset  = agino & ((1 << inopblog) - 1)
    /// fsblock = agno * agblocks + agblock
    /// byte    = fsblock * blocksize + offset * inodesize
    /// ```
    ///
    /// Panic-free: every shift is masked to `< 64` and every multiply is
    /// saturating, so a hostile inode number or absurd geometry yields a
    /// clamped location rather than a panic or overflow (the Paranoid
    /// Gatekeeper standard). It never fails, so it returns the location
    /// directly rather than a `Result`.
    #[must_use]
    pub fn inode_to_location(&self, ino: u64) -> InodeLocation {
        let inopblog = u32::from(self.inopblog);
        let agino_bits = u32::from(self.agblklog) + inopblog;

        // agno takes the high bits, agino the low `agino_bits`. A shift >= 64
        // (malformed geometry) means agino holds the whole value and agno is 0.
        let agno = shr(ino, agino_bits);
        let agino = ino & low_mask(agino_bits);

        // Split agino into (agblock, offset) on the inopblog boundary.
        let agblock = shr(agino, inopblog);
        let offset = agino & low_mask(inopblog);

        // fsblock = agno * agblocks + agblock; saturate so absurd geometry can
        // never overflow (a hostile ino must yield a clamped value, not UB).
        let fsblock = agno
            .saturating_mul(u64::from(self.agblocks))
            .saturating_add(agblock);

        // byte = fsblock * blocksize + offset * inodesize (saturating).
        let byte_offset = fsblock
            .saturating_mul(u64::from(self.blocksize))
            .saturating_add(offset.saturating_mul(u64::from(self.inodesize)));

        InodeLocation {
            agno,
            agino,
            agblock,
            offset,
            fsblock,
            byte_offset,
        }
    }

    /// Read and parse the inode `ino` from a whole-image byte buffer.
    ///
    /// Locates the inode via [`Self::inode_to_location`], slices exactly
    /// `sb_inodesize` bytes at its byte offset, and parses the core with
    /// [`Inode::parse`]. This is the convenience path the reader exposes on top
    /// of the raw [`Inode::parse`] (which takes the already-sliced bytes).
    ///
    /// # Errors
    ///
    /// - [`XfsError::Truncated`] if the located byte window lies wholly or
    ///   partly past the end of `image` (a hostile inode number, or a truncated
    ///   image) — never a panic.
    /// - Any error from [`Inode::parse`] (bad magic, short core).
    pub fn read_inode(&self, image: &[u8], ino: u64) -> Result<Inode, XfsError> {
        let loc = self.inode_to_location(ino);
        let start = usize::try_from(loc.byte_offset).unwrap_or(usize::MAX);
        let size = usize::from(self.inodesize);
        let end = start.saturating_add(size);
        let slice = image.get(start..end).ok_or(XfsError::Truncated {
            structure: "inode (image slice)",
            need: end,
            have: image.len(),
        })?;
        Inode::parse(slice)
    }
}

/// Right-shift that yields `0` when `bits >= 64` (rather than panicking on an
/// out-of-range shift — a malformed superblock can carry shift fields >= 64).
#[inline]
fn shr(value: u64, bits: u32) -> u64 {
    value.checked_shr(bits).unwrap_or(0)
}

/// A mask of the low `bits` bits: `(1 << bits) - 1`, saturating to all-ones
/// when `bits >= 64` so the mask never overflows.
#[inline]
fn low_mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// The decoded location of an inode: its allocation group, in-AG coordinates,
/// absolute filesystem block, and absolute byte position in the image.
///
/// Produced by [`Superblock::inode_to_location`]; every field mirrors the
/// corresponding `xfs_db convert inode N <field>` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeLocation {
    /// Allocation-group number (`ino >> (agblklog + inopblog)`).
    pub agno: u64,
    /// AG-relative inode number (`ino & ((1 << (agblklog + inopblog)) - 1)`).
    pub agino: u64,
    /// AG-relative block holding the inode (`agino >> inopblog`).
    pub agblock: u64,
    /// Inode slot within its block (`agino & ((1 << inopblog) - 1)`).
    pub offset: u64,
    /// Absolute filesystem block (`agno * agblocks + agblock`).
    pub fsblock: u64,
    /// Absolute byte position in the image
    /// (`fsblock * blocksize + offset * inodesize`).
    pub byte_offset: u64,
}
