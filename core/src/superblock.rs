//! XFS superblock (`xfs_dsb`) parse and geometry.
//!
//! One superblock sits at **offset 0** of every allocation group (AG 0 primary;
//! secondaries are backups). Field offsets follow the kernel on-disk struct
//! `struct xfs_dsb` in `fs/xfs/libxfs/xfs_format.h`; `XFSLABEL_MAX = 12`.

use crate::bytes::{be_u16, be_u32, be_u64, u8_at};
use crate::error::XfsError;

/// The XFS superblock magic number, ASCII `"XFSB"` at byte 0.
pub const XFS_SB_MAGIC: u32 = 0x5846_5342;

/// Minimum bytes required to parse every field this reader extracts
/// (through `sb_agblklog` at offset 124).
const SB_MIN_LEN: usize = 125;

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
        Ok(Self {
            magic,
            blocksize: be_u32(data, 4),
            rootino: be_u64(data, 56),
            agblocks: be_u32(data, 84),
            agcount: be_u32(data, 88),
            versionnum: be_u16(data, 100),
            inodesize: be_u16(data, 104),
            inopblock: be_u16(data, 106),
            blocklog: u8_at(data, 120),
            inodelog: u8_at(data, 122),
            inopblog: u8_at(data, 123),
            agblklog: u8_at(data, 124),
        })
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
}
