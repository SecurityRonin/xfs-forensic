//! Allocation-group headers: AGF, AGI, and AGFL.
//!
//! Each allocation group opens with three single-sector metadata headers,
//! laid out (as confirmed against `xfs_db` on the minted images) at:
//!
//! | sector | byte within AG | header |
//! |---|---|---|
//! | 0 | `0`               | superblock ([`crate::Superblock`]) |
//! | 1 | `1 * sectorsize`  | **AGF** — free-space B+tree roots + freelist |
//! | 2 | `2 * sectorsize`  | **AGI** — inode-btree root + `unlinked[64]` |
//! | 3 | `3 * sectorsize`  | **AGFL** — free-list block ring |
//!
//! The AG's base byte is `agno * sb_agblocks * sb_blocksize`; the caller adds
//! the per-header sector offset. Field offsets follow `struct xfs_agf` /
//! `xfs_agi` / `struct xfs_agfl` in `fs/xfs/libxfs/xfs_format.h`.
//!
//! **v4 vs v5:** AGF and AGI share the same core layout on both; v5 appends
//! `uuid/lsn/crc` (AGF) and `uuid/crc/…/free_root/free_level/ino_blocks/
//! fino_blocks` (AGI). The **AGFL differs structurally**: v5 has an `XAFL`
//! header (`magic/seqno/uuid/lsn/crc`) before the `bno[]` ring; v4 has **no
//! header at all** — the ring starts at byte 0.

#[allow(unused_imports)] // wired in by P2 GREEN; kept so the stub compiles clean
use crate::bytes::{be_u32, be_u64};
use crate::error::XfsError;

/// AGF magic — ASCII `"XAGF"`.
pub const XFS_AGF_MAGIC: u32 = 0x5841_4746;
/// AGI magic — ASCII `"XAGI"`.
pub const XFS_AGI_MAGIC: u32 = 0x5841_4749;
/// AGFL magic (v5 only) — ASCII `"XAFL"`.
pub const XFS_AGFL_MAGIC: u32 = 0x5841_464c;

/// Number of `unlinked` hash buckets in an AGI.
pub const XFS_AGI_UNLINKED_BUCKETS: usize = 64;

/// The AGF free-space header.
///
/// Carries the roots and levels of the by-block (`bno`) and by-size (`cnt`)
/// free-space B+trees, the free-list window, and the largest free extent —
/// plus, on v5, the reverse-map and reference-count btree roots.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Agf {
    /// `agf_magicnum` — validated to [`XFS_AGF_MAGIC`].
    pub magicnum: u32,
    /// `agf_versionnum`.
    pub versionnum: u32,
    /// `agf_seqno` — this AG's index.
    pub seqno: u32,
    /// `agf_length` — size of this AG in filesystem blocks.
    pub length: u32,
    /// `agf_roots[BNO]` — by-block free-space btree root block.
    pub bno_root: u32,
    /// `agf_roots[CNT]` — by-size free-space btree root block.
    pub cnt_root: u32,
    /// `agf_roots[RMAP]` — reverse-map btree root (v5; 0 on v4).
    pub rmap_root: u32,
    /// `agf_levels[BNO]` — depth of the by-block btree.
    pub bno_level: u32,
    /// `agf_levels[CNT]` — depth of the by-size btree.
    pub cnt_level: u32,
    /// `agf_levels[RMAP]` — depth of the reverse-map btree (v5).
    pub rmap_level: u32,
    /// `agf_flfirst` — first valid index into the AGFL ring.
    pub flfirst: u32,
    /// `agf_fllast` — last valid index into the AGFL ring.
    pub fllast: u32,
    /// `agf_flcount` — number of blocks currently on the free list.
    pub flcount: u32,
    /// `agf_freeblks` — free blocks in this AG.
    pub freeblks: u32,
    /// `agf_longest` — longest contiguous free extent.
    pub longest: u32,
    /// `agf_btreeblks` — blocks held by the free-space btrees beyond the roots.
    pub btreeblks: u32,
    /// `agf_rmap_blocks` — blocks used by the reverse-map btree (v5).
    pub rmap_blocks: u32,
    /// `agf_refcount_blocks` — blocks used by the refcount btree (v5).
    pub refcount_blocks: u32,
    /// `agf_refcount_root` — reference-count btree root (v5).
    pub refcount_root: u32,
    /// `agf_refcount_level` — depth of the refcount btree (v5).
    pub refcount_level: u32,
}

/// The AGI inode-allocation header.
///
/// Carries the inode-btree root/level, allocated/free inode counts, and the
/// forensically valuable `unlinked[64]` hash-bucket array — heads of chains of
/// inodes that were unlinked while still open (orphaned-but-live inodes).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Agi {
    /// `agi_magicnum` — validated to [`XFS_AGI_MAGIC`].
    pub magicnum: u32,
    /// `agi_versionnum`.
    pub versionnum: u32,
    /// `agi_seqno` — this AG's index.
    pub seqno: u32,
    /// `agi_length` — size of this AG in filesystem blocks.
    pub length: u32,
    /// `agi_count` — inodes allocated in this AG.
    pub count: u32,
    /// `agi_root` — inode-btree (inobt) root block.
    pub root: u32,
    /// `agi_level` — depth of the inode btree.
    pub level: u32,
    /// `agi_freecount` — free inodes in this AG.
    pub freecount: u32,
    /// `agi_newino` — most-recently-allocated inode chunk.
    pub newino: u32,
    /// `agi_dirino` — unused (`0xffffffff` = null on a normal filesystem).
    pub dirino: u32,
    /// `agi_unlinked[64]` — heads of the unlinked-inode hash chains; each slot
    /// is an AG-relative inode number, or `0xffffffff` (null) when empty.
    pub unlinked: [u32; XFS_AGI_UNLINKED_BUCKETS],
    /// `agi_free_root` — free-inode btree (finobt) root (v5; 0 on v4).
    pub free_root: u32,
    /// `agi_free_level` — depth of the finobt (v5).
    pub free_level: u32,
    /// `agi_iblocks` — blocks used by the inobt (v5, inobtcount feature).
    pub ino_blocks: u32,
    /// `agi_fblocks` — blocks used by the finobt (v5, inobtcount feature).
    pub fino_blocks: u32,
}

/// The AGFL free-list block ring.
///
/// A fixed-size ring of AG-relative block numbers the allocator keeps in
/// reserve. On v5 an `XAFL` header precedes the ring; on v4 there is no header
/// and the ring begins at byte 0. Live entries are those in
/// `[agf_flfirst ..= agf_fllast]` (see [`Agf`]); other slots read `0xffffffff`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Agfl {
    /// `agfl_magicnum` — [`XFS_AGFL_MAGIC`] on v5; `None` on v4 (no header).
    pub magicnum: Option<u32>,
    /// `agfl_seqno` — this AG's index (v5 only; `None` on v4).
    pub seqno: Option<u32>,
    /// The `bno[]` ring: AG-relative block numbers, `0xffffffff` where empty.
    pub bno: Vec<u32>,
}

impl Agf {
    /// Parse an AGF from the start of `data` (the AG's sector 1).
    ///
    /// # Errors
    /// [`XfsError::BadMagic`] if the magic is not `XAGF`; [`XfsError::Truncated`]
    /// if the buffer is shorter than the v4 core.
    pub fn parse(_data: &[u8]) -> Result<Self, XfsError> {
        unimplemented!("P2 GREEN")
    }
}

impl Agi {
    /// Parse an AGI from the start of `data` (the AG's sector 2).
    ///
    /// # Errors
    /// [`XfsError::BadMagic`] if the magic is not `XAGI`; [`XfsError::Truncated`]
    /// if the buffer is shorter than the core + `unlinked[64]`.
    pub fn parse(_data: &[u8]) -> Result<Self, XfsError> {
        unimplemented!("P2 GREEN")
    }
}

impl Agfl {
    /// Parse a **v5** AGFL (with `XAFL` header) from the start of `data`.
    ///
    /// `sectorsize` sizes the ring: `(sectorsize - header_len) / 4` slots.
    ///
    /// # Errors
    /// [`XfsError::BadMagic`] if the magic is not `XAFL`; [`XfsError::Truncated`]
    /// if the buffer is shorter than the header.
    pub fn parse_v5(_data: &[u8], _sectorsize: u32) -> Result<Self, XfsError> {
        unimplemented!("P2 GREEN")
    }

    /// Parse a **v4** AGFL — a bare `bno[]` ring with no header. `sectorsize`
    /// sizes the ring: `sectorsize / 4` slots.
    #[must_use]
    pub fn parse_v4(_data: &[u8], _sectorsize: u32) -> Self {
        unimplemented!("P2 GREEN")
    }
}
