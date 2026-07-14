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

use crate::bytes::{be_u32, u8_at};
use crate::crc::{crc_status, AGFL_CRC_OFF, AGF_CRC_OFF, AGI_CRC_OFF};
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
    /// The v5 CRC32c status of the AGF sector: `Some(true/false)` when parsed via
    /// [`Self::parse_verified`] on a v5 filesystem, `None` on v4 (no CRC) or when
    /// parsed via the version-agnostic [`Self::parse`]. **Non-fatal** — a bad CRC
    /// never fails the parse; the `-forensic` layer turns it into a Finding.
    pub crc_valid: Option<bool>,
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
    /// The v5 CRC32c status of the AGI sector: `Some(true/false)` when parsed via
    /// [`Self::parse_verified`] on a v5 filesystem, `None` on v4 (no CRC) or when
    /// parsed via the version-agnostic [`Self::parse`]. **Non-fatal** — a bad CRC
    /// never fails the parse; the `-forensic` layer turns it into a Finding.
    pub crc_valid: Option<bool>,
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
    /// The v5 CRC32c status of the AGFL sector: `Some(true/false)` from
    /// [`Self::parse_v5`] (which verifies `agfl_crc` at offset 32 over the whole
    /// sector), or `None` from [`Self::parse_v4`] (a bare ring with no CRC).
    /// **Non-fatal** — a bad CRC never fails the parse.
    pub crc_valid: Option<bool>,
}

/// Null sentinel for an unused AGFL slot / null AG pointer.
const XFS_NULL_AGBLOCK: u32 = 0xffff_ffff;

/// Minimum AGF length: through `agf_refcount_level` at offset 92 (v5 core). The
/// v4 fields all lie below offset 64, so this bound also covers v4 (which
/// simply reads 0 for the absent refcount/rmap fields — they sit in v4's
/// reserved padding).
const AGF_MIN_LEN: usize = 96;

/// Byte offset of `agi_unlinked[0]` within an AGI.
const AGI_UNLINKED_OFF: usize = 40;

/// Minimum AGI length: core through the full `unlinked[64]` array
/// (`40 + 64*4 = 296`). The v5 tail (finobt roots, inobtcount) lies above this
/// and is read with the bounds-checked helpers, yielding 0 on v4 (where those
/// fields sit in reserved space) without requiring a longer buffer.
const AGI_MIN_LEN: usize = AGI_UNLINKED_OFF + XFS_AGI_UNLINKED_BUCKETS * 4;

/// Read the four bytes at `off` as a magic and reject a mismatch, naming the
/// offending value (fail-loud, per "show the unrecognized value").
fn check_magic(data: &[u8], expected: u32) -> Result<u32, XfsError> {
    let bytes = [
        u8_at(data, 0),
        u8_at(data, 1),
        u8_at(data, 2),
        u8_at(data, 3),
    ];
    let found = u32::from_be_bytes(bytes);
    if found == expected {
        Ok(found)
    } else {
        Err(XfsError::BadMagic { found, bytes })
    }
}

impl Agf {
    /// Parse an AGF from the start of `data` (the AG's sector 1), leaving
    /// [`Self::crc_valid`] as `None` (version-agnostic — no CRC check).
    ///
    /// Use [`Self::parse_verified`] on a v5 filesystem to also verify `agf_crc`.
    ///
    /// # Errors
    /// [`XfsError::BadMagic`] if the magic is not `XAGF`; [`XfsError::Truncated`]
    /// if the buffer is shorter than the AGF core.
    pub fn parse(data: &[u8]) -> Result<Self, XfsError> {
        Self::parse_inner(data, None)
    }

    /// Parse an AGF and verify its v5 CRC32c (`agf_crc` at offset 216 over the
    /// whole sector `data`). On `is_v5 == false` the status is `None` (v4 has no
    /// CRC). The CRC check is **non-fatal**: a mismatch sets `crc_valid` to
    /// `Some(false)` and still returns the parsed AGF.
    ///
    /// # Errors
    /// Same as [`Self::parse`].
    pub fn parse_verified(data: &[u8], is_v5: bool) -> Result<Self, XfsError> {
        Self::parse_inner(data, Some(is_v5))
    }

    /// Shared AGF parse; `verify` is `None` (skip CRC) or `Some(is_v5)`.
    fn parse_inner(data: &[u8], verify: Option<bool>) -> Result<Self, XfsError> {
        // Identity before length so a wrong-sector error names the bytes.
        let magicnum = check_magic(data, XFS_AGF_MAGIC)?;
        if data.len() < AGF_MIN_LEN {
            return Err(XfsError::Truncated {
                structure: "AGF",
                need: AGF_MIN_LEN,
                have: data.len(),
            });
        }
        // Offsets from `struct xfs_agf`: roots[3] @16, levels[3] @28,
        // flfirst/last/count @40/44/48, freeblks/longest/btreeblks @52/56/60,
        // then (v5) rmap_blocks @80, refcount_blocks @84, refcount_root @88,
        // refcount_level @92.
        let crc_valid = verify.and_then(|is_v5| crc_status(is_v5, data, AGF_CRC_OFF));
        Ok(Self {
            magicnum,
            versionnum: be_u32(data, 4),
            seqno: be_u32(data, 8),
            length: be_u32(data, 12),
            bno_root: be_u32(data, 16),
            cnt_root: be_u32(data, 20),
            rmap_root: be_u32(data, 24),
            bno_level: be_u32(data, 28),
            cnt_level: be_u32(data, 32),
            rmap_level: be_u32(data, 36),
            flfirst: be_u32(data, 40),
            fllast: be_u32(data, 44),
            flcount: be_u32(data, 48),
            freeblks: be_u32(data, 52),
            longest: be_u32(data, 56),
            btreeblks: be_u32(data, 60),
            rmap_blocks: be_u32(data, 80),
            refcount_blocks: be_u32(data, 84),
            refcount_root: be_u32(data, 88),
            refcount_level: be_u32(data, 92),
            crc_valid,
        })
    }
}

impl Agi {
    /// Parse an AGI from the start of `data` (the AG's sector 2), leaving
    /// [`Self::crc_valid`] as `None` (version-agnostic — no CRC check).
    ///
    /// Use [`Self::parse_verified`] on a v5 filesystem to also verify `agi_crc`.
    ///
    /// # Errors
    /// [`XfsError::BadMagic`] if the magic is not `XAGI`; [`XfsError::Truncated`]
    /// if the buffer is shorter than the core + `unlinked[64]`.
    pub fn parse(data: &[u8]) -> Result<Self, XfsError> {
        Self::parse_inner(data, None)
    }

    /// Parse an AGI and verify its v5 CRC32c (`agi_crc` at offset 312 over the
    /// whole sector `data`). On `is_v5 == false` the status is `None` (v4 has no
    /// CRC). The CRC check is **non-fatal**: a mismatch sets `crc_valid` to
    /// `Some(false)` and still returns the parsed AGI.
    ///
    /// # Errors
    /// Same as [`Self::parse`].
    pub fn parse_verified(data: &[u8], is_v5: bool) -> Result<Self, XfsError> {
        Self::parse_inner(data, Some(is_v5))
    }

    /// Shared AGI parse; `verify` is `None` (skip CRC) or `Some(is_v5)`.
    fn parse_inner(data: &[u8], verify: Option<bool>) -> Result<Self, XfsError> {
        let magicnum = check_magic(data, XFS_AGI_MAGIC)?;
        if data.len() < AGI_MIN_LEN {
            return Err(XfsError::Truncated {
                structure: "AGI",
                need: AGI_MIN_LEN,
                have: data.len(),
            });
        }
        // `struct xfs_agi`: count @16, root @20, level @24, freecount @28,
        // newino @32, dirino @36, unlinked[64] @40 (256 bytes -> 296), then
        // (v5) uuid @296, crc @312, pad @316, lsn @320, free_root @328,
        // free_level @332, ino_blocks @336, fino_blocks @340.
        let mut unlinked = [0u32; XFS_AGI_UNLINKED_BUCKETS];
        for (i, slot) in unlinked.iter_mut().enumerate() {
            *slot = be_u32(data, AGI_UNLINKED_OFF + i * 4);
        }
        let crc_valid = verify.and_then(|is_v5| crc_status(is_v5, data, AGI_CRC_OFF));
        Ok(Self {
            magicnum,
            versionnum: be_u32(data, 4),
            seqno: be_u32(data, 8),
            length: be_u32(data, 12),
            count: be_u32(data, 16),
            root: be_u32(data, 20),
            level: be_u32(data, 24),
            freecount: be_u32(data, 28),
            newino: be_u32(data, 32),
            dirino: be_u32(data, 36),
            unlinked,
            free_root: be_u32(data, 328),
            free_level: be_u32(data, 332),
            ino_blocks: be_u32(data, 336),
            fino_blocks: be_u32(data, 340),
            crc_valid,
        })
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
    pub fn parse_v5(data: &[u8], sectorsize: u32) -> Result<Self, XfsError> {
        let magicnum = check_magic(data, XFS_AGFL_MAGIC)?;
        if data.len() < AGFL_V5_HEADER_LEN {
            return Err(XfsError::Truncated {
                structure: "AGFL",
                need: AGFL_V5_HEADER_LEN,
                have: data.len(),
            });
        }
        // `struct xfs_agfl`: magicnum @0, seqno @4, uuid @8, lsn @24, crc @32,
        // then bno[] @36. Ring length is sector-relative:
        // (sectorsize - 36) / 4 slots.
        let slots = (sectorsize as usize).saturating_sub(AGFL_V5_HEADER_LEN) / 4;
        let bno = read_bno_ring(data, AGFL_V5_HEADER_LEN, slots);
        // A v5 AGFL always carries a CRC (`agfl_crc` at offset 32) over the whole
        // sector; verify it non-fatally.
        let crc_valid = crc_status(true, data, AGFL_CRC_OFF);
        Ok(Self {
            magicnum: Some(magicnum),
            seqno: Some(be_u32(data, 4)),
            bno,
            crc_valid,
        })
    }

    /// Parse a **v4** AGFL — a bare `bno[]` ring with no header. `sectorsize`
    /// sizes the ring: `sectorsize / 4` slots. Infallible: out-of-range slots
    /// read the null sentinel rather than panicking.
    #[must_use]
    pub fn parse_v4(data: &[u8], sectorsize: u32) -> Self {
        let slots = (sectorsize as usize) / 4;
        let bno = read_bno_ring(data, 0, slots);
        Self {
            magicnum: None,
            seqno: None,
            bno,
            crc_valid: None,
        }
    }
}

/// Byte length of the v5 `XAFL` header preceding the `bno[]` ring.
const AGFL_V5_HEADER_LEN: usize = 36;

/// Read `slots` big-endian `u32` block numbers starting at `off`. Slots past
/// the end of `data` read the null sentinel (`0xffffffff`) so a short buffer
/// yields a fully-sized, null-padded ring rather than panicking.
fn read_bno_ring(data: &[u8], off: usize, slots: usize) -> Vec<u32> {
    (0..slots)
        .map(|i| {
            let at = off + i * 4;
            if at + 4 <= data.len() {
                be_u32(data, at)
            } else {
                XFS_NULL_AGBLOCK
            }
        })
        .collect()
}
