//! v5 CRC32c self-describing-metadata verification (`xfs_verify_cksum`).
//!
//! Every v5 (and ONLY v5 — v4 has no CRCs) metadata block carries a CRC32c over
//! the whole on-disk object, with the 4-byte CRC field itself treated as zero
//! during the computation. XFS uses the Castagnoli/iSCSI polynomial and stores
//! the *complemented* result little-endian at a per-structure `cksum_offset`.
//!
//! This module is the shared verifier. It reproduces the kernel's
//! `xfs_verify_cksum(buffer, length, cksum_offset)` byte-exactly
//! (`fs/xfs/libxfs/xfs_cksum.h`): compute the CRC over the buffer with the CRC
//! field zeroed, then compare against the stored value. Verification is
//! **non-fatal** — a bad CRC never fails a parse; it is surfaced as
//! `crc_valid: Some(false)` so the `-forensic` layer can turn it into a Finding
//! (a forensic reader must still parse a tampered block and report the
//! mismatch). On a v4 (no-CRC) structure the status is `None`.
//!
//! ## CRC field offsets (VERBATIM from `fs/xfs/libxfs/xfs_format.h` +
//! `xfs_da_format.h`, confirmed against the on-disk struct layout)
//!
//! | structure | CRC field | offset | coverage length |
//! |---|---|---|---|
//! | superblock (`xfs_dsb`) | `sb_crc` | [`SB_CRC_OFF`] = 224 | sectorsize |
//! | AGF (`xfs_agf`) | `agf_crc` | [`AGF_CRC_OFF`] = 216 | sectorsize |
//! | AGI (`xfs_agi`) | `agi_crc` | [`AGI_CRC_OFF`] = 312 | sectorsize |
//! | AGFL (`xfs_agfl`) | `agfl_crc` | [`AGFL_CRC_OFF`] = 32 | sectorsize |
//! | inode v3 (`xfs_dinode`) | `di_crc` | [`DINODE_CRC_OFF`] = 100 | inodesize |
//! | dir data/block (`xfs_dir3_blk_hdr`) | `crc` | [`DIR3_DATA_CRC_OFF`] = 4 | blocksize |
//! | dir leaf/node (`xfs_da3_blkinfo`) | `crc` | [`DA3_BLKINFO_CRC_OFF`] = 12 | blocksize |
//! | bmbt long-form (`xfs_btree_block_lhdr`) | `bb_crc` | [`BMBT_CRC_OFF`] = 64 | blocksize |
//!
//! The coverage length is always the object's whole on-disk buffer (the value
//! the kernel passes as `BBTOB(bp->b_length)` to `xfs_buf_verify_cksum`), which
//! for a caller here is simply `buffer.len()` — the caller slices the exact
//! sector / inode / block.

/// `XFS_SB_CRC_OFF` — `offsetof(struct xfs_dsb, sb_crc)`.
pub const SB_CRC_OFF: usize = 224;
/// `XFS_AGF_CRC_OFF` — `offsetof(struct xfs_agf, agf_crc)`.
pub const AGF_CRC_OFF: usize = 216;
/// `XFS_AGI_CRC_OFF` — `offsetof(struct xfs_agi, agi_crc)`. The `agi_crc` sits
/// **after** the 256-byte `agi_unlinked[64]` array and the 16-byte `agi_uuid`
/// (magicnum/versionnum/seqno/length/count/root/level/freecount/newino/dirino =
/// 40 bytes, + unlinked → 296, + uuid → 312).
pub const AGI_CRC_OFF: usize = 312;
/// `XFS_AGFL_CRC_OFF` — `offsetof(struct xfs_agfl, agfl_crc)`.
pub const AGFL_CRC_OFF: usize = 32;
/// `XFS_DINODE_CRC_OFF` — `offsetof(struct xfs_dinode, di_crc)` (v3 core).
pub const DINODE_CRC_OFF: usize = 100;
/// `XFS_DIR3_DATA_CRC_OFF` — `offsetof(struct xfs_dir3_blk_hdr, crc)` (the
/// `hdr.crc` of every v5 dir data / single-block data block).
pub const DIR3_DATA_CRC_OFF: usize = 4;
/// `XFS_DIR3_LEAF_CRC_OFF` — `offsetof(struct xfs_da3_blkinfo, crc)` (the
/// `info.crc` of every v5 dir leaf / node / freeindex block: the 12-byte
/// `xfs_da_blkinfo` header precedes it).
pub const DA3_BLKINFO_CRC_OFF: usize = 12;
/// `XFS_BTREE_LBLOCK_CRC_OFF` — `offsetof(struct xfs_btree_block, bb_u.l.bb_crc)`
/// (the long-form v5 bmbt/`BMA3` block CRC, inside the 72-byte header).
pub const BMBT_CRC_OFF: usize = 64;

/// The XFS CRC32c parameters: Castagnoli polynomial, reflected in/out, init and
/// xorout `0xFFFFFFFF`. This is the `CRC_32_ISCSI` algorithm, whose final digest
/// equals the kernel's `~crc32c(~0, buffer)` — i.e. the exact value XFS stores
/// on disk (little-endian) via `xfs_end_cksum`. Constructing the `Crc` is cheap
/// (it references a static algorithm), so it is built per call.
fn crc32c() -> crc::Crc<u32> {
    crc::Crc::<u32>::new(&crc::CRC_32_ISCSI)
}

/// Verify the XFS CRC32c of a metadata `buffer` whose 4-byte CRC field lies at
/// `crc_offset`, exactly as the kernel's `xfs_verify_cksum` does: compute the
/// CRC over the whole buffer with the CRC field treated as zero, and compare it
/// to the stored little-endian value.
///
/// Panic-free and bounds-checked: a buffer too short to hold the CRC field
/// (`crc_offset + 4 > buffer.len()`) returns `false` (verification fails)
/// rather than panicking — a truncated/hostile block is a failed check, never a
/// crash.
///
/// The XFS semantics ("zero the CRC field, then CRC the whole buffer") are
/// replicated with a scratch copy: the four bytes at `[crc_offset..crc_offset+4]`
/// are zeroed in the copy, the copy is CRC'd whole, and the result is compared
/// to the stored bytes. (A two-range split — CRC `[..crc_offset]`, then four
/// zero bytes, then `[crc_offset+4..]` — is byte-identical; the copy is chosen
/// for clarity and is bounded by the fixed metadata-object size.)
#[must_use]
pub fn verify_crc(buffer: &[u8], crc_offset: usize) -> bool {
    // A hostile `crc_offset` near `usize::MAX` would overflow `crc_offset + 4`;
    // guard it so the API is panic-free for any caller-supplied offset (this is
    // a public, fuzz-facing entry point, not only the fixed internal offsets).
    let Some(end) = crc_offset.checked_add(4) else {
        return false;
    };
    // The buffer must hold the whole CRC field to carry a checksum at all.
    let Some(stored_bytes) = buffer.get(crc_offset..end) else {
        return false;
    };
    let stored = u32::from_le_bytes([
        stored_bytes[0],
        stored_bytes[1],
        stored_bytes[2],
        stored_bytes[3],
    ]);

    // Scratch copy with the CRC field zeroed in place (kernel semantics), then
    // CRC the whole object. `CRC_32_ISCSI`'s digest already applies the final
    // complement + reflection, so it equals the stored on-disk value directly.
    let mut scratch = buffer.to_vec();
    // `end <= buffer.len()` was just proven by the successful `get`, so this
    // slice is in range on the equal-length copy.
    if let Some(field) = scratch.get_mut(crc_offset..end) {
        field.fill(0);
    }
    let computed = crc32c().checksum(&scratch);
    computed == stored
}

/// Compute the non-fatal CRC status for a metadata `buffer`: `Some(bool)` on a
/// v5 structure (verified via [`verify_crc`]), or `None` on a v4 structure
/// (which carries no CRC — a bad-CRC finding would be a false positive).
///
/// This is the single seam every parser uses to fill its `crc_valid` field, so
/// the v4→`None` / v5→`Some` decision lives in exactly one place.
#[must_use]
pub fn crc_status(is_v5: bool, buffer: &[u8], crc_offset: usize) -> Option<bool> {
    if is_v5 {
        Some(verify_crc(buffer, crc_offset))
    } else {
        None
    }
}
