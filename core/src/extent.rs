//! Extent-list (`di_format == EXTENTS`) decode and file read.
//!
//! An extents-format inode stores its block map as an inline array of 16-byte
//! packed `xfs_bmbt_rec` records in the data fork (starting at
//! [`Inode::data_fork_offset`]). Each record maps a run of the file's logical
//! blocks to a contiguous run of absolute filesystem blocks. Reading the file
//! is: decode the records, then for each extent copy `blockcount * blocksize`
//! bytes from `startblock * blocksize` in the image to `startoff * blocksize`
//! in the output, zero-filling any logical gap (a sparse hole), and finally
//! truncating the assembled buffer to the inode's `di_size` (the last block's
//! tail is slack).
//!
//! ## The `xfs_bmbt_rec` bit-packing (VERBATIM from `fs/xfs/libxfs/xfs_format.h`)
//!
//! Two big-endian `u64` words `l0`, `l1` (bit 63 = MSB):
//!
//! ```text
//!  l0:63     = extent flag (1 = unwritten/preallocated)
//!  l0:9..=62 = startoff   (54 bits)
//!  l0:0..=8  = startblock high 9 bits
//!  l1:21..=63 = startblock low 43 bits
//!  l1:0..=20 = blockcount (21 bits)
//!  startblock(52) = (l0:0..=8 << 43) | l1:21..=63
//! ```
//!
//! The 52-bit `startblock` is SPLIT across both words — getting the split
//! inverted "ships green" against a self-encoded round-trip, so P3 validates
//! every unpacked extent against `xfs_db bmap` and validates the reconstructed
//! file content against a mount-ro sha256 (the LZNT1-trap this module guards).

use crate::btree::read_btree_extents;
use crate::error::XfsError;
use crate::inode::{Inode, InodeFormat};
use crate::superblock::Superblock;

/// Bit width of `startoff` (`l0:9-62`).
const STARTOFF_BITS: u32 = 54;
/// Bit width of the `startblock` high part (`l0:0-8`).
const STARTBLOCK_HI_BITS: u32 = 9;
/// Bit width of the `startblock` low part (`l1:21-63`).
const STARTBLOCK_LO_BITS: u32 = 43;
/// Bit width of `blockcount` (`l1:0-20`).
const BLOCKCOUNT_BITS: u32 = 21;

/// A mask of the low `n` bits. All call sites pass a fixed field width `< 64`,
/// so the `>= 64` arm is a defensive guard against a future caller — kept so the
/// helper degrades gracefully rather than overflow-shifting.
#[inline]
const fn low_mask(n: u32) -> u64 {
    if n >= 64 {
        u64::MAX // cov:unreachable: every call site passes a field width < 64
    } else {
        (1u64 << n) - 1
    }
}

/// The allocation-bomb rejection error: a file `size` larger than the image
/// cannot be real. Single constructor so both guard arms share one code path
/// (the arm that fires on a genuinely-huge size is exercised by tests).
fn size_error(need: usize, have: usize) -> XfsError {
    XfsError::Truncated {
        structure: "extent-list file (size exceeds image)",
        need,
        have,
    }
}

/// A decoded 16-byte `xfs_bmbt_rec` extent descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BmbtRec {
    /// File logical block offset of this extent (`l0:9-62`, 54 bits).
    pub startoff: u64,
    /// Absolute filesystem block of the extent's first block
    /// (`l0:0-8` << 43 | `l1:21-63`, 52 bits).
    pub startblock: u64,
    /// Length of the extent in filesystem blocks (`l1:0-20`, 21 bits).
    pub blockcount: u64,
    /// `l0:63` — set for an unwritten/preallocated extent. The blocks are
    /// allocated, so the reader still reads their on-disk bytes.
    pub unwritten: bool,
}

impl BmbtRec {
    /// Decode a 16-byte packed `xfs_bmbt_rec` (panic-free; bit-exact to the
    /// kernel `xfs_format.h` layout documented at the module head).
    #[must_use]
    pub fn unpack(raw: &[u8; 16]) -> Self {
        let l0 = u64::from_be_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]);
        let l1 = u64::from_be_bytes([
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ]);

        let unwritten = (l0 >> 63) & 1 == 1;
        let startoff = (l0 >> STARTBLOCK_HI_BITS) & low_mask(STARTOFF_BITS);
        let startblock_hi = l0 & low_mask(STARTBLOCK_HI_BITS);
        let startblock_lo = (l1 >> BLOCKCOUNT_BITS) & low_mask(STARTBLOCK_LO_BITS);
        let startblock = (startblock_hi << STARTBLOCK_LO_BITS) | startblock_lo;
        let blockcount = l1 & low_mask(BLOCKCOUNT_BITS);

        Self {
            startoff,
            startblock,
            blockcount,
            unwritten,
        }
    }
}

/// Decode up to `nextents` consecutive 16-byte `xfs_bmbt_rec` records from a
/// data fork. Records past the end of `fork` are not read (bounds-stopping):
/// a truncated or lying `nextents` yields only the records that fully fit,
/// never an over-read.
#[must_use]
pub fn read_extents(fork: &[u8], nextents: u32) -> Vec<BmbtRec> {
    let mut recs = Vec::new();
    for i in 0..nextents as usize {
        let start = i * 16;
        let Some(chunk) = fork.get(start..start + 16) else {
            break;
        };
        let mut raw = [0u8; 16];
        raw.copy_from_slice(chunk);
        recs.push(BmbtRec::unpack(&raw));
    }
    recs
}

/// Reconstruct an extent-list file's bytes from its raw data fork.
///
/// Decodes the `nextents` inline `xfs_bmbt_rec` records, copies each extent's
/// blocks from the image, zero-fills sparse holes, and truncates to `size`.
///
/// # Errors
///
/// - [`XfsError::Truncated`] if `size` exceeds the image length (an
///   allocation-bomb guard: a real file's bytes live within the image, so a
///   size larger than the whole image is rejected rather than allocated).
pub fn read_file_from_fork(
    image: &[u8],
    sb: &Superblock,
    fork: &[u8],
    nextents: u32,
    size: u64,
) -> Result<Vec<u8>, XfsError> {
    let recs = read_extents(fork, nextents);
    assemble_extents(image, sb, &recs, size)
}

/// Reconstruct a file's bytes from an already-decoded extent list.
///
/// The shared assembly used by both the inline extent-list path
/// ([`read_file_from_fork`]) and the bmap-B+tree path
/// ([`Superblock::read_file`] on a `Btree` inode): copy each extent's blocks
/// from the image, zero-fill sparse holes, and truncate to `size`.
///
/// # Errors
///
/// [`XfsError::Truncated`] if `size` exceeds the image length (allocation-bomb
/// guard — a real file's bytes live within the image).
pub fn assemble_extents(
    image: &[u8],
    sb: &Superblock,
    recs: &[BmbtRec],
    size: u64,
) -> Result<Vec<u8>, XfsError> {
    // Allocation-bomb guard: a genuine file cannot be larger than the image it
    // lives in. Refuse an absurd size rather than trying to allocate it. On a
    // 64-bit target `usize == u64` so the try_from never fails; the guard stays
    // so the code is correct on a hypothetical <64-bit target too.
    let size = match usize::try_from(size) {
        Ok(s) => s,
        // usize == u64 on the supported (64-bit) targets, so a u64 size always
        // fits; a smaller-usize target would take this arm.
        Err(_) => return Err(size_error(usize::MAX, image.len())), // cov:unreachable: usize == u64 on 64-bit targets
    };
    if size > image.len() {
        return Err(size_error(size, image.len()));
    }

    let blocksize = sb.blocksize as usize;
    // A zero-filled output makes sparse holes free: any logical block not
    // covered by an extent stays zero.
    let mut out = vec![0u8; size];

    for rec in recs {
        // Byte window this extent occupies in the OUTPUT (logical position).
        let dst_start = (rec.startoff as usize).saturating_mul(blocksize);
        let ext_bytes = (rec.blockcount as usize).saturating_mul(blocksize);
        // Byte window this extent reads from the IMAGE (physical position).
        let src_start = (rec.startblock as usize).saturating_mul(blocksize);

        // Clip the copy to what actually lands within `size` (the tail of the
        // last extent past di_size is slack) and to what the image holds.
        let dst_end = dst_start.saturating_add(ext_bytes).min(size);
        if dst_end <= dst_start {
            continue; // extent starts past end-of-file — nothing to place.
        }
        let want = dst_end - dst_start;
        let src_end = src_start.saturating_add(want);
        let Some(src) = image.get(src_start..src_end) else {
            // The extent points outside the image (corrupt/truncated): leave
            // the logical range zero-filled rather than over-read or panic.
            continue;
        };
        // `dst_start < size` and `dst_end <= size`, so this range is in-bounds.
        let Some(dst) = out.get_mut(dst_start..dst_end) else {
            continue; // cov:unreachable: dst_end <= size == out.len()
        };
        dst.copy_from_slice(src);
    }

    Ok(out)
}

impl Superblock {
    /// Reconstruct a file's bytes from its inode, dispatching on the data-fork
    /// format.
    ///
    /// - [`InodeFormat::Extents`] — decode the inode's inline extent array (its
    ///   [`Inode::data_fork`]) directly.
    /// - [`InodeFormat::Btree`] — walk the inline `xfs_bmdr_block` root and its
    ///   on-disk bmbt leaf blocks ([`read_btree_extents`]) to collect the full
    ///   extent map, then assemble from that.
    ///
    /// Either way the extents are assembled identically: copy each extent's
    /// blocks from the image, zero-fill sparse holes, truncate to `di_size`.
    /// A [`InodeFormat::Local`] inode holds its data inline (not via extents),
    /// and a [`InodeFormat::Dev`] inode has no file body — both yield an empty
    /// (fully zero-filled to `di_size`) result via the empty extent list rather
    /// than misinterpreting the fork as an extent array.
    ///
    /// # Errors
    ///
    /// [`XfsError::Truncated`] if `di_size` exceeds the image length
    /// (allocation-bomb guard); see [`assemble_extents`].
    pub fn read_file(&self, image: &[u8], inode: &Inode) -> Result<Vec<u8>, XfsError> {
        match inode.format {
            InodeFormat::Extents => {
                read_file_from_fork(image, self, &inode.data_fork, inode.nextents, inode.size)
            }
            InodeFormat::Btree => {
                let recs = read_btree_extents(image, self, &inode.data_fork)?;
                assemble_extents(image, self, &recs, inode.size)
            }
            // Local/Dev/Other: no extent-mapped body. Assemble from an empty
            // extent list -> a `di_size`-length zero fill (never misread the
            // inline fork as an extent array).
            _ => assemble_extents(image, self, &[], inode.size),
        }
    }
}
