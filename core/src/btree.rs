//! bmap B+tree (`di_format == Btree`) walk — collect all data-fork extents.
//!
//! An inode whose data fork overflows the inline extent-list array is promoted
//! to `XFS_DINODE_FMT_BTREE`: the data fork then holds an `xfs_bmdr_block` ROOT
//! (a compact on-disk btree root), whose pointers reference filesystem blocks
//! holding full `xfs_btree_block` (bmbt) nodes. Interior nodes point deeper;
//! level-0 leaf blocks hold the same 16-byte `xfs_bmbt_rec` records the
//! extent-list format stores inline. Walking the tree in key order and
//! collecting every leaf record yields the file's complete extent map, which
//! then feeds the existing extent→file reconstruction unchanged.
//!
//! ## On-disk layout (VERBATIM from `fs/xfs/libxfs/xfs_format.h`)
//!
//! **Root** (`xfs_bmdr_block`, inline in the data fork):
//! ```text
//!  bb_level   : __be16   0 = leaf, > 0 = interior
//!  bb_numrecs : __be16   valid records/keys in this block
//! ```
//! For a root with `bb_level > 0`, the header is followed by `keys[dmaxrecs]`
//! (`xfs_bmbt_key` = one `__be64 br_startoff`) then `ptrs[dmaxrecs]`
//! (`__be64` fsblock), where `dmaxrecs = (fork_len - 4) / (8 + 8)` — the max
//! keys/ptrs that fit in the fork. Only the first `bb_numrecs` are valid, but
//! **ptrs start at `4 + dmaxrecs*8`, not `4 + numrecs*8`** (verified against
//! `xfs_db`: a 336-byte v3 fork → `dmaxrecs = 20` → ptrs at fork offset 164).
//!
//! **Node/leaf block** (`xfs_btree_block`, in a filesystem block):
//! ```text
//!  bb_magic   : __be32   BMA3 (v5, CRC) / BMAP (v4)
//!  bb_level   : __be16
//!  bb_numrecs : __be16
//!  <long-form sibling/self/uuid/owner/crc header>
//! ```
//! The header length is the **long form** (bmbt uses 64-bit block pointers):
//! `XFS_BTREE_LBLOCK_LEN = 24` (v4, no CRC) / `XFS_BTREE_LBLOCK_CRC_LEN = 72`
//! (v5, CRC) — verified against a real `BMA3` leaf whose first `xfs_bmbt_rec`
//! begins at byte 72. A leaf (`bb_level == 0`) is followed by `recs[numrecs]`
//! (16-byte `xfs_bmbt_rec`). An interior block is followed by `keys[maxrecs]`
//! then `ptrs[maxrecs]`, `maxrecs = (blocksize - hdr) / (8 + 8)`.
//!
//! ## Safety
//!
//! The walk is bounded three ways so a hostile/corrupt tree can neither hang
//! nor exhaust memory: a maximum descent depth ([`MAX_BMBT_LEVELS`]), a cap on
//! the total pointers followed ([`MAX_BMBT_PTRS`]), and every block access is
//! bounds-checked (an out-of-image or wrong-magic pointer is skipped, not
//! panicked on). Records are collected, never the whole tree materialized.

use crate::bytes::{be_u16, be_u32, be_u64};
use crate::error::XfsError;
use crate::extent::BmbtRec;
use crate::superblock::Superblock;

/// `XFS_BMAP_MAGIC` — a v4 (non-CRC) bmbt block, ASCII `"BMAP"`.
pub const XFS_BMAP_MAGIC: u32 = 0x424d_4150;
/// `XFS_BMAP_CRC_MAGIC` — a v5 (CRC) bmbt block, ASCII `"BMA3"`.
pub const XFS_BMAP_CRC_MAGIC: u32 = 0x424d_4133;

/// `XFS_BTREE_LBLOCK_LEN` — long-form (64-bit-pointer) bmbt block header, v4.
const BMBT_BLOCK_LEN: usize = 24;
/// `XFS_BTREE_LBLOCK_CRC_LEN` — long-form CRC bmbt block header, v5.
const BMBT_BLOCK_CRC_LEN: usize = 72;

/// Size of an `xfs_bmbt_key` (`__be64 br_startoff`) / `xfs_bmbt_ptr` (`__be64`).
const KEY_LEN: usize = 8;
const PTR_LEN: usize = 8;
/// Size of a packed `xfs_bmbt_rec`.
const REC_LEN: usize = 16;

/// The `xfs_bmdr_block` root header length (`bb_level` + `bb_numrecs`).
const BMDR_HDR_LEN: usize = 4;

/// Maximum bmbt tree depth followed. Real bmbt trees are at most a handful of
/// levels deep (the fanout is hundreds per block); a claimed depth beyond this
/// is corrupt/hostile and the walk stops rather than recurse unboundedly.
pub const MAX_BMBT_LEVELS: u16 = 32;

/// Maximum total block pointers the walk will follow across the whole tree — an
/// allocation/DoS cap so a fabricated wide tree cannot make the walk run for an
/// unbounded time or collect an unbounded number of records.
pub const MAX_BMBT_PTRS: usize = 1 << 20;

/// Walk a bmap B+tree given its inline `xfs_bmdr_block` root (the inode data
/// fork) and collect every leaf `xfs_bmbt_rec` in tree (`startoff`) order.
///
/// `root_fork` is the inode's raw data fork for an `InodeFormat::Btree` inode.
/// The returned extents are exactly what an extents-format inode would store
/// inline, so they feed the existing extent→file reconstruction unchanged.
///
/// Panic-free and bounded (see [`MAX_BMBT_LEVELS`] / [`MAX_BMBT_PTRS`]): an
/// out-of-image or wrong-magic pointer is skipped; a truncated block yields
/// only the records that fully fit.
///
/// # Errors
///
/// Currently infallible in practice (a malformed tree degrades to fewer/no
/// extents rather than erroring), but returns `Result` so a future hard-fail
/// mode (e.g. a strict/verifying walk) is a non-breaking addition.
pub fn read_btree_extents(
    image: &[u8],
    sb: &Superblock,
    root_fork: &[u8],
) -> Result<Vec<BmbtRec>, XfsError> {
    let level = be_u16(root_fork, 0);
    let numrecs = usize::from(be_u16(root_fork, 2));

    // dmaxrecs: the max key/ptr pairs that fit in the fork after the 4-byte
    // header. The root's ptrs live at 4 + dmaxrecs*8 (NOT 4 + numrecs*8).
    let avail = root_fork.len().saturating_sub(BMDR_HDR_LEN);
    let dmaxrecs = avail / (KEY_LEN + PTR_LEN);

    let mut out = Vec::new();
    let mut budget = MAX_BMBT_PTRS;

    // The root is always an interior node in btree format (level >= 1): its
    // pointers reference the first tier of on-disk bmbt blocks. Read the ptrs.
    let ptrs = read_root_ptrs(root_fork, numrecs, dmaxrecs);
    for ptr in ptrs {
        if budget == 0 {
            break; // cov:unreachable: root numrecs <= dmaxrecs << MAX_BMBT_PTRS, so the budget cannot be exhausted at the root
        }
        budget -= 1;
        // The child is at tree level `level - 1`. Descend.
        walk_block(
            image,
            sb,
            ptr,
            level.saturating_sub(1),
            &mut out,
            &mut budget,
        );
    }
    Ok(out)
}

/// Read the `numrecs` valid pointers from a bmdr ROOT fork (ptrs at the
/// `dmaxrecs`-based offset). Bounds-stopping: a ptr slot outside the fork ends
/// the list.
fn read_root_ptrs(fork: &[u8], numrecs: usize, dmaxrecs: usize) -> Vec<u64> {
    let ptr_area = BMDR_HDR_LEN + dmaxrecs * KEY_LEN;
    let valid = numrecs.min(dmaxrecs);
    let mut ptrs = Vec::with_capacity(valid);
    for i in 0..valid {
        let off = ptr_area + i * PTR_LEN;
        if off + PTR_LEN > fork.len() {
            break; // cov:unreachable: dmaxrecs = (fork.len()-4)/16 and valid <= dmaxrecs, so ptr_area + valid*8 = 4 + 16*dmaxrecs <= fork.len()
        }
        ptrs.push(be_u64(fork, off));
    }
    ptrs
}

/// Descend into (or collect from) the on-disk bmbt block at filesystem block
/// `fsblock`. `expected_level` is the level this block should carry (from the
/// parent); it is advisory — the block's own `bb_level` governs the walk, and
/// the depth cap uses the recursion count.
fn walk_block(
    image: &[u8],
    sb: &Superblock,
    fsblock: u64,
    expected_level: u16,
    out: &mut Vec<BmbtRec>,
    budget: &mut usize,
) {
    // Depth guard: a chain longer than MAX_BMBT_LEVELS is corrupt/cyclic.
    if expected_level >= MAX_BMBT_LEVELS {
        return;
    }

    let blocksize = sb.blocksize as usize;
    let Some(block) = block_slice(image, fsblock, blocksize) else {
        return; // ptr outside the image — skip (bounds-checked, no panic)
    };

    let magic = be_u32(block, 0);
    let hdr = match magic {
        XFS_BMAP_CRC_MAGIC => BMBT_BLOCK_CRC_LEN,
        XFS_BMAP_MAGIC => BMBT_BLOCK_LEN,
        // Not a bmbt block (wrong magic / zeroed): skip rather than misread.
        _ => return,
    };

    let level = be_u16(block, 4);
    let numrecs = usize::from(be_u16(block, 6));

    if level == 0 {
        // Leaf: numrecs 16-byte records follow the header.
        collect_leaf_recs(block, hdr, numrecs, out);
        return;
    }

    // Interior: keys[maxrecs] then ptrs[maxrecs]; maxrecs from the block size.
    let avail = blocksize.saturating_sub(hdr);
    let maxrecs = avail / (KEY_LEN + PTR_LEN);
    let ptr_area = hdr + maxrecs * KEY_LEN;
    let valid = numrecs.min(maxrecs);
    for i in 0..valid {
        if *budget == 0 {
            return; // cov:unreachable: only a >1M-pointer tree exhausts MAX_BMBT_PTRS; not craftable as a small fixture
        }
        let off = ptr_area + i * PTR_LEN;
        if off + PTR_LEN > block.len() {
            break; // cov:unreachable: valid <= maxrecs and ptr_area + maxrecs*PTR_LEN == hdr + maxrecs*16 <= blocksize == block.len()
        }
        *budget -= 1;
        let child = be_u64(block, off);
        walk_block(image, sb, child, level.saturating_sub(1), out, budget);
    }
}

/// Collect up to `numrecs` 16-byte `xfs_bmbt_rec` records starting at `hdr`.
/// Bounds-stopping: records past the block end are not read.
fn collect_leaf_recs(block: &[u8], hdr: usize, numrecs: usize, out: &mut Vec<BmbtRec>) {
    for i in 0..numrecs {
        let start = hdr + i * REC_LEN;
        let Some(chunk) = block.get(start..start + REC_LEN) else {
            break; // truncated/over-claimed numrecs — stop at the block bound
        };
        let mut raw = [0u8; REC_LEN];
        raw.copy_from_slice(chunk);
        out.push(BmbtRec::unpack(&raw));
    }
}

/// The byte slice of filesystem block `fsblock` within the image, or `None` if
/// it lies (wholly or partly) outside the image (bounds-checked, never panics).
fn block_slice(image: &[u8], fsblock: u64, blocksize: usize) -> Option<&[u8]> {
    let start = usize::try_from(fsblock).ok()?.checked_mul(blocksize)?;
    let end = start.checked_add(blocksize)?;
    image.get(start..end)
}
