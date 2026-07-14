//! Directory parsing — short-form and block directories (P4).
//!
//! This module turns the two most common XFS directory formats into a flat
//! `Vec<DirEntry>` and composes them into the real forensic entrypoint,
//! [`read_by_path`]. Leaf / node / btree directories are deferred (P4b/P5): a
//! directory in one of those formats fails LOUD with [`XfsError::UnsupportedDir`]
//! naming the format, never a silent empty listing.
//!
//! ## The two formats
//!
//! **Short-form** ([`crate::InodeFormat::Local`] on a directory inode) — packed
//! inline in the inode data fork (`xfs_dir2_sf_hdr` + entries). Layout, verbatim
//! from `fs/xfs/libxfs/xfs_format.h` and confirmed against raw `xfs_db` byte
//! dumps of the minted images:
//!
//! ```text
//!  count   : u8            number of entries
//!  i8count : u8            entries needing a 64-bit inode number
//!  parent  : u32|u64 (BE)  parent inode (4 bytes if i8count==0 else 8)
//!  per entry:
//!    namelen : u8
//!    offset  : u16 (BE)    dir2 data offset — not needed for listing
//!    name    : [u8; namelen]
//!    ftype   : u8          ONLY when the fs ftype feature is on (see below)
//!    inumber : u32|u64 (BE) 4 bytes if i8count==0 else 8
//! ```
//!
//! `.`/`..` are implicit in short-form (`.` = the dir's own inode, `..` = the
//! header `parent`); the entry list holds only the named children.
//!
//! **Block directory** ([`crate::InodeFormat::Extents`] with `size == blocksize`,
//! i.e. a single directory block). The block opens with a data-block header
//! (`xfs_dir3_data_hdr` on v5, magic **`XDB3`**; `xfs_dir2_data_hdr` on v4, magic
//! **`XD2B`**), followed by `xfs_dir2_data_entry` records interleaved with
//! `xfs_dir2_data_unused` free records (freetag `0xFFFF` — skipped), and a
//! leaf/hash array + `xfs_dir2_block_tail` at the block tail. Each data entry is:
//!
//! ```text
//!  inumber : u64 (BE)
//!  namelen : u8
//!  name    : [u8; namelen]
//!  ftype   : u8          ONLY when the fs ftype feature is on
//!  tag     : u16 (BE)    back-pointer; ignored for listing
//!  (padded up to an 8-byte boundary)
//! ```
//!
//! The data-entry region ends where the leaf array begins, computed structurally
//! from the block tail: `leaf_start = blocksize - 8 - count*8`.
//!
//! ## The ftype byte is a FEATURE bit, not a version bit
//!
//! Both formats carry a trailing `ftype` byte per entry **iff the filesystem's
//! ftype feature is enabled** ([`Superblock::has_ftype`]). Modern `mkfs.xfs`
//! enables it by default even on v4, so this reader branches on the feature bit,
//! never on the v4/v5 version — the classic off-by-one this module guards.

use crate::bytes::{be_u16, be_u32, be_u64, u8_at};
use crate::error::XfsError;
use crate::inode::{Inode, InodeFormat};
use crate::superblock::Superblock;

/// The v5 block-directory data-block magic (`XFS_DIR3_BLOCK_MAGIC`, `"XDB3"`).
pub const XFS_DIR3_BLOCK_MAGIC: u32 = 0x5844_4233;
/// The v4 block-directory data-block magic (`XFS_DIR2_BLOCK_MAGIC`, `"XD2B"`).
pub const XFS_DIR2_BLOCK_MAGIC: u32 = 0x5844_3242;

/// The `xfs_dir3_data_hdr` (v5) header length preceding the first data entry.
const DIR3_DATA_HDR_LEN: usize = 64;
/// The `xfs_dir2_data_hdr` (v4) header length preceding the first data entry.
const DIR2_DATA_HDR_LEN: usize = 16;
/// The `xfs_dir2_block_tail` size (`count: u32`, `stale: u32`) at the block end.
const BLOCK_TAIL_LEN: usize = 8;
/// Each `xfs_dir2_leaf_entry` in the block tail's leaf array is 8 bytes.
const LEAF_ENTRY_LEN: usize = 8;
/// The `xfs_dir2_data_unused` freetag marking a free (deleted/hole) record.
const DATA_FREE_TAG: u16 = 0xffff;

/// A single directory entry: a name, the inode it points at, and — when the
/// filesystem's ftype feature is on — the on-disk file-type byte.
///
/// `.` and `..` are not surfaced for short-form directories (they are implicit);
/// a block directory carries them explicitly and they appear verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry name, raw bytes (XFS names are not guaranteed UTF-8).
    pub name: Vec<u8>,
    /// The inode number this entry points at.
    pub inode: u64,
    /// The on-disk `ftype` byte, or `None` when the filesystem has no ftype
    /// feature (a no-ftype short-form/block directory omits the byte entirely).
    pub ftype: Option<u8>,
}

/// Round `n` up to the next multiple of 8 (XFS directory entries are 8-byte
/// aligned). Saturating so a hostile length can never overflow.
#[inline]
const fn align8(n: usize) -> usize {
    n.saturating_add(7) & !7
}

/// Parse a short-form directory from its inode data fork.
///
/// `has_ftype` selects whether each entry carries a trailing `ftype` byte (see
/// the module docs — it tracks the fs feature bit, not the version). Bounds-
/// stopping: a truncated fork yields only the entries that fully fit, never an
/// over-read or panic.
#[must_use]
pub fn read_shortform_dir(fork: &[u8], has_ftype: bool) -> Vec<DirEntry> {
    let count = usize::from(u8_at(fork, 0));
    let i8count = u8_at(fork, 1);
    // i8count==0 -> 4-byte inode numbers (incl. parent); else 8-byte.
    let inum_width = if i8count == 0 { 4 } else { 8 };

    // Header: count(1) + i8count(1) + parent(inum_width). Parent is `..`, not a
    // listed child, so we skip it and start the entry cursor after it.
    let mut off = 2 + inum_width;

    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        // namelen(1) + offset(2) then the name.
        let namelen = usize::from(u8_at(fork, off));
        let name_start = off + 3;
        let name_end = name_start + namelen;
        let Some(name) = fork.get(name_start..name_end) else {
            break; // fork ends inside this entry -> stop (bounds-stopping)
        };

        // Optional ftype byte, then the inode number.
        let ftype_off = name_end;
        let (ftype, inum_off) = if has_ftype {
            (Some(u8_at(fork, ftype_off)), ftype_off + 1)
        } else {
            (None, ftype_off)
        };

        let inum_end = inum_off + inum_width;
        let Some(inum_bytes) = fork.get(inum_off..inum_end) else {
            break; // no room for the inode number -> stop
        };
        let inode = read_inum(inum_bytes);

        entries.push(DirEntry {
            name: name.to_vec(),
            inode,
            ftype,
        });
        off = inum_end;
    }
    entries
}

/// Read a big-endian directory inode number from a 4- or 8-byte slice.
#[inline]
fn read_inum(bytes: &[u8]) -> u64 {
    match bytes.len() {
        4 => u64::from(be_u32(bytes, 0)),
        _ => be_u64(bytes, 0),
    }
}

/// Parse a single-block (block-format) directory from its raw data-block bytes.
///
/// `has_ftype` selects the per-entry ftype byte. Walks `xfs_dir2_data_entry`
/// records from the header end up to the leaf array (bounded structurally by the
/// block tail), skipping `xfs_dir2_data_unused` (freetag `0xFFFF`) records.
///
/// # Errors
///
/// [`XfsError::UnsupportedDir`] if the block magic is neither `XDB3` (v5) nor
/// `XD2B` (v4) — the offending magic bytes are named in the error.
pub fn read_block_dir(block: &[u8], has_ftype: bool) -> Result<Vec<DirEntry>, XfsError> {
    let magic = be_u32(block, 0);
    let hdr_len = match magic {
        XFS_DIR3_BLOCK_MAGIC => DIR3_DATA_HDR_LEN,
        XFS_DIR2_BLOCK_MAGIC => DIR2_DATA_HDR_LEN,
        other => {
            return Err(XfsError::UnsupportedDir {
                detail: format!(
                    "block directory: unrecognized data-block magic {other:#010x} \
                     (bytes {:02x?}), expected XDB3 (0x58444233) or XD2B (0x58443242)",
                    &block.get(0..4).unwrap_or(&[])
                ),
            });
        }
    };

    // The block tail (`count: u32, stale: u32`) is the last 8 bytes; the leaf
    // array of `count` 8-byte entries sits immediately before it. Data entries
    // occupy `[hdr_len .. leaf_start)`. Deriving the stop structurally (not from
    // bestfree) means a lying/free record can't run the walk into the leaf area.
    let blocksize = block.len();
    let leaf_start = if blocksize >= BLOCK_TAIL_LEN {
        let count = usize::try_from(be_u32(block, blocksize - BLOCK_TAIL_LEN)).unwrap_or(0);
        let leaf_bytes = count.saturating_mul(LEAF_ENTRY_LEN);
        blocksize
            .saturating_sub(BLOCK_TAIL_LEN)
            .saturating_sub(leaf_bytes)
    } else {
        0
    };
    // A malformed count could push leaf_start below hdr_len; clamp so the walk
    // range is never inverted (yielding an empty listing, not a panic).
    let region_end = leaf_start.max(hdr_len).min(blocksize);

    let mut entries = Vec::new();
    let mut off = hdr_len;
    // Each iteration advances `off` by at least the minimum record size, so the
    // loop always terminates; the explicit bound is a belt-and-suspenders guard.
    while off + 3 <= region_end {
        // A data-unused record starts with the freetag 0xFFFF in the first two
        // bytes (the inumber's high half can never be 0xFFFF for a real entry).
        if be_u16(block, off) == DATA_FREE_TAG {
            let free_len = usize::from(be_u16(block, off + 2));
            // A zero/insane free length would stall or run backwards: enforce
            // forward progress of at least 8 bytes (the minimum record grain).
            off = off.saturating_add(free_len.max(align8(1)));
            continue;
        }

        // A real data entry: inumber(8) namelen(1) name[] [ftype(1)] tag(2).
        let inode = be_u64(block, off);
        let namelen = usize::from(u8_at(block, off + 8));
        // A dirent always has a non-empty name; a zero namelen means we have run
        // off the end of the real entries into zero padding (or a malformed
        // record). Stop rather than fabricate phantom empty-name entries.
        if namelen == 0 {
            break;
        }
        let name_start = off + 9;
        let name_end = name_start + namelen;
        let Some(name) = block.get(name_start..name_end) else {
            break; // entry runs past the block -> stop (bounds-stopping)
        };
        let ftype = if has_ftype {
            Some(u8_at(block, name_end))
        } else {
            None
        };
        entries.push(DirEntry {
            name: name.to_vec(),
            inode,
            ftype,
        });

        // Advance past this record: inumber(8)+namelen(1)+name+ftype?+tag(2),
        // aligned up to 8. `align8` guarantees forward progress.
        let ftype_len = usize::from(has_ftype);
        let raw = 8 + 1 + namelen + ftype_len + 2;
        off = off.saturating_add(align8(raw));
    }

    Ok(entries)
}

impl Superblock {
    /// List a directory inode's entries, dispatching on its on-disk format.
    ///
    /// Handles the two most common formats:
    /// - **short-form** ([`InodeFormat::Local`]) — parsed from the inode's inline
    ///   data fork;
    /// - **block** ([`InodeFormat::Extents`] with `size == blocksize`) — the
    ///   single directory block read via the inode's one extent.
    ///
    /// # Errors
    ///
    /// - [`XfsError::UnsupportedDir`] — a leaf / node / btree directory (a
    ///   multi-block `Extents` dir, or a `Btree` dir), or an unrecognized
    ///   block-directory magic. The error NAMES the format/value (fail loud).
    /// - [`XfsError::Truncated`] — the directory block extent lies outside the
    ///   image (propagated from the file read).
    pub fn read_dir(&self, image: &[u8], inode: &Inode) -> Result<Vec<DirEntry>, XfsError> {
        match inode.format {
            InodeFormat::Local => Ok(read_shortform_dir(&inode.data_fork, self.has_ftype())),
            InodeFormat::Extents => {
                let blocksize = u64::from(self.blocksize);
                if inode.size == blocksize {
                    // Single-block (block) directory: read the one extent and
                    // walk the data block. read_file gives exactly `size` bytes.
                    let block = self.read_file(image, inode)?;
                    read_block_dir(&block, self.has_ftype())
                } else {
                    Err(XfsError::UnsupportedDir {
                        detail: format!(
                            "leaf/node directory not yet supported (multi-block \
                             extents dir: size {} != blocksize {}, {} extents)",
                            inode.size, blocksize, inode.nextents
                        ),
                    })
                }
            }
            other => Err(XfsError::UnsupportedDir {
                detail: format!("directory format {other:?} not yet supported (btree/dev/other)"),
            }),
        }
    }
}

/// List a directory inode's entries (free-function form of
/// [`Superblock::read_dir`]).
///
/// # Errors
///
/// See [`Superblock::read_dir`].
pub fn read_dir(image: &[u8], sb: &Superblock, inode: &Inode) -> Result<Vec<DirEntry>, XfsError> {
    sb.read_dir(image, inode)
}

/// Read a file by its absolute path, navigating the directory tree from the root.
///
/// The capstone entrypoint: starting at [`Superblock::rootino`], split `path` on
/// `/`, and for each component [`Superblock::read_dir`] the current directory and
/// name-match to descend to the component's inode; the final inode's bytes are
/// reconstructed with [`Superblock::read_file`]. This composes P1 (inode-number
/// decode) + P2 (inode core) + P3 (extent-list read) + P4 (directory listing)
/// into the real read-file-by-path forensic operation.
///
/// # Errors
///
/// - [`XfsError::PathNotFound`] — a component was not found in its parent, or a
///   non-final component was not a directory.
/// - [`XfsError::UnsupportedDir`] — a directory along the path uses a format not
///   yet handled (fail loud, never a silent miss).
/// - Any error from [`Superblock::read_inode`] / [`Superblock::read_file`].
pub fn read_by_path(image: &[u8], sb: &Superblock, path: &str) -> Result<Vec<u8>, XfsError> {
    let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();

    let mut current = sb.read_inode(image, sb.rootino)?;
    for (idx, comp) in components.iter().enumerate() {
        // The current inode must be a directory to descend into it.
        let entries = sb.read_dir(image, &current)?;
        let Some(entry) = entries.iter().find(|e| e.name == comp.as_bytes()) else {
            return Err(XfsError::PathNotFound {
                path: path.to_string(),
                component: (*comp).to_string(),
            });
        };
        let next = sb.read_inode(image, entry.inode)?;

        let is_last = idx + 1 == components.len();
        if is_last {
            return sb.read_file(image, &next);
        }
        // A non-final component must itself be a directory to continue.
        if !next.is_dir() {
            return Err(XfsError::PathNotFound {
                path: path.to_string(),
                component: (*comp).to_string(),
            });
        }
        current = next;
    }

    // An empty path (no components) resolves to the root, which is a directory,
    // not a file — read_file on it would be meaningless. Report it as not found.
    Err(XfsError::PathNotFound {
        path: path.to_string(),
        component: String::new(),
    })
}
