//! Extent-list (`di_format == EXTENTS`) decode and file read.
//!
//! STUB (P3 RED): types and signatures only; the bit-split and block math land
//! in GREEN.

use crate::error::XfsError;
use crate::inode::Inode;
use crate::superblock::Superblock;

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
    /// `l0:63` — set for an unwritten/preallocated extent.
    pub unwritten: bool,
}

impl BmbtRec {
    /// Decode a 16-byte packed `xfs_bmbt_rec` (STUB).
    #[must_use]
    pub fn unpack(_raw: &[u8; 16]) -> Self {
        Self {
            startoff: 0,
            startblock: 0,
            blockcount: 0,
            unwritten: false,
        }
    }
}

/// Read `nextents` consecutive 16-byte records from a data fork (STUB).
#[must_use]
pub fn read_extents(_fork: &[u8], _nextents: u32) -> Vec<BmbtRec> {
    Vec::new()
}

/// Reconstruct an extent-list file's bytes from its fork (STUB).
///
/// # Errors
/// Returns [`XfsError`] on an absurd size or unreadable geometry.
pub fn read_file_from_fork(
    _image: &[u8],
    _sb: &Superblock,
    _fork: &[u8],
    _nextents: u32,
    _size: u64,
) -> Result<Vec<u8>, XfsError> {
    Ok(Vec::new())
}

impl Superblock {
    /// Reconstruct an extent-list file's bytes (STUB).
    ///
    /// # Errors
    /// Returns [`XfsError`] on an absurd size or unreadable geometry.
    pub fn read_file(&self, _image: &[u8], _inode: &Inode) -> Result<Vec<u8>, XfsError> {
        Ok(Vec::new())
    }
}
