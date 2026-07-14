//! `xfs-core` — a pure-Rust, from-scratch XFS filesystem reader.
//!
//! Parses the on-disk XFS structures a forensic tool needs — superblock and
//! geometry, allocation-group headers, inodes, extents, and the five directory
//! formats — over any byte source. The reader targets both v4 (legacy) and v5
//! (self-describing CRC-stamped) filesystems.
//!
//! Import path is `xfs` (see `[lib] name`): `use xfs::Superblock;`.
//!
//! # Safety and robustness
//!
//! This crate parses untrusted, attacker-controllable disk images. It is
//! `#![forbid(unsafe_code)]` and every integer is read through bounds-checked
//! big-endian helpers that yield `0`/`None` out of range rather than panic
//! (the Paranoid Gatekeeper standard).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod agheaders;
mod btree;
pub mod bytes;
pub mod crc;
mod dir;
mod error;
mod extent;
mod inode;
mod superblock;

pub use agheaders::{
    Agf, Agfl, Agi, XFS_AGFL_MAGIC, XFS_AGF_MAGIC, XFS_AGI_MAGIC, XFS_AGI_UNLINKED_BUCKETS,
};
pub use btree::{
    read_btree_extents, verify_bmbt_block_crc, MAX_BMBT_LEVELS, MAX_BMBT_PTRS, XFS_BMAP_CRC_MAGIC,
    XFS_BMAP_MAGIC,
};
pub use crc::{crc_status, verify_crc};
pub use dir::{
    read_block_dir, read_by_path, read_data_dir_block, read_dir, read_shortform_dir,
    verify_dir_block_crc, DirEntry, XFS_DIR2_BLOCK_MAGIC, XFS_DIR2_DATA_MAGIC,
    XFS_DIR3_BLOCK_MAGIC, XFS_DIR3_DATA_MAGIC,
};
pub use error::XfsError;
pub use extent::{assemble_extents, read_extents, read_file_from_fork, BmbtRec};
pub use inode::{
    FileType, Inode, InodeFormat, XfsTimestamp, XFS_DIFLAG2_BIGTIME, XFS_DINODE_MAGIC,
};
pub use superblock::{InodeLocation, Superblock, XFS_SB_MAGIC};
