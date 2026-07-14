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

pub mod bytes;
mod error;
mod superblock;

pub use error::XfsError;
pub use superblock::{Superblock, XFS_SB_MAGIC};
