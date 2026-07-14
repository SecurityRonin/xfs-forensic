//! `xfs-forensic` — anomaly auditor for XFS filesystems.
//!
//! Emits graded [`forensicnomicon::report::Finding`]s for XFS-specific forensic
//! signals: deleted-inode recovery (extent records surviving in inode slack),
//! directory-slack residue (freed dirents keeping their inode number), and v5
//! self-describing-metadata integrity (CRC / owner / blkno mismatches).
//!
//! Built on `xfs-core` for valid-path reading; where the audit must see slack
//! and malformed structure the reader normalizes away, it parses the raw bytes
//! directly (the reader/analyzer-split principle).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
