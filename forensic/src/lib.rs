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
//!
//! Each finding is an **observation** ("consistent with …"); the examiner draws
//! the conclusions. Mirrors the fleet producer pattern (typed `AnomalyKind` +
//! `impl Observation` + `audit_*` → `Vec<Anomaly>` + `audit_findings` →
//! `Vec<Finding>`), as in `ntfs-forensic`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub use forensicnomicon::report::Severity;
use forensicnomicon::report::{Evidence, Finding, Location, Observation, Source};

use xfs::{BmbtRec, Inode, Superblock, XfsTimestamp};

// ── F3: structural-integrity anomaly kinds ───────────────────────────────────

/// Classification of an XFS structural-integrity anomaly (F3). Each variant
/// carries the evidence needed to reproduce the observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// A v5 self-describing metadata block whose stored CRC32c does not verify
    /// over its buffer — corruption or post-write tampering.
    CrcMismatch {
        /// The metadata structure that failed (`superblock`, `AGI`, `AGF`,
        /// `inode`, …).
        structure: &'static str,
        /// Absolute byte offset of the block in the image.
        offset: u64,
    },
    /// A secondary superblock (AG 1..n) whose geometry differs from the AG-0
    /// primary — consistent with a spliced/edited image.
    SbMirrorDivergence {
        /// The allocation group whose secondary SB diverged.
        agno: u64,
        /// The geometry field that differs (e.g. `agblocks`).
        field: &'static str,
        /// The primary AG-0 value.
        primary: u64,
        /// The secondary (diverging) value.
        secondary: u64,
        /// Absolute byte offset of the secondary superblock.
        offset: u64,
    },
    /// A non-null entry in an AGI `agi_unlinked[64]` bucket — an inode unlinked
    /// while still open (orphaned-but-live), a recovery lead.
    OrphanedInode {
        /// The allocation group whose AGI carried the entry.
        agno: u64,
        /// The `unlinked[64]` bucket index (`0..64`).
        bucket: usize,
        /// The AG-relative inode number the bucket points at.
        agino: u32,
    },
    /// A geometry field beyond sane bounds relative to the image size — an
    /// allocation-bomb / corruption guard.
    ImpossibleGeometry {
        /// The offending field name.
        field: &'static str,
        /// The value read from the structure.
        value: u64,
        /// The sane upper bound derived from the image size / spec.
        limit: u64,
    },
}

impl AnomalyKind {
    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::CrcMismatch { .. }
            | AnomalyKind::SbMirrorDivergence { .. }
            | AnomalyKind::ImpossibleGeometry { .. } => Severity::High,
            AnomalyKind::OrphanedInode { .. } => Severity::Medium,
        }
    }

    /// Stable machine-readable, scheme-prefixed code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::CrcMismatch { .. } => "XFS-CRC-MISMATCH",
            AnomalyKind::SbMirrorDivergence { .. } => "XFS-SB-MIRROR-DIVERGENCE",
            AnomalyKind::OrphanedInode { .. } => "XFS-ORPHANED-INODE",
            AnomalyKind::ImpossibleGeometry { .. } => "XFS-IMPOSSIBLE-GEOMETRY",
        }
    }

    /// Human-readable, "consistent with" note.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::CrcMismatch { structure, offset } => format!(
                "{structure} at byte {offset}: stored v5 CRC32c does not verify — consistent with corruption or post-write tampering"
            ),
            AnomalyKind::SbMirrorDivergence {
                agno,
                field,
                primary,
                secondary,
                ..
            } => format!(
                "AG {agno} secondary superblock: {field} = {secondary} differs from AG-0 primary {primary} — consistent with a spliced or edited image"
            ),
            AnomalyKind::OrphanedInode {
                agno,
                bucket,
                agino,
            } => format!(
                "AG {agno} AGI unlinked bucket {bucket} points at agino {agino} — an inode unlinked while still open (orphaned-but-live), a recovery lead"
            ),
            AnomalyKind::ImpossibleGeometry {
                field,
                value,
                limit,
            } => format!(
                "geometry field {field} = {value} exceeds the sane bound {limit} for this image — consistent with corruption or an allocation-bomb"
            ),
        }
    }

    fn evidence(&self) -> Vec<Evidence> {
        match self {
            AnomalyKind::CrcMismatch { structure, offset } => vec![Evidence {
                field: "structure".to_string(),
                value: (*structure).to_string(),
                location: Some(Location::ByteOffset(*offset)),
            }],
            AnomalyKind::SbMirrorDivergence {
                agno,
                field,
                primary,
                secondary,
                offset,
            } => vec![Evidence {
                field: (*field).to_string(),
                value: format!("AG{agno} secondary={secondary} vs primary={primary}"),
                location: Some(Location::ByteOffset(*offset)),
            }],
            AnomalyKind::OrphanedInode {
                agno,
                bucket,
                agino,
            } => vec![Evidence {
                field: "agi_unlinked".to_string(),
                value: format!("AG{agno} bucket[{bucket}] -> agino {agino}"),
                location: Some(Location::Other {
                    space: "xfs:agino".to_string(),
                    value: u64::from(*agino),
                }),
            }],
            AnomalyKind::ImpossibleGeometry {
                field,
                value,
                limit,
            } => vec![Evidence {
                field: (*field).to_string(),
                value: format!("{value} (limit {limit})"),
                location: None,
            }],
        }
    }
}

/// An XFS structural-integrity anomaly: an observation graded by severity, with
/// a stable code and note derived from its [`AnomalyKind`] so they cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly with its evidence.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind`.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn evidence(&self) -> Vec<Evidence> {
        self.kind.evidence()
    }
}

// ── F3: the image auditor ─────────────────────────────────────────────────────

/// Audit a whole XFS image for structural-integrity anomalies (F3): parse the
/// primary superblock, walk every AG, and check each of CRC validity, secondary
/// superblock divergence, orphaned inodes, and impossible geometry.
///
/// A clean image yields an empty vector. Malformed input never panics.
#[must_use]
pub fn audit_image(_image: &[u8]) -> Vec<Anomaly> {
    todo!("GREEN")
}

/// Audit an image and convert each F3 anomaly to a canonical [`Finding`] tagged
/// with `scope`.
#[must_use]
pub fn audit_findings(image: &[u8], scope: &str) -> Vec<Finding> {
    let source = Source {
        analyzer: "xfs-forensic".to_string(),
        scope: scope.to_string(),
        version: None,
    };
    audit_image(image)
        .iter()
        .map(|a| a.to_finding(source.clone()))
        .collect()
}

// ── F1: deleted-inode recovery ────────────────────────────────────────────────

/// A recovered deleted inode: a freed (`di_mode == 0`) inode whose residual
/// extent records survived the delete, so its content is carvable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedInode {
    /// The allocation group the inode lives in.
    pub agno: u64,
    /// The absolute inode number.
    pub inode_number: u64,
    /// The residual `xfs_bmbt_rec` extent records recovered from the freed
    /// inode's data fork (offset 176 v3 / 100 v2), which the delete did not zero.
    pub residual_extents: Vec<BmbtRec>,
    /// `di_ctime` — the deletion time (updated on unlink).
    pub ctime: XfsTimestamp,
    /// Estimated recoverable size (bytes) — the residual extents' block span.
    pub recovered_size_estimate: u64,
    /// The carved bytes, when the residual extents point within the image.
    pub carved: Vec<u8>,
}

/// Scan the inode space for deleted inodes with residual extent records (F1).
///
/// On delete XFS zeroes `di_mode`/`di_nlink`/`di_size`/`di_nblocks`/`di_nextents`
/// and increments the generation, but the extent records at the inode's data-fork
/// offset (176 v3 / 100 v2) survive. This scans for `di_mode == 0` inodes whose
/// data fork still holds non-zero residual extent records, decodes them, and
/// carves their bytes via the extent reader where the blocks are readable.
///
/// Malformed input never panics.
#[must_use]
pub fn recover_deleted(_image: &[u8], _sb: &Superblock) -> Vec<DeletedInode> {
    todo!("GREEN")
}

// Keep the `Inode` import used in the signatures for a later helper.
#[doc(hidden)]
pub fn _inode_marker(_i: &Inode) {}
