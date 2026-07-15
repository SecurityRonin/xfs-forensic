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

use xfs::{
    assemble_extents, Agf, Agi, BmbtRec, Inode, Superblock, XfsTimestamp, XFS_DINODE_MAGIC,
    XFS_SB_MAGIC,
};

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
pub fn audit_image(image: &[u8]) -> Vec<Anomaly> {
    let mut out = Vec::new();

    // Too small to hold a superblock, or not XFS: nothing to audit (never panic).
    if image.len() < 220 || be_u32(image, 0) != XFS_SB_MAGIC {
        return out;
    }

    // Sector size (`xfs_dsb.sb_sectsize` @102) locates the per-AG headers. Clamp an
    // absurd value so a corrupt field cannot mis-slice; a real image is unaffected.
    let raw_sect = usize::from(be_u16(image, 102));
    let sect = if raw_sect.is_power_of_two() && (512..=65536).contains(&raw_sect) {
        raw_sect
    } else {
        512
    };

    // Parse the primary superblock over EXACTLY its sector so its CRC covers the
    // sector — parsing over the whole image would CRC the whole image and mis-fire
    // `Some(false)` on a clean filesystem.
    let sb_end = sect.min(image.len());
    let Ok(sb) = Superblock::parse(&image[..sb_end]) else {
        return out; // cov:unreachable: magic + length already validated above
    };
    let is_v5 = sb.is_v5();

    if is_v5 && sb.crc_valid == Some(false) {
        out.push(Anomaly::new(AnomalyKind::CrcMismatch {
            structure: "superblock",
            offset: 0,
        }));
    }

    let bsize = u64::from(sb.blocksize);
    let agblocks = u64::from(sb.agblocks);
    let agcount = u64::from(sb.agcount);
    let ag_bytes = agblocks.saturating_mul(bsize);
    let image_len = image.len() as u64;

    // Impossible geometry: `agcount` so large the last AG's base lies past the
    // image (a spliced/corrupt count or an allocation-bomb); `agcount == 0` too.
    if agcount == 0 {
        out.push(Anomaly::new(AnomalyKind::ImpossibleGeometry {
            field: "agcount",
            value: 0,
            limit: 1,
        }));
    } else if ag_bytes > 0 {
        let last_base = agcount.saturating_sub(1).saturating_mul(ag_bytes);
        if last_base >= image_len {
            out.push(Anomaly::new(AnomalyKind::ImpossibleGeometry {
                field: "agcount",
                value: agcount,
                limit: image_len / ag_bytes + 1,
            }));
        }
    }

    // Walk each allocation group that actually fits in the image: check the
    // secondary superblock (CRC + geometry divergence), the AGF CRC, the AGI CRC,
    // and the AGI `unlinked[64]` orphan buckets. The loop stops at the first AG
    // whose base lies past the image, so an absurd `agcount` cannot spin.
    if ag_bytes > 0 {
        for agno in 0..agcount {
            let base = agno.saturating_mul(ag_bytes);
            let base_us = usize::try_from(base).unwrap_or(usize::MAX);
            if base_us >= image.len() {
                break;
            }

            // Secondary superblock (AG 1..n): CRC + geometry divergence vs AG-0.
            if agno >= 1 {
                if let Some(slice) = image.get(base_us..base_us.saturating_add(sect)) {
                    if let Ok(sec) = Superblock::parse(slice) {
                        if is_v5 && sec.crc_valid == Some(false) {
                            out.push(Anomaly::new(AnomalyKind::CrcMismatch {
                                structure: "superblock",
                                offset: base,
                            }));
                        }
                        push_sb_divergence(&mut out, agno, base, &sb, &sec);
                    }
                }
            }

            // AGF at sector 1.
            let agf_off = base_us.saturating_add(sect);
            if let Some(slice) = image.get(agf_off..agf_off.saturating_add(sect)) {
                if let Ok(agf) = Agf::parse_verified(slice, is_v5) {
                    if agf.crc_valid == Some(false) {
                        out.push(Anomaly::new(AnomalyKind::CrcMismatch {
                            structure: "AGF",
                            offset: agf_off as u64,
                        }));
                    }
                }
            }

            // AGI at sector 2 — CRC + the `unlinked[64]` orphan buckets.
            let agi_off = base_us.saturating_add(sect.saturating_mul(2));
            if let Some(slice) = image.get(agi_off..agi_off.saturating_add(sect)) {
                if let Ok(agi) = Agi::parse_verified(slice, is_v5) {
                    if agi.crc_valid == Some(false) {
                        out.push(Anomaly::new(AnomalyKind::CrcMismatch {
                            structure: "AGI",
                            offset: agi_off as u64,
                        }));
                    }
                    for (bucket, &agino) in agi.unlinked.iter().enumerate() {
                        if agino != NULL_AGINO {
                            out.push(Anomaly::new(AnomalyKind::OrphanedInode {
                                agno,
                                bucket,
                                agino,
                            }));
                        }
                    }
                }
            }
        }
    }

    // Inode CRC sweep (v5 only — v4 inodes carry no CRC). A slot is a genuine
    // inode iff its `di_ino` self-reference equals the inode number its byte
    // offset decodes to; that filter keeps a stray `IN` in file data from
    // mis-flagging as a corrupt inode.
    if is_v5 {
        let inode_size = usize::from(sb.inodesize);
        if inode_size >= 176 {
            let mut off = 0usize;
            while off.saturating_add(inode_size) <= image.len() {
                if be_u16(image, off) == XFS_DINODE_MAGIC {
                    if let Some(slice) = image.get(off..off.saturating_add(inode_size)) {
                        if let Ok(inode) = Inode::parse(slice) {
                            if let Some((_, ino)) = offset_to_inode(&sb, off as u64) {
                                if inode.di_ino == Some(ino) && inode.crc_valid == Some(false) {
                                    out.push(Anomaly::new(AnomalyKind::CrcMismatch {
                                        structure: "inode",
                                        offset: off as u64,
                                    }));
                                }
                            }
                        }
                    }
                }
                off = off.saturating_add(inode_size);
            }
        }
    }

    out
}

/// Emit an [`AnomalyKind::SbMirrorDivergence`] for each geometry field of a
/// secondary superblock that differs from the AG-0 primary.
fn push_sb_divergence(
    out: &mut Vec<Anomaly>,
    agno: u64,
    offset: u64,
    primary: &Superblock,
    secondary: &Superblock,
) {
    let checks: [(&'static str, u64, u64); 4] = [
        (
            "agblocks",
            u64::from(primary.agblocks),
            u64::from(secondary.agblocks),
        ),
        (
            "agcount",
            u64::from(primary.agcount),
            u64::from(secondary.agcount),
        ),
        (
            "blocksize",
            u64::from(primary.blocksize),
            u64::from(secondary.blocksize),
        ),
        (
            "inodesize",
            u64::from(primary.inodesize),
            u64::from(secondary.inodesize),
        ),
    ];
    for (field, p, s) in checks {
        if p != s {
            out.push(Anomaly::new(AnomalyKind::SbMirrorDivergence {
                agno,
                field,
                primary: p,
                secondary: s,
                offset,
            }));
        }
    }
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
pub fn recover_deleted(image: &[u8], sb: &Superblock) -> Vec<DeletedInode> {
    let mut out = Vec::new();
    let inode_size = usize::from(sb.inodesize);
    let bsize = u64::from(sb.blocksize);
    // Need room for a v3 core + at least one 16-byte extent record in the fork,
    // and a non-zero block size to bound the extents.
    if inode_size < 176 || bsize == 0 {
        return out;
    }
    let total_blocks = image_len_blocks(image.len(), bsize);

    let mut off = 0usize;
    while off.saturating_add(inode_size) <= image.len() {
        let Some(slice) = image.get(off..off.saturating_add(inode_size)) else {
            break; // cov:unreachable: the while-guard already proved the range fits
        };
        if be_u16(slice, 0) == XFS_DINODE_MAGIC {
            if let Ok(inode) = Inode::parse(slice) {
                // A freed inode: `di_mode` is zeroed on unlink (as are nlink /
                // size / nblocks / nextents), but the extent records in the data
                // fork survive. v2 inodes carry no `di_ino` and no CRC; the minted
                // oracle is v5, so require v3 here.
                if inode.version >= 3 && inode.mode == 0 {
                    let residual = decode_residual(&inode.data_fork, total_blocks);
                    if !residual.is_empty() {
                        if let Some((agno, ino)) = offset_to_inode(sb, off as u64) {
                            let blocks: u64 = residual.iter().map(|e| e.blockcount).sum();
                            let recovered_size_estimate = blocks.saturating_mul(bsize);
                            let carved =
                                assemble_extents(image, sb, &residual, recovered_size_estimate)
                                    .unwrap_or_default();
                            out.push(DeletedInode {
                                agno,
                                inode_number: ino,
                                residual_extents: residual,
                                ctime: inode.ctime,
                                recovered_size_estimate,
                                carved,
                            });
                        }
                    }
                }
            }
        }
        off = off.saturating_add(inode_size);
    }
    out
}

// ── shared private helpers ────────────────────────────────────────────────────

/// Null sentinel for an empty AGI `unlinked[64]` bucket / null AG-relative inode.
const NULL_AGINO: u32 = 0xffff_ffff;

/// Total whole filesystem blocks an image can hold (`len / blocksize`); `0` when
/// the block size is degenerate. Used to reject an extent that points past the
/// image during residual-extent recovery.
fn image_len_blocks(len: usize, bsize: u64) -> u64 {
    if bsize == 0 {
        return 0; // cov:unreachable: callers guard bsize != 0 before calling
    }
    len as u64 / bsize
}

/// Decode residual `xfs_bmbt_rec` records from a freed inode's data fork.
///
/// A freed inode has `di_nextents == 0`, so the records cannot be counted from
/// the core; instead read consecutive 16-byte records until the first empty or
/// out-of-range one. A record is a real surviving extent iff it is non-zero, has
/// a positive block count, a non-zero start block (block 0 is the superblock,
/// never file data), and points within the image.
fn decode_residual(fork: &[u8], total_blocks: u64) -> Vec<BmbtRec> {
    let mut recs = Vec::new();
    let mut p = 0usize;
    while p.saturating_add(16) <= fork.len() {
        let Some(chunk) = fork.get(p..p.saturating_add(16)) else {
            break; // cov:unreachable: the while-guard already proved the range fits
        };
        let mut raw = [0u8; 16];
        raw.copy_from_slice(chunk);
        if raw == [0u8; 16] {
            break;
        }
        let rec = BmbtRec::unpack(&raw);
        if rec.blockcount == 0 || rec.startblock == 0 {
            break;
        }
        if rec.startblock.saturating_add(rec.blockcount) > total_blocks {
            break;
        }
        recs.push(rec);
        p = p.saturating_add(16);
    }
    recs
}

/// Reverse of [`Superblock::inode_to_location`]: map an absolute image byte
/// offset back to `(agno, inode_number)` using the superblock's geometry and
/// log2 shift fields. Returns `None` for degenerate geometry (a zero divisor or
/// a shift width ≥ 64), never panicking.
fn offset_to_inode(sb: &Superblock, off: u64) -> Option<(u64, u64)> {
    let bsize = u64::from(sb.blocksize);
    let agblocks = u64::from(sb.agblocks);
    let inode_size = u64::from(sb.inodesize);
    if bsize == 0 || agblocks == 0 || inode_size == 0 {
        return None; // cov:unreachable: a superblock parsed from a real image has nonzero geometry
    }
    let ag_bytes = agblocks.checked_mul(bsize)?;
    let agno = off / ag_bytes;
    let within = off % ag_bytes;
    let agblock = within / bsize;
    let slot = (within % bsize) / inode_size;
    let inopblog = u32::from(sb.inopblog);
    let agino_bits = u32::from(sb.agblklog) + inopblog;
    if inopblog >= 64 || agino_bits >= 64 {
        return None; // cov:unreachable: real XFS shift widths are far below 64
    }
    let agino = (agblock << inopblog) | slot;
    let ino = (agno << agino_bits) | agino;
    Some((agno, ino))
}

/// Bounds-checked big-endian `u16` read (yields `0` out of range). The analyzer
/// parses raw image bytes directly (the reader/analyzer split), so it carries
/// its own panic-free readers rather than reaching into the core's private ones.
fn be_u16(d: &[u8], o: usize) -> u16 {
    d.get(o..o.saturating_add(2))
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map_or(0, u16::from_be_bytes)
}

/// Bounds-checked big-endian `u32` read (yields `0` out of range).
fn be_u32(d: &[u8], o: usize) -> u32 {
    d.get(o..o.saturating_add(4))
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(0, u32::from_be_bytes)
}
