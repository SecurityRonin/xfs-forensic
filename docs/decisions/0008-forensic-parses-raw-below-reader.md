# 8. The analyzer parses raw bytes below the reader's API where the audit needs slack

Date: 2026-07-24

Status: Accepted

## Context

The fleet crate-structure standard states the binding design principle that
`<x>-forensic` is *not required* to depend only on `<x>-core`: a `-core` reader
is built to read *valid* data robustly, so it abstracts away exactly the detail
a forensic auditor must see — slack between records, deleted/overwritten regions,
malformed fields a robust reader normalizes or skips, checksums it
verifies-and-discards. The standard names `ntfs-forensic` as the model that takes
raw bytes directly so it can see records the reader would reject, and flags XFS
as a strong candidate for the same treatment.

The XFS anomalies this repo targets are precisely of that kind:
deleted-inode recovery reads extent records surviving in inode slack after
`di_mode`/`nextents` are zeroed; directory-slack residue reads freed dirents that
keep their inode number; secondary-superblock divergence compares raw per-AG
copies. A happy-path reader would normalize or drop all three.

## Decision

`xfs-forensic` depends on `xfs-core` for valid-path reading and reuse of its
parsed types (`Superblock`, `Inode`, `BmbtRec`, `assemble_extents`, …), but where
the audit must see structure the reader normalizes away it parses the raw image
bytes directly, keying off `forensicnomicon` format constants (`XFS_SB_MAGIC`,
`XFS_DINODE_MAGIC`).

This is stated in the `forensic/src/lib.rs` module doc: "Built on `xfs-core` for
valid-path reading; where the audit must see slack and malformed structure the
reader normalizes away, it parses the raw bytes directly (the
reader/analyzer-split principle)." Implemented in the F1 (deleted-inode
recovery) and F3 (structural-integrity) paths (commits `b586adf`/`68a64c5`,
`85ff575`).

## Consequences

- The auditor can surface residue a reader-API-only analyzer would never see —
  the whole point of a forensic layer.
- It carries some duplicate low-level parsing (raw inode/superblock field reads)
  rather than routing everything through `xfs-core`; this is the accepted cost of
  seeing the un-normalized structure, exactly as `ntfs-forensic` does.
- Both crates share the same bounds-checked, panic-free posture (ADR 0004), so
  raw-byte parsing in the analyzer is no less safe than in the reader.
