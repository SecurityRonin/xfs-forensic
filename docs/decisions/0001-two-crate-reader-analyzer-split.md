# 1. Two-crate reader/analyzer split (Pattern A workspace)

Date: 2026-07-24

Status: Accepted

## Context

XFS is a single filesystem format. The fleet's crate-structure standard
(`ronin-issen/CLAUDE.md`, "Crate-structure standard — reader/analyzer split")
prescribes, for every single-format repo, exactly two crates in one workspace
named `<x>-forensic`: a `core/` reader with no findings and a `forensic/`
analyzer that emits graded `forensicnomicon::report::Finding`s. The reference
implementation is `ntfs-forensic`; `vmdk`/`vhdx`/`ntfs`/`qcow2` are all migrated
to it.

The two concerns are genuinely different. `xfs-core` must read *valid* XFS
robustly and expose clean geometry, inodes, extents, and directories. The audit
must instead *see* residue the reader normalizes away — freed inodes, directory
slack, CRC-failed blocks — so it cannot be a thin wrapper over the reader's
happy path.

## Decision

Ship a single workspace repo `xfs-forensic` with two members
(`Cargo.toml` `members = ["core", "forensic"]`):

- `core/` → crate **`xfs-core`** — the pure reader (superblock, AG headers,
  inodes, extents, directories, v5 CRC), no findings.
- `forensic/` → crate **`xfs-forensic`** — the anomaly auditor: typed
  `AnomalyKind`/`Anomaly` + `audit_image` / `audit_findings` / `recover_deleted`,
  emitting `forensicnomicon::report::Finding` via `impl Observation`.

This is "Pattern A" from the fleet naming grammar: exactly two crates, no
umbrella crate, versioned independently (`xfs-core 0.1.5`, `xfs-forensic 0.1.2`).
Scaffolded in commit `650a9da` ("scaffold Pattern-A workspace").

## Consequences

- Third parties can depend on the lean `xfs-core` reader without pulling the
  forensic model (`forensicnomicon`) — the reader stays a reusable library core.
- The analyzer is free to parse raw bytes below the reader's API when the audit
  needs slack it hides (see ADR 0008).
- Two crates version and publish independently via release-plz, so a reader-only
  fix does not force an analyzer bump.
- Consumers of graded findings get the same `report::Finding` model every other
  fleet analyzer emits, so XFS anomalies aggregate uniformly with the partition
  and container layers.
