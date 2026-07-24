# 2. Build a from-scratch XFS reader rather than reuse an existing crate

Date: 2026-07-24

Status: Accepted

## Context

The research-first survey (`docs/RESEARCH.md` §2, "Existing implementations
(build-vs-reuse)") found real Rust XFS readers before any code was written:

- **`xfuse`** (`xfs-fuse`, Khaled Emara) — the most mature Rust XFS reader
  (~14k downloads, active 2026), but a FUSE *binary* built on `fuser`, not a
  library core. BSD-2-Clause (confirmed via the GitHub license API, recorded in
  `docs/PRECODE-GAPS.md` Gap 1).
- **`lamxfs`** (Lamco) — clean-room, `no_std`, read-only, MIT/Apache-2.0, but
  v0.1.0 and likely narrow (boot-path only).

The fleet's build-vs-reuse discipline requires this survey, and its dependency
policy ("prefer our own crates"; "no crate is a forensic-grade library core")
biases toward building when no existing crate meets the forensic bar — a reader
that must expose slack, malformed structure, and per-block CRC state, not just
"what files are here."

## Decision

Build our own `xfs-core` from scratch, per the RESEARCH.md §2 recommendation
("build our own `xfs-core`"). Study `xfuse` (most complete) and `lamxfs`
(cleanest, permissive) for on-disk packing but depend on neither. Cross-check
every parsed structure against `xfs_db` + TSK oracles rather than trusting a
third-party reader.

Reuse is confined to genuinely-solved leaf primitives: the `crc` crate for v5
CRC32c (ADR 0006) and `thiserror` for error plumbing.

## Consequences

- Full control over exposing forensic detail a happy-path reader hides, which
  ADR 0001's analyzer split depends on.
- `xfuse`/`lamxfs` remain independent cross-check references, not dependencies —
  a compromised or narrow upstream cannot regress the reader.
- The cost is reimplementing the whole on-disk format (superblock, AG headers,
  v2/v3 inodes, inline + bmap-B+tree extents, five directory shapes), carried by
  the phased P0–P6 build order in RESEARCH.md §4 and the git history.
- Highest-risk bit-splits (the bmbt 52-bit startblock split across two words)
  were resolved from the authoritative kernel header, not memory
  (`docs/PRECODE-GAPS.md` Gap 2), and validated against `xfs_db bmap`.
