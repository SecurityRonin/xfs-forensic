# xfs-forensic — Design (Purpose & Scope)

This is the library design/intent doc for the `xfs-forensic` workspace. It is
**not a PRD**: the repo ships no binary an examiner runs — it is two library
crates linked by other fleet tools. For the decision rationale behind the choices
summarized here, see `docs/decisions/`.

## Purpose

Give the forensic fleet a pure-Rust, from-scratch **XFS** reader and a
severity-graded **anomaly auditor** over it, so an XFS volume's structure and
residue aggregate into the same `forensicnomicon::report` model as every other
container and filesystem layer.

XFS is the default filesystem of RHEL/CentOS/Rocky/Alma and common on Linux
servers, yet forensic tooling for it is thin — The Sleuth Kit builds shipped by
Debian/Ubuntu have **no XFS support** (`docs/PRECODE-GAPS.md` Gap 3). This
workspace fills that gap for the fleet.

## Users

- **Fleet orchestration** (`Issen`, `disk4n6`, `forensic-vfs-engine`) — consumes
  `xfs-core` as a filesystem reader (optionally via the `vfs` feature's
  `Arc<dyn FileSystem>` adapter) and `xfs-forensic`'s graded findings.
- **Third-party Rust developers** — depend on the lean `xfs-core` reader
  (imported as `xfs`) for read-only XFS parsing over any `&[u8]`.
- **Forensic examiners** (indirectly) — receive `XFS-*` findings and recovered
  deleted inodes through whichever fleet front-end wires this in.

## What it does

`xfs-core` (reader):

- Superblock + geometry for v4 (legacy) and v5 (self-describing) filesystems,
  including sparse-inode geometry.
- AGF / AGI / AGFL allocation-group headers (v4 + v5).
- Inode cores — v2 (100-byte) and v3 (176-byte), with 64-bit **bigtime**
  timestamp decoding.
- Extents — inline extent list and bmap-B+tree (`di_format = btree`) walk.
- All five directory formats — short-form, block, data, leaf, node — and
  slash-path resolution from the root inode (`read_by_path`).
- v5 CRC32c verification per block (v4 → `None`, no false positives).
- Optional `forensic_vfs::FileSystem` adapter behind the `vfs` feature.

`xfs-forensic` (auditor) — emits graded `report::Finding`s (each an *observation*,
"consistent with …"; the examiner draws conclusions):

| Code | Severity | Observes |
|---|---|---|
| `XFS-CRC-MISMATCH` | High | v5 metadata block whose stored crc32c does not verify |
| `XFS-SB-MIRROR-DIVERGENCE` | High | secondary superblock field differing from the AG-0 primary |
| `XFS-IMPOSSIBLE-GEOMETRY` | High | geometry field beyond what the image can hold (alloc-bomb guard) |
| `XFS-ORPHANED-INODE` | Medium | AGI `unlinked[64]` bucket pointing at a live inode |

Plus deleted-inode recovery (`recover_deleted`): freed (`di_mode == 0`) inodes
whose data fork still holds residual extent records are decoded and carved,
returning inode number, size, recovered content, and a sha256 recovery gate.

## Scope

- Read-only parsing and forensic auditing of on-disk XFS images over any byte
  source.
- v4 and v5 on-disk formats; the structures listed above.
- Anomaly detection framed as observations feeding `forensicnomicon::report`.

## Non-goals

- **No writing / repair / fsck** — read-only by construction.
- **No log (journal) replay** — on-disk state only.
- **No realtime-device or DAX-specific paths** beyond standard on-disk layout.
- **No front-end binary** — no CLI/GUI/MCP; front-ends live in the fleet
  (`disk4n6`, `Issen`). A debug harness, if any, does not make this product-tier.
- **No `unsafe`, no C bindings, no mmap** (ADR 0004).

## Validation approach

Correctness is tiered by *who authored the artifact and its answer key*
(fleet Evidence-Based Rigor); full detail in `docs/validation.md`.

- **Tier-1 (independent oracle, always-on):** the reader is validated against a
  genuine third-party image, `tests/data/xfs_dfvfs.raw` from log2timeline/dfvfs
  (Apache-2.0, 16 MiB, committed), whose ground truth comes from three
  independent oracles — `xfs_db` (xfsprogs), the Linux kernel's read-only mount,
  and `libfsxfs` (which uses this same image as its reference corpus). Runs in CI
  on every push. Its real-world sparse-inode geometry (`rootino = 11072`,
  single-AG) is a case no self-mint reproduced.
- **Tier-1 (env-gated):** the bigtime timestamp path against a second dfvfs image
  (`xfs_bigtime.raw`, `XFS_BIGTIME_ORACLE`).
- **Tier-2 (self-minted backstops):** our own `mkfs.xfs` images exercise
  directory shapes, btree-format files, v4/no-ftype variants, and deleted-inode
  recovery — fast regression scaffolding *beneath* the Tier-1 oracle, never the
  sole proof for a value-producing path.
- **Fuzzed:** one `cargo-fuzz` target per parsed structure plus a
  `fuzz_forensic` pipeline target; `fuzz.yml` builds every target per push and
  deep-fuzzes weekly.
