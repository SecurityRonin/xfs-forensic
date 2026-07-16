# xfs-forensic

[![xfs-core](https://img.shields.io/crates/v/xfs-core.svg?label=xfs-core)](https://crates.io/crates/xfs-core)
[![xfs-forensic](https://img.shields.io/crates/v/xfs-forensic.svg?label=xfs-forensic)](https://crates.io/crates/xfs-forensic)
[![Docs.rs](https://img.shields.io/docsrs/xfs-forensic?label=docs.rs)](https://docs.rs/xfs-forensic)
[![Rust 1.83+](https://img.shields.io/badge/rust-1.83%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/xfs-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/xfs-forensic/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25%20lines-brightgreen.svg)](https://securityronin.github.io/xfs-forensic/validation/)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![Security audit](https://img.shields.io/badge/security-cargo--deny-brightgreen.svg)](deny.toml)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://securityronin.github.io/xfs-forensic/)

**A from-scratch XFS reader and a graded anomaly auditor — walk the superblock, allocation-group headers, inodes, extents (inline and bmap-B+tree), and the five directory formats of an XFS image over any byte source, then turn its residue into evidence: v5 CRC-mismatched metadata, secondary-superblock divergence, AGI-unlinked orphaned inodes, and deleted inodes still carvable from their surviving residual extent records.**

Two crates, one workspace:

- **[`xfs-core`](https://crates.io/crates/xfs-core)** — the reader (imported as `xfs`): superblock + geometry, AGF / AGI / AGFL headers, inode cores (v2 100-byte / v3 176-byte, bigtime timestamps), inline and bmap-B+tree extents, short-form / block / data / leaf directories, and v5 CRC32c verification, over any byte slice. No `unsafe`, no C bindings.
- **[`xfs-forensic`](https://crates.io/crates/xfs-forensic)** — the auditor: turns parsed XFS structures into severity-graded [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)s, and recovers deleted inodes, so an XFS volume's anomalies aggregate uniformly with the partition and container layers.

## Audit an XFS image in 30 seconds

```toml
[dependencies]
xfs-forensic = "0.1"   # pulls in xfs-core
```

```rust
use xfs_forensic::audit_findings;

// Feed it the raw image bytes; get back graded findings.
for finding in audit_findings(&image_bytes, "xfs") {
    println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
    // e.g. [Some(High)] XFS-SB-MIRROR-DIVERGENCE — AG 2 secondary superblock: agcount …
}
```

`audit_findings` parses the superblock, AG headers, and inode residue in place and grades what it finds. A structurally invalid image yields no findings (corruption is surfaced as its own finding, never a panic). For the typed form, `audit_image(&image)` returns `Vec<Anomaly>` — each `anomaly.to_finding(source)` converts to a `report::Finding`.

## The anomaly codes

Each finding is an **observation** ("consistent with …"); the examiner draws the conclusions. Codes are a stable, published contract.

| Code | Severity | What it observes |
|---|---|---|
| `XFS-CRC-MISMATCH` | High | A v5 self-describing metadata block whose stored crc32c does not verify — consistent with corruption or post-write tampering |
| `XFS-SB-MIRROR-DIVERGENCE` | High | A secondary (per-AG) superblock field that differs from the AG-0 primary — consistent with a spliced or edited image |
| `XFS-IMPOSSIBLE-GEOMETRY` | High | A geometry field beyond what the image can hold — an allocation-bomb / corruption guard |
| `XFS-ORPHANED-INODE` | Medium | An AGI `unlinked[64]` bucket pointing at a live inode — unlinked while still open (orphaned-but-live), a recovery lead |

Deleted-inode recovery is separate: `recover_deleted(&image, &sb)` scans for freed (`di_mode == 0`) inodes whose data fork still holds non-zero residual extent records, decodes them, and returns each carved `DeletedInode` — inode number, size, the recovered content, and the content's sha256 recovery gate.

## The reader: navigate an image

`xfs-core` (imported as `xfs`) reads an XFS image over any byte slice:

```rust
use xfs::{Superblock, read_by_path};

// The primary superblock lives at physical offset 0; parse its geometry, then
// resolve a slash-separated path from the root inode to its file bytes,
// walking short-form / block / leaf directories and inline / btree extents.
let sb = Superblock::parse(&image[0..512])?;
let bytes = read_by_path(&image, &sb, "etc/hostname")?;
# Ok::<(), xfs::XfsError>(())
```

The bare crate name `xfs` on crates.io is an abandoned 2016 perf-data parser unrelated to the filesystem, so this on-disk reader publishes as `xfs-core` and takes the import path `xfs`.

## What makes this different from a general-purpose XFS crate

Most XFS crates answer one question: "what files are on this volume?" This workspace answers the questions a digital forensics examiner actually needs:

| Capability | General-purpose XFS crate | this workspace |
|---|---|---|
| Superblock + geometry (v4 and v5) | ✅ | ✅ |
| AGF / AGI / AGFL allocation-group headers | ✅ | ✅ |
| Inode cores — v2 (100-byte) / v3 (176-byte) | ✅ | ✅ |
| bigtime (64-bit) timestamp decoding | partial | ✅ |
| Inline extent list → file content | ✅ | ✅ |
| bmap-B+tree (`di_format = btree`) extent walk | partial | ✅ |
| Short-form / block / data / leaf directory formats | ✅ | ✅ |
| v5 CRC32c metadata verification (per block) | — | ✅ |
| Secondary-superblock divergence detection (splice tell) | — | ✅ |
| Orphaned-inode (AGI `unlinked[64]`) enumeration | — | ✅ |
| Deleted-inode recovery from surviving residual extents | — | ✅ |
| Impossible-geometry / allocation-bomb guards | — | ✅ |
| Severity-graded `report::Finding` output | — | ✅ |
| `#![forbid(unsafe_code)]` | — | ✅ |

## Trust but verify

- **`#![forbid(unsafe_code)]`** in both crates — no `unsafe`, no C bindings.
- **Panic-free** — every integer / length / offset field is read through bounds-checked big-endian helpers; a malformed image degrades to an empty or typed result, never a panic.
- **Fuzzed** — one `cargo-fuzz` target per parsed structure (`superblock`, `agheaders`, `inode`, `extent`, `btree`, `dir`, `crc`) plus a `fuzz_forensic` target driving the full `audit_image` / `recover_deleted` pipeline. `fuzz.yml` builds every target on each push and deep-fuzzes each for 10 minutes weekly.
- **Tier-1 validated** — the reader is checked against a real third-party XFS filesystem, log2timeline/dfvfs's `xfs.raw` (Apache-2.0), whose ground truth comes from three implementations wholly separate from ours: `xfs_db` (xfsprogs), the Linux kernel's own read-only mount, and `libfsxfs` (which uses this same image as its reference corpus). See [`docs/validation.md`](https://securityronin.github.io/xfs-forensic/validation/).

## Reader API (`xfs-core`)

| Item | Purpose |
|---|---|
| `Superblock::parse` / `inode_to_location` / `read_inode` | Superblock geometry, inode-number → (AG, block, offset), inode read |
| `Agf::parse` / `Agi::parse` / `Agfl::parse_v5` | Allocation-group free-space / inode / free-list headers (v4 + v5) |
| `Inode::parse` | On-disk inode core, format, timestamps (incl. bigtime), fork offset |
| `read_extents` / `read_file_from_fork` / `assemble_extents` | Inline extent list → file bytes (holes zero-filled, size-truncated) |
| `read_btree_extents` | bmap-B+tree (`di_format = btree`) extent walk |
| `read_shortform_dir` / `read_block_dir` / `read_data_dir_block` / `read_by_path` | Directory decode across all shapes + path resolution |
| `crc_status` / `verify_crc` / `verify_dir_block_crc` / `verify_bmbt_block_crc` | v5 CRC32c verification (v4 → `None`, no false positives) |

## Optional `vfs` feature (forensic-vfs adapter)

Enable the `vfs` feature to get `impl forensic_vfs::FileSystem for XfsFs` — an XFS
volume composes as `Arc<dyn FileSystem>` in the [forensic-vfs](https://crates.io/crates/forensic-vfs)
engine (single fs-agnostic navigation across any container + partition + FS stack).
Opt-in, so the bare reader stays dependency-light:

```toml
xfs-core = { version = "0.1", features = ["vfs"] }   # pulls forensic-vfs 0.2
```

---

[Privacy Policy](https://securityronin.github.io/xfs-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/xfs-forensic/terms/) · © 2026 Security Ronin Ltd
