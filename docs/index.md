# xfs-forensic

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

`audit_findings` parses the superblock, AG headers, and inode residue in place and grades what it finds. A structurally invalid image yields no findings (corruption is surfaced as its own finding, never a panic).

## The anomaly codes

Each finding is an **observation** ("consistent with …"); the examiner draws the conclusions. Codes are a stable, published contract.

| Code | Severity | What it observes |
|---|---|---|
| `XFS-CRC-MISMATCH` | High | A v5 self-describing metadata block whose stored crc32c does not verify — consistent with corruption or post-write tampering |
| `XFS-SB-MIRROR-DIVERGENCE` | High | A secondary (per-AG) superblock field that differs from the AG-0 primary — consistent with a spliced or edited image |
| `XFS-IMPOSSIBLE-GEOMETRY` | High | A geometry field beyond what the image can hold — an allocation-bomb / corruption guard |
| `XFS-ORPHANED-INODE` | Medium | An AGI `unlinked[64]` bucket pointing at a live inode — unlinked while still open (orphaned-but-live), a recovery lead |

Deleted-inode recovery is separate: `recover_deleted(&image, &sb)` scans for freed (`di_mode == 0`) inodes whose data fork still holds residual extent records, decodes them, and carves each `DeletedInode`'s bytes from the readable blocks.

## The reader: navigate an image

`xfs-core` (imported as `xfs`) reads an XFS image over any byte slice:

```rust
use xfs::{Superblock, read_by_path};

let sb = Superblock::parse(&image[0..512])?;
let bytes = read_by_path(&image, &sb, "etc/hostname")?;
# Ok::<(), xfs::XfsError>(())
```

The bare crate name `xfs` on crates.io is an abandoned 2016 perf-data parser unrelated to the filesystem, so this on-disk reader publishes as `xfs-core` and imports as `xfs`.

## Trust but verify

- **`#![forbid(unsafe_code)]`** in both crates — no `unsafe`, no C bindings.
- **Panic-free** — every integer/length/offset field is read through bounds-checked big-endian helpers; a malformed image degrades to an empty/typed result, never a panic.
- **Fuzzed** — one `cargo-fuzz` target per parsed structure (superblock, agheaders, inode, extent, btree, dir, crc) plus a `fuzz_forensic` target driving the full `audit_image` / `recover_deleted` pipeline. See [Validation](validation.md).
- **Tier-1 validated** — the reader is checked against a real third-party XFS image (log2timeline/dfvfs `xfs.raw`, Apache-2.0), with ground truth from `xfs_db`, the Linux kernel mount, and `libfsxfs` — implementations wholly separate from ours. See [Validation](validation.md).

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd.
