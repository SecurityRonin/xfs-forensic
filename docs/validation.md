# Validation

How `xfs-core` (and the `xfs-forensic` auditor over it) is proven correct, and at
what evidentiary tier. The axis is **who authored the artifact and its answer
key** — not whether the data is "synthetic" — following the fleet's
Evidence-Based Rigor discipline.

## Summary

- **Tier-1 (independent oracle, always-on):** the reader is validated against a
  genuine third-party XFS image, `tests/data/xfs_dfvfs.raw`, whose ground truth
  comes from three independent oracles (`xfs_db`, the Linux kernel mount, and —
  by construction — `libfsxfs`, which uses this same image). Neither the image
  nor its answer key was authored by us. This test is committed and runs in CI
  on every push (not env-gated).
- **Tier-1 (independent oracle, env-gated):** the bigtime timestamp path is
  validated against a second dfvfs image, `xfs-bigtime.raw` (gitignored,
  `XFS_BIGTIME_ORACLE`).
- **Tier-2 (self-minted regression backstops):** our own `mkfs.xfs` images
  (`v5.img`, `v4.img`, `v4dir.img`, `v5frag.img`, `del.img`) exercise directory
  shapes, btree-format files, v4/no-ftype variants, and deleted-inode recovery.
  These are **not Tier-1**: we authored both the fixture and the expected answer,
  so they inherit our blind spots. They sit *beneath* the Tier-1 image as
  fast, deterministic regression scaffolding, cross-checked at mint time against
  `xfs_db`/`xfs_info`/`mount -o ro` but not authored by an independent party.

Self-minted ≠ Tier-1. The distinction is load-bearing: our self-mint only ever
produced `rootino = 128` with `agcount = 4`; the dfvfs image's real-world
sparse-inode geometry (`rootino = 11072`, `agcount = 1`, `agblklog = 12`) is a
quirk no self-mint here reproduced, and it is exactly the kind of case a Tier-1
image exists to catch.

## Tier-1 — dfvfs `xfs.raw` (third-party, Apache-2.0)

**Source.** `test_data/xfs.raw` from
[log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) (Joachim Metz),
Apache-2.0 — committed here as `tests/data/xfs_dfvfs.raw` (16 MiB, md5
`5578c5c54ec8055243a40ada1f4d8836`). This is the image `libfsxfs` uses as its
own reference corpus, so an independent, widely-used implementation already
agrees on its contents.

**Oracles (all independent of our reader and of each other).**

| Oracle | What it establishes |
|---|---|
| `xfs_db -r -c 'sb 0' -c print` (xfsprogs 6.6.0) | superblock geometry — magic, blocksize, inodesize, versionnum, rootino, agblocks, agcount, log2 shifts |
| `xfs_db -r -c 'inode N' -c print` | inode cores, short-form directory entries, extent maps |
| `mount -o ro,loop` + `ls -iR` + `sha256sum` | the Linux kernel's own directory walk and file-content hashes — a wholly separate implementation from `xfs_db` |

**Ground truth captured** (verbatim in `tests/data/README.md`):

- Superblock: magic `0x58465342`, blocksize 4096, inodesize 512, versionnum
  `0xb4b5` (v5), **rootino 11072**, agblocks 4096, agcount 1, agblklog 12,
  inopblog 3, `sb_crc = 0x7a195fb4 (correct)`.
- Root (inode 11072, short-form dir): `a_directory` → 11075 (dir),
  `passwords.txt` → 11077 (file), `a_link` → 11079 (symlink →
  `a_directory/another_file`).
- `a_directory` (11075): `a_file` → 11076, `another_file` → 11078.
- `passwords.txt` (11077): size 116, single extent (startblock 1379, count 1),
  carries a `security.selinux` attribute fork; sha256
  `02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252`.
- `a_directory/another_file` sha256
  `c7fbc0e821c0871805a99584c6a384533909f68a6bbe9a2a687d28d9f3b10c16`.

**Test** — `core/tests/tier1_dfvfs.rs` (always-on). It asserts:

1. `Superblock::parse` fields == the `xfs_db sb 0` values (incl. v5 `sb_crc`
   verifying over the sector).
2. `read_dir(root)` names + inode numbers + ftype bytes == the kernel `ls -i`.
3. The nested `a_directory/` listing == the kernel `ls -i`.
4. `read_by_path("/passwords.txt")` and `/a_directory/another_file` bytes hash
   to the kernel `sha256sum`.
5. `inode_to_location(11072)` lands on the byte offset the sparse-inode geometry
   dictates, and the parsed inode's `di_ino` self-reference matches.

**Run command.** This image is **committed** (excluded from the crate tarball
via `exclude` / `.gitignore` rules), so a clean clone already has it — no
download needed:

```bash
cargo test -p xfs-core --test tier1_dfvfs
```

**Result.** All assertions pass: `xfs-core` reads the real third-party image
correctly on the first pass. The `rootino = 11072`, `agblklog = 12`,
single-AG geometry — which our self-mint never produced — decodes correctly, so
no reader change was required. This is a "validates existing code" result, not a
bug fix.

## Tier-1 (env-gated) — bigtime timestamps

**Source.** `test_data/xfs_bigtime.raw` from log2timeline/dfvfs (Apache-2.0),
16 MiB, md5 `390e15e9bb523662e2037ea4c86d9193`. A v5 image whose every inode
uses the 64-bit **bigtime** timestamp counter (`sec = raw/1e9 - 2^31`) instead
of the legacy `(sec:i32, nsec:i32)` packing.

**Not committed.** One committed 16 MiB image is enough; a second would bloat the
repo. This one is gitignored and env-gated on `XFS_BIGTIME_ORACLE`
(`tests/data/README.md` documents where to fetch it). CI without it stays green.

**Ground truth** (`TZ=UTC xfs_db -r -c 'inode 16128' -c print`): rootino 16128,
root inode `v3.bigtime = 1`; mtime = 2026-07-01 13:32:33 UTC = epoch
1 782 912 753, nsec 497 950 218; crtime = same second, nsec 68 099 000.

**Test** — `core/tests/bigtime_dfvfs.rs`. Asserts the reader takes the bigtime
branch (BIGTIME bit set) and decodes mtime/crtime to the exact UTC epoch the
oracle reports. A legacy decode of the same raw `__be64` would yield a wildly
different value, so this pins the bigtime math specifically. Passes with the
image present, skips cleanly without.

**Run command** (after downloading the image to any path):

```bash
XFS_BIGTIME_ORACLE=/abs/path/to/xfs-bigtime.raw \
  cargo test -p xfs-core --test bigtime_dfvfs
```

## Reproduce Tier-1 from a clean clone

Both Tier-1 checks below run from a fresh `git clone` with no local corpus of
your own.

1. **`xfs_dfvfs.raw` (always-on, committed).** Already present in the clone.
   Verify + run:
   ```bash
   md5 tests/data/xfs_dfvfs.raw      # == 5578c5c54ec8055243a40ada1f4d8836
   cargo test -p xfs-core --test tier1_dfvfs
   ```
2. **`xfs-bigtime.raw` (env-gated, not committed).** Download, verify, run:
   ```bash
   curl -L -o /tmp/xfs-bigtime.raw \
     https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data/xfs_bigtime.raw
   md5 /tmp/xfs-bigtime.raw          # == 390e15e9bb523662e2037ea4c86d9193
   XFS_BIGTIME_ORACLE=/tmp/xfs-bigtime.raw \
     cargo test -p xfs-core --test bigtime_dfvfs
   ```

Both images are dfvfs `test_data`, Apache-2.0 (freely redistributable);
`xfs_dfvfs.raw` is committed because 16 MiB is acceptable, the second is
gitignored to avoid doubling that.

## Tier-2 — self-minted regression backstops

Minted on a controlled Linux VM (`mkfs.xfs`, xfsprogs) and cross-checked at mint
time against `xfs_db` / `xfs_info` / `mount -o ro` + `sha256sum`. Provenance and
verbatim mint commands are in `tests/data/README.md`. These are env-gated (the
512 MiB `.img` files are gitignored) and cover:

- `v5.img` / `v4.img` — superblock, AG headers, inode cores, the three directory
  shapes (short-form, block, leaf), multi-extent files.
- `v4dir.img` — a genuine no-ftype short-form directory (`sfdir2`).
- `v5frag.img` — a `btree`-format (`di_format = 3`) file with 700 single-block
  extents; the reconstructed content sha256 is the walk-completeness gate.
- `del.img` / `v5del.freed_inode.bin` — the **deleted-inode recovery** oracle:
  a freed extent-format inode with zeroed `nextents` but a surviving residual
  extent record; carving the physical blocks reproduces the original file's
  sha256. Consumed by `xfs-forensic`'s F1 tests.

They remain valuable as fast, deterministic CI regression scaffolding, but their
correctness is defined by fixtures we authored, so they never stand alone as the
sole proof for a value-producing path — the dfvfs Tier-1 image is the
independent oracle above them.
