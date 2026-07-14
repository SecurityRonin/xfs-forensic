# Pre-Code Gap Findings (RESEARCH.md §4)

The three gaps flagged in `RESEARCH.md` as "close before coding" — resolved with
authoritative sources, not memory. Recorded here so P3 (bmbt) does not code the
highest-risk bit-split from recollection.

## Gap 1 — xfuse LICENSE

**BSD-2-Clause "Simplified" License** (SPDX `BSD-2-Clause`), file `LICENSE.md` on
the `main` branch of <https://github.com/KhaledEmaraDev/xfuse>. Confirmed via the
GitHub license API (`/repos/KhaledEmaraDev/xfuse/license` → `"spdx_id":
"BSD-2-Clause"`). Permissive and non-copyleft — compatible with using xfuse as a
**study/cross-check reference** alongside our Apache-2.0 fleet. We do not depend
on it (a FUSE binary, not a library core); we study its packing.

## Gap 2 — bmbt 16-byte record bit-field widths (VERBATIM)

The kernel HTML docs (`kernel.org/doc/html/latest/filesystems/xfs/`) currently
carry only 4 chapters (Maintainer Profile, Self-Describing Metadata, Online Fsck
Design) — **the on-disk-format "Data Extents" chapter is NOT there**; it lives in
the standalone SGI *XFS Algorithms & Data Structures* PDF (FlateDecode-compressed).
The authoritative, machine-checkable source is the kernel header
`fs/xfs/libxfs/xfs_format.h`. Verbatim:

```c
/*
 * Bmap btree record and extent descriptor.
 *  l0:63 is an extent flag (value 1 indicates non-normal).
 *  l0:9-62 are startoff.
 *  l0:0-8 and l1:21-63 are startblock.
 *  l1:0-20 are blockcount.
 */
#define BMBT_EXNTFLAG_BITLEN    1
#define BMBT_STARTOFF_BITLEN    54
#define BMBT_STARTBLOCK_BITLEN  52
#define BMBT_BLOCKCOUNT_BITLEN  21

typedef struct xfs_bmbt_rec { __be64 l0, l1; } xfs_bmbt_rec_t;
```

Source: <https://raw.githubusercontent.com/torvalds/linux/master/fs/xfs/libxfs/xfs_format.h>
(the file is GPL-2.0 — this is a **spec citation for field widths**, not a code copy).

**The trap (why this matters for P3):** the 52-bit `startblock` is SPLIT across
both 64-bit words — the top **9** bits are `l0:0-8`, the low **43** bits are
`l1:21-63`. Getting the split inverted "ships green" against a self-encoded
round-trip. P3 must validate every unpacked extent against `xfs_db bmap`
(oracle `v5.bmap_big.txt`: `data offset 0 startblock 24 (0/24) count 4096`).

Layout of the two big-endian u64s (bit 63 = MSB):

```
l0 = [ flag(1) | startoff(54) | startblock_hi(9) ]   bits 63 | 62..9 | 8..0
l1 = [ startblock_lo(43) | blockcount(21) ]           bits 63..21 | 20..0
startblock(52) = (startblock_hi << 43) | startblock_lo
```

## Gap 3 — TSK XFS coverage on the minted image

**TSK 4.12.1 (Ubuntu 24.04 `sleuthkit` package) has NO XFS support.** `fsstat`
and `fls -r` both fail on the minted v5 and v4 images:

- v5.img → `Possible encryption detected (High entropy (8.00))` then failure.
- v4.img → `Cannot determine file system type`.
- `fsstat -f xfs v5.img` → `Unsupported file system type: xfs`.
- `fsstat -f list` does **not** list `xfs` (ntfs/fat/ext/iso9660/hfs/apfs/ufs/…
  only). The Debian/Ubuntu build is compiled without the XFS module.

**Consequence:** the Tier-1 structural oracle set is **`xfs_db` + `xfs_info` +
`mount -o ro`/`sha256sum`** — still three independent oracles, none ours, but
**minus TSK** on this host. To use TSK as the cross-impl reader later, build TSK
from source with XFS enabled (or use a distro that ships it). The failed TSK
outputs are committed verbatim (`v5.fls.txt`, `v5.fsstat.txt`, v4 equivalents) as
the evidence of this gap.
