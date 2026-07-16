# XFS Forensic Test Data — Provenance

Two classes of fixture live here, at two different evidentiary tiers (see
[`../../docs/validation.md`](../../docs/validation.md) for the full story):

- **REAL-ext Tier-1** — a genuine third-party image, `xfs_dfvfs.raw` (from
  log2timeline/dfvfs, Apache-2.0), whose answer key comes from oracles we did
  not author. This is the load-bearing correctness proof; it is committed and
  its test is always-on.
- **REAL-self Tier-2** — our own `mkfs.xfs` images, minted on a controlled Linux
  VM and cross-checked at mint time against `xfs_db` / `xfs_info` / `mount -o ro`
  + `sha256sum`. These are regression backstops; **self-minted ≠ Tier-1** (we
  authored both the fixture and the expected answer, so they inherit our blind
  spots). The 512 MiB `.img` files are gitignored — only the oracle **text
  outputs** are committed; re-mint from the verbatim commands to reproduce them.

See the fleet catalog at
[`issen/docs/corpus-catalog.md`](../../../issen/docs/corpus-catalog.md) for the
machine index; this README is the co-located human detail.

<!-- TODO(corpus-catalog): add a REAL-ext row for tests/data/xfs_dfvfs.raw
     (dfvfs XFS Tier-1, Apache-2.0, md5 5578c5c54ec8055243a40ada1f4d8836) and a
     gitignored row for xfs-bigtime.raw (md5 390e15e9bb523662e2037ea4c86d9193)
     to issen/docs/corpus-catalog.md. NOT done here — the issen repo is held by
     another session; add it there when that session is free. -->

## REAL-ext Tier-1 — dfvfs `xfs_dfvfs.raw` (committed, always-on)

**The genuine third-party Tier-1 image.** `test_data/xfs.raw` from
[log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) (Joachim Metz),
committed verbatim as `xfs_dfvfs.raw`. This is the image `libfsxfs` uses as its
own oracle, so an independent widely-used implementation already agrees on its
contents.

- **Source:** <https://github.com/log2timeline/dfvfs> — `test_data/xfs.raw`.
- **Download URL:**
  <https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data/xfs.raw>
- **Size / md5:** 16 MiB (16 777 216 bytes) / `5578c5c54ec8055243a40ada1f4d8836`.
- **Redistribution:** Apache-2.0 (dfvfs' license) — committable; committed here.
- **Consumed by:** `core/tests/tier1_dfvfs.rs` (always-on, not env-gated) — the
  primary correctness gate. Also documented in `docs/validation.md`.

**Ground truth — `xfs_db -r -c 'sb 0' -c print` (xfsprogs 6.6.0):**

```
magicnum = 0x58465342   blocksize = 4096    inodesize = 512    inopblock = 8
versionnum = 0xb4b5 (v5)   rootino = 11072   agblocks = 4096    agcount = 1
blocklog = 12   inodelog = 9   inopblog = 3   agblklog = 12
features_incompat = 0x3 (FTYPE|SPINODES)   spino_align = 4   crc = 0x7a195fb4 (correct)
```

Note `rootino = 11072`, **not** 128 — the sparse-inode geometry
(`spino_align`, `agcount = 1`, `agblklog = 12`) differs from our `mkfs.xfs`
self-mint (`rootino = 128`, `agcount = 4`). This is the real-world quirk the
Tier-1 image exists to exercise.

**Ground truth — directory tree + content (`xfs_db inode N print`, and the
independent `mount -o ro,loop` + `ls -iR` + `sha256sum` kernel oracle):**

| path | inode | kind (ftype) | notes |
|---|---|---|---|
| `/a_directory` | 11075 | dir (2) | short-form dir, 2 children |
| `/a_directory/a_file` | 11076 | file (1) | sha256 `4a49638d…0ec92d` |
| `/a_directory/another_file` | 11078 | file (1) | sha256 `c7fbc0e8…3b10c16` |
| `/passwords.txt` | 11077 | file (1) | size 116, extent [startblock 1379, count 1], has a `security.selinux` attr fork; sha256 `02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252` |
| `/a_link` | 11079 | symlink (7) | → `a_directory/another_file` |

`passwords.txt` content (kernel `cat`): a 5-row CSV led by the header
`place,user,password`.

## REAL-ext Tier-1 (env-gated) — dfvfs `xfs-bigtime.raw` (NOT committed)

The **bigtime timestamp** oracle — a v5 dfvfs image whose inodes carry
`XFS_DIFLAG2_BIGTIME`, so timestamps use the 64-bit post-2486 counter
(`sec = raw/1e9 - 2^31`) rather than the legacy `(sec:i32, nsec:i32)` packing.

- **Source / download URL:**
  <https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data/xfs_bigtime.raw>
- **Size / md5:** 16 MiB / `390e15e9bb523662e2037ea4c86d9193`.
- **Redistribution:** Apache-2.0.
- **Committed?** **No** — one committed 16 MiB image (`xfs_dfvfs.raw`) is enough;
  a second would bloat the repo. Gitignored (`/tests/data/xfs-bigtime.raw`) and
  **env-gated** on `XFS_BIGTIME_ORACLE` (absolute path to the downloaded file).
- **Consumed by:** `core/tests/bigtime_dfvfs.rs` — skips cleanly when the env var
  is unset.

**Ground truth (`TZ=UTC xfs_db -r -c 'inode 16128' -c print`):** rootino 16128,
versionnum `0xb4b5`; root inode `v3.bigtime = 1`, `di_flags2 = 0x18`;
mtime = 2026-07-01 13:32:33 UTC = epoch `1782912753`, nsec `497950218`;
crtime = same second, nsec `68099000`.

---

## REAL-self Tier-2 — self-minted `mkfs.xfs` regression backstops

The images below are **self-minted (Tier-2)** — minted on a controlled Linux VM
with `mkfs.xfs` and cross-checked at mint time against three oracles (`xfs_db`,
`xfs_info`, `mount -o ro` + `sha256sum`). They are regression backstops beneath
the Tier-1 dfvfs image above, never the sole proof for a value-producing path.
The two 512 MiB images (`v5.img`, `v4.img`) are **gitignored** — only the oracle
**text outputs** below are committed. Re-mint from the verbatim commands.

## Minting host

- Parallels VM `Ubuntu 24.04 (with Rosetta)`, `Linux 6.8.0-86-generic aarch64`.
- `xfsprogs` (`mkfs.xfs` / `xfs_db` / `xfs_info`), and `sleuthkit 4.12.1`.
- **`mkfs.xfs` on this host places `rootino = 128`** (not the historically-quoted
  64) because inode-alignment differs by geometry — the oracle value governs.
- **The short-form `ftype` byte tracks the filesystem's `ftype` FEATURE bit, not
  the v4/v5 version.** Modern `mkfs.xfs` enables `ftype` by default even on v4
  (`-m crc=0`) — the `v4.img` used by P0–P3 is such an image and its entries DO
  carry the ftype byte (`xfs_db` shows the `sfdir3` struct with `filetype`). A
  genuine no-ftype directory requires `mkfs.xfs -m crc=0 -n ftype=0`, captured
  below as `v4dir.img` (`xfs_db` shows the `sfdir2` struct with no `filetype`).
  The feature bit is read from the superblock: v5 uses
  `sb_features_incompat & 0x1` (FTYPE); v4 uses `sb_features2 & 0x200` (FTYPE).

## Verbatim mint + populate commands

```bash
cd /tmp && rm -rf xfs-oracle && mkdir xfs-oracle && cd xfs-oracle

# v5 (default: CRC + bigtime + ftype) — 512 MiB
truncate -s 512M v5.img
mkfs.xfs -f v5.img
xfs_info v5.img > v5.xfs_info.txt

# v4 (legacy, no CRC)
truncate -s 512M v4.img
mkfs.xfs -f -m crc=0 v4.img
xfs_info v4.img > v4.xfs_info.txt

# populate v5: the 3 key dir shapes + a multi-extent file + a deleted-file case
mkdir mnt && mount -o loop v5.img mnt
mkdir mnt/sf    && for i in 1 2 3; do echo "content-$i" > mnt/sf/file$i.txt; done       # short-form dir
mkdir mnt/block && for i in $(seq -w 1 40);   do echo x > mnt/block/e$i; done            # block dir
mkdir mnt/leaf  && for i in $(seq -w 1 2000); do :      > mnt/leaf/f$i; done             # leaf dir
dd if=/dev/urandom of=mnt/big.bin bs=1M count=16                                         # multi-extent file
sha256sum mnt/sf/file1.txt mnt/big.bin > content.sha256
echo "delete-me" > mnt/sf/DELETED_secret.txt
sync; rm mnt/sf/DELETED_secret.txt; sync                                                 # deleted-file case
umount mnt
```

### F1 deleted-inode recovery oracle (`v5del.*`) — Tier-2, self-minted

The `v5.img` `DELETED_secret.txt` case leaves **no** recoverable residue: it was a
10-byte inline (`Local`-format) file with no extents, and every other freed inode
slot on `v5.img` is a born-zeroed preallocated chunk (verified — 79 freed inodes,
none with residual data-fork bytes). A dedicated **extent-format** deletion case is
the proper F1 oracle, minted on Parallels "Ubuntu 24.04 (with Rosetta)":

```bash
dd if=/dev/zero of=del.img bs=1M count=512 status=none
mkfs.xfs -q -f del.img                                    # v5 default (crc=1 isize=512 agcount=4)
mount -o loop del.img mnt
python3 -c "import sys;sys.stdout.buffer.write((b'SECRET-XFS-DELETED-INODE-ORACLE-0123456789ABCDEF'*700)[:32768])" | tee mnt/keepme_control.bin >/dev/null  # ino 131 (control)
python3 -c "import sys;sys.stdout.buffer.write((b'DELETED-XFS-CARVE-TARGET-abcdef0123456789-!!!!!!'*700)[:32768])" | tee mnt/DELETED_target.bin >/dev/null  # ino 132 (deleted)
sync; rm mnt/DELETED_target.bin; sync; umount mnt
xfs_db -r del.img -c 'inode 132' -c 'print'               # post-delete: mode=0 size=0 nextents=0, bmx count 0
dd if=del.img bs=1 skip=$((132*512)) count=512 | base64    # -> v5del.freed_inode.bin (512 B, committed)
```

Ground truth (see `v5del.ground-truth.txt`): the freed inode 132 zeroes
`mode/size/nblocks/nextents` and increments `gen`, yet the raw 16-byte extent record
at inode **offset 176 survives verbatim** (`l1=0x04000008` → `startoff=0, startblock=32,
blockcount=8`). Carving physical blocks 32..40 reproduces the original
`DELETED_target.bin` sha256 `e34be105623327ff457b879a66d110ce877d3b754f0e1a704537598d42d61b98`.

| Fixture | Committed? | Use |
|---|---|---|
| `v5del.freed_inode.bin` (sha256 `3198a655…`) | yes (512 B) | residual-extent decode: freed inode with zeroed `nextents` but a surviving extent record |
| `v5del.ground-truth.txt` | yes | full mint procedure + xfs_db pre/post + carve hash |
| `del.img` (512 MiB, sha256 `98709b6e…`) | **no** (gitignored `*.img`) | env-gated carve-and-hash test via `XFS_DEL_ORACLE=/path/to/del.img` |

## Oracle capture commands (Tier-1 structural ground truth)

```bash
for v in v5 v4; do
  xfs_db -r $v.img -c 'sb 0'   -c 'print' > $v.sb0.txt
  xfs_db -r $v.img -c 'agi 0'  -c 'print' > $v.agi0.txt
  xfs_db -r $v.img -c 'agf 0'  -c 'print' > $v.agf0.txt
  xfs_db -r $v.img -c 'agfl 0' -c 'print' > $v.agfl0.txt
  xfs_db -r $v.img -c 'inode 64'  -c 'print' > $v.inode64.txt
  xfs_db -r $v.img -c 'inode 128' -c 'print' > $v.inode128.txt   # root dir inode (P2)
  fsstat $v.img > $v.fsstat.txt   # NOTE: TSK 4.12.1 (Ubuntu) has NO XFS support — fails
  fls -r $v.img > $v.fls.txt      #       both fsstat and fls fail (recorded verbatim)
done
# big.bin inode (135) — single-extent decode + bmap ground truth
xfs_db -r v5.img -c 'inode 135' -c 'print'                      > v5.inode_big.txt
xfs_db -r v5.img -c 'inode 135' -c 'bmap'                       > v5.bmap_big.txt
# file1.txt inode (132) — small single-extent file (10 bytes in a 1-block extent)
xfs_db -r v5.img -c 'inode 132' -c 'print'                      > v5.inode_small.txt
xfs_db -r v5.img -c 'inode 132' -c 'bmap'                       > v5.bmap_small.txt
xfs_db -r v5.img -c 'convert inode 135 agno'  -c '... agino' \
                 -c '... agblock' -c '... offset' -c '... fsblock' > v5.convert_big.txt
# AG-spanning inodes (block dir 262272 -> agno 1, leaf dir 655488 -> agno 2)
xfs_db -r v5.img ... convert                                    > v5.convert_agspan.txt
```

## P4 directory oracle (short-form + block; name->inode via mount `ls -i`)

```bash
# v5 BLOCK directory (inode 262272): dump the single data block (fsblock 32783).
# v5 magic XDB3 (0x58444233); entries are xfs_dir2_data_entry (bu[]), '.' and
# '..' present explicitly, freetag 0xFFFF marks unused, leaf/hash + btail at end.
xfs_db -r v5.img -c 'inode 262272' -c 'dblock 0' -c 'print' > v5.dir_block_dblock.txt

# INDEPENDENT oracle: mount read-only and capture name -> inode (Tier-1 for the
# directory listing — distinct impl from xfs_db, cross-checks the parser).
mount -o ro,loop v5.img mnt
ls -i mnt          # root:  135 big.bin / 262272 block / 655488 leaf / 131 sf
ls -i mnt/sf       # sf:    132 file1.txt / 133 file2.txt / 134 file3.txt
ls -i mnt/block    # block: 262273..262312 = e01..e40 (40 entries)
sha256sum mnt/sf/file1.txt mnt/sf/file2.txt mnt/sf/file3.txt
umount mnt

# v4 NO-FTYPE short-form image (sfdir2, no filetype byte) — a dedicated image,
# because the P0–P3 v4.img has ftype enabled. 512 MiB, ftype disabled.
truncate -s 512M v4dir.img
mkfs.xfs -f -m crc=0 -n ftype=0 v4dir.img > v4dir.mkfs.txt
mount -o loop v4dir.img mnt4
mkdir mnt4/sf && for i in 1 2 3; do echo "content-$i" > mnt4/sf/file$i.txt; done
sync; umount mnt4
xfs_db -r v4dir.img -c 'inode 128' -c 'print' > v4dir.inode128.txt  # root sfdir2
xfs_db -r v4dir.img -c 'inode 131' -c 'print' > v4dir.inode131.txt  # sf sfdir2
# name->inode (mount ls -i): root 131 sf ; sf 132/133/134 file1/2/3.txt
# file1.txt content sha256 = 1894d80d... (identical bytes to v5 file1.txt)
```

## P5 oracle — bmap B+tree file (`di_format=btree`) + leaf directory

**Part 1 — a heavily-fragmented `btree`-format file** (`v5frag.img`, a dedicated
512 MiB v5 image, gitignored). Delayed allocation coalesces buffered writes, so
fragmentation is forced with **direct I/O** (`xfs_io -d`): each target block is
written with its own `pwrite` interleaved with a separator file that grabs the
adjacent block, so every target block lands physically isolated. Removing the
separators leaves 700 non-coalescable single-block extents — enough to overflow
the inline data fork and push the inode to `di_format = 3 (btree)`.

```bash
truncate -s 512M v5frag.img
mkfs.xfs -f v5frag.img > v5frag.mkfs.txt
mount -o loop v5frag.img mntfrag
F=mntfrag/frag.bin ; N=700
for i in $(seq 0 $((N-1))); do
  xfs_io -f -d -c "pwrite -b 4096 $((i*4096)) 4096" "$F"          # direct: real alloc now
  xfs_io -f -d -c "pwrite -b 4096 0 4096" "mntfrag/sep_$i"        # separator grabs next block
done
sync
xfs_io -c "pwrite -S 0xAB -b 65536 0 $((N*4096))" "$F"           # deterministic content
sync ; rm -f mntfrag/sep_* ; sync
sha256sum "$F" | awk '{print $1}' > v5frag.content.sha256         # Tier-1 content hash
umount mntfrag
xfs_db -r v5frag.img -c 'inode 131' -c 'print' > v5frag.inode_print.txt  # core.format=3 (btree)
xfs_db -r v5frag.img -c 'inode 131' -c 'bmap'  > v5frag.bmap.txt         # ALL 700 extents, startoff order
```

The minted result (`v5frag.inode_print.txt`): `core.format = 3 (btree)`,
`core.nextents = 700`, `core.size = 2867200`, and the bmbt root header
`u3.bmbt.level = 1`, `u3.bmbt.numrecs = 3`, `u3.bmbt.ptrs[1-3] = 1:64 2:558
3:1101` (three leaf blocks). Leaf block fsblock 64 header (raw): magic `42 4d 41
33` = **`BMA3`** (v5 CRC bmbt), `bb_level = 0`, `bb_numrecs = 251`; the first
16-byte `xfs_bmbt_rec` begins at byte **72** (`XFS_BTREE_LBLOCK_CRC_LEN` — long
form + CRC header). `bmap` lists all 700 extents (`offset 0 startblock 13 count
1` … `offset 699 startblock 1522 count 1`) — the Part-1 walk-completeness oracle.
The reconstructed content sha256 is the Tier-1 gate.

**Part 2 — leaf directory listing** (`v5.img`, inode 655488, `~2000` entries).
The `~2000`-child `leaf/` directory is multi-block `Extents` format (`core.size =
49152`, `core.nextents = 19`) — its dir data blocks carry magic **`XDD3`**
(`0x58444433`, the *multi-block* data-block magic, distinct from the single-block
`XDB3`), and the leaf/hash + freeindex live in separate blocks above the
`XFS_DIR2_LEAF_OFFSET` address-space boundary (extent `startoff` 0x800000 and
0x1000000). Listing needs only the DATA blocks. Independent oracle = mount-ro
`ls -i` (a from-scratch parse cross-checked against the kernel's own walk):

```bash
mount -o ro,loop v5.img mntleaf
ls -i mntleaf/leaf | sort -V > leaf.ls_i.txt      # 2000 lines: "<inode> f0001".."f2000"
umount mntleaf
xfs_db -r v5.img -c 'inode 655488' -c 'dblock 0' -c 'print' > v5.dir_leaf_dblock0.txt  # XDD3 data block
```

`leaf.ls_i.txt`: names `f0001`..`f2000` (exact), inodes `655489`..`657680`
(2000 unique; 3 gaps in the sequence — the test compares against the committed
listing, never an assumed contiguity). This is the Part-2 `read_dir(leaf/)`
Tier-1 gate.

## Committed oracle files (index)

| file | oracle | what it anchors |
|---|---|---|
| `v5.sb0.txt` / `v4.sb0.txt` | `xfs_db sb 0 print` | **P0 superblock field values** (magic, blocksize, inodesize, agblocks, agcount, rootino, versionnum, log2 shifts) |
| `v5.xfs_info.txt` / `v4.xfs_info.txt` | `xfs_info` | human geometry cross-check |
| `v5.agi0.txt` / `v5.agf0.txt` (+ v4) | `xfs_db agi/agf 0` | P1 AG headers incl. `agi_unlinked[]` |
| `v5.agfl0.txt` / `v4.agfl0.txt` | `xfs_db agfl 0 print` | P1 AGFL free-list ring; v5 has the `XAFL` header (magic/seqno/uuid/lsn/crc) + 119 `bno[]` slots, v4 is a bare 128-slot `bno[]` array (no header) |
| `v5.inode64.txt` / `v5.inode128.txt` | `xfs_db inode N print` | P2 inode core (v3), rootino=128 |
| `v4.inode64.txt` | `xfs_db inode 64 print` | P2 inode core (v2), unallocated slot (all-zero, `di_format = dev`) |
| `v4.inode128.txt` | `xfs_db inode 128 print` | **P2 inode core (v2)**, v4 root dir — `version = 2`, `format = local`, legacy `(sec:i32, nsec:i32)` timestamp path |
| `v5.inode_big.txt` / `v5.bmap_big.txt` | `xfs_db inode 135 print` + `bmap` | P3 extent-list file (single extent, startblock 24, count 4096) |
| `v5.inode_small.txt` / `v5.bmap_small.txt` | `xfs_db inode 132 print` + `bmap` | P3 small extent-list file (`file1.txt`, size 10, single extent startblock 13 count 1 — content-hash check) |
| `v5.convert_big.txt` / `v5.convert_root.txt` / `v5.convert_agspan.txt` | `xfs_db convert` | **P1 inode-number decode ground truth** (agno/agino/agblock/offset/fsblock) |
| `v5.dir_sf.txt` / `v5.dir_block.txt` / `v5.dir_leaf.txt` | `xfs_db inode N print` | P4 the three dir shapes (sf inode 131 / block inode 262272 / leaf inode 655488) |
| `v5frag.inode_print.txt` / `v5frag.bmap.txt` | `xfs_db inode 131 print` + `bmap` (v5frag.img) | **P5 bmbt B+tree file** — `core.format=3 (btree)`, 700 single-block extents, bmbt root `level=1 numrecs=3 ptrs=64/558/1101`; bmap = all 700 extents (walk-completeness oracle) |
| `v5frag.content.sha256` / `v5frag.inode.txt` / `v5frag.mkfs.txt` | `sha256sum` / provenance | **P5 Part-1 content Tier-1** (reconstructed btree file sha256), frag inode/size, mkfs provenance |
| `leaf.ls_i.txt` | `mount -o ro` + `ls -i mnt/leaf` (v5.img) | **P5 Part-2 leaf-dir listing Tier-1** — 2000 `{name f0001..f2000 -> inode}` cross-checked vs the kernel walk |
| `v5.dir_leaf_dblock0.txt` | `xfs_db inode 655488 dblock 0 print` | **P5 leaf-dir data block** — v5 `XDD3` (0x58444433) multi-block data magic, `.`/`..` + f-entries |
| `v5.dir_block_dblock.txt` | `xfs_db inode 262272 dblock 0 print` | **P4 block-dir data block** — v5 `XDB3` header, `.`/`..` + e01..e40, `btail.count = 42` |
| `v4dir.inode128.txt` / `v4dir.inode131.txt` | `xfs_db inode N print` (v4dir.img) | **P4 v4 no-ftype short-form** — `sfdir2` struct (NO `filetype`), root 131 sf, sf 132/133/134 |
| `v4dir.mkfs.txt` | `mkfs.xfs -m crc=0 -n ftype=0` | provenance of the no-ftype v4 image |
| `content.sha256` / `content.ro.sha256` | `sha256sum` (rw + ro mount) | P3 content Tier-1 |
| `v5.fls.txt` / `v5.fsstat.txt` (+ v4) | TSK `fls`/`fsstat` | records TSK's **lack of XFS support** on this host (see gap 3) |

## Image hashes (gitignored artifacts, provenance only)

```
sha256  v5.img     85b770945e3d3f2d76e3c858cfbb35abaab66b3c88e17189b14a06c087a2969c
sha256  v4.img     425b894b8d616526a238c4d3432f43e337bf1d7fc56dd1fb60f8c9cffe0fde36
sha256  v4dir.img  f2411a9109cc65d21a2bbebe0c2e53391f396464cb037ebe13aff09ee8587acf
sha256  v5frag.img de2c11114bde8f379a7c26d9b72d93bcc135207a065a305df992003d475c332c
```

The `v5frag.img` btree file (inode 131) reconstructed content sha256:
```
frag.bin  b8fa13c187668448f4bff29323b1d65b60b75deafb8baa1dd05a864f96fa8c78
```

Content hashes (from `mount -o ro` + `sha256sum`):
```
sf/file1.txt  1894d80da16dd47db42e2a47e33e709254908a30d4a5985df4bf6e1ba18ce350
sf/file2.txt  e581112dc8525e865b0896be01d082082c32a2633701321438e1efdd4137f05b
sf/file3.txt  9302e07efd6bac7fe50f8e310f5392128577100c46a3ef6a4ccecf64047d92e9
big.bin       1c473b2dfaef2727826973b231b3076185c2eca46a2db7ba12b8259a772abe7c
```

`v4dir.img` shares the identical `content-1\n` bytes, so `sf/file1.txt` there has
the same sha256 (`1894d80d…`).

## Env-gated test consumption

Oracle-gated tests read the images from `XFS_ORACLE_V5_IMG` / `XFS_ORACLE_V4_IMG`
/ `XFS_ORACLE_V4DIR_IMG` / `XFS_ORACLE_V5FRAG_IMG` (absolute paths). They skip
cleanly when the env vars are unset — the images are not committed, so CI without
the minted corpus is green, while a local run with the corpus present validates
against the oracle. Default path (when unset): `tests/data/v5.img` /
`tests/data/v4.img` / `tests/data/v4dir.img` / `tests/data/v5frag.img` (the P5
btree-format fragmented file).

## SYNTHETIC crafted in-code fixtures (CI coverage path — no external oracle)

The `Coverage (100% lines)` CI job runs `cargo llvm-cov --workspace --all-features`
on a runner that has ONLY the committed data (the env-gated 512 `MiB` images are
absent). To carry every reader/auditor line without an external oracle, these
tests craft VALID on-disk XFS structures in code (correct magics + coherent
geometry — never a special case in the reader) or reuse the always-on committed
`xfs_dfvfs.raw` (and the committed 512-byte `v5del.freed_inode.bin`). No new data
file is committed; the fixtures are built by these functions:

| fixture (builder fn) | file:fn | drives |
|---|---|---|
| two-AG v5 / v4 image (diverged AG-1 backup SB + valid AGF/AGI magics) | `forensic/tests/f3_integrity.rs` → `two_ag()` / `two_ag_v5()` / `two_ag_v4()` (+ `write_sb`, `write_ag_headers`) | `audit_image` secondary-SB divergence walk (`push_sb_divergence`), the `agno >= 1` branch, `Agf`/`Agi::parse_verified`, and the v4 skip-CRC path |
| corruptions over a copy of committed `xfs_dfvfs.raw` (byte-flip inode/SB/AGF/AGI, craft AGI unlinked bucket, absurd/zero agcount) | `forensic/tests/f3_integrity.rs` (crafted over `dfvfs()`) | every `audit_image` CRC / orphan / geometry push branch + the clean walk |
| committed `v5del.freed_inode.bin` spliced into a copy of `xfs_dfvfs.raw` | `forensic/tests/f1_deleted.rs` → `recovers_freed_inode_residual_extent_from_fixture` | `recover_deleted` residual-extent decode (always-on) |
| crafted v5 SB + block / multi-block directory + btree-format file inodes; direct `verify_bmbt_block_crc` / `verify_dir_block_crc` / `Agfl::parse_v5` calls; crafted v4 SB | `core/tests/crafted_coverage.rs` (`v5_sb`, `stamp_inode`, `pack`) | `read_dir` block (`read_file`→`read_block_dir`) + multi-block (`read_multiblock_dir`) dispatch, btree `read_file`, the v5 dir/bmbt CRC-claim arms, v5 AGFL parse, v4 `has_ftype`, inode `is_reg`/`data_fork_offset` |
| `read_by_path` not-found arms over committed `xfs_dfvfs.raw` | `core/tests/crafted_coverage.rs` → `read_by_path_*_is_not_found` | missing-component / non-dir-intermediate / empty-path `PathNotFound` |

The env-gated Tier-1 correctness tests above are unchanged: when the minted
images are present the same behaviours are re-validated against a genuine
`mkfs.xfs` filesystem; absent, they skip while the crafted path keeps CI green.
