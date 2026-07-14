# XFS Forensic Test Data — Provenance

All fixtures here are **REAL-self Tier-1**: minted on a controlled Linux VM with
`mkfs.xfs` (xfsprogs) and cross-checked against three independent oracles
(`xfs_db`, `xfs_info`, `mount -o ro` + `sha256sum`). See the fleet catalog at
[`issen/docs/corpus-catalog.md`](../../../issen/docs/corpus-catalog.md) for the
machine index; this README is the co-located human detail.

The two 512 MiB images (`v5.img`, `v4.img`) are **gitignored** (see
`.gitignore`) — only the oracle **text outputs** below are committed. Re-mint
the images from the verbatim commands to reproduce the corpus.

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
