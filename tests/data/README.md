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
  xfs_db -r $v.img -c 'inode 64' -c 'print' > $v.inode64.txt
  fsstat $v.img > $v.fsstat.txt   # NOTE: TSK 4.12.1 (Ubuntu) has NO XFS support — fails
  fls -r $v.img > $v.fls.txt      #       both fsstat and fls fail (recorded verbatim)
done
# big.bin inode (135) — single-extent decode + bmap ground truth
xfs_db -r v5.img -c 'inode 135' -c 'print'                      > v5.inode_big.txt
xfs_db -r v5.img -c 'inode 135' -c 'bmap'                       > v5.bmap_big.txt
xfs_db -r v5.img -c 'convert inode 135 agno'  -c '... agino' \
                 -c '... agblock' -c '... offset' -c '... fsblock' > v5.convert_big.txt
# AG-spanning inodes (block dir 262272 -> agno 1, leaf dir 655488 -> agno 2)
xfs_db -r v5.img ... convert                                    > v5.convert_agspan.txt
```

## Committed oracle files (index)

| file | oracle | what it anchors |
|---|---|---|
| `v5.sb0.txt` / `v4.sb0.txt` | `xfs_db sb 0 print` | **P0 superblock field values** (magic, blocksize, inodesize, agblocks, agcount, rootino, versionnum, log2 shifts) |
| `v5.xfs_info.txt` / `v4.xfs_info.txt` | `xfs_info` | human geometry cross-check |
| `v5.agi0.txt` / `v5.agf0.txt` (+ v4) | `xfs_db agi/agf 0` | P1 AG headers incl. `agi_unlinked[]` |
| `v5.agfl0.txt` / `v4.agfl0.txt` | `xfs_db agfl 0 print` | P1 AGFL free-list ring; v5 has the `XAFL` header (magic/seqno/uuid/lsn/crc) + 119 `bno[]` slots, v4 is a bare 128-slot `bno[]` array (no header) |
| `v5.inode64.txt` / `v5.inode128.txt` | `xfs_db inode N print` | P2 inode core (v3), rootino=128 |
| `v4.inode64.txt` | `xfs_db inode 64 print` | P2 inode core (v2) |
| `v5.inode_big.txt` / `v5.bmap_big.txt` | `xfs_db inode 135 print` + `bmap` | P3 extent-list file (single extent, startblock 24, count 4096) |
| `v5.convert_big.txt` / `v5.convert_root.txt` / `v5.convert_agspan.txt` | `xfs_db convert` | **P1 inode-number decode ground truth** (agno/agino/agblock/offset/fsblock) |
| `v5.dir_sf.txt` / `v5.dir_block.txt` / `v5.dir_leaf.txt` | `xfs_db inode N print` | P4 the three dir shapes |
| `content.sha256` / `content.ro.sha256` | `sha256sum` (rw + ro mount) | P3 content Tier-1 |
| `v5.fls.txt` / `v5.fsstat.txt` (+ v4) | TSK `fls`/`fsstat` | records TSK's **lack of XFS support** on this host (see gap 3) |

## Image hashes (gitignored artifacts, provenance only)

```
sha256  v5.img  85b770945e3d3f2d76e3c858cfbb35abaab66b3c88e17189b14a06c087a2969c
sha256  v4.img  425b894b8d616526a238c4d3432f43e337bf1d7fc56dd1fb60f8c9cffe0fde36
```

Content hashes (from `mount -o ro` + `sha256sum`):
```
sf/file1.txt  1894d80da16dd47db42e2a47e33e709254908a30d4a5985df4bf6e1ba18ce350
big.bin       1c473b2dfaef2727826973b231b3076185c2eca46a2db7ba12b8259a772abe7c
```

## Env-gated test consumption

P0 superblock tests read the images from `XFS_ORACLE_V5_IMG` / `XFS_ORACLE_V4_IMG`
(absolute paths). They skip cleanly when the env vars are unset — the images are
not committed, so CI without the minted corpus is green, while a local run with
the corpus present validates against the oracle. Default path (when unset):
`tests/data/v5.img` / `tests/data/v4.img`.
