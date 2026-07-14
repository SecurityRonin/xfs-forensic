# XFS Forensic Reader — Research-First Report (`xfs-core` + `xfs-forensic`)

Read-only Research-First deliverable (spec, prior art, oracle, phased build) — the
mandatory pre-implementation research per the fleet Research-First discipline.
Confidence is marked; items not fetched verbatim are flagged as gaps.

## 1. Authoritative spec

**Primary — the SGI/kernel "XFS Algorithms & Data Structures" document.**
- Title: *XFS Algorithms & Data Structures* (formerly *XFS Filesystem Structure*,
  3rd ed., SGI / Dave Chinner / xfsprogs team), now maintained in-tree as reST and
  rendered at **https://www.kernel.org/doc/html/latest/filesystems/xfs/index.html**
  (chapters: Common types, AG headers, Journaling, Internal Inodes, Data extents,
  Directories, …). The older standalone `xfs_filesystem_structure.pdf` under
  `mirrors.edge.kernel.org/pub/linux/utils/fs/xfs/docs/` is FlateDecode-compressed —
  **use the HTML kernel docs, not the PDF**.
  - Gap: the Princeton mirror of the standalone algorithms HTML 404'd; the
    kernel.org `Documentation/filesystems/xfs/` tree is the live authoritative source.
- v5 companion: **https://www.kernel.org/doc/html/latest/filesystems/xfs/xfs-self-describing-metadata.html**
  (the v5 `xfs_ondisk_hdr` verbatim).
- Secondary canonical inspector reference doubling as the oracle:
  **`xfs_db(8)`** (https://www.mankier.com/8/xfs_db) — documents every on-disk type
  field-by-field.

**Core structures a reader must parse:**

- **Superblock** — at **offset 0**, one per AG (AG 0 primary; secondaries are backups).
  - `sb_magicnum` = **0x58465342** = ASCII `"XFSB"` at byte 0.
  - `sb_blocksize` bytes 4–7 (default **4096** on v5); `sb_inodesize` bytes 104–105
    (default **512** on v5).
  - `sb_rootino` bytes 56–63 (**normally 64**); `sb_logstart` bytes 48–55;
    `sb_agblocks` bytes 84–87 (blocks/AG); `sb_agcount` bytes 88–91; `sb_logblocks`
    bytes 96–99.
  - `sb_versionnum` — low nibble = version (**4 vs 5**); + `sb_features2` /
    `sb_features_incompat` for v5. v5 adds CRCs, UUID-stamped metadata,
    `owner`/`blkno`/`lsn` in headers, bigtime, ftype-in-dirent, inobtcount, reflink, rmapbt.
  - Also need the **log2 shift fields** `sb_inopblog`, `sb_agblklog`, `sb_inodelog`,
    `sb_blocklog` — required for the inode-number decode.

- **Allocation Groups + AG headers.** `sb_agcount` AGs of `sb_agblocks` blocks each;
  sector-0 of each AG holds:
  - **AGF** (magic `XAGF` 0x58414746) — free-space B+trees (bnobt/cntbt roots,
    freelist, longest free extent); v5 adds rmapbt/refcountbt roots.
  - **AGI** (magic `XAGI` 0x58414749) — inode allocation: `agi_root` (inobt root),
    `agi_count`/`agi_freecount`, the **`agi_unlinked[64]` hash bucket array**
    (orphaned-but-open inodes — forensically valuable); v5 adds finobt root.
  - **AGFL** (magic `XAFL` on v5) — the AG free-list block ring.

- **Inode format.** Magic `0x494e` = `"IN"`. Inodes live in **chunks of 64**. Core
  is **v2** (256-byte inode, v4) or **v3** (v5, larger core with CRC/`di_crtime`/
  `di_ino`/`di_uuid`). Key fields: `di_mode`, `di_version` (1/2/3), `di_format`
  (data-fork format selector), `di_aformat`, `di_size`, `di_nblocks`, `di_nextents`,
  timestamps. Data starts at **inode offset 176** on v3. `di_format`: **0 = DEV**,
  **1 = LOCAL** (inline: short-form dir or symlink), **2 = EXTENTS** (inline extent
  array), **3 = BTREE** (bmap B+tree root inline).

- **Inode-number → (AG, block, offset) decode** (the crux; confirm vs `xfs_db convert`):
  - `agno = ino >> (sb_agblklog + sb_inopblog)`;
    `agino = ino & ((1 << (sb_agblklog + sb_inopblog)) - 1)`.
  - `agblock = agino >> sb_inopblog`; `offset = agino & ((1 << sb_inopblog) - 1)`.
  - `fsblock = (agno * sb_agblocks) + agblock`;
    byte = `fsblock * sb_blocksize + offset * sb_inodesize`.
  - Live example (`sb_inopblog=3` → 8 inodes/block): `ino 67761631 → agno 0x2,
    agino 0x9f5df, agblock 0x13ebb, offset 0x7`. The decoder must reproduce
    `xfs_db convert` exactly (a Tier-1 structural check).

- **The 5 directory formats** (by size / `di_format`):
  1. **Short-form (local, `di_format=1`)** — entries packed inline; parent inode +
     per-entry (namelen, offset, name, inumber, v5 ftype). Residue: deleting shifts
     entries down, leaving the **tail entry in inode slack**.
  2. **Block directory** — single block: data entries front, bestfree/free-space
     array in header, hash/leaf array + tail at end. Deletion sets dirent inumber to
     **0xFFFF**, zeroes the hash offset, updates free array — but the **original
     32-bit inode number stays visible** in the freed entry (recovery signal).
  3. **Leaf directory** — data blocks + a leaf block (name-hash → data-block-offset).
  4. **Node directory** — a dabtree (da_btree) of leaf blocks.
  5. **B+tree directory** — largest; dir data uses a bmap B+tree to map logical
     dir-blocks → fsblocks.
  Non-shortform dir blocks carry a `blkinfo`/`da_blkinfo` header (forw/back/magic
  v4; v5 adds crc/owner/blkno/lsn + magics `XDD3`/`XDB3`/`XDLF`/…).

- **Extent lists vs bmap B+tree.** `di_format=2` (EXTENTS): inline array of **16-byte
  packed `xfs_bmbt_rec`** records — packing across two BE u64s:
  `[flag:1 (unwritten)] [startoff:54] [startblock:52] [blockcount:21]`. `startblock`
  is an absolute fsblock (decode via the same agno/agblock split). `di_format=3`
  (BTREE): bmbt root header + keys/ptrs; leaves hold the same 16-byte records.
  Realtime/rmap variants (rtrmapbt magic `MAPR` 0x4d415052) are out of MVP scope.

- **v4 vs v5:** v5 = self-describing metadata (`magic/crc(crc32c)/uuid/owner/blkno/lsn`
  per metadata block); v5 inodes are **v3 core** (has `di_crtime`, `di_ino`, `di_uuid`,
  `di_flags2` incl. **bigtime** — 64-bit timestamp vs v4's `(secs:i32,nsec:i32)`);
  v5 dirents carry a trailing **ftype** byte (v4 do not — off-by-one risk). CRC32c =
  Castagnoli/iSCSI polynomial.

## 2. Existing implementations (build-vs-reuse)

**Rust:**

| Name | URL | Maturity | R/W | License | Role |
|---|---|---|---|---|---|
| **`xfs-fuse`/`xfuse`** (Khaled Emara) | github.com/KhaledEmaraDev/xfuse, crates.io `xfs-fuse` | Most mature Rust XFS reader; ~14k dl, active 2026. Deps `bincode-next`/`crc`/`fuser`/`uuid`. | Read-only | **verify LICENSE before close reading** | Best reference + cross-check; a FUSE binary, not a library core — study, don't depend. |
| **`lamxfs`** (Lamco) | github.com/lamco-admin/lamxfs, crates.io | v0.1.0, `no_std`, read-only, clean-room; `crc 3.2` CRC_32_ISCSI for v5. | Read-only | **MIT OR Apache-2.0** | Best reuse/reference candidate — permissive, clean-room, dependency-light; likely narrow (boot-path). |
| `mkfs-xfs` (justincormack) | github.com/justincormack/mkfs-xfs | v0.1.0, dependency-free, writer | Write | (check) | Inverse reference — an encoder shows exact byte layouts; good for synthetic fixtures. |
| `xfs` (2016) | crates.io | Abandoned; parses XFS **perf data**, not the FS | — | — | Irrelevant (name collision only). |

**Non-Rust references / oracles:**
- **The Sleuth Kit — XFS support (TSK 4.7.0, 2019).** Read-only; `fsstat`/`fls`/
  `istat`/`icat`. **Our strongest independent forensic oracle** (from-scratch C, not
  libxfs → genuine cross-impl validation). Caveat: rough on v5/newer feature bits —
  reconcile divergences.
- **`xfs_db(8)`** — canonical structural oracle (`convert` = inode-number ground truth).
- **`xfs_info`/`xfs_spaceman`**, **libxfs** (reference C, tiebreaker).
- Deleted-recovery refs for `-forensic`: `xfsr`, `xfs_irecover`, the righteousit.com
  XFS series (parts 1–4+).

**Recommendation: build our own `xfs-core`** (fleet policy; no crate is a
forensic-grade library core). Reuse the `crc` crate (CRC_32_ISCSI) for v5 + fleet
`blazehash-core` for content hashing. Learn packing from `xfuse` (most complete) and
`lamxfs` (cleanest, permissive); cross-check every structure vs `xfs_db` + TSK.
**Verify `xfuse`'s exact license before close reading.**

## 3. Real sample data + oracle (Tier-1 plan)

Mint controlled real images on the Parallels Ubuntu VM (`xfsprogs` = `mkfs.xfs`,
`xfs_db`, `xfs_info`; `sleuthkit` for the second oracle):

```bash
sudo apt-get install -y xfsprogs sleuthkit coreutils
cd /tmp && rm -rf xfs-oracle && mkdir xfs-oracle && cd xfs-oracle
# v5 (default: CRC + bigtime + ftype)
truncate -s 512M v5.img
mkfs.xfs -f v5.img
xfs_info v5.img > v5.xfs_info.txt
# v4 (legacy, no CRC)
truncate -s 512M v4.img
mkfs.xfs -f -m crc=0 v4.img
# populate the 3 key dir shapes + a multi-extent file + a deleted-file case
mkdir mnt && sudo mount -o loop v5.img mnt
sudo mkdir mnt/sf && for i in 1 2 3; do echo "content-$i" | sudo tee mnt/sf/file$i.txt >/dev/null; done
sudo mkdir mnt/block && for i in $(seq -w 1 40); do echo x | sudo tee mnt/block/e$i >/dev/null; done
sudo mkdir mnt/leaf && for i in $(seq -w 1 2000); do : | sudo tee mnt/leaf/f$i >/dev/null; done
sudo dd if=/dev/urandom of=mnt/big.bin bs=1M count=16
sudo sha256sum mnt/sf/file1.txt mnt/big.bin > /tmp/xfs-oracle/content.sha256
echo "delete-me" | sudo tee mnt/sf/DELETED_secret.txt >/dev/null
sync; sudo rm mnt/sf/DELETED_secret.txt; sync
sudo umount mnt
```

Oracles:
```bash
# A: xfs_db — structural ground truth (Tier-1 for structure)
xfs_db -r v5.img -c 'sb 0' -c 'print'
xfs_db -r v5.img -c 'agi 0' -c 'print'      # AGI incl. unlinked[]
xfs_db -r v5.img -c 'agf 0' -c 'print'
xfs_db -r v5.img -c 'inode 64' -c 'print'
xfs_db -r v5.img -c 'convert inode <N> agno' -c 'convert inode <N> agino' \
                 -c 'convert inode <N> agblock' -c 'convert inode <N> offset'
xfs_db -r v5.img -c 'inode <big_ino>' -c 'bmap'
# B: The Sleuth Kit — independent second reader (Tier-1 cross-impl)
fsstat v5.img ; fls -r v5.img ; istat v5.img 64 ; icat v5.img <big_ino> | sha256sum
# C: mount-ro + sha256 — content Tier-1
sudo mount -o ro,loop v5.img mnt; sha256sum mnt/sf/file1.txt mnt/big.bin; sudo umount mnt
```

**Corpora:** no well-known public XFS forensic image (CFReDS/Digital Corpora are
ext/NTFS/FAT/HFS-centric) → treat as **REAL-self Tier-1 via three independent
oracles** (xfs_db + TSK + mount). A RHEL/CentOS 7+ disk image (RHEL defaults to XFS)
from a DFIR challenge would be an excellent real corpus if licensing permits.
Document every minted image's commands in `tests/data/README.md` + the fleet
`docs/corpus-catalog.md`.

## 4. Scope/difficulty + phased build order

**MVP reader:** superblock → AG headers → inode-by-number (v2+v3, shift decode) →
the 5 dir formats → extent-list + bmbt file read → v3 timestamps incl. bigtime →
v4/v5 branch.

**Hard (ranked):**
1. **bmap B+tree (`di_format=3`)** — multi-level; same 16-byte record packing at
   leaves. **The 54/52/21-bit split is the single highest-risk number** — the classic
   "inverted bit-split ships green" trap; pull it **verbatim from the spec's
   Data-extents chapter**, validate every extent vs `xfs_db bmap`.
2. The 5 directory formats (esp. node dabtree + btree dirs; v4/v5 header-shift +
   trailing ftype = off-by-one sources).
3. v4/v5 divergence woven through everything — branch cleanly at the top.
4. Sparse inodes (v5 SPINODES) — inode chunks partially allocated; deferrable past MVP.
5. CRC32c verification (v5) — easy with `crc` (CRC_32_ISCSI); owner/blkno
   self-consistency is the forensically useful part.

**Difficulty vs ext4:** comparable, a notch harder (~1.3–1.5×): AG model + shift-based
inode-number encoding + five dir formats + self-describing v5 metadata.

**`xfs-core` phases:**
- **P0** Superblock + geometry (derive all shifts; magic `XFSB`). Oracle: `xfs_db sb 0`, `xfs_info`, `fsstat`.
- **P1** Inode-number decode + AG headers (AGF/AGI/AGFL incl. `agi_unlinked[64]`). Oracle: `xfs_db convert` (exact-match), `agi/agf print`.
- **P2** Inode core (v2 + v3; bigtime). Oracle: `xfs_db inode N print`, `istat`.
- **P3** Extent-list files (`di_format=2`) — 16-byte bmbt unpack → file read. Oracle: `xfs_db bmap`, `icat|sha256`, mount content.
- **P4** Directories (short-form → block → leaf → node → btree). Oracle: `fls -r`, `xfs_db` dir dumps.
- **P5** bmap B+tree (`di_format=3`) + sparse inodes. Oracle: `xfs_db bmap`, `fls -r` full, TSK.
- **P6** v5 CRC32c + self-describing header validation.

**`xfs-forensic` (analyzer, over raw `Read+Seek`/bytes per the reader/analyzer-split
principle — the auditor must see slack the reader normalizes):**
- **F1** Deleted-inode recovery — on delete XFS zeroes only mode/nlink/size/nblocks/
  nextents + attr-fork offset; **the extent records + attr data at inode offset 176
  survive**, ctime becomes deletion time, generation increments → carve residual
  extents. High-value, distinctive.
- **F2** Directory-slack residue — short-form tail entries in inode slack; block-dir
  freed dirent keeps its 32-bit inode number (inumber→0xFFFF but original often
  readable) → recover deleted filenames + links.
- **F3** Structural integrity — v5 CRC mismatch, owner/blkno mismatch (relocation),
  SB-vs-secondary divergence, AGI `unlinked[]` non-empty (orphaned open inodes),
  impossible geometry (allocation-bomb guards).
- **F4** Timestamp anomalies (bigtime-vs-classic mismatch, crtime>mtime) — Info leads
  (mirror the timestomp-is-Info fleet stance).

**Oracle tiering:** **Structure = Tier-1** (xfs_db + TSK cross-impl + xfs_info/fsstat,
none ours). **Content = Tier-1** (mount-ro + sha256, icat|sha256). **Deleted-file
recovery = Tier-2** from self-minted delete cases; strengthen by reconciling vs an
independent recovery oracle (`xfsr`/`xfs_irecover`) on the same image, explaining
divergence, per the fleet carving-validation standard.

**Gaps to close before coding:** (1) confirm `xfuse`'s exact LICENSE; (2) pull the
verbatim bmbt bit-field widths from the kernel Data-extents chapter (not memory —
that bit split is the highest-risk number in the reader); (3) verify TSK's exact XFS
v5 feature coverage on the minted image before trusting it as tiebreaker on
bigtime/sparse-inode/reflink cases.
