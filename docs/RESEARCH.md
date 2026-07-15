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
    `xfs_db convert` exactly (an independent structural check; self-minted image => Tier-2).

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

## 3. Real sample data + oracle (Tier-2 self-mint backstop; Tier-1 real corpus pending)

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
# A: xfs_db — structural ground truth (independent oracle; self-minted image => Tier-2)
xfs_db -r v5.img -c 'sb 0' -c 'print'
xfs_db -r v5.img -c 'agi 0' -c 'print'      # AGI incl. unlinked[]
xfs_db -r v5.img -c 'agf 0' -c 'print'
xfs_db -r v5.img -c 'inode 64' -c 'print'
xfs_db -r v5.img -c 'convert inode <N> agno' -c 'convert inode <N> agino' \
                 -c 'convert inode <N> agblock' -c 'convert inode <N> offset'
xfs_db -r v5.img -c 'inode <big_ino>' -c 'bmap'
# B: The Sleuth Kit — independent second reader (cross-impl; still Tier-2 on a self-minted image)
fsstat v5.img ; fls -r v5.img ; istat v5.img 64 ; icat v5.img <big_ino> | sha256sum
# C: mount-ro + sha256 — content check (Tier-2: self-minted content)
sudo mount -o ro,loop v5.img mnt; sha256sum mnt/sf/file1.txt mnt/big.bin; sudo umount mnt
```

**Corpora:** no well-known public XFS forensic image surfaced in the first pass
(CFReDS/Digital Corpora skew ext/NTFS/FAT/HFS). A self-minted `mkfs.xfs` image is
**REAL-self = Tier-2** even with three independent oracles (xfs_db + TSK + mount) —
independence of the *oracle* does not lift a self-authored *artifact* to Tier-1.
Genuine **Tier-1** needs a *third-party* artifact: a RHEL/Rocky/AlmaLinux/CentOS 7+
disk image (the RHEL family defaults to XFS), a DFIR-challenge image, or libyal
`libfsxfs` test data — sourcing this is an open task (in progress).
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
- **P4** Directories — **short-form + block DONE** (`read_dir`/`read_by_path`,
  oracle: `xfs_db` dir dumps + mount-ro `ls -i` name→inode + capstone content
  sha256 through path navigation; TSK has no XFS on this host so `fls` is not the
  oracle). The ftype byte tracks the fs FEATURE bit (`Superblock::has_ftype`),
  not the v4/v5 version — modern mkfs enables ftype on v4. leaf → node → btree
  handled in P5.
- **P5 DONE** — two parts, both Tier-2 validated (independent oracle, self-minted image):
  - **Part 1: bmap B+tree file read (`di_format=3`, `read_btree_extents`).** The
    inline `xfs_bmdr_block` root (fork: `bb_level`/`bb_numrecs` then keys[dmaxrecs]
    + ptrs[dmaxrecs] at the `4 + dmaxrecs*8` offset) → on-disk bmbt blocks (`BMA3`
    v5, 72-byte CRC long-form header / `BMAP` v4, 24-byte header) → 16-byte
    `xfs_bmbt_rec` leaves, walked in `startoff` order and fed to the shared
    extent→file `assemble_extents`. Bounded (MAX_BMBT_LEVELS/MAX_BMBT_PTRS caps,
    every block access bounds-checked). Layouts verbatim from `xfs_format.h`,
    ptr-offset + header-size verified against `xfs_db` on a real 700-extent btree
    file. **Oracle:** `v5frag.img` inode 131 — `read_file` sha256 ==
    mount-ro `b8fa13c1…`; `read_btree_extents` == all 700 extents of `xfs_db bmap`.
  - **Part 2: leaf/node/btree directories.** `read_dir` extended: multi-block
    `Extents` dirs (`size > blocksize`) and `Btree` dirs walk their DATA extents
    (logical offset below `XFS_DIR2_LEAF_OFFSET = 1<<35`), reading each `XDD3`
    (v5) / `XD2D` (v4) multi-block data block (no block tail — entries fill the
    block) via the shared entry walker. leaf/hash + freeindex index blocks are
    skipped. **Oracle:** `read_dir(leaf/, inode 655488)` == mount-ro `ls -i`
    (2000 `{f0001..f2000 → inode}`); `read_by_path("/leaf/f0001")` resolves.
  - Sparse inodes remain deferred (past MVP).
- **P6 — DONE.** v5 CRC32c self-describing-metadata validation. On v5 (and ONLY
  v5 — v4 has no CRCs) every metadata block carries a CRC32c
  (Castagnoli/`CRC_32_ISCSI`) over the whole on-disk object with the 4-byte CRC
  field treated as zero, stored little-endian. `crc::verify_crc(buffer,
  crc_offset)` reproduces the kernel `xfs_verify_cksum` byte-exactly (scratch
  copy, CRC field zeroed in place); `crc::crc_status(is_v5, buffer, off)` is the
  v4→`None` / v5→`Some` seam. CRC verification is **non-fatal** — a bad CRC never
  fails a parse; it surfaces as `crc_valid: Option<bool>` for the `-forensic`
  layer (F3) to turn into a Finding. **CRC offsets (VERBATIM from `xfs_format.h`
  / `xfs_da_format.h`, each `offsetof(...)`):** SB `sb_crc` 224 · AGF `agf_crc`
  216 · AGI `agi_crc` **312** (after `unlinked[64]`+uuid — NOT the naive early
  offset) · AGFL `agfl_crc` 32 · inode v3 `di_crc` 100 · dir data/single-block
  `xfs_dir3_blk_hdr.crc` 4 · dir leaf/node `xfs_da3_blkinfo.crc` 12 · bmbt
  long-form `bb_u.l.bb_crc` 64. Coverage length = the object's whole buffer
  (sector / inodesize / blocksize), matching the kernel `BBTOB(bp->b_length)`.
  Surfaced on `Superblock`/`Inode` (computed in `parse` — they self-describe
  version), `Agf`/`Agi` (`parse_verified(data, is_v5)`; plain `parse` leaves
  `None`), `Agfl` (`parse_v5` verifies, `parse_v4` → `None`), and standalone
  `verify_dir_block_crc` / `verify_bmbt_block_crc` (detect v5 vs v4 by magic).
  **Oracle (Tier-2; xfsprogs is the independent CRC author, but the image is self-minted):** every unmodified
  metadata block from `v5.img` / `v5frag.img` verifies `Some(true)` — SB, AG-0
  AGF/AGI/AGFL, root inode 128, an `XDD3` dir data block, a da3 leaf/node block,
  a `BMA3` bmbt block; a single flipped byte flips to `Some(false)`; the v4
  images report `None`. This **completes `xfs-core` (P0–P6)** — the reader parses
  all file formats (inline/extents/btree) + all dir formats and validates v5
  self-describing metadata.

**`xfs-forensic` analyzer status — F1 + F3 DONE; F2 + F4 follow-on.**

**`xfs-forensic` (analyzer, over raw `Read+Seek`/bytes per the reader/analyzer-split
principle — the auditor must see slack the reader normalizes):**
- **F1 — DONE.** Deleted-inode recovery. On delete XFS zeroes only mode/nlink/size/
  nblocks/nextents; **the extent records at inode offset 176 (v3) can survive**, ctime
  becomes deletion time, generation increments. `recover_deleted` sweeps the inode
  space for freed (`di_mode == 0`) v3 inodes, decodes the residual `xfs_bmbt_rec`
  records directly from the fork (`di_nextents` is zeroed, so it cannot be counted),
  and carves the content via the extent reader → `XFS-DELETED-INODE-CARVED`.
  Validated against xfs_db ground truth on the committed 512-byte freed-inode fixture
  (`[startoff=0, startblock=32, blockcount=8]`, ctime, size).
  **Kernel-dependent residue caveat (Doer-Checker, verified 2026-07-15):** residual
  extent survival is *not* deterministic. Re-minting the delete case on the current
  Ubuntu kernel zeroes the inode data fork on inactivation (measured: freed-with-fork
  count 0, even pre-unmount), so no extents survive a clean delete there. The committed
  fixture comes from the original image where they *did* survive; the env-gated
  full-image carve-hash gate (`XFS_DEL_ORACLE`) therefore requires a residue-bearing
  image and is not reproducible by re-mint on this kernel. Recovery is correct — it
  carves residue when present and finds nothing when the fork is zeroed.
- **F2** Directory-slack residue — short-form tail entries in inode slack; block-dir
  freed dirent keeps its 32-bit inode number (inumber→0xFFFF but original often
  readable) → recover deleted filenames + links. **(follow-on)**
- **F3 — DONE.** Structural integrity. `audit_image` parses the primary superblock
  over its sector (correct CRC coverage), walks every AG that fits the image, and emits
  `XFS-CRC-MISMATCH` (superblock / AGF / AGI / inode — the inode sweep gated on the
  `di_ino` self-reference so a stray `IN` in file data cannot mis-flag),
  `XFS-SB-MIRROR-DIVERGENCE` (secondary-SB geometry vs AG-0), `XFS-ORPHANED-INODE`
  (AGI `unlinked[64]`), and `XFS-IMPOSSIBLE-GEOMETRY` (allocation-bomb guards). Clean
  v5 image emits nothing; crafted corruption detected for each code. Directory-block
  and bmbt-block CRC checking is deferred to F2.
- **F4** Timestamp anomalies (bigtime-vs-classic mismatch, crtime>mtime) — Info leads
  (mirror the timestomp-is-Info fleet stance). **(follow-on)**

**Oracle tiering (corrected — self-minted ≠ Tier-1):** our `v5.img`/`v4.img` are
**REAL-self = Tier-2** — real `mkfs.xfs` output confirmed by independent oracles
(xfs_db + TSK + mount-ro/sha256), but *we chose the scenario*, so they can miss
real-world quirks. A non-ours **oracle** does not make a self-minted **artifact**
Tier-1; Tier-1 requires a *third-party-authored or real-world* image. So both
structure and content are validated at **Tier-2** today, and deleted-file recovery
is also Tier-2 (self-minted delete cases). **Open task:** add a genuine **Tier-1**
XFS corpus (a real RHEL/Rocky/AlmaLinux/CentOS default-XFS image or a DFIR-challenge
image, or libyal `libfsxfs` third-party test data) and validate against it with
xfs_db/TSK as the independent oracle on *their* bytes.

**Gaps to close before coding:** (1) confirm `xfuse`'s exact LICENSE; (2) pull the
verbatim bmbt bit-field widths from the kernel Data-extents chapter (not memory —
that bit split is the highest-risk number in the reader); (3) verify TSK's exact XFS
v5 feature coverage on the minted image before trusting it as tiebreaker on
bigtime/sparse-inode/reflink cases.
