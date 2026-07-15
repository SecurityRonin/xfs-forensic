//! `impl forensic_vfs::FileSystem for XfsFs` — the forensic-vfs adapter
//! (behind the `vfs` feature).
//!
//! [`XfsFs`] mounts an XFS volume onto the [`forensic_vfs::FileSystem`] contract
//! so an XFS filesystem composes as `Arc<dyn FileSystem>` in the forensic-vfs
//! engine, auto-detected through the same probe registry as NTFS/ext4/APFS/…
//!
//! ## The `&[u8]`-vs-`Read + Seek` bridge (the load-bearing design choice)
//!
//! `xfs-core` is a **slice reader**: [`Superblock::parse`], [`Superblock::read_inode`],
//! [`Superblock::read_dir`], [`Superblock::read_file`] all take the *whole image*
//! as `&[u8]`, not a `Read + Seek` cursor (unlike ext4fs-core / fat-core, which
//! stream). A forensic-vfs [`DynSource`], by contrast, is a positioned-read byte
//! source. The adapter bridges the two by reading the **entire source into an
//! owned `Vec<u8>` once at [`XfsFs::open`]** and serving every subsequent call
//! from that buffer (the same choice the engine's HFS+ probe makes for its
//! slice-based reader). Consequence: an XFS volume is held wholly in RAM — a
//! memory consideration for multi-GB volumes, and the reason a streaming
//! `read_at` cannot window the source directly (there is no windowed reader API
//! to defer to).
//!
//! ## Mapping notes / known limits
//! - **Identity.** XFS has no dedicated [`forensic_vfs::FileId`] variant, so nodes
//!   are addressed by [`FileId::Opaque`] carrying the inode number — the natural
//!   XFS identity. Any other identity domain is a caller error, surfaced loud.
//! - **Single stream.** XFS data forks are a single unnamed stream; every
//!   non-`Default` [`StreamId`] is refused loud rather than silently read as the
//!   default.
//! - **`read_at`** reconstructs the whole file via [`Superblock::read_file`] and
//!   windows the result — the reader exposes no partial-read API, so a huge file
//!   is reconstructed in full per call. Correctness over cleverness for now.
//! - **Deleted / unallocated** are empty streams here; XFS deleted-inode carving
//!   is the `xfs-forensic` layer's job, not the reader adapter's.
//! - **Symlinks.** `read_link` reconstructs the (Local or Extents) target bytes
//!   for a symlink node and reads as an empty target for a non-symlink, matching
//!   the ext4/NTFS adapters.

use forensic_vfs::{
    Allocation, ByteRun, Confidence, DirEntry as VfsDirEntry, DirStream, DynSource, ExtentStream,
    FileId, FileSystem, FsKind, FsMeta, MacbTimes, NodeKind, NodeStream, ResidencyKind, RunAlloc,
    RunFlags, RunInfo, SectorSizes, SmallHex, SniffWindow, StreamId, TimeResolution, TimeSource,
    TimeStamp, TimeZonePolicy, VfsError, VfsResult,
};

use crate::error::XfsError;
use crate::extent::read_extents;
use crate::inode::{FileType, Inode, InodeFormat, XfsTimestamp};
use crate::superblock::Superblock;

/// The XFS superblock magic `XFSB` (`0x5846_5342`) at byte 0 of AG 0.
const XFSB_MAGIC: &[u8] = b"XFSB";

/// Probe a sniff window for the XFS superblock magic `XFSB` at offset 0.
///
/// A definite [`Confidence::Yes`] on a match, [`Confidence::No`] otherwise —
/// panic-free (a short window declines). Exposed so the engine registers it
/// without re-deriving the magic, and so tests drive the probe directly.
#[must_use]
pub fn xfs_probe(w: &SniffWindow) -> Confidence {
    if w.has_magic(0, XFSB_MAGIC) {
        Confidence::Yes {
            how: "XFS XFSB superblock magic",
        }
    } else {
        Confidence::No
    }
}

/// A mounted, read-only XFS filesystem over an in-memory image.
///
/// Holds the whole volume bytes (see the module docs on the `&[u8]` bridge) plus
/// the parsed [`Superblock`]; every navigation call reads from the buffer.
pub struct XfsFs {
    image: Vec<u8>,
    sb: Superblock,
}

impl XfsFs {
    /// Read the entire `source` into memory and parse the XFS superblock.
    ///
    /// # Errors
    ///
    /// [`VfsError::Decode`] if the bytes are not a valid XFS superblock (wrong
    /// magic, truncated), keeping the underlying [`XfsError`] message.
    pub fn open(source: &DynSource) -> VfsResult<Self> {
        let len = source.len();
        // Read the whole source into an owned buffer. usize::try_from can only
        // fail on a <64-bit target (usize == u64 on the supported ones); clamp
        // rather than panic.
        let cap = usize::try_from(len).unwrap_or(usize::MAX);
        let mut image = vec![0u8; cap];
        let n = source.read_at(0, &mut image)?;
        image.truncate(n);
        let sb = Superblock::parse(&image).map_err(map_err)?;
        Ok(Self { image, sb })
    }

    /// Read and parse the inode carried by a VFS [`FileId`].
    fn inode(&self, id: FileId) -> VfsResult<Inode> {
        let ino = ino_of(id)?;
        self.sb.read_inode(&self.image, ino).map_err(map_err)
    }
}

/// The inode number carried by a [`FileId`]. XFS addresses nodes by inode number
/// in a [`FileId::Opaque`]; any other identity domain is a caller error.
fn ino_of(id: FileId) -> VfsResult<u64> {
    match id {
        FileId::Opaque(ino) => Ok(ino),
        other => Err(VfsError::Unsupported {
            layer: "xfs file-id",
            scheme: format!("{other:?}"),
        }),
    }
}

/// XFS exposes a single unnamed data stream; a named-stream id is refused loud
/// rather than silently read as the default stream.
fn require_default_stream(stream: StreamId) -> VfsResult<()> {
    match stream {
        StreamId::Default => Ok(()),
        other => Err(VfsError::Unsupported {
            layer: "xfs stream",
            scheme: format!("{other:?}"),
        }),
    }
}

/// Translate an xfs-core error into the VFS error type.
fn map_err(e: XfsError) -> VfsError {
    match e {
        XfsError::Truncated { need, have, .. } => VfsError::OutOfRange {
            what: "xfs image slice",
            offset: need as u64,
            len: 1,
            bound: have as u64,
        },
        other => VfsError::Decode {
            layer: "xfs",
            offset: 0,
            detail: other.to_string(),
            bytes: SmallHex::new(&[]),
        },
    }
}

/// Map an XFS `S_IFMT` file type to the unified node kind.
fn node_kind(ft: FileType) -> NodeKind {
    match ft {
        FileType::Regular => NodeKind::File,
        FileType::Directory => NodeKind::Dir,
        FileType::Symlink => NodeKind::Symlink,
        FileType::CharDevice | FileType::BlockDevice => NodeKind::Device,
        FileType::Fifo | FileType::Socket | FileType::Other(_) => NodeKind::Other,
    }
}

/// Convert a decoded XFS timestamp to a VFS [`TimeStamp`] with inode-table
/// provenance and nanosecond resolution (XFS records ns since the epoch).
fn to_ts(ts: XfsTimestamp) -> TimeStamp {
    TimeStamp {
        unix_nanos: i128::from(ts.secs) * 1_000_000_000 + i128::from(ts.nsecs),
        source: TimeSource::InodeTable,
        resolution: TimeResolution::Nanos,
    }
}

impl FileSystem for XfsFs {
    fn kind(&self) -> FsKind {
        FsKind::Xfs
    }

    fn root(&self) -> FileId {
        FileId::Opaque(self.sb.rootino)
    }

    fn sector_sizes(&self) -> SectorSizes {
        SectorSizes {
            logical: 512,
            physical: 512,
            cluster_or_block: self.sb.blocksize,
        }
    }

    fn timestamp_zone(&self) -> TimeZonePolicy {
        // XFS timestamps are seconds/nanoseconds from the Unix epoch, in UTC.
        TimeZonePolicy::Utc
    }

    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
        let inode = self.inode(ino)?;
        let entries = self.sb.read_dir(&self.image, &inode).map_err(map_err)?;
        let out: Vec<VfsResult<VfsDirEntry>> = entries
            .into_iter()
            .map(|e| {
                Ok(VfsDirEntry {
                    name: e.name,
                    id: FileId::Opaque(e.inode),
                    // The on-disk ftype byte is not always present (no-ftype
                    // filesystems), so classify via a cheap inode read instead.
                    kind: self.entry_kind(e.inode),
                })
            })
            .collect();
        Ok(DirStream::new(out.into_iter()))
    }

    fn extents(&self, ino: FileId, stream: StreamId) -> VfsResult<ExtentStream> {
        require_default_stream(stream)?;
        let inode = self.inode(ino)?;
        let blocksize = u64::from(self.sb.blocksize);
        // Only inline extent-list forks are surfaced here; a btree-format fork's
        // runs come through read_at (which walks the tree) — extent enumeration
        // over the btree map is a follow-up, matching the fleet adapters that
        // leave richer forensic surfaces default-empty.
        let recs = match inode.format {
            InodeFormat::Extents => read_extents(&inode.data_fork, inode.nextents),
            _ => Vec::new(),
        };
        let out: Vec<VfsResult<RunInfo>> = recs
            .into_iter()
            .map(|r| {
                Ok(RunInfo {
                    run: ByteRun {
                        image_offset: r.startblock.saturating_mul(blocksize),
                        len: r.blockcount.saturating_mul(blocksize),
                        flags: RunFlags::default(),
                    },
                    alloc: RunAlloc::Allocated,
                })
            })
            .collect();
        Ok(ExtentStream::new(out.into_iter()))
    }

    fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
        let inode = self.inode(parent)?;
        let entries = self.sb.read_dir(&self.image, &inode).map_err(map_err)?;
        Ok(entries
            .into_iter()
            .find(|e| e.name == name)
            .map(|e| FileId::Opaque(e.inode)))
    }

    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        let inode_no = ino_of(ino)?;
        let inode = self.sb.read_inode(&self.image, inode_no).map_err(map_err)?;
        let residency = match inode.format {
            InodeFormat::Local => ResidencyKind::Resident {
                inline_len: u32::try_from(inode.data_fork.len()).unwrap_or(u32::MAX),
            },
            _ => ResidencyKind::NonResident,
        };
        Ok(FsMeta {
            ino: inode_no,
            kind: node_kind(inode.file_type()),
            allocated: Allocation::Allocated,
            size: inode.size,
            nlink: 1,
            uid: None,
            gid: None,
            mode: Some(u32::from(inode.mode)),
            times: MacbTimes {
                modified: Some(to_ts(inode.mtime)),
                accessed: Some(to_ts(inode.atime)),
                changed: Some(to_ts(inode.ctime)),
                born: inode.crtime.map(to_ts),
            },
            streams: Vec::new(),
            residency,
            link_target: None,
        })
    }

    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize> {
        require_default_stream(stream)?;
        let inode = self.inode(ino)?;
        // xfs-core exposes only whole-file reconstruction; window its result to
        // [off, off+buf.len()). A start past EOF reads zero bytes (never panics).
        let file = self.sb.read_file(&self.image, &inode).map_err(map_err)?;
        let start = usize::try_from(off).unwrap_or(usize::MAX);
        let Some(slice) = file.get(start..) else {
            return Ok(0);
        };
        let n = slice.len().min(buf.len());
        buf[..n].copy_from_slice(&slice[..n]);
        Ok(n)
    }

    fn read_link(&self, ino: FileId, cap: usize) -> VfsResult<Vec<u8>> {
        let inode = self.inode(ino)?;
        if inode.file_type() != FileType::Symlink {
            // A non-symlink reads as an empty target (matches ext4/NTFS adapters).
            return Ok(Vec::new());
        }
        // A symlink target is either inline in the data fork (Local) or in data
        // blocks (Extents); read_file reconstructs both to di_size.
        let mut target = self.sb.read_file(&self.image, &inode).map_err(map_err)?;
        target.truncate(cap);
        Ok(target)
    }

    fn deleted(&self) -> VfsResult<NodeStream> {
        // Deleted-inode carving is the xfs-forensic layer's job; the reader
        // adapter's default surface is an empty stream, not a bootstrap failure.
        Ok(NodeStream::empty())
    }

    fn unallocated(&self) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
}

impl XfsFs {
    /// Classify a child by reading its inode; degrade to `Other` (never panic) if
    /// the inode read fails on a volume this handle was already opened from.
    fn entry_kind(&self, ino: u64) -> NodeKind {
        self.sb
            .read_inode(&self.image, ino)
            .map_or(NodeKind::Other, |i| node_kind(i.file_type()))
    }
}
