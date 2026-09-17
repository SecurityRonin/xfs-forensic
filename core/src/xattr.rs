//! XFS extended attributes — reading the attribute fork.
//!
//! An XFS inode has two forks in one literal area. The data fork starts at the
//! literal-area offset; the attribute fork starts `di_forkoff * 8` bytes later,
//! and `di_aformat` says which of three shapes it takes:
//!
//! | `di_aformat` | shape | where the attributes are |
//! |---|---|---|
//! | 0 | none | the inode has no attribute fork |
//! | 1 (`LOCAL`) | **shortform** | inline, in the literal area |
//! | 2 (`EXTENTS`) | **leaf** | in blocks the fork's extents point at |
//! | 3 (`BTREE`) | btree | in blocks a bmap btree points at |
//!
//! ## Layout, established from a real image
//!
//! Every constant here was read out of an image the Linux XFS driver wrote
//! (`tests/data/xfs_xattr.img.gz`) rather than recalled, and one was wrong on
//! the first attempt — see [`LEAF_HDR_LEN`].
//!
//! **Shortform** is a 4-byte header (`totsize` be16, `count`, `padding`)
//! followed by `count` entries of `namelen`, `valuelen`, `flags`, then the name
//! and value laid end to end with no alignment or terminator.
//!
//! **Leaf** blocks carry `xfs_da3_blkinfo` with the magic at offset 8, then a
//! header, then 8-byte entries (`hashval` be32, `nameidx` be16, `flags`, pad).
//! `nameidx` is a byte offset from the start of the BLOCK, pointing at either a
//! local record (`valuelen` be16, `namelen`, name, value) or a remote one
//! (`valueblk` be32, `valuelen` be32, `namelen`, name).
//!
//! **Remote values** are the subtle case. `valueblk` is a *logical* block
//! offset within the attribute fork, so it must be mapped through the fork's
//! own extents, and on v5 every remote block begins with a 56-byte
//! `xfs_attr3_rmt_hdr` that is not part of the value. Miss the headers and the
//! value comes back the right length with 56 bytes of garbage spliced in at
//! each block boundary.
//!
//! ## Namespace
//!
//! XFS does not store `"security.selinux"`. It stores `"selinux"` plus flag
//! bits, and the full name is reconstructed from them. Getting that wrong
//! renames the artifact rather than merely mislabelling a field.

use crate::bytes::{be_u16, be_u32, u8_at};
use crate::error::XfsError;
use crate::extent::{read_extents, BmbtRec};
use crate::inode::Inode;
use crate::superblock::Superblock;

/// `XFS_ATTR_LOCAL` — the leaf entry's value is held in the leaf block itself.
const ATTR_LOCAL: u8 = 0x01;
/// `XFS_ATTR_ROOT` — the `trusted.` namespace.
const ATTR_ROOT: u8 = 0x02;
/// `XFS_ATTR_SECURE` — the `security.` namespace.
const ATTR_SECURE: u8 = 0x04;
/// `XFS_ATTR_INCOMPLETE` — the attribute was mid-update when the filesystem
/// stopped. The entry is still reported: a half-written attribute is evidence
/// about what was happening, and hiding it would be the larger error.
const ATTR_INCOMPLETE: u8 = 0x80;

/// `di_aformat` — attribute fork held inline (shortform).
const AFORMAT_LOCAL: u8 = 1;
/// `di_aformat` — attribute fork described by an inline extent array.
const AFORMAT_EXTENTS: u8 = 2;
/// `di_aformat` — attribute fork described by a bmap btree.
const AFORMAT_BTREE: u8 = 3;

/// `XFS_ATTR3_LEAF_MAGIC` — a v5 (CRC) leaf block.
const ATTR3_LEAF_MAGIC: u16 = 0x3BEE;
/// `XFS_ATTR_LEAF_MAGIC` — a v4 leaf block.
const ATTR_LEAF_MAGIC: u16 = 0xFBEE;

/// The magic sits at offset 8, past `xfs_da_blkinfo`'s `forw`/`back`.
const LEAF_MAGIC_OFF: usize = 8;

/// Length of the v5 `xfs_attr3_leaf_hdr`.
///
/// **76 was tried first and was wrong.** It yields entries with `namelen = 221`
/// and a `nameidx` past the end of the block — garbage that a length check
/// alone would not have caught. The block states the answer itself: its
/// `freemap[0].base` reads 96 and it holds two 8-byte entries, so the entry
/// array starts at 80. The v5 header carries a trailing `__be32 pad2` that the
/// 76-byte sum omits.
const LEAF_HDR_LEN: usize = 80;
/// Length of the v4 `xfs_attr_leaf_hdr`: `xfs_da_blkinfo` (12) + `count`,
/// `usedbytes`, `firstused` (6) + `holes`, `pad1` (2) + `freemap[3]` (12).
const LEAF_HDR_LEN_V4: usize = 32;
/// Offset of `count` within a v5 leaf header, past `xfs_da3_blkinfo`.
const LEAF_COUNT_OFF: usize = 56;
/// Offset of `count` within a v4 leaf header, past `xfs_da_blkinfo`.
const LEAF_COUNT_OFF_V4: usize = 12;
/// One `xfs_attr_leaf_entry`.
const LEAF_ENTRY_LEN: usize = 8;

/// Length of `xfs_attr3_rmt_hdr`, prefixed to every remote value block on v5.
const RMT_HDR_LEN: usize = 56;
/// `XFS_ATTR3_RMT_MAGIC` (`"XARM"`).
const RMT_MAGIC: u32 = 0x5841_524D;

/// Refuse to assemble an attribute value larger than this. A value is bounded
/// by `XATTR_SIZE_MAX` (64 `KiB`) on Linux; the ceiling here is generous enough
/// to read a non-conforming image while still refusing an allocation bomb built
/// from a hostile `valuelen`.
const MAX_VALUE_LEN: usize = 16 * 1024 * 1024;

/// Which namespace an attribute belongs to, decoded from its flag bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrNamespace {
    /// No namespace bit set.
    User,
    /// `XFS_ATTR_ROOT`.
    Trusted,
    /// `XFS_ATTR_SECURE`.
    Security,
}

impl XattrNamespace {
    /// Decode the namespace from an entry's flag byte.
    ///
    /// `ROOT` and `SECURE` are mutually exclusive in practice; if both are set
    /// the image is malformed and `ROOT` wins, which is the kernel's own
    /// precedence.
    #[must_use]
    pub fn from_flags(flags: u8) -> Self {
        if flags & ATTR_ROOT != 0 {
            Self::Trusted
        } else if flags & ATTR_SECURE != 0 {
            Self::Security
        } else {
            Self::User
        }
    }

    /// The prefix prepended to the stored name to form the full name.
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            Self::User => "user.",
            Self::Trusted => "trusted.",
            Self::Security => "security.",
        }
    }
}

/// Where in the filesystem an attribute's bytes were found.
///
/// Reported rather than flattened: it is a fact about where the bytes
/// physically are, and the three shapes have very different meanings for a
/// reader trying to explain what it recovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrStorage {
    /// Inline in the inode's literal area.
    Shortform,
    /// In a leaf block, value held in the same block as the name.
    LeafLocal,
    /// In a leaf block, value out in its own blocks.
    LeafRemote {
        /// Logical block offset of the value within the attribute fork.
        valueblk: u32,
    },
}

/// One extended attribute.
#[derive(Debug, Clone)]
pub struct Xattr {
    /// The stored name, WITHOUT its namespace prefix — `selinux`, not
    /// `security.selinux`. Use [`Self::full_name`] for the presentable form.
    pub name: Vec<u8>,
    /// Namespace decoded from the entry flags.
    pub namespace: XattrNamespace,
    /// The attribute's value.
    pub value: Vec<u8>,
    /// Where the value was found.
    pub storage: XattrStorage,
    /// `XFS_ATTR_INCOMPLETE` was set: the attribute was mid-update when the
    /// filesystem stopped. Surfaced rather than filtered — the flag is itself
    /// evidence, and a caller that wants only complete attributes can say so.
    pub incomplete: bool,
}

impl Xattr {
    /// The attribute's full name, as the system presents it.
    #[must_use]
    pub fn full_name(&self) -> String {
        let prefix = self.namespace.prefix();
        let mut s = String::with_capacity(prefix.len() + self.name.len());
        s.push_str(prefix);
        s.push_str(&String::from_utf8_lossy(&self.name));
        s
    }
}

/// The attribute fork's bytes within the inode's literal area.
///
/// Returns an empty slice when `di_forkoff` is 0 — which means there is no
/// attribute fork at all, not that it is empty.
fn attr_fork(inode: &Inode) -> &[u8] {
    let off = (inode.forkoff as usize).saturating_mul(8);
    inode.data_fork.get(off..).unwrap_or(&[])
}

/// List every extended attribute on `inode`.
///
/// An inode with no attribute fork yields an empty list; that is not an error.
///
/// # Errors
///
/// [`XfsError::UnsupportedAttrFork`] when `di_aformat` is the btree form or an
/// unrecognised value. A btree attribute fork is rare — it needs more
/// attributes than a leaf can index — and returning an empty list for one would
/// report "no attributes" for a file that has many, which is the worst
/// available answer. The offending format byte is named in the error.
pub fn list_xattrs(image: &[u8], sb: &Superblock, inode: &Inode) -> Result<Vec<Xattr>, XfsError> {
    // forkoff == 0 means no attribute fork. Checked before aformat because a
    // forkless inode can still carry a stale aformat byte.
    if inode.forkoff == 0 {
        return Ok(Vec::new());
    }
    match inode.aformat {
        0 => Ok(Vec::new()),
        AFORMAT_LOCAL => Ok(parse_shortform(attr_fork(inode))),
        AFORMAT_EXTENTS => Ok(parse_leaf_fork(image, sb, inode)),
        other => Err(XfsError::UnsupportedAttrFork {
            aformat: other,
            detail: if other == AFORMAT_BTREE {
                "btree attribute fork (di_aformat = 3)"
            } else {
                "unrecognised di_aformat"
            },
        }),
    }
}

/// Parse the shortform attribute fork: a 4-byte header then packed entries.
///
/// A truncated or malformed entry ENDS the walk. The entries are laid end to
/// end with no terminator and no length to resynchronise on, so once one is
/// unreadable there is no trustworthy place to resume; continuing would emit
/// attributes assembled from the wrong bytes.
fn parse_shortform(fork: &[u8]) -> Vec<Xattr> {
    // hdr: totsize(be16) count(u8) padding(u8). The 4-byte length is derived,
    // not assumed: for the reference image the entries sum to 93 bytes and
    // hdr.totsize reads 97.
    const HDR_LEN: usize = 4;
    if fork.len() < HDR_LEN {
        return Vec::new();
    }
    let count = u8_at(fork, 2) as usize;
    let mut out = Vec::with_capacity(count.min(64));
    let mut off = HDR_LEN;
    for _ in 0..count {
        let Some(hdr) = fork.get(off..off + 3) else {
            break;
        };
        let namelen = hdr[0] as usize;
        let valuelen = hdr[1] as usize;
        let flags = hdr[2];
        let name_start = off + 3;
        let Some(name) = fork.get(name_start..name_start + namelen) else {
            break;
        };
        let value_start = name_start + namelen;
        let Some(value) = fork.get(value_start..value_start + valuelen) else {
            break;
        };
        out.push(Xattr {
            name: name.to_vec(),
            namespace: XattrNamespace::from_flags(flags),
            value: value.to_vec(),
            storage: XattrStorage::Shortform,
            incomplete: flags & ATTR_INCOMPLETE != 0,
        });
        off = value_start + valuelen;
    }
    out
}

/// Read the attribute fork's extent list and parse every leaf block in it.
fn parse_leaf_fork(image: &[u8], sb: &Superblock, inode: &Inode) -> Vec<Xattr> {
    let recs = read_extents(attr_fork(inode), u64::from(inode.aextents));
    let bs = sb.blocksize as usize;
    let mut out = Vec::new();
    for rec in &recs {
        for i in 0..rec.blockcount {
            let Some(block) = block_bytes(image, bs, rec.startblock.saturating_add(i)) else {
                continue;
            };
            // Only leaf blocks hold entries; a remote VALUE block sits in the
            // same fork and must not be parsed as one. The magic decides.
            let Some(v5) = leaf_kind(block) else { continue };
            parse_leaf_block(image, sb, block, &recs, v5, &mut out);
        }
    }
    out
}

/// `Some(true)` for a v5 leaf, `Some(false)` for v4, `None` if not a leaf.
fn leaf_kind(block: &[u8]) -> Option<bool> {
    match be_u16(block, LEAF_MAGIC_OFF) {
        ATTR3_LEAF_MAGIC => Some(true),
        ATTR_LEAF_MAGIC => Some(false),
        _ => None,
    }
}

/// The bytes of one filesystem block.
fn block_bytes(image: &[u8], blocksize: usize, fsblock: u64) -> Option<&[u8]> {
    let start = usize::try_from(fsblock).ok()?.checked_mul(blocksize)?;
    image.get(start..start.checked_add(blocksize)?)
}

/// Parse one leaf block's entries, appending to `out`.
fn parse_leaf_block(
    image: &[u8],
    sb: &Superblock,
    block: &[u8],
    recs: &[BmbtRec],
    v5: bool,
    out: &mut Vec<Xattr>,
) {
    let (hdr_len, count_off) = if v5 {
        (LEAF_HDR_LEN, LEAF_COUNT_OFF)
    } else {
        (LEAF_HDR_LEN_V4, LEAF_COUNT_OFF_V4)
    };
    let count = be_u16(block, count_off) as usize;
    // An entry array cannot extend past the block; a hostile count would
    // otherwise drive `nameidx` reads across the whole image.
    let max = block.len().saturating_sub(hdr_len) / LEAF_ENTRY_LEN;
    for i in 0..count.min(max) {
        let eo = hdr_len + i * LEAF_ENTRY_LEN;
        let nameidx = be_u16(block, eo + 4) as usize;
        let flags = u8_at(block, eo + 6);
        let namespace = XattrNamespace::from_flags(flags);
        let incomplete = flags & ATTR_INCOMPLETE != 0;

        if flags & ATTR_LOCAL != 0 {
            // xfs_attr_leaf_name_local: valuelen(be16) namelen(u8) name value
            let valuelen = be_u16(block, nameidx) as usize;
            let namelen = u8_at(block, nameidx + 2) as usize;
            let ns = nameidx + 3;
            let (Some(name), Some(value)) = (
                block.get(ns..ns + namelen),
                block.get(ns + namelen..ns + namelen + valuelen),
            ) else {
                continue;
            };
            out.push(Xattr {
                name: name.to_vec(),
                namespace,
                value: value.to_vec(),
                storage: XattrStorage::LeafLocal,
                incomplete,
            });
        } else {
            // xfs_attr_leaf_name_remote: valueblk(be32) valuelen(be32) namelen name
            let valueblk = be_u32(block, nameidx);
            let valuelen = be_u32(block, nameidx + 4) as usize;
            let namelen = u8_at(block, nameidx + 8) as usize;
            let ns = nameidx + 9;
            let Some(name) = block.get(ns..ns + namelen) else {
                continue;
            };
            let value = read_remote_value(image, sb, recs, valueblk, valuelen, v5);
            out.push(Xattr {
                name: name.to_vec(),
                namespace,
                value,
                storage: XattrStorage::LeafRemote { valueblk },
                incomplete,
            });
        }
    }
}

/// Assemble a remote attribute value.
///
/// `valueblk` is a LOGICAL block offset inside the attribute fork, so it is
/// mapped through the fork's own extents rather than used as a filesystem
/// block. On v5 each block carries a 56-byte `xfs_attr3_rmt_hdr` which is
/// stripped; on v4 there is no such header.
///
/// Returns as many bytes as could be read. A short result is visible to the
/// caller as a length mismatch against the leaf entry's `valuelen`, which is
/// more useful than an error that discards the bytes that WERE recoverable.
fn read_remote_value(
    image: &[u8],
    sb: &Superblock,
    recs: &[BmbtRec],
    valueblk: u32,
    valuelen: usize,
    v5: bool,
) -> Vec<u8> {
    if valuelen > MAX_VALUE_LEN {
        return Vec::new();
    }
    let bs = sb.blocksize as usize;
    let payload = if v5 {
        bs.saturating_sub(RMT_HDR_LEN)
    } else {
        bs
    };
    if payload == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(valuelen);
    let mut logical = u64::from(valueblk);
    while out.len() < valuelen {
        let Some(fsb) = map_logical(recs, logical) else {
            break;
        };
        let Some(block) = block_bytes(image, bs, fsb) else {
            break;
        };
        let body = if v5 {
            // Validate the header rather than trusting the offset: a block that
            // is not a remote-value block means the extent map was misread, and
            // splicing its bytes in would fabricate part of the value.
            if be_u32(block, 0) != RMT_MAGIC {
                break;
            }
            block.get(RMT_HDR_LEN..).unwrap_or(&[])
        } else {
            block
        };
        let want = (valuelen - out.len()).min(body.len());
        out.extend_from_slice(&body[..want]);
        logical += 1;
    }
    out
}

/// Map a logical block offset within a fork to its filesystem block.
fn map_logical(recs: &[BmbtRec], logical: u64) -> Option<u64> {
    recs.iter()
        .find(|r| logical >= r.startoff && logical < r.startoff.saturating_add(r.blockcount))
        .map(|r| r.startblock.saturating_add(logical - r.startoff))
}
