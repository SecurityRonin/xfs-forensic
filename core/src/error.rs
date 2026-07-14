//! Error types for the XFS reader.

use thiserror::Error;

/// Errors surfaced while parsing XFS on-disk structures.
///
/// Every variant names the offending value so an "unknown/invalid" report hands
/// the investigator the evidence (raw bytes / offset), never a bare "invalid".
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum XfsError {
    /// The buffer was too small to hold the structure being parsed.
    #[error("buffer too small for {structure}: need {need} bytes, have {have}")]
    Truncated {
        /// Name of the structure that could not be read.
        structure: &'static str,
        /// Minimum byte length required.
        need: usize,
        /// Byte length actually available.
        have: usize,
    },

    /// The superblock magic number did not match `XFSB` (`0x5846_5342`).
    ///
    /// Carries the four bytes actually found so the caller can identify what the
    /// image really is (fail-loud with the offending value).
    #[error("bad superblock magic: found {found:#010x} (bytes {bytes:02x?}), expected 0x58465342 (\"XFSB\")")]
    BadMagic {
        /// The 32-bit big-endian value read at offset 0.
        found: u32,
        /// The four raw bytes at offset 0.
        bytes: [u8; 4],
    },

    /// A directory used a format this reader does not yet handle (leaf / node /
    /// btree), or a block directory carried an unrecognized data-block magic.
    ///
    /// Fail-loud rather than return an empty listing: `detail` names the format
    /// and the offending value (magic bytes / size), so the investigator sees
    /// *what* could not be read, never a silently-empty directory.
    #[error("unsupported directory: {detail}")]
    UnsupportedDir {
        /// Human description naming the format and the offending value.
        detail: String,
    },

    /// A path component did not resolve during [`crate::read_by_path`]: the named
    /// component was not found in its parent directory, or a non-final component
    /// was not itself a directory. Carries the offending path and component.
    #[error("path not found: component {component:?} of {path:?} did not resolve")]
    PathNotFound {
        /// The full path being resolved.
        path: String,
        /// The specific component that failed to resolve.
        component: String,
    },
}
