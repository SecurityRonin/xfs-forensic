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
}
