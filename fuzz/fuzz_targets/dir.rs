#![no_main]
//! The three on-disk directory layouts XFS uses — shortform (inline in the
//! inode fork), block (single-block dir), and data/leaf blocks — are all
//! attacker-controlled. Every decoder, with and without the ftype byte, plus
//! the v5 directory-block CRC verifier, must never panic on any byte string.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for has_ftype in [true, false] {
        let _ = xfs::read_shortform_dir(data, has_ftype);
        let _ = xfs::read_block_dir(data, has_ftype);
        let _ = xfs::read_data_dir_block(data, has_ftype);
    }
    let _ = xfs::verify_dir_block_crc(data);
});
