#![no_main]
//! Extent decoding is a top attacker-exposed surface: a data fork carries a
//! claimed `nextents` count of 16-byte `xfs_bmbt_rec` records, each packing a
//! start-block / block-count that indexes into the image. Neither the record
//! unpack, the extent-list read, nor the block-assembly (with a hostile `size`)
//! may panic, over-read, or allocation-bomb.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A single packed extent record from the first 16 bytes.
    if let Some(chunk) = data.get(0..16) {
        let mut raw = [0u8; 16];
        raw.copy_from_slice(chunk);
        let _ = xfs::BmbtRec::unpack(&raw);
    }

    // The superblock geometry the assembler needs; drive the full fork paths
    // over the same arbitrary bytes when a superblock parses out of them.
    if let Ok(sb) = xfs::Superblock::parse(data) {
        // Untrusted nextents (bounded internally by the fork length) and an
        // untrusted size (the allocation-bomb guard is what we exercise).
        for nextents in [0u32, 1, 3, u32::MAX] {
            let recs = xfs::read_extents(data, nextents);
            let _ = xfs::assemble_extents(data, &sb, &recs, data.len() as u64);
            let _ = xfs::assemble_extents(data, &sb, &recs, u64::MAX);
            let _ = xfs::read_file_from_fork(data, &sb, data, nextents, u64::MAX);
        }
    }
});
