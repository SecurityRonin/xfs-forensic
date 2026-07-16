#![no_main]
//! The superblock sector is fully attacker-controlled — `parse` must never
//! panic, and neither must the geometry/inode-location helpers driven from it.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(sb) = xfs::Superblock::parse(data) {
        // Geometry-derived helpers exercised over the arbitrary superblock.
        let _ = sb.has_ftype();
        let _ = sb.version();
        let _ = sb.is_v5();
        for ino in [0u64, 1, 64, u64::MAX] {
            let _ = sb.inode_to_location(ino);
            let _ = sb.read_inode(data, ino);
        }
    }
});
