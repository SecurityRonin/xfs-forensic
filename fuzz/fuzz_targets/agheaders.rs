#![no_main]
//! The per-AG headers — AGF (free-space btree roots), AGI (inode btree roots +
//! unlinked buckets), AGFL (free list) — are attacker-controlled sector bytes.
//! Both the plain and the v5 CRC-verifying parse paths must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = xfs::Agf::parse(data);
    let _ = xfs::Agf::parse_verified(data, true);
    let _ = xfs::Agf::parse_verified(data, false);

    let _ = xfs::Agi::parse(data);
    let _ = xfs::Agi::parse_verified(data, true);
    let _ = xfs::Agi::parse_verified(data, false);

    // AGFL is sector-size-relative — drive a couple of plausible sizes.
    for sectorsize in [512u32, 4096] {
        let _ = xfs::Agfl::parse_v5(data, sectorsize);
        let _ = xfs::Agfl::parse_v4(data, sectorsize);
    }
});
