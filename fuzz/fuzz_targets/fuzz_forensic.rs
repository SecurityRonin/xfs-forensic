#![no_main]
//! Full inspect/audit + carve pipeline over an arbitrary "image": the auditor
//! (`audit_image` / `audit_findings`) and the deleted-inode recovery
//! (`recover_deleted`) must never panic on any byte string — this is the
//! end-to-end forensic front door driven by attacker-controlled disk bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Structural anomaly audit (typed anomalies + graded findings).
    let _ = xfs_forensic::audit_image(data);
    let _ = xfs_forensic::audit_findings(data, "fuzz");

    // Deleted-inode recovery needs the superblock geometry; drive it whenever a
    // superblock parses out of the same arbitrary bytes.
    if let Ok(sb) = xfs::Superblock::parse(data) {
        let _ = xfs_forensic::recover_deleted(data, &sb);
    }
});
