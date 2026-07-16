#![no_main]
//! The on-disk inode core (`xfs_dinode`, v2 100-byte / v3 176-byte) is
//! attacker-controlled. `parse` and every field/format helper derived from it
//! must never panic on any byte string.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(inode) = xfs::Inode::parse(data) {
        let _ = inode.file_type();
        let _ = inode.is_dir();
        let _ = inode.is_reg();
        let _ = inode.is_bigtime();
        let _ = inode.data_fork_offset();
    }
});
