#![no_main]
//! v5 self-describing metadata carries an embedded CRC32c at a per-structure
//! offset. Both the raw verifier (with a hostile, near-`usize::MAX` offset that
//! must not overflow) and the v4/v5 status seam must be panic-free for any
//! buffer and any offset.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    // First 8 bytes select a (possibly hostile) CRC offset; the rest is buffer.
    let crc_offset = usize::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let buffer = &data[8..];
    let _ = xfs::verify_crc(buffer, crc_offset);
    let _ = xfs::crc_status(true, buffer, crc_offset);
    let _ = xfs::crc_status(false, buffer, crc_offset);
});
