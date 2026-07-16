#![no_main]
//! The bmap B+tree (bmbt) root and on-disk blocks are attacker-controlled: the
//! root fork carries a level/numrecs header followed by key/ptr pairs pointing
//! at further blocks that index into the image. `read_btree_extents` (ptr walk +
//! block decode, bounded by `MAX_BMBT_PTRS`) and the block CRC verifier must
//! never panic, recurse unbounded, or over-read.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // v5 bmbt block CRC verifier over arbitrary bytes.
    let _ = xfs::verify_bmbt_block_crc(data);

    // Full ptr-walk from an arbitrary root fork against an arbitrary image.
    if let Ok(sb) = xfs::Superblock::parse(data) {
        let _ = xfs::read_btree_extents(data, &sb, data);
    }
});
