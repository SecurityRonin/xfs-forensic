# 6. Reuse the `crc` crate for v5 CRC32c; accept the resulting 1.83 MSRV floor

Date: 2026-07-24

Status: Accepted

## Context

XFS v5 (self-describing) metadata stamps each block with a CRC32c
(Castagnoli / iSCSI polynomial). Verifying it is required for the
`XFS-CRC-MISMATCH` finding and for Tier-1 superblock validation. The fleet's
never-hand-roll discipline and DRY-via-search-first rule say a solved checksum
should reuse a mature, audited crate, not a hand-derived table.

The competing constraint is the library MSRV policy: published fleet libraries
keep a **low, CI-verified MSRV** (1.75/1.80) as a compatibility feature.
`xfs-core`'s own source compiles as low as 1.75. But the batteries-included
default resolution of `crc = "3"` pulls `crc 3.4.0`, which declares
`rust-version = 1.83`, so a plain `cargo build -p xfs-core` fails below 1.83.

## Decision

- Use the `crc` crate (`CRC_32_ISCSI`) for all v5 CRC32c verification
  (`core/src/crc.rs`, `crc = "3"` in `[workspace.dependencies]`), rather than
  hand-rolling the polynomial.
- Set the declared/CI-verified MSRV floor to **1.83** (`[workspace.package]
  rust-version = "1.83"`), the value default resolution can actually honour,
  and verify it in the `msrv` CI job — rather than advertise a 1.75 that
  `cargo build` cannot meet.

The full reasoning is recorded verbatim in the `Cargo.toml`
`[workspace.package]` comment: "xfs-core's own code compiles as low as 1.75; the
floor is dictated by a dependency, not our source … `crc 3.4.0` declares
`rust-version = 1.83` … we keep the floor as low as the deps allow and verify it
in the `msrv` CI job."

## Consequences

- No hand-derived checksum table to get wrong; the audited `crc` crate carries
  the CRC32c.
- The advertised MSRV is honest — it matches what default resolution builds —
  at the cost of a floor higher than the source alone would allow. Following the
  fleet rule "keep the floor as low as the deps allow," 1.83 is the real floor,
  not an arbitrary bump.
- If a future `crc` release lowers its `rust-version`, the floor can drop with
  it in a deliberate, CI-verified pass.
