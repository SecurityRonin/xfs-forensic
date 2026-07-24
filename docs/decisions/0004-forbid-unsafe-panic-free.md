# 4. `#![forbid(unsafe_code)]`, pure-Rust, panic-free parsing

Date: 2026-07-24

Status: Accepted

## Context

Both crates parse untrusted, attacker-controllable disk images. The fleet's
Paranoid Gatekeeper standard (`ronin-issen/CLAUDE.md`) and the global Rust lint
posture require: never panic, never read out of bounds, never trust a length
field. The `unsafe`-exception law makes `forbid(unsafe)` the default and the
goal — a *provable*, badge-able "zero places a crafted input can corrupt memory"
— to be downgraded to `deny` + a bounded per-site `#[allow]` only when a real
benefit (e.g. an `mmap`) justifies it.

`xfs-core` reads over a byte slice (`&[u8]`), not a memory map. There is no
mmap, no C `-sys` dependency, and no performance path that needs `get_unchecked`.
So the justification the mmap readers (`ewf`, `memory-forensic`) invoke to drop
to `deny` does not apply here.

## Decision

- `unsafe_code = "forbid"` in the workspace lints (`Cargo.toml`
  `[workspace.lints.rust]`), inherited by both members; `#![forbid(unsafe_code)]`
  also stated at the top of `core/src/lib.rs` and `forensic/src/lib.rs`. No
  `unsafe`, no C bindings.
- Panic-free by lint: `unwrap_used = "deny"` and `expect_used = "deny"` in
  `[workspace.lints.clippy]`, with `clippy.toml` `allow-unwrap-in-tests`
  exempting tests only.
- Every integer/length/offset field is read through bounds-checked big-endian
  helpers that yield `0`/`None` out of range (see ADR 0005), so a malformed or
  truncated image degrades to an empty/typed result, never a panic.
- Robustness is *measured*, not merely asserted: one `cargo-fuzz` target per
  parsed structure plus a `fuzz_forensic` pipeline target (`fuzz.yml`), so the
  README leads with "fuzzed" and qualifies the static half as "panic-free by
  lint".

## Consequences

- The repo can wear the genuine `unsafe forbidden` badge (unlike the mmap
  crates, which must say "`deny` + N bounded allows").
- A crafted image cannot reintroduce the C/C++ memory-corruption class; the
  compiler proves it fleet-wide for this reader.
- No zero-copy mmap fast path; the reader works over slices the caller provides.
  This is the accepted trade for a provable safety posture on an evidence parser.
