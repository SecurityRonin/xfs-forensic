# 5. Bounds-checked big-endian readers live in a local `bytes.rs`, not the fleet `safe-read` crate

Date: 2026-07-24

Status: Accepted

## Context

The fleet Paranoid Gatekeeper standard (`ronin-issen/CLAUDE.md`) is explicit:
"Bounds-checked readers on the image — route through the `safe-read` crate;
NEVER hand-roll a per-crate `bytes.rs`." `safe-read` is the fleet's single
audited, `no_std`, `forbid(unsafe)`, fuzzed implementation, and it provides
big-endian (`be_u16`/`be_u32`/`be_u64`) as well as little-endian helpers — so
XFS's big-endian on-disk layout is within its remit. The stated failure mode the
rule guards against is hand-rolled copies drifting and some `data.get(off..off+n)`
variants overflowing `usize`.

`xfs-core` instead carries its own `core/src/bytes.rs` with `be_u16`, `be_u32`,
`be_u64`, and `u8_at`, each returning `0` out of range via `data.get(off..off+n)`.
These readers do meet the *behavioral* bar (bounds-checked, panic-free, and
fuzzed by the repo's own `cargo-fuzz` targets), but they are a local
reimplementation of exactly what `safe-read` already provides.

## Decision

Keep the hand-rolled `core/src/bytes.rs` readers as the reader's integer-field
edge, rather than depending on `safe-read`.

Rationale reconstructed from structure; original intent not recovered in
available history. The git log and code comments record *what* the readers do
(the `bytes.rs` module doc cites "the Paranoid Gatekeeper standard") but not
*why* `safe-read` was not adopted — no commit message, issue, or comment
explains the divergence. It may be an oversight predating the `safe-read`
mandate, or a deliberate choice to keep `xfs-core` free of the extra dependency;
the evidence does not distinguish these.

## Consequences

- The readers satisfy the panic-free/bounds-checked *behavior* the standard
  requires, so there is no correctness or safety regression today.
- The repo nonetheless diverges from the binding "never hand-roll `bytes.rs`"
  rule and forgoes the shared-audit and drift-resistance benefits of the single
  `safe-read` implementation.
- **Follow-up (flagged, not actioned here):** migrate `core/src/bytes.rs` to
  `safe-read` (or record an explicit, evidence-backed reason to keep the local
  copy) so this ADR's unrecovered rationale is replaced by a decided one. Until
  then the divergence is documented, not hidden.
