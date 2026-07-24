# 7. forensic-vfs adapter behind an opt-in `vfs` feature

Date: 2026-07-24

Status: Accepted

## Context

The fleet's VFS/universal-container policy (`ronin-issen/CLAUDE.md`, "VFS &
Universal Container Abstraction") makes `forensic-vfs` the KNOWLEDGE-leaf
navigation contract: filesystem readers implement its traits so a whole stack
(`E01 → GPT → BitLocker → NTFS`) reads as one `Arc<dyn FileSystem>` and no
consumer special-cases one filesystem. An XFS reader should compose the same way.

But not every consumer of `xfs-core` wants the filesystem-navigation contract.
A caller that only needs the parser should not pay the `forensic-vfs`
dependency. The `forensic-vfs` contract has also been a moving target during
early development — the git log shows migrations across 0.2 → 0.3 (FsKind
newtype) → 0.4 → 0.5 → 0.7 (`c46ca4d`, `cefcb21`, `09f3746`, `7ba8026`,
`1798067`, `a5e2be9`), and the adapter was initially deferred until
`forensic-vfs 0.2` published (`c8b4347`).

## Decision

Provide `impl forensic_vfs::FileSystem for XfsFs` in `core/src/vfs.rs`, gated
behind an **opt-in `vfs` Cargo feature** (`core/Cargo.toml`
`vfs = ["dep:forensic-vfs"]`; the module is `#[cfg(feature = "vfs")]`). The bare
`xfs-core` reader has no `forensic-vfs` dependency; a consumer enables it with
`xfs-core = { version = "0.1", features = ["vfs"] }`.

## Consequences

- The bare reader stays dependency-light (parser-only consumers pay no
  `forensic-vfs` cost), while forensic-vfs-engine consumers get an XFS volume as
  `Arc<dyn FileSystem>` — the fleet's fs-agnostic navigation.
- `forensic-vfs` churn is contained to the optional path; a bump touches one
  workspace-dependency line and the `vfs` module, not every parser consumer.
- The adapter is covered by non-gated synthetic-tree tests (`c53982a`,
  `513858b`) so the feature does not rot.
