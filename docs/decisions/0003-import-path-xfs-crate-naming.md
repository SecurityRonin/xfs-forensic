# 3. Publish as `xfs-core` but take the import path `xfs`

Date: 2026-07-24

Status: Accepted

## Context

The fleet naming grammar (`ronin-issen/CLAUDE.md`, "Crate naming grammar")
reserves `<x>-core` for the reader and `<x>-forensic` for the analyzer, and adds
an import-path rule: if the bare `<x>` name is taken on crates.io by an
*unpopular / unrelated* third party we can safely coexist with, publish
`<x>-core` with `[lib] name = "<x>"` so consumers write `use <x>::…`; if the
bare name is a *popular* crate, do not hijack the import.

The bare `xfs` name on crates.io is an **abandoned 2016 crate that parses XFS
performance data, not the filesystem** — unrelated and not popular
(`docs/RESEARCH.md` §2 lists it: "Irrelevant (name collision only)").

## Decision

- Publish the reader as **`xfs-core`** and the analyzer as **`xfs-forensic`**.
- Set `[lib] name = "xfs"` in `core/Cargo.toml` so the import path is the natural
  `use xfs::Superblock;` (see `core/src/lib.rs`).
- Keep `xfs-forensic` importing `xfs` (`use xfs::{Superblock, …}` in
  `forensic/src/lib.rs`), unaffected by the package/lib-name distinction.

The reasoning is captured verbatim in the `core/Cargo.toml` `[lib]` comment:
"The bare `xfs` crate name on crates.io is an abandoned 2016 perf-data parser
(unrelated to the filesystem, not popular), so we take the import path `xfs`."

## Consequences

- Consumers get an ergonomic `xfs::` import while the published package name
  stays self-describing on crates.io as the core of the `xfs-forensic` suite.
- No collision with the popular-crate case (unlike `ntfs`, where the fleet keeps
  `ntfs_core` to avoid hijacking Colin Finck's `ntfs`).
- If the abandoned `xfs` crate were ever revived and became popular, the import
  path — not the package name — would be the thing to reconsider.
