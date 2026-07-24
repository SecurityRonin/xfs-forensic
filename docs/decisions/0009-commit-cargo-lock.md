# 9. Commit `Cargo.lock` in the pure-library workspace (reversing the earlier gitignore)

Date: 2026-07-24

Status: Accepted

## Context

Early in the repo's life `Cargo.lock` was gitignored, following the old
convention that a pure-library workspace does not commit its lock (commit
`6c1e3cf`, "gitignore Cargo.lock (pure-library workspace)").

The fleet later adopted `cargo-vet` for supply-chain review (commit `4081219`).
`cargo vet --locked` combined with an *un*-committed lock makes CI fresh-resolve
the latest of every dependency on every run, so the moment any transitive dep
publishes a new version the version-pinned vet exemptions go stale and the gate
turns red — the "freshness treadmill." This is the exact failure the fleet
batteries-included standard ("Commit `Cargo.lock` in EVERY fleet repo — binary
AND library") documents: for libraries the reason is cargo-vet stability, not
shipping a graph.

## Decision

Commit `Cargo.lock`, reversing the earlier gitignore. Done in commit `c8dc19f`
("commit Cargo.lock to stabilize cargo-vet (end freshness treadmill)"), after
adopting the fleet Renovate + pre-commit + cargo-vet supply-chain config
(`5bffa92`, `4081219`).

## Consequences

- CI honours the pinned graph, so vet exemptions stay valid until the lock is
  deliberately bumped — no more red gate on an unrelated upstream release.
- Renovate `lockFileMaintenance` bumps the lock in a controlled, reviewed PR
  where the exemption/audit regen happens once, not on every push.
- Committing a library's lock is harmless to downstream consumers (a dependent
  still ignores a dependency's lock); it governs only this workspace's own
  CI/dev, which is what needed stabilizing.
