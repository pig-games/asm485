# opThread v0.1 Rollout Criteria and Deferred Work

Status: draft implementation gate
Last updated: 2026-02-14

## Feature-flag policy

- Keep opThread parity checks and package/runtime integration behind feature flag surfaces until parity gates are green.
- Current parity smoke gate runs with `--features opthread-parity`.
- MOS6502 pilot runtime/package differential gate runs with `--features opthread-runtime`.

## Enablement criteria for expanding beyond pilot family

1. Pilot family parity smoke passes for bytes + diagnostics on the `.optst` corpus.
2. MOS6502 base-CPU differential parity corpus passes in both native and package-runtime modes.
3. Full project validation is green (`cargo fmt`, `cargo clippy -- -D warnings`, `cargo audit`, `make test`).
4. Deterministic package snapshots remain stable for hierarchy chunks.
5. Documentation and migration notes are synchronized with runtime behavior.

## Known limitations (v0.1)

- opThread package execution is still staged; native Rust handlers remain the production encode path.
- Parity harness is still line/corpus-level; full program/package bytecode execution parity is deferred.
- `.optst` vectors are draft line-level cases (not yet full program-level suites).

## Deferred work for v0.2

- Full package bytecode encode path execution in runtime.
- Expanded parity corpus (full examples, relocation-heavy suites, larger diagnostics coverage).
- Multi-family rollout with per-family migration playbooks.
