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
3. MOS6502 example-program differential parity passes for `6502_simple.asm`, `6502_allmodes.asm`, and `mos6502_modes.asm`.
4. Full project validation is green (`cargo fmt`, `cargo clippy -- -D warnings`, `cargo audit`, `make test`).
5. Deterministic package snapshots remain stable for hierarchy chunks.
6. Documentation and migration notes are synchronized with runtime behavior.

## Known limitations (v0.1)

- opThread package execution is still staged; native Rust handlers remain the production encode path.
- Parity harness is still line/corpus-level; full program/package bytecode execution parity is deferred.
- `.optst` vectors are draft line-level cases (not yet full program-level suites).

## Deferred work for v0.2

- Full package bytecode encode path execution in runtime.
- Expanded parity corpus (full examples, relocation-heavy suites, larger diagnostics coverage).
- Multi-family rollout with per-family migration playbooks.

## Active v0.2 execution plan (MOS6502 family only)

- Current execution checklist: `dev-docs/NextSteps/opthread_vm_mos6502_v0_2_realization_plan.md`.
- This v0.2 track is intentionally limited to the MOS6502 family (`m6502`, `65c02`, `65816`) before any multi-family rollout.

## Active v0.3 execution plan (MOS6502 parse/resolve realization)

- Current execution checklist: `dev-docs/NextSteps/opthread_vm_parse_resolve_v0_3_mos6502_plan.md`.
- This v0.3 track starts with `m6502` parse/resolve realization before extending to `65c02` and `65816`.
