# opForge v0.9.4 Release Notes

## Scope

This release extends opForge with initial Motorola 6800-family support,
starting with Motorola 6809 and Hitachi HD6309 CPU targets.

## Highlights

- New CPU family: `motorola6800`.
- New CPUs: `m6809` and `hd6309` (with documented aliases).
- Baseline 6809 encode coverage includes:
  - inherent forms (`NOP`, `RTS`, `ABX`)
  - immediate/direct/extended loads (`LDA`, `LDB`, `LDD`)
  - indexed baseline forms (`n,R`, `A/B/D,R`, and auto inc/dec `,R+`, `,R++`, `,-R`, `,--R`)
  - short and long branch core forms (`BRA`/conditionals and `LBRA`/`LBSR`)
  - register-pair and register-list ops (`TFR`, `EXG`, `PSHS`, `PULS`, `PSHU`, `PULU`)
- HD6309 extension coverage added (accepted only under `.cpu hd6309`):
  - `SEXW`, `CLRD`, `CLRW`, `CLRE`, `CLRF`.

## Added

- Family module: `src/families/m6800/*`
- CPU modules: `src/m6809/*`, `src/hd6309/*`
- Examples:
  - `examples/6809_simple.asm`
  - `examples/6809_indexed_modes.asm`
  - `examples/6809_branches.asm`
  - `examples/6809_register_ops.asm`
  - `examples/6309_extensions.asm`
- Reference outputs for each added example under `examples/reference/`.

## Changed

- Registry wiring now advertises Motorola 6800-family CPUs in capability/cpusupport paths.
- Unknown CPU diagnostics include 6809/6309 aliases.
- CLI/help and docs now list 6809/6309 CPU targets.

## Validation

Validated with targeted and full test gates during implementation:

- `cargo fmt`
- `cargo clippy -- -D warnings`
- `cargo audit`
- `cargo test`

## Upgrade Notes

- No breaking directive/macro syntax changes were introduced for existing families.
- VM runtime support for Motorola 6800-family encode is tracked as a follow-up phase and remains staged (non-authoritative rollout).
