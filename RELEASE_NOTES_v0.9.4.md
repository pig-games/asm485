# opForge v0.9.4 Release Notes

## Scope

This release extends opForge in two major areas:

- initial Motorola 6800-family support (`m6809` and `hd6309`)
- a new Rust Language Server Protocol implementation (`opforge-lsp`)

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
- New `opforge-lsp` binary for editor integration over LSP 3.17.
- LSP feature surface includes:
  - diagnostics + quick-fix code actions from fixits
  - CPU-aware completion (nearest prior `.cpu` context)
  - semantic hover and completion metadata (kind/scope/value/declaration hints)
  - go-to-definition, references, rename, document symbols, workspace symbols
  - deterministic definition/workspace-symbol ordering across multi-file candidates
  - debounce/on-save validation behavior with stale-result suppression
  - unsaved overlay remap support for dependency diagnostics

## Added

- Family module: `src/families/m6800/*`
- CPU modules: `src/m6809/*`, `src/hd6309/*`
- LSP binary entrypoint: `src/bin/opforge_lsp.rs`
- LSP implementation modules: `src/lsp/*`
- Shared registry constructor used across assembler/VM/LSP: `build_default_registry()`
- VS Code reference client scaffold: `clients/vscode/*`
- Client-perspective LSP integration test harness and coverage:
  - `tests/common/lsp_client.rs`
  - `tests/lsp_client_integration.rs`
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
- Registry defaults are centralized for parity between CLI assembler behavior,
  VM tooling, and editor (LSP) capability resolution.
- VM editor token/runtime bridge defaults now consume the shared registry
  constructor to avoid CPU/family/dialect drift across surfaces.

## Validation

Validated with targeted and full test gates during implementation:

- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo audit`
- `cargo test`
- `cargo test --test lsp_client_integration`

## Upgrade Notes

- No breaking directive/macro syntax changes were introduced for existing families.
- Motorola 6800-family VM rollout is now aligned with other authoritative families:
  instruction encode/runtime, expression evaluation VM, and expression parser VM are all default-authoritative.
- `opforge-lsp` is a new stdio-based language server binary; existing `opforge`
  CLI behavior remains unchanged.
- VS Code reference-client settings are available under the `opforgeLsp.*`
  namespace (roots/includePaths/modulePaths/defines/defaultCpu/validation/opforgePath).
