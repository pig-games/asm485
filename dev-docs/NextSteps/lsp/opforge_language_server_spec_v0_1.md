# opForge Language Server Specification v0.1 (LSP 3.17, Hybrid Engine)

Status: Draft for implementation handoff
Date: 2026-02-25

## Summary

Build a new `opforge-lsp` server that is protocol-first (LSP 3.17), ships a VS Code reference client, and supports all current and future opForge CPU/family/dialect pipelines via runtime registry/chunk discovery instead of hard-coded tables.

Phase 1 scope is Core Authoring:
- diagnostics
- quick-fix code actions from fixits
- CPU-aware completion
- hover
- go-to-definition (workspace symbols/modules)
- document symbols

Execution model is hybrid:
- in-process engine for low-latency editor intelligence
- debounced/on-save full validation through `opforge` CLI JSON diagnostics with unsaved-buffer overlay

## Agreed Defaults

- Phase 1 scope: Core Authoring
- backend: Hybrid
- protocol/client target: LSP 3.17 + VS Code reference client
- CPU context: nearest prior `.cpu`
- validation cadence: debounced on-change + on-save
- root policy: configured roots + active-file fallback
- unsaved overlay: enabled

## Public APIs / Interfaces / Types

No assembler behavior changes in this spec branch.

Planned implementation surface (for later code branch) should expose reusable helper APIs so LSP does not reimplement parsing/CPU semantics:

1. Add a public default-registry constructor used by assembler, VM, and LSP to guarantee identical CPU/family/dialect registration order and coverage.
2. Expose VM token-bridge parsing/tokenization APIs through a public editor-safe surface.
3. Add runtime-directive introspection so completion/hover can discover CPU-specific runtime directives (for now `.assume` on 65816) without hard-coding in LSP.
4. Keep `.dialect` unsupported in source. Dialect resolution remains pipeline-driven.

## Architecture

1. Add a new binary entrypoint `opforge-lsp`.
2. Keep `opforge` CLI behavior unchanged.
3. Add dedicated LSP modules for:
- session/config
- CPU-context resolver
- completion/hover
- workspace symbol index
- CLI validation runner
- protocol adapters

4. Build capability snapshot from `ModuleRegistry + build_hierarchy_chunks_from_registry` so families/cpus/dialects/forms/registers are discovered dynamically.
5. Maintain per-document incremental state:
- text version
- CPU transitions by line
- lightweight symbol declarations
- pending validation task handle

6. Enforce cancellation semantics: newest document version wins; stale validation responses are discarded.

## CPU / Family / Dialect Contract

1. Resolve CPU names with existing registry rules (`cpu_name_list` / `resolve_cpu_name`) so aliases remain first-class (`8080`, `6502`, `65c816`, `mega65`, etc.).
2. Resolve effective context at cursor using nearest prior `.cpu` in same file.
3. If no in-file `.cpu`, use workspace default CPU.
4. If no workspace default is configured, use opForge default CPU.
5. Resolve dialect exclusively through existing pipeline resolution rules.
6. Mnemonic completion/validation uses precedence: dialect -> cpu -> family.

Support coverage intent is registry-driven and must include currently shipped pipelines:
- Intel8080 family (`8085/intel8080`, `z80/zilog`)
- MOS6502 family (`m6502`, `65c02`, `65816`, `45gs02` with `transparent`)

## LSP Feature Specification (Phase 1)

1. `textDocument/completion`
- directives
- `.cpu` names/aliases
- mnemonics valid in resolved pipeline
- registers valid in resolved pipeline
- symbol candidates from current scope/workspace index

2. `textDocument/hover`
- symbols: definition/location/value context where available
- mnemonics: owning scope (dialect/cpu/family) and compatibility notes

3. `textDocument/definition`
- local symbol definitions
- workspace symbol definitions
- `.use` module target navigation
- deterministic handling of ambiguous matches (multi-result)

4. `textDocument/documentSymbol`
- modules
- namespaces
- labels
- assignments
- macros/segments/statements

5. `textDocument/codeAction`
- convert diagnostic fixits to quick-fix edits
- mark `machine-applicable` fixes as preferred
- expose `maybe-incorrect` fixes as non-preferred

6. `textDocument/publishDiagnostics`
- publish deduplicated diagnostics keyed by stable tuple
  `(code,file,line,col_start,col_end,message)`
- avoid duplicate pass1/pass2 emission noise

## Hybrid Validation Lane

1. Run low-latency in-process analysis continuously for completion/hover/definition.
2. Run full validation through `opforge --format json` on debounce and on-save.
3. Use configured root files first.
4. If no configured root applies, validate active file as root.
5. Use temp overlay workspace mirror so unsaved buffers participate in full validation.
6. Remap overlay paths in diagnostics/fixits back to original workspace URIs before publish/code-action generation.
7. Pass configured include/module paths/defines/cpu into CLI validation invocation.

## Workspace Symbol Index

Build and incrementally update an index over configured roots and reachable module files.

Track at minimum:
- label declarations
- assignment-defined symbols
- `.use` imports (module, alias, selective items)
- scope/module ownership + visibility context where available

Definition resolution order should be deterministic and semantics-aligned:
- local scope first
- module/import rules
- global fallback

## Configuration Surface

Proposed LSP settings:

- `opforgeLsp.roots`
- `opforgeLsp.includePaths`
- `opforgeLsp.modulePaths`
- `opforgeLsp.defines`
- `opforgeLsp.defaultCpu`
- `opforgeLsp.validation.debounceMs` (default 500)
- `opforgeLsp.validation.onSave` (default true)
- `opforgeLsp.opforgePath` (optional explicit CLI path)

## Constraints

1. Reuse opForge tokenizer/parser/runtime bridge logic; do not build a second grammar.
2. Reuse existing diagnostics schema and fixit applicability semantics.
3. Preserve architecture boundaries:
- core/generic behavior in `src/core/*`
- family/cpu behavior in `src/families/*` and cpu modules
- LSP orchestration in dedicated LSP modules/binary

## Test Cases / Acceptance Scenarios

1. CPU flow-sensitive context
- mixed `.cpu` file uses correct completion/hover/diagnostic context by cursor position

2. Alias correctness
- `.cpu 8080`, `.cpu 6502`, `.cpu 65c816`, `.cpu mega65` resolve expected pipelines

3. Dialect correctness
- z80/intel8080 compatibility and fixit behavior matches existing pipeline logic

4. Validation cadence + cancellation
- debounce works
- on-save always runs
- stale results are dropped

5. Unsaved overlay correctness
- diagnostics reflect unsaved root and unsaved dependency edits

6. Definition coverage
- local + imported (`.use`) + workspace definition resolution works

7. Code action correctness
- `machine-applicable` fixits create preferred quick-fixes
- `maybe-incorrect` fixits are available and non-preferred

## Commit Message Suggestion

Title:
- docs: add opForge language server spec v0.1

Summary:
- Create standalone LSP implementation handoff spec in dedicated branch/worktree.
- Lock phase scope, hybrid backend, CPU-context resolution, validation cadence, root policy, and unsaved-overlay behavior.
- Define architecture, constraints, and acceptance scenarios without changing assembler/runtime behavior.
