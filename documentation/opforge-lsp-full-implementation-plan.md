# opForge LSP Full Functionality Plan (From Current State)

Date: 2026-02-27
Baseline branch state: `codex/opforge-lsp` after commits:
- `8bcef92` (`feat: implement opforge-lsp phase-1 foundation`)
- `8acd744` (`test(lsp): add client-perspective integration harness`)
- `a20257b` (`test(lsp): expand client-perspective acceptance coverage`)

Primary gap to close: current LSP works end-to-end, but several user-facing behaviors still provide thin/placeholder-grade symbol intelligence instead of rich semantic results.

---

## 1. Target Definition: “Full LSP Functionality”

This plan defines “full” as all of the following:

- Protocol-complete Phase 1 features from spec with production-grade responses:
  - diagnostics
  - quick-fix code actions from fixits
  - CPU-aware completion
  - hover
  - go-to-definition
  - document symbols
  - workspace symbols
- Rich symbol semantics:
  - scope/module/visibility-aware symbol model
  - accurate source locations and owner context
  - non-placeholder hover/completion text
- Validation behavior:
  - debounce + on-save + true cancellation (newest version wins under concurrency)
  - unsaved overlay correctness for root + dependencies
  - deterministic diagnostics publishing by affected URI
- Dialect and pipeline parity:
  - explicit z80/intel8080 LSP integration parity checks
  - precedence correctness: dialect -> cpu -> family
- Quality gate:
  - stable integration test framework and acceptance trace with no unresolved required scenarios for current scope.

---

## 2. Current State Summary

### Completed foundations
- Shared registry constructor and VM/editor API exposure.
- LSP binary and protocol/session loop.
- Initial completion/hover/definition/document symbols/code actions handlers.
- CLI validation runner + diagnostics dedup + overlay path remap.
- VS Code reference client scaffold.
- Client-perspective integration tests and acceptance trace matrix.

### Known deficits to resolve
- Symbol info richness is low in hover/completion/definition payloads.
- Symbol model is lightweight and not yet semantic enough (scope/value/visibility depth).
- Validation lane is synchronous in-session; cancellation semantics are only partial.
- Dialect-specific LSP parity assertions are incomplete.

---

## 3. Execution Strategy

- Keep server behavior shippable at each phase.
- Prefer additive refactors with compatibility adapters, then switch call sites.
- Gate each phase with integration tests (client perspective first).
- Ask the user only at explicit decision gates (listed below).

---

## 4. Decision Gates (Only Ask If Needed)

- DG1: Hover content format policy
  Recommendation: concise Markdown with symbol signature + scope/owner + value context + file:line.

- DG2: Definition ranking policy for ambiguous results
  Recommendation: local > imported > workspace global; stable tie-break by URI then line.

- DG3: Cancellation architecture
  Recommendation: background validation worker per workspace with generation tokens and result discard.

- DG4: Workspace indexing scope for large projects
  Recommendation: root-bounded recursive indexing with lazy expansion of unopened module trees.

---

## 5. Implementation Phases (Commit-Oriented)

## Phase A: Semantic Symbol Core

- [ ] A01. Introduce `SymbolId` + semantic symbol model structs (kind, scope, owner module, visibility, declaration span, value excerpt).
- [ ] A02. Refactor `DocumentState` extraction to emit semantic symbols, not just lightweight labels.
- [ ] A03. Add semantic symbol normalization helpers (identifier canonicalization, span utilities, deterministic ordering).
- [ ] A04. Add unit tests for symbol extraction across labels/assignments/modules/namespaces/macros/sections/.use.

Acceptance gate:
- [ ] Symbol extraction tests cover mixed constructs and nested scopes.

## Phase B: Workspace Semantic Index

- [ ] B01. Upgrade `WorkspaceIndex` storage to semantic symbols with per-document and global lookup tables.
- [ ] B02. Add import graph metadata (`.use` edges, alias/selective imports) to index.
- [ ] B03. Implement deterministic resolution API:
  - local scope
  - imported scope/module rules
  - global fallback
- [ ] B04. Add incremental update invalidation strategy (open/change/save/close, root reload).
- [ ] B05. Add index tests for conflicts, shadowing, and deterministic ordering.

Acceptance gate:
- [ ] Multi-file symbol navigation tests pass with stable ordering.

## Phase C: Feature Quality Upgrade (No placeholders)

- [ ] C01. Rework completion payloads to include semantic detail:
  - kind-specific detail
  - owner/module/scope hints
  - pipeline ownership for mnemonics/registers/directives
- [ ] C02. Rework hover payloads to include:
  - symbol kind + declaration site
  - scope/module/visibility
  - value or expression snippet where available
  - mnemonic compatibility context
- [ ] C03. Rework definition payload assembly to use semantic index ranking API.
- [ ] C04. Rework document symbols to output full semantic ranges and kinds.
- [ ] C05. Add client-perspective tests asserting non-placeholder hover/completion content.

Acceptance gate:
- [ ] Hover/completion outputs include semantic metadata; placeholder-only text removed.

## Phase D: Validation Worker + True Cancellation

- [ ] D01. Introduce async validation scheduler module (worker thread/task queue).
- [ ] D02. Add generation/version tokens per document update.
- [ ] D03. Ensure stale validation results are discarded before publish.
- [ ] D04. Preserve debounce and on-save semantics via scheduler interface.
- [ ] D05. Add integration test with slow validator script proving newest-version-wins behavior.

Acceptance gate:
- [ ] Cancellation test demonstrates stale result suppression under overlapping runs.

## Phase E: Overlay and Diagnostics Robustness

- [ ] E01. Extract overlay FS operations into dedicated module with explicit lifecycle and cleanup guarantees.
- [ ] E02. Harden multi-URI publish diagnostics bookkeeping:
  - clear stale URIs per root
  - deterministic publish order
- [ ] E03. Add tests for unsaved root + unsaved dependency with remapped diagnostics/fixits.
- [ ] E04. Add diagnostics regression tests for stable dedup key and no duplicate pass1/pass2 noise.

Acceptance gate:
- [ ] Overlay/remap scenarios pass with deterministic URI mapping.

## Phase F: Dialect/Pipeline Parity Completion

- [ ] F01. Add z80/intel8080 dialect-specific integration fixtures for completion and hover.
- [ ] F02. Add parity tests for CPU alias + dialect mapping interactions.
- [ ] F03. Add code action parity assertions against fixit applicability categories across dialects.
- [ ] F04. Verify precedence (dialect -> cpu -> family) in feature responses with explicit tests.

Acceptance gate:
- [ ] Acceptance trace has no unresolved required dialect scenarios for current release scope.

## Phase G: VS Code Reference Client Completion

- [ ] G01. Add extension smoke tests for initialize + diagnostics + completion path.
- [ ] G02. Validate dynamic config reload behavior with real setting changes.
- [ ] G03. Document known limitations and troubleshooting in client README.

Acceptance gate:
- [ ] Extension host smoke checks pass with documented setup.

## Phase H: Documentation and Release Readiness

- [ ] H01. Update `documentation/opforge-lsp-acceptance-trace.md` to mark resolved items.
- [ ] H02. Add developer docs section for integration harness usage and adding new LSP tests.
- [ ] H03. Update release notes with “semantic symbol upgrade” and cancellation guarantees.
- [ ] H04. Final hardening run:
  - `cargo fmt --all`
  - `cargo clippy -- -D warnings`
  - `cargo test -q`
  - `cargo test --test lsp_client_integration`

Acceptance gate:
- [ ] All quality gates pass and acceptance trace unresolved-required count is zero for release scope.

---

## 6. Suggested Commit Sequence

1. `feat(lsp-symbols): add semantic symbol core model`
2. `feat(lsp-index): add semantic workspace index and deterministic resolution`
3. `feat(lsp-ui): upgrade completion/hover/definition/document symbols payload quality`
4. `feat(lsp-validation): add async validation scheduler with cancellation tokens`
5. `feat(lsp-overlay): harden overlay and multi-uri diagnostics publish`
6. `test(lsp): add dialect and cancellation integration coverage`
7. `feat(vscode): complete reference client smoke checks and config reload validation`
8. `docs(lsp): finalize acceptance trace and release readiness notes`

---

## 7. Risk Register

- Risk: symbol extraction complexity creates regressions.
  Mitigation: dual-path validation in tests during migration phase.

- Risk: cancellation introduces race bugs.
  Mitigation: generation-token assertions in scheduler tests + deterministic integration fixtures.

- Risk: workspace indexing cost for large trees.
  Mitigation: bounded indexing + lazy expansion + cache invalidation metrics.

---

## 8. Definition of Done

- [ ] No placeholder-grade feature responses in completion/hover/definition/document symbols.
- [ ] Cancellation semantics proven by integration tests with concurrent validation.
- [ ] Dialect parity scenarios covered in LSP integration lane.
- [ ] Acceptance trace required scenarios all mapped to passing tests.
- [ ] Full fmt/clippy/test gates pass.
