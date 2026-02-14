# opThread Family-CPU-Dialect Hierarchy Implementation Plan (v0.1 Checklist)

Status: Draft execution checklist  
Last updated: 2026-02-14  
Scope baseline: `dev-docs/NextSteps/opthread_vm_cpu_package_spec_v0_1.md`

## Objective

Implement the opThread package/runtime changes needed to represent and execute the full hierarchy:

- Family owns canonical operand model and canonical dialect.
- CPU belongs to one family and provides default dialect plus extensions.
- Dialect belongs to one family and rewrites syntax before encoding.

Execution must preserve opForge-compatible resolution semantics:

- resolve CPU
- resolve owning family
- dialect selection = override (if provided) else CPU default else family canonical
- no source-level `.dialect` directive in compatibility mode

## Progress Tracking Conventions

- `[ ]` not started
- `[x]` completed
- Keep this checklist updated in commit-sized increments.
- Link each completed item to PR/commit hash in parentheses.

## Phase 0 - Design Lock and Boundaries

- [ ] Confirm normative hierarchy and pipeline rules are frozen in `opthread_vm_cpu_package_spec_v0_1.md`.
- [ ] Freeze chunk names and required/optional status: `META`, `STRS`, `DIAG`, `FAMS`, `CPUS`, `DIAL`, `REGS`, `FORM`, `TABL`, optional `TOKS`, `TEST`.
- [ ] Freeze compatibility behavior: no source `.dialect` directive, dialect override only via host policy.
- [ ] Define package compatibility/versioning policy for future schema evolution.

## Phase 1 - Rust Data Model for Hierarchy

- [x] Create package schema structs/enums for `FamilyDescriptor`, `CpuDescriptor`, `DialectDescriptor`. (`src/opthread/hierarchy.rs`)
- [x] Add normalized identifier handling for family/cpu/dialect ids (case-insensitive lookup keys). (`src/opthread/hierarchy.rs`)
- [x] Add scoped ownership model for `REGS` and `FORM` entries:
- [x] family-scoped
- [x] CPU-scoped
- [x] optional dialect-scoped overlays
- [x] Add validation errors covering:
- [x] missing family for CPU
- [x] missing dialect refs
- [x] cross-family dialect selection
- [x] CPU blocked by dialect compatibility allow-list

## Phase 2 - Package Binary Schema and Loader

- [x] Implement binary read/write support for new hierarchy chunks (`FAMS`, `CPUS`, `DIAL`). (`src/opthread/package.rs`)
- [x] Add schema integrity checks at load time:
- [x] all cross references resolve
- [x] each CPU has exactly one family
- [x] each dialect belongs to exactly one family
- [x] family canonical dialect exists
- [x] Build deterministic diagnostics for malformed packages (stable error codes/messages). (`OpcpuCodecError::code`)
- [x] Add round-trip tests for package serialization/deserialization. (`opthread::package::tests`)

## Phase 3 - Pipeline Resolver (Registry Parity)

- [x] Implement runtime resolver equivalent to `ModuleRegistry::resolve_pipeline`. (`HierarchyPackage::resolve_pipeline`)
- [x] Implement dialect selection order:
- [x] explicit override (error if missing)
- [x] CPU default dialect
- [x] family canonical dialect fallback
- [x] Enforce dialect compatibility policy against selected CPU.
- [x] Return resolved pipeline context: `{family_id, cpu_id, dialect_id}` plus handlers/tables. (`HierarchyPackage::resolve_pipeline_context`)
- [x] Add tests for all resolver branches and failure modes. (`opthread::hierarchy::tests`)

## Phase 4 - Builder/Compiler for Hierarchical Packages

- [x] Implement package builder that emits `FAMS`, `CPUS`, `DIAL` from opForge source model. (`src/opthread/builder.rs`)
- [x] Generate scoped register banks into `REGS`. (`HierarchyChunks::registers`, `REGS` codec chunk)
- [x] Generate scoped form sets into `FORM`:
- [x] family base forms
- [x] CPU extension/override forms
- [x] optional dialect overlays
- [x] Emit stable indices and deterministic ordering for reproducible package bytes. (`canonicalize_hierarchy_metadata`, shared by builder + codec)
- [x] Add snapshot tests for package metadata and table determinism. (`opthread::package::tests::{metadata_snapshot_is_stable,toc_snapshot_is_stable}`)

## Phase 5 - VM Runtime Integration

- [ ] Add active target selection API (`set_active_cpu` equivalent in host/runtime bridge).
- [ ] Add hierarchy-aware `resolve_pipeline(cpu, dialect_override?)` host hook.
- [ ] Wire instruction encode path to resolved hierarchy context.
- [ ] Ensure dialect mapping executes before family/CPU encode path.
- [ ] Ensure dialect layer rewrites only and never directly encodes.
- [ ] Add pass-through behavior for host-owned features (directives/macros/linker/output) unchanged in v0.1 scope.

## Phase 6 - Dialect Rewrite Engine Constraints

- [ ] Implement bounded rewrite passes and growth limits per statement.
- [ ] Implement deterministic matching and rewrite application order.
- [ ] Implement compatibility filtering:
- [ ] family-only dialect namespace
- [ ] optional CPU allow-list
- [ ] Add diagnostics for rewrite overflow and invalid rewrite outputs.
- [ ] Add tests for mixed-family rejection, allow-list rejection, and successful canonical mapping.

## Phase 7 - Pilot Family Migration

- [ ] Select pilot family with at least two CPUs and two dialects (recommended: Intel8080 family with 8085 + Z80 dialect behavior).
- [ ] Port family base forms into package representation.
- [ ] Port CPU extensions for each pilot CPU.
- [ ] Port dialect rewrites for pilot dialect(s).
- [ ] Validate package path output parity against native path for pilot programs.

## Phase 8 - Differential Parity Harness

- [ ] Add harness to run native Rust encoding and opThread package encoding side-by-side.
- [ ] Compare bytes, relocation records, and diagnostics per instruction case.
- [ ] Add parity corpus:
- [ ] existing examples
- [ ] targeted edge cases for ambiguous operands
- [ ] dialect-specific syntax cases
- [ ] unresolved/reloc expression cases
- [ ] Add CI mode for parity smoke tests behind feature flag.

## Phase 9 - Tests and Golden Fixtures

- [ ] Add unit tests for hierarchy schema validators.
- [ ] Add unit tests for resolver selection and errors.
- [ ] Add integration tests for package loading and end-to-end statement encoding.
- [ ] Add `.optst` vectors for family/cpu/dialect-specific behavior.
- [ ] Run tests without updating references first.
- [ ] If only expected diagnostic text/output fixtures differ, regenerate references and rerun tests.

## Phase 10 - Documentation and Developer UX

- [ ] Update `documentation/opForge-reference-manual.md` with hierarchy-aware package/runtime behavior.
- [ ] Document host-policy dialect override mechanism (if exposed), explicitly noting no source `.dialect`.
- [ ] Add package authoring notes for hierarchy ownership:
- [ ] when to put logic in family vs CPU vs dialect
- [ ] compatibility rules and fallback semantics
- [ ] Add migration notes for maintainers converting native handlers to package form.

## Phase 11 - Validation Gates

- [ ] Run `cargo fmt`.
- [ ] Run `cargo clippy -- -D warnings` (or project-equivalent strict clippy target).
- [ ] Run `cargo audit`.
- [ ] Run full test suite (`make test` or `cargo test`).
- [ ] Confirm parity harness pass for enabled pilot targets.
- [ ] Confirm no unexpected reference output drift remains.

## Phase 12 - Rollout and Release Readiness

- [ ] Keep package execution behind feature flag until parity gate is green.
- [ ] Define enablement criteria to expand from pilot family to additional families.
- [ ] Add changelog/release note entries for hierarchy-capable package schema.
- [ ] Record known limitations and deferred work items for v0.2.

## Cross-Cutting Risks and Mitigations

- [ ] Risk: hierarchy metadata drift between builder and loader.
- [ ] Mitigation: schema round-trip tests + deterministic snapshots.
- [ ] Risk: dialect rewrite behavior diverges from native path.
- [ ] Mitigation: differential parity harness on dialect-heavy corpora.
- [ ] Risk: CPU extension ownership ambiguity between family and CPU form sets.
- [ ] Mitigation: explicit ownership rules in docs + validator lint checks.
- [ ] Risk: regressions in existing assembler behavior outside opThread scope.
- [ ] Mitigation: keep integration feature-flagged and run full suite continuously.

## Definition of Done

- [ ] Hierarchy is explicit and validated in package schema (`FAMS`/`CPUS`/`DIAL`).
- [ ] Resolver semantics match opForge registry behavior for all tested branches.
- [ ] VM path correctly applies `Family -> CPU -> Dialect` pipeline order.
- [ ] Pilot family reaches byte/reloc/diagnostic parity with native path.
- [ ] Full required validation workflow is clean (`fmt`, `clippy`, `audit`, full tests).
- [ ] Documentation and migration notes are updated and internally consistent.
